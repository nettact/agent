package collector

import (
	"context"
	"errors"
	"net/netip"

	"github.com/nettact/agent/internal/netguard"
	"github.com/nettact/agent/internal/platform"
	pcfg "github.com/nettact/protocol/config"
	"github.com/nettact/protocol/telemetry"
)

// GatewayPingCollector pings the default gateway of a chosen NIC and reports RTT
// + loss on the LAN layer. A dead gateway is the first branch of the §4 layered
// diagnosis (local/LAN fault vs WAN fault).
//
// Unlike the old always-on probe, gateways are now user-configured monitors
// (kind="gateway") pushed down as DesiredState, self-scheduled per target like
// the public-ping collector — each due target's cycle runs on its own goroutine
// (see pingRunner). Each target may name a NIC in Params.Interface (matched
// against IfaceInfo.ID or Name); an empty value resolves the default gateway
// (first IPv4 gateway on an up, non-loopback interface). Target string is the
// server-normalized "gateway" (stable across gateway IP changes); the resolved IP
// and chosen interface travel in labels.
type GatewayPingCollector struct {
	p     platform.Platform
	guard *netguard.Guard
	*pingRunner
}

func NewGatewayPingCollector(p platform.Platform, guard *netguard.Guard) *GatewayPingCollector {
	// 10s fallback matches the old base-tier cadence, so targets that don't set
	// interval_seconds keep probing at the previous rate rather than every tick.
	return &GatewayPingCollector{p: p, guard: guard, pingRunner: newPingRunner(pcfg.DefaultGatewayInterval)}
}

// SetTargets replaces the gateway target list from a DesiredState update.
func (c *GatewayPingCollector) SetTargets(targets []pcfg.ProbeTarget) {
	var gw []pcfg.ProbeTarget
	for _, t := range targets {
		if t.Kind == "gateway" {
			gw = append(gw, t)
		}
	}
	c.sched.set(gw)
}

func (c *GatewayPingCollector) Name() string { return "gateway_ping" }

func (c *GatewayPingCollector) Tier() Tier { return TierBase }

// Collect hands back the cycles that finished since the last pass and starts the
// targets that have come due. A target's samples therefore surface on a later
// tick than the Collect that started it — see pingRunner for why the cycles no
// longer run inline.
func (c *GatewayPingCollector) Collect(ctx context.Context) (Result, error) {
	return c.collect(ctx, c.runTarget), nil
}

// runTarget resolves and probes one gateway target, returning everything that
// one cycle produced. It runs on its own goroutine.
func (c *GatewayPingCollector) runTarget(ctx context.Context, sp scheduledProbe) Result {
	t := sp.Target
	// A cycle aborted by run cancellation (agent shutdown) must not fabricate
	// loss samples or unreachable events — they would replay from the WAL as a
	// false LAN outage on the next start.
	if ctx.Err() != nil {
		return Result{}
	}
	var res Result
	gw, known := c.gatewayFor(t.Params.Interface)
	if !known {
		// The agent could not read the routes, so whether this host has a gateway
		// is UNKNOWN. Skipping leaves an honest gap in the series; the branch
		// below would instead publish 100% loss and a LAN-outage event for a
		// restriction on the agent itself.
		return Result{}
	}
	if gw == "" {
		// No gateway found on the selected/default NIC: report LAN-layer down.
		now := cycleNow().UTC()
		appendICMPMetrics(&res, now, t.MonitorID, t.ConfigSerial, t.Target, telemetry.LayerLAN,
			gatewayLabels("", t.Params.Interface), pingCycleResult{Loss: 100, Reason: telemetry.ProbeReasonUnreachable,
				Detail: "no IPv4 gateway on the selected interface"})
		res.Events = append(res.Events, telemetry.Event{
			ID: newID(), TS: now, Type: telemetry.EventGatewayUnreachable,
			Layer: telemetry.LayerLAN, Severity: telemetry.SeverityWarn,
			Message: "no gateway detected on the selected interface",
			Attrs:   gatewayLabels("", t.Params.Interface),
		})
		return res
	}

	// The gateway must be an address the OS currently reports as a gateway, and
	// must survive an explicit ip:/cidr: deny. The OS-supplied gateway otherwise
	// bypasses scope denies (so a default scope:link-local deny does not break an
	// fe80:: gateway). A block here is a target-policy block, not a ping failure.
	if a, perr := netip.ParseAddr(gw); perr == nil {
		if dec := c.guard.CheckGateway(a.Unmap(), c.osGateways()); !dec.Allowed {
			res.Blocked = append(res.Blocked, BlockedProbe{MonitorID: t.MonitorID, ConfigSerial: t.ConfigSerial, Matched: dec.Matched, Reason: "literal_denied"})
			return res
		}
	}

	r := pingCycle(ctx, c.p, gw, t.Params, pacingDeadline(sp))
	if ctx.Err() != nil {
		return Result{} // cycle aborted mid-flight: unsent echoes are not lost echoes
	}
	// Stamped at completion, not at the start of the pass: a spread cycle spans
	// most of its interval, and the sample summarizes the window that just ended.
	now := cycleNow().UTC()
	labels := gatewayLabels(gw, t.Params.Interface)
	appendICMPMetrics(&res, now, t.MonitorID, t.ConfigSerial, t.Target, telemetry.LayerLAN, labels, r)
	if r.Received == 0 {
		res.Events = append(res.Events, telemetry.Event{
			ID: newID(), TS: now, Type: telemetry.EventGatewayUnreachable,
			Layer: telemetry.LayerLAN, Severity: telemetry.SeverityWarn,
			Message: "gateway " + gw + " did not answer ICMP", Attrs: labels,
		})
	}
	return res
}

// osGateways returns every gateway address the OS currently reports across all
// interfaces, so CheckGateway can confirm the target is a real gateway.
func (c *GatewayPingCollector) osGateways() []netip.Addr {
	// An unreadable routing table still leaves each adapter's gateway addresses
	// populated on platforms that read them separately, and the guard only needs
	// to recognize the address. Returning nothing there would have it reject a
	// gateway the OS does report.
	ifaces, err := c.p.Interfaces(platform.IfaceQuery{Gateways: true})
	if err != nil && !errors.Is(err, platform.ErrRoutesUnreadable) {
		return nil
	}
	var out []netip.Addr
	for _, ifc := range ifaces {
		for _, gw := range ifc.Gateways {
			if a, perr := netip.ParseAddr(gw); perr == nil {
				out = append(out, a.Unmap())
			}
		}
	}
	return out
}

// gatewayLabels builds the metric/event label set. The chosen interface is only
// included when set (empty means "default NIC").
func gatewayLabels(ip, iface string) map[string]string {
	labels := map[string]string{}
	if ip != "" {
		labels["ip"] = ip
	}
	if iface != "" {
		labels["interface"] = iface
	}
	return labels
}

// gatewayFor returns the IPv4 gateway of the chosen interface. When iface is
// empty it resolves default egress. When iface is set but not found (or has no
// IPv4 default route) it returns "", so the caller reports the gateway as
// unreachable rather than silently probing a different NIC's gateway.
//
// The bool reports whether the OS answered at all. A failed interface
// enumeration or an unreadable routing table (ErrRoutesUnreadable — a seccomp
// policy, a locked-down container) leaves the question UNKNOWN, and unknown is
// not absent: collapsing the two into an empty gateway made the collector report
// a restriction on the agent as a dead LAN.
func (c *GatewayPingCollector) gatewayFor(iface string) (string, bool) {
	ifaces, err := c.p.Interfaces(platform.IfaceQuery{Gateways: true})
	if err != nil {
		return "", false
	}
	gateway, _ := platform.ResolveIPv4Gateway(ifaces, iface)
	return gateway, true
}
