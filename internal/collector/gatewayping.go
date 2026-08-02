package collector

import (
	"context"
	"net/netip"
	"time"

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
// the public-ping collector. Each target may name a NIC in Params.Interface
// (matched against IfaceInfo.ID or Name); an empty value resolves the default
// gateway (first IPv4 gateway on an up, non-loopback interface). Target string
// is the server-normalized "gateway" (stable across gateway IP changes); the
// resolved IP and chosen interface travel in labels.
type GatewayPingCollector struct {
	p     platform.Platform
	guard *netguard.Guard
	sched *schedState
}

func NewGatewayPingCollector(p platform.Platform, guard *netguard.Guard) *GatewayPingCollector {
	// 10s fallback matches the old base-tier cadence, so targets that don't set
	// interval_seconds keep probing at the previous rate rather than every tick.
	return &GatewayPingCollector{p: p, guard: guard, sched: newSchedState(pcfg.DefaultGatewayInterval)}
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

func (c *GatewayPingCollector) Collect(ctx context.Context) (Result, error) {
	targets := c.sched.due(time.Now())
	if len(targets) == 0 {
		return Result{}, nil
	}

	var res Result
	for _, t := range targets {
		// A pass aborted by run cancellation (agent shutdown) must not fabricate
		// loss samples or unreachable events — they would replay from the WAL as a
		// false LAN outage on the next start.
		if ctx.Err() != nil {
			break
		}
		now := time.Now().UTC()
		gw := c.gatewayFor(t.Params.Interface)
		if gw == "" {
			// No gateway found on the selected/default NIC: report LAN-layer down.
			appendICMPMetrics(&res, now, t.MonitorID, t.ConfigSerial, t.Target, telemetry.LayerLAN,
				gatewayLabels("", t.Params.Interface), pingCycleResult{Loss: 100, Reason: telemetry.ProbeReasonUnreachable,
					Detail: "no IPv4 gateway on the selected interface"})
			res.Events = append(res.Events, telemetry.Event{
				ID: newID(), TS: now, Type: telemetry.EventGatewayUnreachable,
				Layer: telemetry.LayerLAN, Severity: telemetry.SeverityWarn,
				Message: "no gateway detected on the selected interface",
				Attrs:   gatewayLabels("", t.Params.Interface),
			})
			continue
		}

		// The gateway must be an address the OS currently reports as a gateway, and
		// must survive an explicit ip:/cidr: deny. The OS-supplied gateway otherwise
		// bypasses scope denies (so a default scope:link-local deny does not break an
		// fe80:: gateway). A block here is a target-policy block, not a ping failure.
		if a, perr := netip.ParseAddr(gw); perr == nil {
			if dec := c.guard.CheckGateway(a.Unmap(), c.osGateways()); !dec.Allowed {
				res.Blocked = append(res.Blocked, BlockedProbe{MonitorID: t.MonitorID, ConfigSerial: t.ConfigSerial, Matched: dec.Matched, Reason: "literal_denied"})
				continue
			}
		}

		r := pingCycle(ctx, c.p, gw, t.Params)
		if ctx.Err() != nil {
			break // cycle aborted mid-flight: unsent echoes are not lost echoes
		}
		labels := gatewayLabels(gw, t.Params.Interface)
		appendICMPMetrics(&res, now, t.MonitorID, t.ConfigSerial, t.Target, telemetry.LayerLAN, labels, r)
		if r.Received == 0 {
			res.Events = append(res.Events, telemetry.Event{
				ID: newID(), TS: now, Type: telemetry.EventGatewayUnreachable,
				Layer: telemetry.LayerLAN, Severity: telemetry.SeverityWarn,
				Message: "gateway " + gw + " did not answer ICMP", Attrs: labels,
			})
		}
	}
	return res, nil
}

// osGateways returns every gateway address the OS currently reports across all
// interfaces, so CheckGateway can confirm the target is a real gateway.
func (c *GatewayPingCollector) osGateways() []netip.Addr {
	ifaces, err := c.p.Interfaces(platform.IfaceQuery{Gateways: true})
	if err != nil {
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

// gatewayFor returns the first IPv4 gateway on the chosen interface. When iface
// is empty it falls back to the default: the first IPv4 gateway on any up,
// non-loopback interface. When iface is set but not found (or has no IPv4
// gateway), it returns "" so the caller reports the gateway as unreachable
// rather than silently probing a different NIC's gateway.
func (c *GatewayPingCollector) gatewayFor(iface string) string {
	ifaces, err := c.p.Interfaces(platform.IfaceQuery{Gateways: true})
	if err != nil {
		return ""
	}
	gateway, _ := platform.ResolveIPv4Gateway(ifaces, iface)
	return gateway
}

// SetMinInterval applies the local per-target probe-interval floor (stability limit).
func (c *GatewayPingCollector) SetMinInterval(d time.Duration) { c.sched.SetMinInterval(d) }
