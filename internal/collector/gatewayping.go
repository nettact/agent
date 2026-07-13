package collector

import (
	"context"
	"net"
	"time"

	"github.com/nettact/agent/internal/platform"
	"github.com/nettact/protocol/capability"
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
	sched *schedState
}

func NewGatewayPingCollector(p platform.Platform) *GatewayPingCollector {
	// 10s fallback matches the old base-tier cadence, so targets that don't set
	// interval_seconds keep probing at the previous rate rather than every tick.
	return &GatewayPingCollector{p: p, sched: newSchedState(10 * time.Second)}
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

func (c *GatewayPingCollector) Capabilities() []capability.Capability {
	return []capability.Capability{capability.ProbeICMP}
}

func (c *GatewayPingCollector) Tier() Tier { return TierBase }

func (c *GatewayPingCollector) Collect(ctx context.Context) (Result, error) {
	targets := c.sched.due(time.Now())
	if len(targets) == 0 {
		return Result{}, nil
	}

	var res Result
	for _, t := range targets {
		now := time.Now().UTC()
		gw := c.gatewayFor(t.Params.Interface)
		if gw == "" {
			// No gateway found on the selected/default NIC: report LAN-layer down.
			res.Metrics = append(res.Metrics, telemetry.Metric{
				TS: now, Kind: telemetry.ICMPLoss, Target: t.Target,
				Layer: telemetry.LayerLAN, Value: 100, Unit: telemetry.UnitPct,
				Labels: gatewayLabels("", t.Params.Interface), MonitorID: t.MonitorID,
			})
			res.Events = append(res.Events, telemetry.Event{
				ID: newID(), TS: now, Type: telemetry.EventGatewayUnreachable,
				Layer: telemetry.LayerLAN, Severity: telemetry.SeverityWarn,
				Message: "no gateway detected on the selected interface",
				Attrs:   gatewayLabels("", t.Params.Interface),
			})
			continue
		}

		loss, avgMs, received := pingCycle(ctx, c.p, gw, t.Params)
		labels := gatewayLabels(gw, t.Params.Interface)
		res.Metrics = append(res.Metrics,
			telemetry.Metric{TS: now, Kind: telemetry.ICMPLoss, Target: t.Target,
				Layer: telemetry.LayerLAN, Value: loss, Unit: telemetry.UnitPct,
				Labels: labels, MonitorID: t.MonitorID},
		)
		if received > 0 {
			res.Metrics = append(res.Metrics,
				telemetry.Metric{TS: now, Kind: telemetry.ICMPRTTms, Target: t.Target,
					Layer: telemetry.LayerLAN, Value: avgMs, Unit: telemetry.UnitMs,
					Labels: labels, MonitorID: t.MonitorID},
			)
		} else {
			res.Events = append(res.Events, telemetry.Event{
				ID: newID(), TS: now, Type: telemetry.EventGatewayUnreachable,
				Layer: telemetry.LayerLAN, Severity: telemetry.SeverityWarn,
				Message: "gateway " + gw + " did not answer ICMP", Attrs: labels,
			})
		}
	}
	return res, nil
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
	ifaces, err := c.p.Interfaces()
	if err != nil {
		return ""
	}
	for _, ifc := range ifaces {
		if ifc.IsLoopback || !ifc.Up {
			continue
		}
		if iface != "" && ifc.ID != iface && ifc.Name != iface {
			continue
		}
		for _, gw := range ifc.Gateways {
			if ip := net.ParseIP(gw); ip != nil && ip.To4() != nil {
				return gw
			}
		}
	}
	return ""
}
