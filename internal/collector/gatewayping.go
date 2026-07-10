package collector

import (
	"context"
	"net"
	"time"

	"github.com/nettact/agent/internal/platform"
	"github.com/nettact/protocol/capability"
	"github.com/nettact/protocol/telemetry"
)

// GatewayPingCollector pings the default gateway and reports RTT + loss. A dead
// gateway is the first branch of the §4 layered diagnosis (local/LAN fault vs
// WAN fault). Target is always "gateway" (stable across gateway IP changes);
// the actual IP is carried in a label.
type GatewayPingCollector struct {
	p       platform.Platform
	timeout time.Duration
}

func NewGatewayPingCollector(p platform.Platform) *GatewayPingCollector {
	return &GatewayPingCollector{p: p, timeout: 2 * time.Second}
}

func (c *GatewayPingCollector) Name() string { return "gateway_ping" }

func (c *GatewayPingCollector) Capabilities() []capability.Capability {
	return []capability.Capability{capability.ProbeICMP}
}

func (c *GatewayPingCollector) Tier() Tier { return TierBase }

func (c *GatewayPingCollector) Collect(ctx context.Context) (Result, error) {
	gw := c.defaultGateway()
	if gw == "" {
		// No gateway configured/detected: report LAN-layer down and an event.
		now := time.Now().UTC()
		return Result{
			Metrics: []telemetry.Metric{{
				TS: now, Kind: telemetry.ICMPLoss, Target: "gateway",
				Layer: telemetry.LayerLAN, Value: 100, Unit: telemetry.UnitPct,
			}},
			Events: []telemetry.Event{{
				ID: newID(), TS: now, Type: telemetry.EventGatewayUnreachable,
				Layer: telemetry.LayerLAN, Severity: telemetry.SeverityWarn,
				Message: "no default gateway detected",
			}},
		}, nil
	}

	pr, err := c.p.Ping(ctx, gw, platform.PingOptions{Timeout: c.timeout})
	if err != nil {
		return Result{}, err
	}
	now := time.Now().UTC()
	labels := map[string]string{"ip": gw}
	var res Result
	if pr.Received {
		res.Metrics = append(res.Metrics,
			telemetry.Metric{TS: now, Kind: telemetry.ICMPRTTms, Target: "gateway",
				Layer: telemetry.LayerLAN, Value: float64(pr.RTT.Microseconds()) / 1000.0,
				Unit: telemetry.UnitMs, Labels: labels},
			telemetry.Metric{TS: now, Kind: telemetry.ICMPLoss, Target: "gateway",
				Layer: telemetry.LayerLAN, Value: 0, Unit: telemetry.UnitPct, Labels: labels},
		)
	} else {
		res.Metrics = append(res.Metrics,
			telemetry.Metric{TS: now, Kind: telemetry.ICMPLoss, Target: "gateway",
				Layer: telemetry.LayerLAN, Value: 100, Unit: telemetry.UnitPct, Labels: labels},
		)
		res.Events = append(res.Events, telemetry.Event{
			ID: newID(), TS: now, Type: telemetry.EventGatewayUnreachable,
			Layer: telemetry.LayerLAN, Severity: telemetry.SeverityWarn,
			Message: "gateway " + gw + " did not answer ICMP", Attrs: labels,
		})
	}
	return res, nil
}

// defaultGateway returns the first IPv4 gateway on an up, non-loopback iface.
func (c *GatewayPingCollector) defaultGateway() string {
	ifaces, err := c.p.Interfaces()
	if err != nil {
		return ""
	}
	for _, ifc := range ifaces {
		if ifc.IsLoopback || !ifc.Up {
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
