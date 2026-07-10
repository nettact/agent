package collector

import (
	"context"
	"sync"
	"time"

	"github.com/nettact/agent/internal/platform"
	"github.com/nettact/protocol/capability"
	pcfg "github.com/nettact/protocol/config"
	"github.com/nettact/protocol/telemetry"
)

// PublicPingCollector pings a set of public targets pushed down from the server
// as DesiredState (architecture §4 internet layer). This is the config-downlink
// demonstration: the target list is not compiled in — the server controls it.
type PublicPingCollector struct {
	p       platform.Platform
	timeout time.Duration
	mu      sync.RWMutex
	targets []string
}

func NewPublicPingCollector(p platform.Platform) *PublicPingCollector {
	return &PublicPingCollector{p: p, timeout: 2 * time.Second}
}

// SetTargets replaces the ICMP target list from a DesiredState update.
func (c *PublicPingCollector) SetTargets(targets []pcfg.ProbeTarget) {
	var ips []string
	for _, t := range targets {
		if t.Kind == "icmp" && t.Target != "" {
			ips = append(ips, t.Target)
		}
	}
	c.mu.Lock()
	c.targets = ips
	c.mu.Unlock()
}

func (c *PublicPingCollector) Name() string { return "public_ping" }

func (c *PublicPingCollector) Capabilities() []capability.Capability {
	return []capability.Capability{capability.ProbeICMP}
}

func (c *PublicPingCollector) Tier() Tier { return TierBase }

func (c *PublicPingCollector) Collect(ctx context.Context) (Result, error) {
	c.mu.RLock()
	targets := append([]string(nil), c.targets...)
	c.mu.RUnlock()

	now := time.Now().UTC()
	var res Result
	for _, tgt := range targets {
		pr, err := c.p.Ping(ctx, tgt, c.timeout)
		if err != nil {
			continue
		}
		labels := map[string]string{"ip": tgt}
		if pr.Received {
			res.Metrics = append(res.Metrics,
				telemetry.Metric{TS: now, Kind: telemetry.ICMPRTTms, Target: tgt, Layer: telemetry.LayerInternet,
					Value: float64(pr.RTT.Microseconds()) / 1000.0, Unit: telemetry.UnitMs, Labels: labels},
				telemetry.Metric{TS: now, Kind: telemetry.ICMPLoss, Target: tgt, Layer: telemetry.LayerInternet,
					Value: 0, Unit: telemetry.UnitPct, Labels: labels},
			)
		} else {
			res.Metrics = append(res.Metrics,
				telemetry.Metric{TS: now, Kind: telemetry.ICMPLoss, Target: tgt, Layer: telemetry.LayerInternet,
					Value: 100, Unit: telemetry.UnitPct, Labels: labels},
			)
		}
	}
	return res, nil
}
