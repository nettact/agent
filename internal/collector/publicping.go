package collector

import (
	"context"
	"time"

	"github.com/nettact/agent/internal/platform"
	"github.com/nettact/protocol/capability"
	pcfg "github.com/nettact/protocol/config"
	"github.com/nettact/protocol/telemetry"
)

// PublicPingCollector pings a set of public targets pushed down from the server
// as DesiredState (architecture §4 internet layer). Each target carries its own
// per-protocol params (timeout, packet size, retries, interval) and is probed on
// its own schedule via schedState — the agent drives Collect on a fine tick.
type PublicPingCollector struct {
	p     platform.Platform
	sched *schedState
}

func NewPublicPingCollector(p platform.Platform) *PublicPingCollector {
	// 10s fallback matches the old base-tier cadence, so targets that don't set
	// interval_seconds keep probing at the previous rate rather than every tick.
	return &PublicPingCollector{p: p, sched: newSchedState(10 * time.Second)}
}

// SetTargets replaces the ICMP target list from a DesiredState update.
func (c *PublicPingCollector) SetTargets(targets []pcfg.ProbeTarget) {
	var icmp []pcfg.ProbeTarget
	for _, t := range targets {
		if t.Kind == "icmp" && t.Target != "" {
			icmp = append(icmp, t)
		}
	}
	c.sched.set(icmp)
}

func (c *PublicPingCollector) Name() string { return "public_ping" }

func (c *PublicPingCollector) Capabilities() []capability.Capability {
	return []capability.Capability{capability.ProbeICMP}
}

func (c *PublicPingCollector) Tier() Tier { return TierBase }

func (c *PublicPingCollector) Collect(ctx context.Context) (Result, error) {
	targets := c.sched.due(time.Now())
	if len(targets) == 0 {
		return Result{}, nil
	}

	now := time.Now().UTC()
	var res Result
	for _, t := range targets {
		count := t.Params.Retries + 1
		if count < 1 {
			count = 1
		}
		timeout := time.Duration(t.Params.TimeoutMs) * time.Millisecond
		if timeout <= 0 {
			timeout = 2 * time.Second
		}
		opts := platform.PingOptions{Timeout: timeout, PayloadSize: t.Params.PacketSize}

		received := 0
		var rttSum time.Duration
		for i := 0; i < count; i++ {
			pr, err := c.p.Ping(ctx, t.Target, opts)
			if err != nil {
				continue
			}
			if pr.Received {
				received++
				rttSum += pr.RTT
			}
		}
		labels := map[string]string{"ip": t.Target}
		loss := float64(count-received) / float64(count) * 100.0
		res.Metrics = append(res.Metrics,
			telemetry.Metric{TS: now, Kind: telemetry.ICMPLoss, Target: t.Target, Layer: telemetry.LayerInternet,
				Value: loss, Unit: telemetry.UnitPct, Labels: labels})
		if received > 0 {
			avgMs := float64(rttSum.Microseconds()) / float64(received) / 1000.0
			res.Metrics = append(res.Metrics,
				telemetry.Metric{TS: now, Kind: telemetry.ICMPRTTms, Target: t.Target, Layer: telemetry.LayerInternet,
					Value: avgMs, Unit: telemetry.UnitMs, Labels: labels})
		}
	}
	return res, nil
}
