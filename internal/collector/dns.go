package collector

import (
	"context"
	"net"
	"time"

	"github.com/nettact/protocol/capability"
	pcfg "github.com/nettact/protocol/config"
	"github.com/nettact/protocol/telemetry"
)

// DNSCollector resolves a server-configured set of names and reports resolve
// latency + success (architecture §4 DNS layer). Each name carries its own
// per-target params (timeout, interval, record type) and is probed on its own
// schedule via schedState.
type DNSCollector struct {
	resolver *net.Resolver
	sched    *schedState
}

func NewDNSCollector() *DNSCollector {
	return &DNSCollector{resolver: net.DefaultResolver, sched: newSchedState(30 * time.Second)}
}

func (c *DNSCollector) SetTargets(targets []pcfg.ProbeTarget) {
	var names []pcfg.ProbeTarget
	for _, t := range targets {
		if t.Kind == "dns" && t.Target != "" {
			names = append(names, t)
		}
	}
	c.sched.set(names)
}

func (c *DNSCollector) Name() string { return "dns" }

func (c *DNSCollector) Capabilities() []capability.Capability {
	return []capability.Capability{capability.ProbeDNS}
}

func (c *DNSCollector) Tier() Tier { return TierRegular }

func (c *DNSCollector) Collect(ctx context.Context) (Result, error) {
	targets := c.sched.due(time.Now())
	if len(targets) == 0 {
		return Result{}, nil
	}

	now := time.Now().UTC()
	var res Result
	for _, t := range targets {
		timeout := time.Duration(t.Params.TimeoutMs) * time.Millisecond
		if timeout <= 0 {
			timeout = 3 * time.Second
		}
		network := "ip"
		switch t.Params.RecordType {
		case "A":
			network = "ip4"
		case "AAAA":
			network = "ip6"
		}

		cctx, cancel := context.WithTimeout(ctx, timeout)
		t0 := time.Now()
		addrs, err := c.resolver.LookupIP(cctx, network, t.Target)
		cancel()
		ok := err == nil && len(addrs) > 0

		okv := 0.0
		if ok {
			okv = 1.0
		}
		res.Metrics = append(res.Metrics, telemetry.Metric{
			TS: now, Kind: telemetry.DNSOK, Target: t.Target, Layer: telemetry.LayerDNS, Value: okv, Unit: telemetry.UnitBool,
		})
		if ok {
			res.Metrics = append(res.Metrics, telemetry.Metric{
				TS: now, Kind: telemetry.DNSResolve, Target: t.Target, Layer: telemetry.LayerDNS,
				Value: float64(time.Since(t0).Microseconds()) / 1000.0, Unit: telemetry.UnitMs,
			})
		} else {
			res.Events = append(res.Events, telemetry.Event{
				ID: newID(), TS: now, Type: telemetry.EventProbeFailed, Layer: telemetry.LayerDNS,
				Severity: telemetry.SeverityWarn, Message: "DNS resolve failed: " + t.Target,
			})
		}
	}
	return res, nil
}
