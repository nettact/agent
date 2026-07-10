package collector

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/nettact/protocol/capability"
	pcfg "github.com/nettact/protocol/config"
	"github.com/nettact/protocol/telemetry"
)

// DNSCollector resolves a server-configured set of names and reports resolve
// latency + success (architecture §4 DNS layer).
type DNSCollector struct {
	mu       sync.RWMutex
	names    []string
	resolver *net.Resolver
	timeout  time.Duration
}

func NewDNSCollector() *DNSCollector {
	return &DNSCollector{resolver: net.DefaultResolver, timeout: 3 * time.Second}
}

func (c *DNSCollector) SetTargets(targets []pcfg.ProbeTarget) {
	var names []string
	for _, t := range targets {
		if t.Kind == "dns" && t.Target != "" {
			names = append(names, t.Target)
		}
	}
	c.mu.Lock()
	c.names = names
	c.mu.Unlock()
}

func (c *DNSCollector) Name() string { return "dns" }

func (c *DNSCollector) Capabilities() []capability.Capability {
	return []capability.Capability{capability.ProbeDNS}
}

func (c *DNSCollector) Tier() Tier { return TierRegular }

func (c *DNSCollector) Collect(ctx context.Context) (Result, error) {
	c.mu.RLock()
	names := append([]string(nil), c.names...)
	c.mu.RUnlock()

	now := time.Now().UTC()
	var res Result
	for _, name := range names {
		cctx, cancel := context.WithTimeout(ctx, c.timeout)
		t0 := time.Now()
		addrs, err := c.resolver.LookupHost(cctx, name)
		cancel()
		ok := err == nil && len(addrs) > 0

		okv := 0.0
		if ok {
			okv = 1.0
		}
		res.Metrics = append(res.Metrics, telemetry.Metric{
			TS: now, Kind: telemetry.DNSOK, Target: name, Layer: telemetry.LayerDNS, Value: okv, Unit: telemetry.UnitBool,
		})
		if ok {
			res.Metrics = append(res.Metrics, telemetry.Metric{
				TS: now, Kind: telemetry.DNSResolve, Target: name, Layer: telemetry.LayerDNS,
				Value: float64(time.Since(t0).Microseconds()) / 1000.0, Unit: telemetry.UnitMs,
			})
		} else {
			res.Events = append(res.Events, telemetry.Event{
				ID: newID(), TS: now, Type: telemetry.EventProbeFailed, Layer: telemetry.LayerDNS,
				Severity: telemetry.SeverityWarn, Message: "DNS resolve failed: " + name,
			})
		}
	}
	return res, nil
}
