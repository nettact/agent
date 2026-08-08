package agentrt

import (
	"testing"
	"time"

	"github.com/nettact/agent/internal/collector"
	"github.com/nettact/agent/internal/netguard"
	"github.com/nettact/agent/internal/platform"
	"github.com/nettact/agent/internal/traceroute"
	"github.com/nettact/agent/internal/wal"
	"github.com/nettact/agent/probepolicy"
	"github.com/nettact/protocol/permission"
)

// probeViews grants every probe kind so buildServer constructs all six probe
// collectors.
func probeViews() permViews {
	all := permission.FromStrings([]string{
		string(permission.NetworkGatewayProbe),
		string(permission.ProbeICMP),
		string(permission.ProbeDNS),
		string(permission.ProbeHTTP),
		string(permission.ProbeTCP),
		string(permission.ProbeNAT),
	})
	return permViews{
		granted:   all,
		supported: all,
		effective: all,
		guard:     netguard.New(probepolicy.Policy{}, true),
		source:    permission.SourceDefault,
		hash:      "test",
	}
}

// budgeted is the accessor every probe collector inherits from probeRunner.
type budgeted interface{ Budget() *collector.ProbeGate }

// The probe budget is the machine's, so every probe collector of every server
// must draw from the SAME one.
//
// This is the assembly half of what ProbeGate documents. Sized per collector it
// would be multiplied by six (gateway, icmp, dns, http, tcp, nat); sized per
// server, by the number of servers on top of that. Either way a user who set
// max_probe_concurrency to 16 would get an agent that runs far more than 16
// probes at once — the knob would read as enforced while enforcing nothing,
// which is worse than the unwired knob this replaced.
func TestEveryProbeCollectorSharesOneBudget(t *testing.T) {
	outbox, err := wal.Open(t.TempDir(), []string{"alpha", "beta"})
	if err != nil {
		t.Fatalf("open wal: %v", err)
	}
	t.Cleanup(func() { _ = outbox.Close() })

	gate := collector.NewProbeGate(16)
	limits := DefaultLimits()
	traceLimit := traceroute.NewLimiter(limits.MaxTraceConcurrency)
	p := platform.New()

	var probes []budgeted
	for _, name := range []string{"alpha", "beta"} {
		rt := buildServer(ServerConfig{Name: name}, probeViews(), report(), outbox, p,
			limits, 30*time.Second, traceLimit, gate, "test-host")
		for _, c := range rt.configurables {
			b, ok := c.(budgeted)
			if !ok {
				// Not every configurable is a probe collector. The traceroute trigger
				// is handed the same pushed targets — it plans a diagnostic from the
				// target that failed — but it runs no probes, so its concurrency is
				// the traceroute limiter's business and not this gate's. The count
				// assertion below is what still catches a probe kind going missing.
				continue
			}
			probes = append(probes, b)
		}
	}

	// Six probe kinds × two servers. A smaller number means a kind stopped being
	// built and this test silently stopped covering it.
	if len(probes) != 12 {
		t.Fatalf("built %d probe collectors, want 12 (6 kinds × 2 servers)", len(probes))
	}
	for i, b := range probes {
		if got := b.Budget(); got != gate {
			t.Fatalf("probe collector %d draws from a different budget (%p, want %p)", i, got, gate)
		}
	}
}

// A zero/absent MaxProbeConcurrency means unlimited rather than some invented
// default: the runtime fills the configured value from DefaultLimits before it
// reaches the gate, so a nil one here would be a wiring bug, not a config to
// guess at.
func TestProbeGateFromLimits(t *testing.T) {
	if g := collector.NewProbeGate(DefaultLimits().MaxProbeConcurrency); g == nil {
		t.Fatal("the default limits produced an unlimited gate")
	} else if got := g.Limit(); got != DefaultLimits().MaxProbeConcurrency {
		t.Fatalf("gate limit = %d, want %d", got, DefaultLimits().MaxProbeConcurrency)
	}
	if collector.NewProbeGate(0) != nil {
		t.Fatal("an unset budget should be unlimited")
	}
}

// report is an empty permission report; buildServer only stores it.
func report() permission.PermissionReport { return permission.PermissionReport{} }
