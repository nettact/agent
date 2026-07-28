package incidentscene

import (
	"context"
	"testing"
	"time"

	"github.com/nettact/agent/internal/netguard"
	"github.com/nettact/agent/probepolicy"
	pcfg "github.com/nettact/protocol/config"
	"github.com/nettact/protocol/telemetry"
)

// A spent collection budget must be reported as a timeout on every target, never
// as a DNS failure. The stdlib resolver wraps a dead context in a *net.DNSError,
// so classifying every resolve error as dns_error made an agent-side budget
// expiry (historically: a request deadline minted on a skewed server clock) look
// like the monitored target's name had stopped resolving.
func TestExpiredBudgetReportsTimeoutNotDNSError(t *testing.T) {
	guard := netguard.New(probepolicy.Default(), false)
	deps := Deps{Guard: guard, Identity: Identity{AgentID: "agent_1"}}
	req := pcfg.IncidentSnapshotRequest{
		RequestID:  "isnapreq_1",
		IncidentID: "inc_1",
		Targets: []pcfg.SnapshotTargetRef{
			{MonitorID: "mon_http", Kind: "http", Target: "http://connect.rom.miui.com/generate_204"},
			{MonitorID: "mon_icmp", Kind: "icmp", Target: "example.invalid"},
		},
	}

	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	snap := Collect(ctx, req, deps)

	if len(snap.Targets) != len(req.Targets) {
		t.Fatalf("targets = %d, want %d", len(snap.Targets), len(req.Targets))
	}
	for _, tg := range snap.Targets {
		if tg.ErrorClass != errClassTimeout {
			t.Errorf("target %s error class = %q, want %q", tg.MonitorID, tg.ErrorClass, errClassTimeout)
		}
		if len(tg.ResolvedIPs) != 0 {
			t.Errorf("target %s resolved %v with a spent budget", tg.MonitorID, tg.ResolvedIPs)
		}
	}

	// The HTTP target still reports the endpoint it would have probed (host:port
	// from the URL), so the scene shows what was attempted even with no answer.
	if got := snap.Targets[0].Endpoints; len(got) != 1 || got[0] != "connect.rom.miui.com:80" {
		t.Errorf("http endpoints = %v, want [connect.rom.miui.com:80]", got)
	}

	// A session teardown is a distinct class from budget exhaustion.
	cctx, ccancel := context.WithCancel(context.Background())
	ccancel()
	if got := Collect(cctx, req, deps).Targets[0].ErrorClass; got != errClassCanceled {
		t.Errorf("canceled error class = %q, want %q", got, errClassCanceled)
	}
}

// A literal-IP target needs no resolver, so a spent budget must not stop it from
// reporting the address and endpoint the probe would have used.
func TestLiteralIPTargetResolvesWithoutBudget(t *testing.T) {
	deps := Deps{Guard: netguard.New(probepolicy.Default(), false)}
	req := pcfg.IncidentSnapshotRequest{
		RequestID: "isnapreq_2", IncidentID: "inc_2",
		Targets: []pcfg.SnapshotTargetRef{{MonitorID: "mon_tcp", Kind: "tcp", Target: "192.0.2.10", Port: 443}},
	}

	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	tg := Collect(ctx, req, deps).Targets[0]

	if tg.ErrorClass != "" {
		t.Errorf("error class = %q, want empty", tg.ErrorClass)
	}
	if len(tg.ResolvedIPs) != 1 || tg.ResolvedIPs[0] != "192.0.2.10" {
		t.Errorf("resolved = %v, want [192.0.2.10]", tg.ResolvedIPs)
	}
	if len(tg.Endpoints) != 1 || tg.Endpoints[0] != "192.0.2.10:443" {
		t.Errorf("endpoints = %v, want [192.0.2.10:443]", tg.Endpoints)
	}
}

// Every attempted group is classified even when the budget is spent and no
// permission is granted, so the server always gets a complete, terminal scene.
func TestGroupsAlwaysReported(t *testing.T) {
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	snap := Collect(ctx, pcfg.IncidentSnapshotRequest{RequestID: "isnapreq_3", IncidentID: "inc_3"},
		Deps{Guard: netguard.New(probepolicy.Default(), false)})

	got := map[string]string{}
	for _, g := range snap.Groups {
		got[g.Group] = g.Status
	}
	for _, group := range []string{
		telemetry.SnapshotGroupNetwork, telemetry.SnapshotGroupAgent,
		telemetry.SnapshotGroupResources, telemetry.SnapshotGroupTargets,
	} {
		if got[group] == "" {
			t.Errorf("group %s missing from %v", group, got)
		}
	}
	if got[telemetry.SnapshotGroupAgent] != telemetry.ScopeCollected {
		t.Errorf("agent group = %q, want %q", got[telemetry.SnapshotGroupAgent], telemetry.ScopeCollected)
	}
}
