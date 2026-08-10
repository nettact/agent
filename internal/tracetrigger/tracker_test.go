package tracetrigger

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/nettact/agent/internal/traceroute"
	pcfg "github.com/nettact/protocol/config"
	"github.com/nettact/protocol/permission"
	"github.com/nettact/protocol/telemetry"
)

// harness is a tracker wired to a recording runner and sink, so a test asserts
// on what would have been traced without opening a socket.
type harness struct {
	t   *testing.T
	trk *Tracker

	mu      sync.Mutex
	reqs    []traceroute.Request
	results []telemetry.TraceResult
	edges   []FaultEdge
}

func newHarness(t *testing.T, targets []pcfg.ProbeTarget, perms ...permission.ID) *harness {
	return newProxyHarness(t, targets, nil, perms...)
}

// newProxyHarness is newHarness with an egress lookup, for the pinned-target
// plans whose cohort depends on the proxy spec's own generation.
func newProxyHarness(t *testing.T, targets []pcfg.ProbeTarget, proxies ProxyLookup, perms ...permission.ID) *harness {
	t.Helper()
	if len(perms) == 0 {
		perms = []permission.ID{permission.DiagnosticTracerouteICMP, permission.DiagnosticTracerouteTCP}
	}
	set := permission.Set{}
	for _, p := range perms {
		set.Add(p)
	}
	h := &harness{t: t}
	h.trk = New("test", set, set, set, proxies,
		func(_ context.Context, req traceroute.Request, _ time.Time) telemetry.TraceResult {
			h.mu.Lock()
			h.reqs = append(h.reqs, req)
			h.mu.Unlock()
			return telemetry.TraceResult{
				ReportID: req.ReportID, Mode: req.Mode, DestKey: req.DestKey,
				Status: telemetry.TraceStatusSucceeded,
			}
		},
		func(res telemetry.TraceResult) {
			h.mu.Lock()
			h.results = append(h.results, res)
			h.mu.Unlock()
		},
		func(e FaultEdge) {
			h.mu.Lock()
			h.edges = append(h.edges, e)
			h.mu.Unlock()
		})
	h.trk.SetTargets(targets)
	h.trk.Start(context.Background())
	return h
}

// settle joins the trace goroutines so the recorded slices are complete.
func (h *harness) settle() {
	h.trk.wg.Wait()
}

func (h *harness) requests() []traceroute.Request {
	h.settle()
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]traceroute.Request(nil), h.reqs...)
}

func (h *harness) sunk() []telemetry.TraceResult {
	h.settle()
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]telemetry.TraceResult(nil), h.results...)
}

// faultEdges is what the scene collector was handed. Edges are delivered inline
// on Observe, so no settling is needed — but it shares the recording mutex with
// the trace goroutines.
func (h *harness) faultEdges() []FaultEdge {
	h.settle()
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]FaultEdge(nil), h.edges...)
}

// icmpRound is one ICMP cycle's metrics at loss percentage pct, complete for a
// three-echo target.
func icmpRound(monitorID string, ts time.Time, pct float64) []telemetry.Metric {
	return []telemetry.Metric{
		{TS: ts, Kind: telemetry.ICMPSent, Value: 3, MonitorID: monitorID},
		{TS: ts, Kind: telemetry.ICMPLoss, Value: pct, MonitorID: monitorID},
		{TS: ts, Kind: telemetry.ICMPErrorClass, Value: telemetry.ProbeReasonTimeout, MonitorID: monitorID},
	}
}

// withSerial stamps a round with the target generation the collector produced it
// under, which is what the tracker matches the round against.
func withSerial(ms []telemetry.Metric, serial int) []telemetry.Metric {
	for i := range ms {
		ms[i].ConfigSerial = serial
	}
	return ms
}

func icmpTarget(id, addr string) pcfg.ProbeTarget {
	return pcfg.ProbeTarget{
		MonitorID: id, Kind: "icmp", Target: addr,
		Params: pcfg.ProbeParams{PacketCount: 3, IntervalSeconds: 10},
	}
}

// The whole point of the trigger: N consecutive hard failures fire exactly one
// trace, and the (N+1)th failure fires nothing. A target that stays down
// produces a failing round every interval forever, so a level trigger would
// traceroute a dead host until it came back.
func TestTracesOnceOnTheFailureEdge(t *testing.T) {
	h := newHarness(t, []pcfg.ProbeTarget{icmpTarget("m1", "1.1.1.1")})
	now := time.Now()

	for i := 0; i < 2; i++ {
		h.trk.Observe(icmpRound("m1", now.Add(time.Duration(i)*time.Second), 100))
	}
	if got := len(h.requests()); got != 0 {
		t.Fatalf("traced after 2 failures, threshold is 3 (%d requests)", got)
	}
	h.trk.Observe(icmpRound("m1", now.Add(2*time.Second), 100))
	reqs := h.requests()
	if len(reqs) != 1 {
		t.Fatalf("want exactly 1 trace at the threshold, got %d", len(reqs))
	}
	if reqs[0].DestKey != "ip:1.1.1.1" || reqs[0].Mode != pcfg.TraceModeICMP {
		t.Fatalf("plan = %s/%s", reqs[0].DestKey, reqs[0].Mode)
	}
	if reqs[0].TriggerReason != telemetry.TraceTriggerConsecutiveFailures || reqs[0].TriggerStreak != 3 {
		t.Fatalf("trigger = %s/%d", reqs[0].TriggerReason, reqs[0].TriggerStreak)
	}
	if reqs[0].FirstFailedAt.IsZero() {
		t.Fatal("the streak's start was not recorded")
	}

	for i := 3; i < 8; i++ {
		h.trk.Observe(icmpRound("m1", now.Add(time.Duration(i)*time.Second), 100))
	}
	if got := len(h.requests()); got != 1 {
		t.Fatalf("a target that stayed down traced %d times, want 1", got)
	}
	if got := len(h.sunk()); got != 1 {
		t.Fatalf("sank %d reports, want 1", got)
	}
}

// Partial loss is not a hard availability failure. A target at 60% loss is still
// answering, and tracing a path that works is the noise the trigger exists to
// avoid — the server is separately free to call it faulty.
func TestPartialLossNeverTriggers(t *testing.T) {
	h := newHarness(t, []pcfg.ProbeTarget{icmpTarget("m1", "1.1.1.1")})
	now := time.Now()
	for i := 0; i < 10; i++ {
		h.trk.Observe(icmpRound("m1", now.Add(time.Duration(i)*time.Second), 60))
	}
	if got := len(h.requests()); got != 0 {
		t.Fatalf("partial loss triggered %d traces, want 0", got)
	}
}

// A truncated ICMP cycle reports 0% or 100% over the echoes it managed, which is
// indistinguishable from a healthy or a dead target on exactly the metric this
// reads. It is not a verdict, so it must neither start a streak nor break one.
func TestTruncatedICMPRoundIsNotAVerdict(t *testing.T) {
	h := newHarness(t, []pcfg.ProbeTarget{icmpTarget("m1", "1.1.1.1")})
	now := time.Now()
	truncated := []telemetry.Metric{
		{TS: now, Kind: telemetry.ICMPSent, Value: 1, MonitorID: "m1"},
		{TS: now, Kind: telemetry.ICMPLoss, Value: 100, MonitorID: "m1"},
	}
	for i := 0; i < 5; i++ {
		h.trk.Observe(truncated)
	}
	if got := len(h.requests()); got != 0 {
		t.Fatalf("truncated rounds triggered %d traces, want 0", got)
	}
	// A round with no sent count at all fails closed the same way.
	noCount := []telemetry.Metric{{TS: now, Kind: telemetry.ICMPLoss, Value: 100, MonitorID: "m1"}}
	for i := 0; i < 5; i++ {
		h.trk.Observe(noCount)
	}
	if got := len(h.requests()); got != 0 {
		t.Fatalf("countless rounds triggered %d traces, want 0", got)
	}
}

// Recovery wipes the streak, so the next outage is counted from one and traces
// again as a fresh finding rather than being suppressed as a continuation.
func TestRecoveryResetsTheStreakAndRearmsTheEdge(t *testing.T) {
	h := newHarness(t, []pcfg.ProbeTarget{icmpTarget("m1", "1.1.1.1")})
	h.trk.ApplyDiagPolicy(&pcfg.DiagPolicy{Enabled: true, ConsecutiveFailures: 3, CooldownSeconds: 1})
	now := time.Now()
	for i := 0; i < 3; i++ {
		h.trk.Observe(icmpRound("m1", now.Add(time.Duration(i)*time.Second), 100))
	}
	if got := len(h.requests()); got != 1 {
		t.Fatalf("first outage traced %d times, want 1", got)
	}
	h.trk.Observe(icmpRound("m1", now.Add(3*time.Second), 0))
	// Two failures after recovery are still short of the threshold.
	h.trk.Observe(icmpRound("m1", now.Add(4*time.Second), 100))
	h.trk.Observe(icmpRound("m1", now.Add(5*time.Second), 100))
	if got := len(h.requests()); got != 1 {
		t.Fatalf("re-traced before the new streak reached the threshold (%d)", got)
	}
	// Let the destination cooldown lapse, then complete the new streak.
	time.Sleep(1100 * time.Millisecond)
	h.trk.Observe(icmpRound("m1", now.Add(6*time.Second), 100))
	if got := len(h.requests()); got != 2 {
		t.Fatalf("second outage traced %d times in total, want 2", got)
	}
}

// The cooldown is keyed by DESTINATION, not by monitor: two monitors on one host
// describe one outage over one path, and tracing it twice answers the same
// question twice.
func TestCooldownIsPerDestination(t *testing.T) {
	h := newHarness(t, []pcfg.ProbeTarget{
		icmpTarget("m1", "1.1.1.1"),
		icmpTarget("m2", "1.1.1.1"),
		icmpTarget("m3", "9.9.9.9"),
	})
	now := time.Now()
	for i := 0; i < 3; i++ {
		ts := now.Add(time.Duration(i) * time.Second)
		h.trk.Observe(icmpRound("m1", ts, 100))
		h.settle() // the first trace must finish before the second monitor is judged
		h.trk.Observe(icmpRound("m2", ts, 100))
		h.settle()
		h.trk.Observe(icmpRound("m3", ts, 100))
		h.settle()
	}
	reqs := h.requests()
	if len(reqs) != 2 {
		t.Fatalf("traced %d times, want 2 (one per destination)", len(reqs))
	}
	keys := map[string]bool{reqs[0].DestKey: true, reqs[1].DestKey: true}
	if !keys["ip:1.1.1.1"] || !keys["ip:9.9.9.9"] {
		t.Fatalf("traced destinations = %v", keys)
	}
}

// Two probes of one host that walk different paths are different questions: an
// ICMP monitor and a TCP:443 monitor failing together must each get their own
// trace. Only the cohort — destination, mode, port, path — dedupes, never the
// bare destination, or the second fault's diagnosis would be silently dropped.
func TestDistinctProbesOfOneHostEachTrace(t *testing.T) {
	h := newHarness(t, []pcfg.ProbeTarget{
		icmpTarget("m1", "1.1.1.1"),
		{
			MonitorID: "m2", Kind: "tcp", Target: "1.1.1.1",
			Params: pcfg.ProbeParams{Port: 443, IntervalSeconds: 20},
		},
	})
	now := time.Now()
	for i := 0; i < 3; i++ {
		ts := now.Add(time.Duration(i) * time.Second)
		h.trk.Observe(icmpRound("m1", ts, 100))
		h.settle()
		h.trk.Observe([]telemetry.Metric{
			{TS: ts, Kind: telemetry.TCPOK, Value: 0, MonitorID: "m2"},
			{TS: ts, Kind: telemetry.TCPErrorClass, Value: telemetry.ProbeReasonRefused, MonitorID: "m2"},
		})
		h.settle()
	}
	reqs := h.requests()
	if len(reqs) != 2 {
		t.Fatalf("traced %d times, want 2 (one per probe mode)", len(reqs))
	}
	modes := map[string]int{}
	for _, r := range reqs {
		if r.DestKey != "ip:1.1.1.1" {
			t.Fatalf("dest key = %s, want ip:1.1.1.1", r.DestKey)
		}
		modes[r.Mode]++
	}
	if modes[pcfg.TraceModeICMP] != 1 || modes[pcfg.TraceModeTCP] != 1 {
		t.Fatalf("modes = %v, want one icmp and one tcp", modes)
	}
}

// An edited target's counters were accumulated against a different endpoint, so
// a generation change drops the streak instead of letting the new address
// inherit the old one's failures.
func TestGenerationChangeDropsTheStreak(t *testing.T) {
	tg := icmpTarget("m1", "1.1.1.1")
	tg.ConfigSerial = 1
	h := newHarness(t, []pcfg.ProbeTarget{tg})
	now := time.Now()
	h.trk.Observe(withSerial(icmpRound("m1", now, 100), 1))
	h.trk.Observe(withSerial(icmpRound("m1", now.Add(time.Second), 100), 1))

	edited := icmpTarget("m1", "8.8.8.8")
	edited.ConfigSerial = 2
	h.trk.SetTargets([]pcfg.ProbeTarget{edited})

	h.trk.Observe(withSerial(icmpRound("m1", now.Add(2*time.Second), 100), 2))
	if got := len(h.requests()); got != 0 {
		t.Fatalf("the edited target inherited the old streak (%d traces)", got)
	}
	h.trk.Observe(withSerial(icmpRound("m1", now.Add(3*time.Second), 100), 2))
	h.trk.Observe(withSerial(icmpRound("m1", now.Add(4*time.Second), 100), 2))
	reqs := h.requests()
	if len(reqs) != 1 || reqs[0].DestKey != "ip:8.8.8.8" {
		t.Fatalf("post-edit traces = %+v", reqs)
	}
}

// A result measured under the superseded generation can still be queued when the
// new one is installed. Counting it would let a failure of the OLD endpoint
// advance the new target's streak and traceroute the address the edit just moved
// away from — a trace of something nobody reported broken, filed under the
// edited monitor.
func TestSupersededGenerationSamplesAreIgnored(t *testing.T) {
	tg := icmpTarget("m1", "1.1.1.1")
	tg.ConfigSerial = 1
	h := newHarness(t, []pcfg.ProbeTarget{tg})
	now := time.Now()
	h.trk.Observe(withSerial(icmpRound("m1", now, 100), 1))

	edited := icmpTarget("m1", "8.8.8.8")
	edited.ConfigSerial = 2
	h.trk.SetTargets([]pcfg.ProbeTarget{edited})

	// Three failing v1 rounds drain after the switch. They describe 1.1.1.1, which
	// this monitor no longer probes, so they must not count at all.
	for i := 1; i < 4; i++ {
		h.trk.Observe(withSerial(icmpRound("m1", now.Add(time.Duration(i)*time.Second), 100), 1))
	}
	if got := len(h.requests()); got != 0 {
		t.Fatalf("stale-generation rounds traced %d times, want 0", got)
	}
	if got := len(h.sunk()); got != 0 {
		t.Fatalf("stale-generation rounds emitted %d reports, want 0", got)
	}
	h.trk.mu.Lock()
	st := h.trk.streaks["m1"]
	h.trk.mu.Unlock()
	if st != nil && st.fails != 0 {
		t.Fatalf("v2's streak advanced to %d on v1's failures", st.fails)
	}

	// The current generation still counts normally, from one.
	for i := 4; i < 7; i++ {
		h.trk.Observe(withSerial(icmpRound("m1", now.Add(time.Duration(i)*time.Second), 100), 2))
	}
	reqs := h.requests()
	if len(reqs) != 1 || reqs[0].DestKey != "ip:8.8.8.8" || reqs[0].TriggerStreak != 3 {
		t.Fatalf("post-edit traces = %+v, want one 3-round streak against 8.8.8.8", reqs)
	}
}

// A disabled policy counts nothing and traces nothing — the operator's answer to
// "should this install run path diagnostics" is not advisory.
func TestDisabledPolicyNeverTraces(t *testing.T) {
	h := newHarness(t, []pcfg.ProbeTarget{icmpTarget("m1", "1.1.1.1")})
	h.trk.ApplyDiagPolicy(&pcfg.DiagPolicy{Enabled: false})
	now := time.Now()
	for i := 0; i < 10; i++ {
		h.trk.Observe(icmpRound("m1", now.Add(time.Duration(i)*time.Second), 100))
	}
	if got := len(h.requests()); got != 0 {
		t.Fatalf("a disabled policy traced %d times", got)
	}
}

// Disabling zeroes the streaks rather than freezing them. Nothing is observed
// while the feature is off, so a count carried across the gap would resume as if
// the unobserved rounds had agreed with it: two failures, a disable, a healthy
// round nobody recorded, a re-enable inside the staleness window and one more
// failure must not add up to three consecutive failing rounds.
func TestDisablingClearsTheStreak(t *testing.T) {
	h := newHarness(t, []pcfg.ProbeTarget{icmpTarget("m1", "1.1.1.1")})
	now := time.Now()
	h.trk.Observe(icmpRound("m1", now, 100))
	h.trk.Observe(icmpRound("m1", now.Add(time.Second), 100))

	h.trk.ApplyDiagPolicy(&pcfg.DiagPolicy{Enabled: false})
	h.trk.Observe(icmpRound("m1", now.Add(2*time.Second), 0)) // healthy, and unobserved
	h.trk.ApplyDiagPolicy(&pcfg.DiagPolicy{Enabled: true})

	h.trk.Observe(icmpRound("m1", now.Add(3*time.Second), 100))
	if got := len(h.requests()); got != 0 {
		t.Fatalf("a failure count survived the disabled interval (%d traces)", got)
	}
	h.trk.Observe(icmpRound("m1", now.Add(4*time.Second), 100))
	if got := len(h.requests()); got != 0 {
		t.Fatalf("traced after 2 failures since the re-enable (%d)", got)
	}
	h.trk.Observe(icmpRound("m1", now.Add(5*time.Second), 100))
	reqs := h.requests()
	if len(reqs) != 1 || reqs[0].TriggerStreak != 3 {
		t.Fatalf("traces since the re-enable = %+v, want one 3-round streak", reqs)
	}

	// The fired bit goes the same way, or an outage that already traced would
	// leave a bit suppressing the first finding of the next one.
	h.trk.ApplyDiagPolicy(&pcfg.DiagPolicy{Enabled: false})
	h.trk.mu.Lock()
	left := len(h.trk.streaks)
	h.trk.mu.Unlock()
	if left != 0 {
		t.Fatalf("%d streaks survived the disable, want none", left)
	}
}

// A plan that can never run is still a finding: "this fault has no diagnosable
// path" is what an operator needs to see instead of a diagnostic that silently
// never appears. It reaches the sink without ever reaching the runner.
func TestUnrunnablePlanIsReportedNotDropped(t *testing.T) {
	h := newHarness(t, []pcfg.ProbeTarget{{
		MonitorID: "m1", Kind: "dns", Target: "example.com",
		Params: pcfg.ProbeParams{IntervalSeconds: 30},
	}})
	now := time.Now()
	// A DNS round that never named its resolver: nothing to trace toward.
	round := func(ts time.Time) []telemetry.Metric {
		return []telemetry.Metric{
			{TS: ts, Kind: telemetry.DNSOK, Value: 0, MonitorID: "m1"},
			{TS: ts, Kind: telemetry.DNSErrorClass, Value: telemetry.ProbeReasonTimeout, MonitorID: "m1"},
		}
	}
	for i := 0; i < 3; i++ {
		h.trk.Observe(round(now.Add(time.Duration(i) * time.Second)))
	}
	if got := len(h.requests()); got != 0 {
		t.Fatalf("an unrunnable plan reached the engine (%d requests)", got)
	}
	sunk := h.sunk()
	if len(sunk) != 1 {
		t.Fatalf("sank %d reports, want 1", len(sunk))
	}
	if sunk[0].Status != telemetry.TraceStatusFailed || sunk[0].Reason != reasonResolverUnknown {
		t.Fatalf("report = %s/%s, want failed/%s", sunk[0].Status, sunk[0].Reason, reasonResolverUnknown)
	}
	if sunk[0].SubjectKind != telemetry.TraceSubjectResolver {
		t.Fatalf("subject = %q, want %q", sunk[0].SubjectKind, telemetry.TraceSubjectResolver)
	}
	if sunk[0].TriggerStreak != 3 {
		t.Fatalf("trigger streak = %d, want 3", sunk[0].TriggerStreak)
	}
}

// A TCP monitor on an agent without the TCP traceroute permission runs as ICMP
// and says so, rather than reporting a bare failure the console cannot explain.
func TestTCPPlanFallsBackToICMPWhenOnlyICMPIsHeld(t *testing.T) {
	h := newHarness(t, []pcfg.ProbeTarget{{
		MonitorID: "m1", Kind: "tcp", Target: "example.com",
		Params: pcfg.ProbeParams{Port: 443, IntervalSeconds: 20},
	}}, permission.DiagnosticTracerouteICMP)
	now := time.Now()
	for i := 0; i < 3; i++ {
		ts := now.Add(time.Duration(i) * time.Second)
		h.trk.Observe([]telemetry.Metric{
			{TS: ts, Kind: telemetry.TCPOK, Value: 0, MonitorID: "m1"},
			{TS: ts, Kind: telemetry.TCPErrorClass, Value: telemetry.ProbeReasonRefused, MonitorID: "m1"},
		})
	}
	reqs := h.requests()
	if len(reqs) != 1 {
		t.Fatalf("traced %d times, want 1", len(reqs))
	}
	if reqs[0].Mode != pcfg.TraceModeICMP || reqs[0].FallbackFrom != pcfg.TraceModeTCP {
		t.Fatalf("mode/fallback = %s/%s", reqs[0].Mode, reqs[0].FallbackFrom)
	}
	// The port is kept even though ICMP will not use it: it is part of what failed.
	if reqs[0].Port != 443 {
		t.Fatalf("port = %d, want 443 (frozen fault evidence)", reqs[0].Port)
	}
}

// An unset policy field means "use the default", never zero: a server that
// states only Enabled must not end up with a zero-hop, zero-attempt trace.
func TestResolvePolicyFillsUnsetFields(t *testing.T) {
	got := ResolvePolicy(&pcfg.DiagPolicy{Enabled: true})
	want := ResolvePolicy(nil)
	if got != want {
		t.Fatalf("bare policy = %+v, want the defaults %+v", got, want)
	}
	if !ResolvePolicy(nil).Enabled {
		t.Fatal("an absent policy must leave the zero-config diagnostic enabled")
	}
	tuned := ResolvePolicy(&pcfg.DiagPolicy{Enabled: true, ConsecutiveFailures: 5, CooldownSeconds: 60, MaxHops: 12})
	if tuned.ConsecutiveFailures != 5 || tuned.Cooldown != time.Minute || tuned.MaxHops != 12 {
		t.Fatalf("tuned policy = %+v", tuned)
	}
	if tuned.Attempts != defaultAttempts || tuned.BudgetMs != defaultBudgetMs {
		t.Fatalf("tuned policy dropped the untouched defaults: %+v", tuned)
	}
}

// A gateway monitor is one hop away, so there is no path worth walking and it
// never produces a trace. It DOES produce a scene edge: an unreachable default
// gateway is the fault whose local network context is worth the most, and the
// server watching it has most likely lost this agent too.
func TestGatewayFaultRaisesASceneEdgeButNoTrace(t *testing.T) {
	h := newHarness(t, []pcfg.ProbeTarget{{
		MonitorID: "gw", Kind: "gateway", Target: "gateway",
		Params: pcfg.ProbeParams{PacketCount: 3, Interface: "eth0"},
	}})
	now := time.Now()
	for i := 0; i < 10; i++ {
		h.trk.Observe(icmpRound("gw", now.Add(time.Duration(i)*time.Second), 100))
	}
	if got := len(h.requests()); got != 0 {
		t.Fatalf("a gateway monitor triggered %d traces", got)
	}
	edges := h.faultEdges()
	if len(edges) != 1 {
		t.Fatalf("gateway fault raised %d scene edges, want exactly one (it is an edge, not a per-round event)", len(edges))
	}
	if edges[0].MonitorID != "gw" || edges[0].Kind != "gateway" || edges[0].Iface != "eth0" {
		t.Fatalf("scene edge = %+v, want the failing gateway monitor with its NIC", edges[0])
	}
	if edges[0].Streak != defaultConsecutiveFailures {
		t.Fatalf("scene edge streak = %d, want the confirmation threshold %d", edges[0].Streak, defaultConsecutiveFailures)
	}
}

// A host monitor names a metric series, not a network destination: neither
// diagnostic has anything to say about it.
func TestHostKindIsNeverCounted(t *testing.T) {
	h := newHarness(t, []pcfg.ProbeTarget{{
		MonitorID: "hst", Kind: "host", Target: "host",
		Params: pcfg.ProbeParams{PacketCount: 3},
	}})
	now := time.Now()
	for i := 0; i < 10; i++ {
		h.trk.Observe(icmpRound("hst", now.Add(time.Duration(i)*time.Second), 100))
	}
	if got := len(h.requests()); got != 0 {
		t.Fatalf("a host monitor triggered %d traces", got)
	}
	if got := len(h.faultEdges()); got != 0 {
		t.Fatalf("a host monitor raised %d scene edges", got)
	}
}

// A scene edge is owed even where the trace is not: an agent with no traceroute
// permission still describes the machine that found the fault.
func TestSceneEdgeSurvivesADeniedTrace(t *testing.T) {
	h := newHarness(t, []pcfg.ProbeTarget{icmpTarget("m1", "1.1.1.1")}, permission.DiagnosticTracerouteTCP)
	now := time.Now()
	for i := 0; i < 3; i++ {
		h.trk.Observe(icmpRound("m1", now.Add(time.Duration(i)*time.Second), 100))
	}
	if got := len(h.requests()); got != 0 {
		t.Fatalf("a denied ICMP traceroute still ran %d sweeps", got)
	}
	if got := len(h.faultEdges()); got != 1 {
		t.Fatalf("denied trace raised %d scene edges, want one", got)
	}
}

// A gap larger than the target's own staleness window breaks the streak: an
// agent suspended for hours resumes with its last round still in memory, and
// calling that round and the next one consecutive asserts a continuity nobody
// observed. The gap is between the ROUNDS' own timestamps — the moment the
// tracker got to look at them says nothing about when they happened.
func TestStaleGapBreaksTheStreak(t *testing.T) {
	h := newHarness(t, []pcfg.ProbeTarget{icmpTarget("m1", "1.1.1.1")})
	before := time.Now().Add(-6 * time.Hour)
	h.trk.Observe(icmpRound("m1", before, 100))
	h.trk.Observe(icmpRound("m1", before.Add(time.Second), 100))

	// The resume: a current round, six hours after the two the suspend interrupted.
	now := time.Now()
	h.trk.Observe(icmpRound("m1", now, 100))
	if got := len(h.requests()); got != 0 {
		t.Fatalf("a streak survived a %v gap (%d traces)", 6*time.Hour, got)
	}
	// Counting restarted at one, so it takes two more rounds — not none — to reach
	// the threshold again.
	h.trk.Observe(icmpRound("m1", now.Add(time.Second), 100))
	if got := len(h.requests()); got != 0 {
		t.Fatalf("traced after 2 post-resume failures (%d)", got)
	}
	h.trk.Observe(icmpRound("m1", now.Add(2*time.Second), 100))
	reqs := h.requests()
	if len(reqs) != 1 || reqs[0].TriggerStreak != 3 {
		t.Fatalf("post-resume traces = %+v, want one 3-round streak", reqs)
	}
}

// A backlog drained after a suspend carries rounds that are consecutive with
// each other but long past. The streak's arithmetic reads their own timestamps,
// and the round that CONFIRMS it must still describe the present — otherwise the
// trace walks a path that recovered while the results sat in a channel, and
// files the result as evidence for a fault that is over.
func TestLateBacklogTracesOnlyOnceItIsCurrent(t *testing.T) {
	tg := icmpTarget("m1", "1.1.1.1")
	h := newHarness(t, []pcfg.ProbeTarget{tg})
	window := staleAfter(tg)
	step := pcfg.EffectiveInterval(tg.Kind, tg.Params)

	// One ongoing outage, delivered in a single drain: rounds one probe interval
	// apart running from two staleness windows ago up to the present.
	now := time.Now()
	start := now.Add(-2 * window)
	var ms []telemetry.Metric
	for ts := start; !ts.After(now); ts = ts.Add(step) {
		ms = append(ms, icmpRound("m1", ts, 100)...)
	}
	h.trk.Observe(ms)

	reqs := h.requests()
	if len(reqs) != 1 {
		t.Fatalf("a drained outage traced %d times, want 1", len(reqs))
	}
	// The streak began when the outage did, not when the agent got round to it.
	if drift := absDuration(reqs[0].FirstFailedAt.Sub(start)); drift > time.Second {
		t.Fatalf("FirstFailedAt = %v, want the first round's own %v", reqs[0].FirstFailedAt, start)
	}
	// And it did not fire on the third round, which was two windows old by the
	// time anyone saw it: the trace waited for a round still speaking for now.
	if reqs[0].TriggerStreak <= 3 {
		t.Fatalf("trigger streak = %d, want the trace held back until the backlog caught up", reqs[0].TriggerStreak)
	}
}

// A backlog that is entirely stale by the time it drains never traces at all.
// Every round in it agrees the target was down, and none of them says it still
// is.
func TestFullyStaleBacklogNeverTraces(t *testing.T) {
	tg := icmpTarget("m1", "1.1.1.1")
	h := newHarness(t, []pcfg.ProbeTarget{tg})
	window := staleAfter(tg)
	step := pcfg.EffectiveInterval(tg.Kind, tg.Params)

	base := time.Now().Add(-4 * window)
	for i := 0; i < 6; i++ {
		h.trk.Observe(icmpRound("m1", base.Add(time.Duration(i)*step), 100))
	}
	if got := len(h.requests()); got != 0 {
		t.Fatalf("a fully stale backlog traced %d times, want 0", got)
	}
	if got := len(h.sunk()); got != 0 {
		t.Fatalf("a fully stale backlog emitted %d reports, want 0", got)
	}
}

// An egress re-pin makes the same fault a NEW path question: the trace is pinned
// to the exact proxy generation the failing round ran under, so a fault after
// the edit must not be suppressed by the cooldown the previous generation left
// behind — the consequences of the edit are precisely what someone is watching
// for.
func TestEgressGenerationIsItsOwnCohort(t *testing.T) {
	tg := icmpTarget("m1", "10.10.0.7")
	tg.ProxyID = "wg1"
	specs := map[string]pcfg.ProxySpec{"wg1": {
		ID: "wg1", Type: pcfg.ProxyTypeWireGuard,
		WGEndpoint: "203.0.113.9:51820", ConfigSerial: 1,
	}}
	h := newProxyHarness(t, []pcfg.ProbeTarget{tg},
		func() map[string]pcfg.ProxySpec { return specs })

	now := time.Now()
	for i := 0; i < 3; i++ {
		h.trk.Observe(icmpRound("m1", now.Add(time.Duration(i)*time.Second), 100))
	}
	if got := len(h.requests()); got != 1 {
		t.Fatalf("the first outage traced %d times, want 1", got)
	}

	// Recovery re-arms the edge; the re-pin changes which tunnel the next fault
	// happened behind. The default 15-minute cooldown has not lapsed.
	h.trk.Observe(icmpRound("m1", now.Add(3*time.Second), 0))
	specs["wg1"] = pcfg.ProxySpec{
		ID: "wg1", Type: pcfg.ProxyTypeWireGuard,
		WGEndpoint: "203.0.113.9:51820", ConfigSerial: 2,
	}
	for i := 4; i < 7; i++ {
		h.trk.Observe(icmpRound("m1", now.Add(time.Duration(i)*time.Second), 100))
	}

	reqs := h.requests()
	if len(reqs) != 2 {
		t.Fatalf("traced %d times, want 2 (one per egress generation)", len(reqs))
	}
	for i, want := range []int{1, 2} {
		if reqs[i].EgressProxyID != "wg1" || reqs[i].EgressConfigSerial != want {
			t.Fatalf("trace %d pinned to %q@%d, want wg1@%d",
				i, reqs[i].EgressProxyID, reqs[i].EgressConfigSerial, want)
		}
		if reqs[i].DestKey != "ip:10.10.0.7" {
			t.Fatalf("trace %d dest = %s, want the in-tunnel target", i, reqs[i].DestKey)
		}
	}
}

// The cohort key is what dedupe and cooldown compare, so the egress generation
// has to be inside it: two plans that differ only by the pin's generation are
// two different path questions.
func TestCohortKeySeparatesEgressGenerations(t *testing.T) {
	first := plan{
		mode: pcfg.TraceModeICMP, destKey: "ip:10.10.0.7",
		pathScope: telemetry.TracePathWireGuardInner,
		egressID:  "wg1", egressConfigSerial: 1,
	}
	second := first
	second.egressConfigSerial = 2
	if first.cohortKey() == second.cohortKey() {
		t.Fatalf("a re-pinned egress kept the cohort key %q", first.cohortKey())
	}
	same := first
	if same.cohortKey() != first.cohortKey() {
		t.Fatalf("identical plans keyed differently: %q vs %q", same.cohortKey(), first.cohortKey())
	}
}
