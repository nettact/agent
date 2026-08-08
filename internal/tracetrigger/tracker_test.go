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
}

func newHarness(t *testing.T, targets []pcfg.ProbeTarget, perms ...permission.ID) *harness {
	t.Helper()
	if len(perms) == 0 {
		perms = []permission.ID{permission.DiagnosticTracerouteICMP, permission.DiagnosticTracerouteTCP}
	}
	set := permission.Set{}
	for _, p := range perms {
		set.Add(p)
	}
	h := &harness{t: t}
	h.trk = New("test", set, set, set, nil,
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

// icmpRound is one ICMP cycle's metrics at loss percentage pct, complete for a
// three-echo target.
func icmpRound(monitorID string, ts time.Time, pct float64) []telemetry.Metric {
	return []telemetry.Metric{
		{TS: ts, Kind: telemetry.ICMPSent, Value: 3, MonitorID: monitorID},
		{TS: ts, Kind: telemetry.ICMPLoss, Value: pct, MonitorID: monitorID},
		{TS: ts, Kind: telemetry.ICMPErrorClass, Value: telemetry.ProbeReasonTimeout, MonitorID: monitorID},
	}
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
	h.trk.Observe(icmpRound("m1", now, 100))
	h.trk.Observe(icmpRound("m1", now.Add(time.Second), 100))

	edited := icmpTarget("m1", "8.8.8.8")
	edited.ConfigSerial = 2
	h.trk.SetTargets([]pcfg.ProbeTarget{edited})

	h.trk.Observe(icmpRound("m1", now.Add(2*time.Second), 100))
	if got := len(h.requests()); got != 0 {
		t.Fatalf("the edited target inherited the old streak (%d traces)", got)
	}
	h.trk.Observe(icmpRound("m1", now.Add(3*time.Second), 100))
	h.trk.Observe(icmpRound("m1", now.Add(4*time.Second), 100))
	reqs := h.requests()
	if len(reqs) != 1 || reqs[0].DestKey != "ip:8.8.8.8" {
		t.Fatalf("post-edit traces = %+v", reqs)
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

// Gateway and host monitors have no diagnosable network path, so they are never
// counted at all.
func TestIneligibleKindsAreNeverCounted(t *testing.T) {
	h := newHarness(t, []pcfg.ProbeTarget{{
		MonitorID: "gw", Kind: "gateway", Target: "gateway",
		Params: pcfg.ProbeParams{PacketCount: 3},
	}})
	now := time.Now()
	for i := 0; i < 10; i++ {
		h.trk.Observe(icmpRound("gw", now.Add(time.Duration(i)*time.Second), 100))
	}
	if got := len(h.requests()); got != 0 {
		t.Fatalf("a gateway monitor triggered %d traces", got)
	}
}

// A gap larger than the target's own staleness window breaks the streak: an
// agent suspended for hours resumes with its last round still in memory, and
// calling that round and the next one consecutive asserts a continuity nobody
// observed.
func TestStaleGapBreaksTheStreak(t *testing.T) {
	h := newHarness(t, []pcfg.ProbeTarget{icmpTarget("m1", "1.1.1.1")})
	now := time.Now()
	h.trk.Observe(icmpRound("m1", now, 100))
	h.trk.Observe(icmpRound("m1", now.Add(time.Second), 100))

	// Rewind the recorded round time far past the staleness window without
	// waiting for it, which is what an agent resuming from suspend looks like.
	h.trk.mu.Lock()
	h.trk.streaks["m1"].lastRoundAt = time.Now().Add(-6 * time.Hour)
	h.trk.mu.Unlock()

	h.trk.Observe(icmpRound("m1", now.Add(2*time.Second), 100))
	if got := len(h.requests()); got != 0 {
		t.Fatalf("a streak survived a %v gap (%d traces)", 6*time.Hour, got)
	}
}
