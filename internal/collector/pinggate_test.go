package collector

import (
	"context"
	"sync"
	"testing"
	"time"

	pcfg "github.com/nettact/protocol/config"
	"github.com/nettact/protocol/telemetry"
)

// AGENT-008's headline acceptance criterion: with max_probe_concurrency 2 and 10
// ICMP targets, no more than 2 echoes are ever in flight at once.
//
// The echoes, not the cycles — a cycle sleeps between its echoes holding nothing,
// so the budget has to apply to the part that costs something. This runs in real
// time (no synthetic clock) because it is about what actually overlaps.
func TestPingEchoesRespectTheConcurrencyBudget(t *testing.T) {
	const budget, targets = 2, 10
	gate := NewProbeGate(budget)

	var mu sync.Mutex
	inflight, peak := 0, 0
	echo := func(ctx context.Context, _ int, _ time.Duration) (time.Duration, int, string, bool) {
		mu.Lock()
		inflight++
		if inflight > peak {
			peak = inflight
		}
		mu.Unlock()

		time.Sleep(2 * time.Millisecond)

		mu.Lock()
		inflight--
		mu.Unlock()
		return time.Millisecond, telemetry.ProbeReasonNone, "", true
	}

	// 2 packets each on a 1s interval: plenty of budget for every cycle to
	// complete, so the only thing under test is the overlap.
	params := pcfg.ProbeParams{PacketCount: 2, IntervalSeconds: 1}
	var wg sync.WaitGroup
	for i := 0; i < targets; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := pingLoop(context.Background(), params, time.Now().Add(time.Second), gate, echo)
			if r.Sent != 2 || r.Received != 2 {
				t.Errorf("cycle = %+v, want 2 sent / 2 received", r)
			}
		}()
	}
	wg.Wait()

	if peak > budget {
		t.Errorf("peak concurrent echoes = %d, want <= %d", peak, budget)
	}
	if peak < 2 {
		t.Errorf("peak concurrent echoes = %d — the targets never actually overlapped, so this proves nothing", peak)
	}
	if turned := gate.TakeOverload(); turned != 0 {
		t.Errorf("turned away %d echoes, want 0 — every cycle had budget to wait", turned)
	}
}

// The spread must not degrade under a budget that can actually serve it: a
// healthy cycle still lays its echoes across the whole interval at the same
// instants it would with no gate at all. If the gate perturbed the pacing, the
// probe rate would drop and the spread's whole reason for existing (observing the
// entire interval, not a burst at the top of it) would be gone.
func TestPingCyclePacingIsUnchangedWhenTheBudgetIsSufficient(t *testing.T) {
	clk := stubCycleClock(t)
	p := &gwTestPlatform{}
	nextDue := clk.Now().Add(10 * time.Second)

	r := pingCycle(context.Background(), p, "1.1.1.1", pcfg.ProbeParams{}, nextDue, NewProbeGate(4))

	if r.Loss != 0 || r.Received != 5 || r.Sent != 5 {
		t.Fatalf("cycle = %+v, want 5 sent / 5 received / 0%% loss", r)
	}
	want := []time.Duration{2250 * time.Millisecond, 2250 * time.Millisecond, 2250 * time.Millisecond, 2250 * time.Millisecond}
	got := clk.gaps()
	if len(got) != len(want) {
		t.Fatalf("gaps = %v, want %v (identical to the ungated cycle)", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("gaps = %v, want %v (identical to the ungated cycle)", got, want)
		}
	}
}

// waitingGate is a gate whose slots are all held, so every acquire has to wait
// out its deadline. It stands in for a machine at its concurrency limit.
func waitingGate(t *testing.T) *ProbeGate {
	t.Helper()
	g := NewProbeGate(1)
	if g.Acquire(context.Background(), time.Now().Add(time.Second)) != AdmittedOK {
		t.Fatal("could not fill the test gate")
	}
	t.Cleanup(g.Release)
	return g
}

// The acceptance criterion that keeps the budget from corrupting measurements:
// waiting for a slot must never come out of an echo's own timeout. An echo that
// queued and then ran must still be handed the full per-echo budget, so a
// healthy-but-slow target is never recorded as lost because the agent was busy.
//
// It runs in real time: the whole point is that wall-clock spent queueing does
// not show up in what the echo is given.
func TestPingCycleQueuedEchoStillGetsItsFullTimeout(t *testing.T) {
	gate := NewProbeGate(1)
	if gate.Acquire(context.Background(), time.Now().Add(time.Second)) != AdmittedOK {
		t.Fatal("could not fill the test gate")
	}
	// Hold the only slot for 300ms, well into the first echo's wait budget.
	go func() {
		time.Sleep(300 * time.Millisecond)
		gate.Release()
	}()

	var timeouts []time.Duration
	var mu sync.Mutex
	echo := func(_ context.Context, _ int, timeout time.Duration) (time.Duration, int, string, bool) {
		mu.Lock()
		timeouts = append(timeouts, timeout)
		mu.Unlock()
		return time.Millisecond, telemetry.ProbeReasonNone, "", true
	}

	// 2 packets, 1s each, inside a 3s global budget: the first echo may wait up
	// to gateBound−2×1s before it must start.
	params := pcfg.ProbeParams{PacketCount: 2, GlobalTimeoutMs: 3_000}
	start := time.Now()
	r := pingLoop(context.Background(), params, start.Add(2500*time.Millisecond), gate, echo)

	if r.Sent != 2 || r.Received != 2 {
		t.Fatalf("cycle = %+v, want both echoes sent and received after the queue cleared", r)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(timeouts) != 2 {
		t.Fatalf("echo timeouts = %v, want two echoes", timeouts)
	}
	if timeouts[0] != pcfg.PingEchoTimeout(params) {
		t.Errorf("queued echo was given %v, want its full %v — the wait was charged to the measurement",
			timeouts[0], pcfg.PingEchoTimeout(params))
	}
}

// A budget that admits some of a cycle's echoes but not all produces a TRUNCATED
// round: loss is a ratio over what was sent, and Sent travels with it so the
// server can tell it apart from a complete round and refuse to move availability
// state on it. Counting the unsent echoes as lost is the bug this guards — it
// would report the agent's own busyness as packet loss, on the one metric the
// availability detector reads.
func TestPingCycleTruncatedRoundReportsWhatItSent(t *testing.T) {
	// One slot, two cycles, echoes that each hold it for a real 40ms. The
	// contention is genuine, so at least one cycle runs out of wait budget before
	// it has sent everything.
	gate := NewProbeGate(1)
	echo := func(context.Context, int, time.Duration) (time.Duration, int, string, bool) {
		time.Sleep(40 * time.Millisecond)
		return 3 * time.Millisecond, telemetry.ProbeReasonNone, "", true
	}
	// 5 packets, a 100ms per-echo timeout and a 250ms whole-cycle deadline: the
	// bound is hard, so the loser cannot simply wait the winner out.
	params := pcfg.ProbeParams{TimeoutMs: 100, GlobalTimeoutMs: 250}

	var mu sync.Mutex
	var results []pingCycleResult
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := pingLoop(context.Background(), params, time.Now().Add(250*time.Millisecond), gate, echo)
			mu.Lock()
			results = append(results, r)
			mu.Unlock()
		}()
	}
	wg.Wait()

	truncated := 0
	for _, r := range results {
		if r.Sent < pcfg.PingCount(params) {
			truncated++
		}
		if r.Received != r.Sent {
			t.Errorf("cycle = %+v: every echo answered, so received must equal sent", r)
		}
		if r.Loss != 0 {
			t.Errorf("cycle = %+v: loss must be 0 — nothing that was SENT was lost", r)
		}
	}
	if truncated == 0 {
		t.Fatalf("no cycle was truncated by the budget: %+v — the test proved nothing", results)
	}
}

// A cycle the budget shut out entirely reports nothing at all. 100% loss over
// zero packets would be the agent's own busyness dressed up as an outage, and it
// would land on exactly the metric the availability detector reads.
func TestPingCycleZeroAttemptsProducesNoResult(t *testing.T) {
	gate := waitingGate(t)
	echo := func(context.Context, int, time.Duration) (time.Duration, int, string, bool) {
		t.Fatal("an echo ran despite a full budget and no slack")
		return 0, 0, "", false
	}

	// A deadline already in the past: no slack to wait for a slot.
	r := pingLoop(context.Background(), pcfg.ProbeParams{}, time.Now().Add(-time.Minute), gate, echo)

	if r.Sent != 0 || r.Received != 0 {
		t.Fatalf("cycle = %+v, want nothing attempted", r)
	}
	if r.Loss != 0 {
		t.Fatalf("loss = %v%%, want 0 — a cycle that sent nothing measured nothing", r.Loss)
	}
	if turned := gate.TakeOverload(); turned != 1 {
		t.Errorf("overload count = %d, want 1", turned)
	}
}

// A target whose worst case cannot fit its own interval (5 packets on a 1s
// interval) must still be able to wait for a slot. Bounded by the interval alone
// its wait budget would be negative from the first echo, and on a busy agent the
// target would go permanently silent — which is worse than the late sample the
// server already allows it (pcfg.CycleDeadline gives such a target count×perEcho).
func TestPingCycleShortIntervalTargetCanStillWaitForASlot(t *testing.T) {
	gate := NewProbeGate(1)
	held := make(chan struct{})
	if gate.Acquire(context.Background(), time.Now().Add(time.Second)) != AdmittedOK {
		t.Fatal("could not fill the test gate")
	}
	go func() {
		time.Sleep(30 * time.Millisecond)
		gate.Release()
		close(held)
	}()

	echo := func(context.Context, int, time.Duration) (time.Duration, int, string, bool) {
		return time.Millisecond, telemetry.ProbeReasonNone, "", true
	}
	// 5 packets, 1s each, on a 1s interval: back-to-back worst case is 5s.
	params := pcfg.ProbeParams{IntervalSeconds: 1}
	r := pingLoop(context.Background(), params, time.Now().Add(time.Second), gate, echo)
	<-held

	if r.Sent == 0 {
		t.Fatal("a short-interval target was refused every slot — it would never report")
	}
	if r.Received != r.Sent {
		t.Fatalf("cycle = %+v, want every sent echo received", r)
	}
}

// The wait deadline is the CYCLE's bound less one timeout, full stop. It is
// allowed to be in the past, and it must never be pushed into the future to
// manufacture budget.
//
// An earlier version floored it at now+timeout so a target with no slack could
// still wait. That granted fresh slack on EVERY acquire, so a contended cycle
// overran its deadline by a timeout per remaining packet and then started its
// already-due next cycle immediately. The floor was also unnecessary: Acquire
// takes a free slot without consulting the clock, so a no-slack target still
// probes whenever the budget has room.
func TestGateWaitDeadlineNeverExtendsIntoTheFuture(t *testing.T) {
	timeout := time.Second
	now := time.Unix(10_000, 0)

	// Comfortable bound: one timeout before it.
	bound := now.Add(10 * time.Second)
	if got, want := gateWaitDeadline(bound, timeout), bound.Add(-timeout); !got.Equal(want) {
		t.Errorf("gateWaitDeadline = %v, want %v", got, want)
	}
	// Bound already reached: the deadline is in the PAST, so nothing waits.
	tight := now
	if got := gateWaitDeadline(tight, timeout); !got.Before(now) {
		t.Errorf("gateWaitDeadline = %v, want an instant before now (%v) — no manufactured budget", got, now)
	}
	// And it must not creep forward as a cycle burns through its bound: the same
	// bound always yields the same deadline, however late it is consulted.
	first := gateWaitDeadline(tight, timeout)
	second := gateWaitDeadline(tight, timeout)
	if !first.Equal(second) {
		t.Errorf("deadline moved between calls: %v then %v", first, second)
	}
}

// The consequence at cycle level: once a contended cycle has spent its bound,
// the remaining echoes are refused rather than run late. Without that the round
// overruns pcfg.CycleDeadline and collides with its own next cycle.
//
// A GlobalTimeoutMs is what makes the bound genuinely tight here. Without one,
// gateBoundary deliberately extends a passed interval to the cycle's own
// back-to-back worst case — which is right, and is why that case cannot show
// this property.
func TestPingCycleTruncatesRatherThanOverrunningItsBound(t *testing.T) {
	gate := NewProbeGate(1)
	// Hold the only slot for the whole test, so every acquire must rely on its
	// wait budget alone.
	if gate.Acquire(context.Background(), time.Now().Add(time.Second)) != AdmittedOK {
		t.Fatal("could not fill the test gate")
	}
	t.Cleanup(gate.Release)

	echo := func(context.Context, int, time.Duration) (time.Duration, int, string, bool) {
		t.Error("an echo ran after the cycle's bound was spent")
		return 0, 0, "", false
	}

	// A 1s hard cycle deadline with a 1s per-echo timeout leaves exactly zero
	// slack: the first echo must start immediately or not at all.
	start := time.Now()
	params := pcfg.ProbeParams{TimeoutMs: 1000, GlobalTimeoutMs: 1000}
	r := pingLoop(context.Background(), params, start.Add(10*time.Second), gate, echo)

	if r.Sent != 0 {
		t.Fatalf("cycle = %+v, want nothing sent — there was no slack to wait in", r)
	}
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Fatalf("cycle spent %v giving up, want it to refuse without waiting", elapsed)
	}
	if turned := gate.TakeOverload(); turned == 0 {
		t.Error("the refused echo was not counted as overload")
	}
}

func TestICMPMetricsCarrySentCount(t *testing.T) {
	var res Result
	appendICMPMetrics(&res, time.Unix(1000, 0).UTC(), "m1", 3, "1.1.1.1",
		telemetry.LayerInternet, nil, pingCycleResult{Sent: 2, Received: 1, Loss: 50})

	var sent, samples float64 = -1, -1
	for _, m := range res.Metrics {
		switch m.Kind {
		case telemetry.ICMPSent:
			sent = m.Value
		case telemetry.ICMPSamples:
			samples = m.Value
		}
	}
	if sent != 2 {
		t.Errorf("probe.icmp.sent = %v, want 2", sent)
	}
	if samples != 1 {
		t.Errorf("probe.icmp.samples = %v, want 1", samples)
	}
}
