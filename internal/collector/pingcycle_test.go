package collector

import (
	"context"
	"testing"
	"time"

	"github.com/nettact/agent/internal/netguard"
	"github.com/nettact/agent/probepolicy"
	pcfg "github.com/nettact/protocol/config"
	"github.com/nettact/protocol/telemetry"
)

func TestSpreadGap(t *testing.T) {
	base := time.Unix(2000, 0)
	const timeout = time.Second
	cases := []struct {
		name      string
		now       time.Time
		boundary  time.Time
		remaining int
		received  bool
		want      time.Duration
	}{
		// The default shape: 5 packets on a 10s interval reserve 1s at the tail,
		// so 9s of budget is shared by the 4 sends left after the first. The
		// feasibility bound (10s − 4×1s = 6s) does not bite here.
		{"even spread", base, base.Add(10 * time.Second), 4, true, 2250 * time.Millisecond},
		{"last send takes the whole residue", base, base.Add(10 * time.Second), 1, true, 9 * time.Second},
		// Fail-fast: a lost echo sends the next one immediately, whatever budget is
		// left, so a dead target finishes its cycle at count×timeout.
		{"lost echo sends immediately", base, base.Add(10 * time.Second), 4, false, 0},
		// Feasibility wins over the even spread when the echoes still to come would
		// not fit their own timeouts: an even 750ms here would leave the last echo
		// short of a full timeout and report a healthy link as lost.
		{"feasibility caps the spread", base, base.Add(2500 * time.Millisecond), 2, true, 500 * time.Millisecond},
		{"count cannot fit the budget at all", base, base.Add(3 * time.Second), 4, true, 0},
		// Behind schedule (slow replies ate the budget): back-to-back is the closest
		// the cycle can still get to its intended cadence.
		{"past the last send instant", base.Add(time.Second), base, 3, true, 0},
		{"exactly at the last send instant", base, base.Add(timeout), 3, true, 0},
		// No pacing budget offered at all (a zero boundary) reads as "already past".
		{"zero budget", base, time.Time{}, 3, true, 0},
		{"nothing left to send", base, base.Add(10 * time.Second), 0, true, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := spreadGap(c.now, c.boundary, timeout, c.remaining, c.received); got != c.want {
				t.Fatalf("spreadGap = %v, want %v", got, c.want)
			}
		})
	}
}

// A healthy cycle must spread its echoes evenly over the interval, reserving one
// per-echo timeout at the tail so the last echo completes before the target is
// due again. Defaults: 5 packets, 1s timeout, 10s interval → 9s of budget, one
// echo every 2.25s.
func TestPingCycleSpreadsEchoesAcrossInterval(t *testing.T) {
	clk := stubCycleClock(t)
	p := &gwTestPlatform{}
	nextDue := clk.Now().Add(10 * time.Second)

	r := pingCycle(context.Background(), p, "1.1.1.1", pcfg.ProbeParams{}, nextDue)

	if r.Loss != 0 || r.Received != 5 {
		t.Fatalf("cycle = %+v, want 5 received / 0%% loss", r)
	}
	want := []time.Duration{2250 * time.Millisecond, 2250 * time.Millisecond, 2250 * time.Millisecond, 2250 * time.Millisecond}
	got := clk.gaps()
	if len(got) != len(want) {
		t.Fatalf("gaps = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("gaps = %v, want %v", got, want)
		}
	}
	// The last echo left at 9s — a full per-echo timeout before the next cycle.
	if elapsed := clk.Now().Sub(nextDue.Add(-10 * time.Second)); elapsed != 9*time.Second {
		t.Fatalf("cycle ended %v after it began, want the last send at 9s", elapsed)
	}
}

// A target that is fully down must not pay the spread: every echo fails, so
// every gap is zero and the cycle (and its 100%-loss round) completes in
// count×timeout. This is the property that keeps alert latency from regressing.
func TestPingCycleFailFastOnLoss(t *testing.T) {
	clk := stubCycleClock(t)
	p := &gwTestPlatform{recv: func(int) bool { return false }}

	r := pingCycle(context.Background(), p, "1.1.1.1", pcfg.ProbeParams{}, clk.Now().Add(10*time.Second))

	if r.Loss != 100 || r.Received != 0 {
		t.Fatalf("cycle = %+v, want 100%% loss", r)
	}
	if gaps := clk.gaps(); len(gaps) != 0 {
		t.Fatalf("a fully-lost cycle waited between echoes: %v", gaps)
	}
	if got := p.pingCount(); got != 5 {
		t.Fatalf("pings=%d want 5 (fail-fast still sends the whole count)", got)
	}
}

// A single loss mid-cycle sends the next echo immediately, then the pacing picks
// the spread back up over whatever budget is left.
func TestPingCycleResumesSpreadAfterOneLoss(t *testing.T) {
	clk := stubCycleClock(t)
	p := &gwTestPlatform{recv: func(seq int) bool { return seq != 1 }}

	r := pingCycle(context.Background(), p, "1.1.1.1", pcfg.ProbeParams{}, clk.Now().Add(10*time.Second))

	if r.Loss != 20 || r.Received != 4 {
		t.Fatalf("cycle = %+v, want 1 of 5 lost", r)
	}
	// echo0 ok at 0s → 2.25s gap → echo1 lost at 2.25s → 0 gap → echo2 at 2.25s,
	// which leaves 6.75s for the last two sends → 3.375s each.
	want := []time.Duration{2250 * time.Millisecond, 3375 * time.Millisecond, 3375 * time.Millisecond}
	got := clk.gaps()
	if len(got) != len(want) {
		t.Fatalf("gaps = %v, want %v (a zero gap is never recorded)", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("gaps = %v, want %v", got, want)
		}
	}
}

// GlobalTimeoutMs shorter than the interval becomes the pacing budget: the cycle
// must finish inside the global deadline, not inside the interval.
func TestPingCyclePacesAgainstGlobalTimeout(t *testing.T) {
	clk := stubCycleClock(t)
	p := &gwTestPlatform{}
	start := clk.Now()

	// 5s global budget, 1s per echo → 4s of send window shared by 4 gaps.
	r := pingCycle(context.Background(), p, "1.1.1.1",
		pcfg.ProbeParams{GlobalTimeoutMs: 5_000}, start.Add(10*time.Second))

	if r.Received != 5 {
		t.Fatalf("cycle = %+v, want all 5 received inside the global budget", r)
	}
	for _, g := range clk.gaps() {
		if g != time.Second {
			t.Fatalf("gaps = %v, want 1s each (global deadline, not the interval)", clk.gaps())
		}
	}
	if elapsed := clk.Now().Sub(start); elapsed != 4*time.Second {
		t.Fatalf("last send at %v, want 4s (5s deadline less one echo timeout)", elapsed)
	}
}

func TestPingCycleSinglePacketNeverPaces(t *testing.T) {
	clk := stubCycleClock(t)
	p := &gwTestPlatform{}

	r := pingCycle(context.Background(), p, "1.1.1.1",
		pcfg.ProbeParams{PacketCount: 1}, clk.Now().Add(10*time.Second))

	if r.Received != 1 {
		t.Fatalf("cycle = %+v, want the single echo received", r)
	}
	if gaps := clk.gaps(); len(gaps) != 0 {
		t.Fatalf("a one-packet cycle waited: %v", gaps)
	}
}

// The regression this pacing was nearly broken by: spreading only reserved ONE
// per-echo timeout at the tail and ignored what the intermediate echoes
// themselves cost, so on a slow-but-healthy link the budget ran out and the last
// echo was sent with a timeout shorter than the link's own RTT. That echo timed
// out, and a target with zero real packet loss reported 20% loss on every single
// cycle — a permanent fabricated loss floor under the availability detector.
func TestPingCycleNeverFabricatesLossOnASlowHealthyLink(t *testing.T) {
	clk := stubCycleClock(t)
	// 900ms RTT against a 1s per-echo timeout: healthy, but only just.
	p := &gwTestPlatform{clk: clk, rtt: 900 * time.Millisecond}
	start := clk.Now()

	r := pingCycle(context.Background(), p, "1.1.1.1",
		pcfg.ProbeParams{GlobalTimeoutMs: 8_000}, start.Add(10*time.Second))

	if r.Loss != 0 || r.Received != 5 {
		t.Fatalf("cycle = %+v, want 0%% loss — every echo answered within its timeout", r)
	}
	if elapsed := clk.Now().Sub(start); elapsed > 8*time.Second {
		t.Fatalf("cycle ran %v, past its 8s global deadline", elapsed)
	}
}

// The same budgeting keeps a packet-heavy target inside the deadline the server
// derives for it. Without it the tail runs back-to-back past the interval, and
// the in-flight guard then silently stretches the target's real cadence.
func TestPingCycleStaysWithinItsDerivedDeadline(t *testing.T) {
	clk := stubCycleClock(t)
	p := &gwTestPlatform{clk: clk, rtt: 999 * time.Millisecond}
	start := clk.Now()
	params := pcfg.ProbeParams{PacketCount: 20, IntervalSeconds: 25}

	r := pingCycle(context.Background(), p, "1.1.1.1", params, start.Add(25*time.Second))

	if r.Received != 20 {
		t.Fatalf("cycle = %+v, want all 20 echoes received", r)
	}
	deadline := pcfg.CycleDeadline("icmp", params)
	if elapsed := clk.Now().Sub(start); elapsed > deadline {
		t.Fatalf("cycle ran %v, past the derived CycleDeadline %v", elapsed, deadline)
	}
}

// A target's very first cycle must not be spread over the whole interval: a
// newly created five-minute monitor would then show nothing at all for five
// minutes, which reads as broken rather than slow. It paces against its own
// worst case instead, and the interval takes over from the second cycle.
func TestFirstCyclePacesAgainstItsOwnWorstCase(t *testing.T) {
	clk := stubCycleClock(t)
	now := clk.Now()
	sp := scheduledProbe{
		Target:  pcfg.ProbeTarget{Kind: "icmp", Target: "1.1.1.1", Params: pcfg.ProbeParams{IntervalSeconds: 300}},
		NextDue: now.Add(300 * time.Second),
		First:   true,
	}
	// 5 packets × 1s, not the 300s interval.
	if got, want := pacingDeadline(sp), now.Add(5*time.Second); !got.Equal(want) {
		t.Fatalf("first-cycle pacing deadline = %v, want %v", got, want)
	}
	sp.First = false
	if got := pacingDeadline(sp); !got.Equal(sp.NextDue) {
		t.Fatalf("steady-state pacing deadline = %v, want the next due instant %v", got, sp.NextDue)
	}
}

// claim must report which probes have never run, since that is what decides the
// first cycle's pacing budget.
func TestSchedStateClaimMarksFirstRun(t *testing.T) {
	s := newSchedState(10 * time.Second)
	now := time.Unix(4000, 0)
	s.set([]pcfg.ProbeTarget{{MonitorID: "m1", Kind: "icmp", Target: "1.1.1.1"}})

	first := s.claim(now)
	if len(first) != 1 || !first[0].First {
		t.Fatalf("claim = %+v, want the target marked as a first run", first)
	}
	s.finish(first[0].Key, true)
	again := s.claim(now.Add(10 * time.Second))
	if len(again) != 1 || again[0].First {
		t.Fatalf("claim = %+v, want the second run NOT marked first", again)
	}
}

// A cycle that reported nothing must not consume the target's one fast first
// cycle: the gateway probe legitimately produces an empty Result when the
// routing table is momentarily unreadable, and if that counted as the first run
// the first REAL measurement would be spread over a whole interval — a
// five-minute monitor blank for ten minutes instead of five.
func TestSchedStateKeepsFirstRunUntilSomethingIsReported(t *testing.T) {
	s := newSchedState(10 * time.Second)
	now := time.Unix(4000, 0)
	s.set([]pcfg.ProbeTarget{{MonitorID: "gw1", Kind: "gateway", Target: "gateway"}})

	empty := s.claim(now)
	if len(empty) != 1 || !empty[0].First {
		t.Fatalf("claim = %+v, want a first run", empty)
	}
	s.finish(empty[0].Key, false) // the cycle produced nothing

	retry := s.claim(now.Add(10 * time.Second))
	if len(retry) != 1 || !retry[0].First {
		t.Fatalf("claim = %+v, want STILL a first run after an empty cycle", retry)
	}
	s.finish(retry[0].Key, true)

	settled := s.claim(now.Add(20 * time.Second))
	if len(settled) != 1 || settled[0].First {
		t.Fatalf("claim = %+v, want the run after a reported cycle NOT marked first", settled)
	}
}

// A cycle spans most of its interval, so the tick that finds a target due again
// can land while its previous cycle is still running. Claiming must not hand the
// same target out twice.
func TestSchedStateClaimGuardsInFlight(t *testing.T) {
	s := newSchedState(10 * time.Second)
	now := time.Unix(3000, 0)
	target := pcfg.ProbeTarget{MonitorID: "m1", Kind: "icmp", Target: "1.1.1.1", ConfigSerial: 1}
	s.set([]pcfg.ProbeTarget{target})

	claimed := s.claim(now)
	if len(claimed) != 1 {
		t.Fatalf("first claim = %+v, want the target", claimed)
	}
	if want := now.Add(10 * time.Second); !claimed[0].NextDue.Equal(want) {
		t.Fatalf("NextDue = %v, want %v (the pacing budget)", claimed[0].NextDue, want)
	}
	// Long past due, but the previous cycle is still running.
	if again := s.claim(now.Add(time.Minute)); len(again) != 0 {
		t.Fatalf("claimed an in-flight target: %+v", again)
	}
	s.finish(claimed[0].Key, true)
	if again := s.claim(now.Add(time.Minute)); len(again) != 1 {
		t.Fatalf("target not claimable after finish: %+v", again)
	}
}

// A new generation must run on the next tick even if the previous generation's
// cycle is still in flight — and that stale cycle's finish must not release the
// replacement's slot.
func TestSchedStateClaimNewGenerationDespiteInFlight(t *testing.T) {
	s := newSchedState(10 * time.Second)
	now := time.Unix(3000, 0)
	target := pcfg.ProbeTarget{MonitorID: "m1", Kind: "icmp", Target: "1.1.1.1", ConfigSerial: 1}
	s.set([]pcfg.ProbeTarget{target})
	stale := s.claim(now)
	if len(stale) != 1 {
		t.Fatalf("first claim = %+v, want the target", stale)
	}

	target.ConfigSerial = 2
	s.set([]pcfg.ProbeTarget{target})
	fresh := s.claim(now.Add(time.Second))
	if len(fresh) != 1 || fresh[0].Target.ConfigSerial != 2 {
		t.Fatalf("new generation claim = %+v, want generation 2 immediately", fresh)
	}
	s.finish(stale[0].Key, true) // the superseded cycle finishing must be a no-op
	if again := s.claim(now.Add(2 * time.Second)); len(again) != 0 {
		t.Fatalf("a stale finish released the live generation: %+v", again)
	}
}

// Samples are stamped when the cycle ends, not when the pass that started it
// began: a spread cycle summarizes the window that just closed. All samples of
// ONE cycle still share a stamp, which is what the server's MonitorID+TS-second
// round keying needs.
func TestPingCycleStampsSamplesAtCompletion(t *testing.T) {
	clk := stubCycleClock(t)
	start := clk.Now()
	p := &gwTestPlatform{}
	c := NewPublicPingCollector(p, netguard.New(probepolicy.Policy{}, true), nil)
	c.SetTargets([]pcfg.ProbeTarget{
		{MonitorID: "m1", Kind: "icmp", Target: "1.1.1.1", Params: pcfg.ProbeParams{PacketCount: 2}},
	})

	res := collectSettled(t, context.Background(), c)

	if len(res.Metrics) == 0 {
		t.Fatal("no metrics after the cycle finished")
	}
	for _, m := range res.Metrics {
		if !m.TS.After(start) {
			t.Fatalf("metric stamped %v, want after the pass start %v", m.TS, start)
		}
		if !m.TS.Equal(res.Metrics[0].TS) {
			t.Fatalf("one cycle produced two timestamps: %v and %v", res.Metrics[0].TS, m.TS)
		}
	}
}

// The whole point of running cycles off the poll loop: Collect must return
// promptly with whatever finished earlier, not block for the cycle it starts.
func TestPingCollectDeliversOnALaterPass(t *testing.T) {
	stubCycleClock(t)
	p := &gwTestPlatform{}
	c := NewPublicPingCollector(p, netguard.New(probepolicy.Policy{}, true), nil)
	c.SetTargets([]pcfg.ProbeTarget{
		{MonitorID: "m1", Kind: "icmp", Target: "1.1.1.1"},
	})

	first, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(first.Metrics) != 0 {
		t.Fatalf("Collect returned a cycle it had only just started: %+v", first)
	}
	c.WaitIdle()
	second, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if lossPct(second) != 0 {
		t.Fatalf("finished cycle did not surface on the next pass: %+v", second)
	}
	var haveLoss bool
	for _, m := range second.Metrics {
		if m.Kind == telemetry.ICMPLoss && m.MonitorID == "m1" {
			haveLoss = true
		}
	}
	if !haveLoss {
		t.Fatalf("drained result missing the target's loss sample: %+v", second.Metrics)
	}
}
