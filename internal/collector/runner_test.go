package collector

import (
	"context"
	"testing"
	"time"

	pcfg "github.com/nettact/protocol/config"
)

// blockingRun is a run function that reports when it started, blocks until its
// own context ends, and records how it ended.
type blockingRun struct {
	started chan scheduledProbe
	ended   chan error // the ctx error the run saw, nil if it was never cancelled
}

func newBlockingRun() *blockingRun {
	return &blockingRun{started: make(chan scheduledProbe, 8), ended: make(chan error, 8)}
}

func (b *blockingRun) run(ctx context.Context, sp scheduledProbe) (Result, func(*Result)) {
	b.started <- sp
	<-ctx.Done()
	b.ended <- ctx.Err()
	return Result{}, nil
}

func (b *blockingRun) awaitStart(t *testing.T) scheduledProbe {
	t.Helper()
	select {
	case sp := <-b.started:
		return sp
	case <-time.After(2 * time.Second):
		t.Fatal("run never started")
		return scheduledProbe{}
	}
}

func (b *blockingRun) awaitEnd(t *testing.T, what string) {
	t.Helper()
	select {
	case <-b.ended:
	case <-time.After(2 * time.Second):
		t.Fatalf("%s: run never unwound", what)
	}
}

func icmpTarget(serial int) pcfg.ProbeTarget {
	return pcfg.ProbeTarget{MonitorID: "m1", Kind: "icmp", Target: "1.1.1.1", ConfigSerial: serial}
}

// A push that supersedes a generation must withdraw the run still executing it.
// The replacement is claimable on the very next tick, so leaving the old one
// alive would have both probing — the obsolete one spending the machine's probe
// budget on samples the tracker is already committed to ignoring. Repeated edits
// during an outage (when probes are at their slowest) would stack them up.
func TestRunnerCancelsSupersededGeneration(t *testing.T) {
	r := newProbeRunner(10*time.Second, nil)
	b := newBlockingRun()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	r.setTargets([]pcfg.ProbeTarget{icmpTarget(1)})
	r.collect(ctx, b.run)
	if sp := b.awaitStart(t); sp.Target.ConfigSerial != 1 {
		t.Fatalf("started generation %d, want 1", sp.Target.ConfigSerial)
	}

	// The edit lands while generation 1 is mid-run.
	r.setTargets([]pcfg.ProbeTarget{icmpTarget(2)})
	b.awaitEnd(t, "superseded generation")

	// And the replacement runs on the next tick regardless.
	r.collect(ctx, b.run)
	if sp := b.awaitStart(t); sp.Target.ConfigSerial != 2 {
		t.Fatalf("started generation %d, want 2", sp.Target.ConfigSerial)
	}
	cancel()
	b.awaitEnd(t, "shutdown")
	r.WaitIdle()
}

// Removing a target entirely (not replacing it) must also withdraw its run.
func TestRunnerCancelsRemovedTarget(t *testing.T) {
	r := newProbeRunner(10*time.Second, nil)
	b := newBlockingRun()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	r.setTargets([]pcfg.ProbeTarget{icmpTarget(1)})
	r.collect(ctx, b.run)
	b.awaitStart(t)

	r.setTargets(nil)
	b.awaitEnd(t, "removed target")
	r.WaitIdle()
}

// A run that is still live must NOT be cancelled by a push that leaves its
// target alone. Re-pushing an unchanged list is routine (every config mutation
// pushes the whole DesiredState), and cancelling on it would mean a spread ICMP
// cycle never completes on a busy server.
func TestRunnerKeepsUnchangedTargetRunning(t *testing.T) {
	r := newProbeRunner(10*time.Second, nil)
	b := newBlockingRun()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	live := icmpTarget(1)
	r.setTargets([]pcfg.ProbeTarget{live})
	r.collect(ctx, b.run)
	b.awaitStart(t)

	// A push that re-states the same generation, plus an unrelated new target.
	r.setTargets([]pcfg.ProbeTarget{live, {MonitorID: "m2", Kind: "icmp", Target: "8.8.8.8", ConfigSerial: 1}})

	select {
	case <-b.ended:
		t.Fatal("an unchanged target's run was cancelled by an unrelated push")
	case <-time.After(100 * time.Millisecond):
	}
	cancel()
	b.awaitEnd(t, "shutdown")
	r.WaitIdle()
}

// A generation can be edited away and restored while its first run is still
// unwinding: the schedState key is derived from the material config, so the
// restored generation reuses it. The first run's exit must not release the
// second run's in-flight mark (which would let a third start alongside it) nor
// delete its cancel (which would leave it unstoppable).
func TestRunnerRestoredGenerationSurvivesItsPredecessorsExit(t *testing.T) {
	s := newSchedState(10 * time.Second)
	now := time.Unix(5000, 0)
	target := icmpTarget(1)

	s.set([]pcfg.ProbeTarget{target})
	first := s.claim(now)
	if len(first) != 1 {
		t.Fatalf("first claim = %+v, want the target", first)
	}

	// Edited away, then restored: same key, fresh slot.
	s.set([]pcfg.ProbeTarget{icmpTarget(2)})
	s.set([]pcfg.ProbeTarget{target})
	second := s.claim(now.Add(time.Second))
	if len(second) != 1 {
		t.Fatalf("restored claim = %+v, want the target claimable again", second)
	}
	if second[0].Key != first[0].Key {
		t.Fatalf("restored key = %q, want the predecessor's key %q", second[0].Key, first[0].Key)
	}
	if second[0].token == first[0].token {
		t.Fatal("restored run reused its predecessor's token")
	}

	// The predecessor finally unwinds. It must release nothing.
	s.finish(first[0], true)
	if again := s.claim(now.Add(time.Minute)); len(again) != 0 {
		t.Fatalf("a superseded run's finish released the live run: %+v", again)
	}
	s.finish(second[0], true)
	if again := s.claim(now.Add(time.Minute)); len(again) != 1 {
		t.Fatalf("target not claimable after the live run finished: %+v", again)
	}
}

// set reports exactly the in-flight runs it dropped — that list is what the
// runner cancels, so a wrong one either strands a run or kills a live one.
func TestSchedStateSetReportsDroppedRuns(t *testing.T) {
	s := newSchedState(10 * time.Second)
	now := time.Unix(6000, 0)
	a := icmpTarget(1)
	b := pcfg.ProbeTarget{MonitorID: "m2", Kind: "icmp", Target: "8.8.8.8", ConfigSerial: 1}

	s.set([]pcfg.ProbeTarget{a, b})
	claimed := s.claim(now)
	if len(claimed) != 2 {
		t.Fatalf("claim = %+v, want both targets", claimed)
	}

	// Keep b, supersede a. Only a's run is dropped.
	dropped := s.set([]pcfg.ProbeTarget{icmpTarget(2), b})
	if len(dropped) != 1 || dropped[0] != schedKey(a) {
		t.Fatalf("dropped = %v, want just the superseded generation of a", dropped)
	}

	// A push that changes nothing in flight drops nothing.
	if dropped := s.set([]pcfg.ProbeTarget{icmpTarget(2), b}); len(dropped) != 0 {
		t.Fatalf("dropped = %v on an unchanged push, want none", dropped)
	}
}

// Claiming a run and registering it for cancellation cannot be one atomic step —
// they are guarded by different mutexes. A push landing in the gap prunes the
// claim while there is still no handle to cancel, so setTargets finds nothing and
// the withdrawn run would probe on to completion, holding a budget slot to
// produce samples the server will discard.
//
// This drives that exact interleaving: the push happens after claim() has taken
// the target but before collect() registers the handle.
func TestRunnerCancelsAGenerationWithdrawnDuringTheClaimGap(t *testing.T) {
	r := newProbeRunner(10*time.Second, nil)
	b := newBlockingRun()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	r.setTargets([]pcfg.ProbeTarget{icmpTarget(1)})

	// Claim by hand, then withdraw the generation — the gap, reproduced exactly.
	claimed := r.sched.claim(time.Now())
	if len(claimed) != 1 {
		t.Fatalf("claim = %+v, want the target", claimed)
	}
	r.setTargets([]pcfg.ProbeTarget{icmpTarget(2)})

	// Now let the runner register and start the run it claimed pre-withdrawal.
	// It must notice the claim is gone and cancel itself.
	r.startClaimed(ctx, claimed, b.run)
	b.awaitStart(t)
	b.awaitEnd(t, "generation withdrawn during the claim gap")
	r.WaitIdle()
}
