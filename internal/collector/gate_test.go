package collector

import (
	"context"
	"sync"
	"testing"
	"time"
)

// far is a deadline no test will ever reach, for acquires that should not be
// bounded by the clock.
func far() time.Time { return time.Now().Add(time.Hour) }

func TestProbeGateNilIsUnlimited(t *testing.T) {
	var g *ProbeGate
	for i := 0; i < 100; i++ {
		if got := g.Acquire(context.Background(), time.Now().Add(-time.Hour)); got != AdmittedOK {
			t.Fatalf("nil gate acquire %d = %v, want AdmittedOK", i, got)
		}
	}
	g.Release() // must not panic
	if got := g.Limit(); got != 0 {
		t.Errorf("nil gate Limit = %d, want 0", got)
	}
	if got := g.TakeOverload(); got != 0 {
		t.Errorf("nil gate TakeOverload = %d, want 0", got)
	}
	if NewProbeGate(0) != nil || NewProbeGate(-1) != nil {
		t.Error("NewProbeGate(<=0) should be an unlimited (nil) gate")
	}
}

// The core acceptance criterion: with a budget of N, no more than N operations
// can ever be in flight at once, however many targets are due.
func TestProbeGateNeverExceedsItsLimit(t *testing.T) {
	const limit, workers = 2, 10
	g := NewProbeGate(limit)

	var mu sync.Mutex
	inflight, peak := 0, 0

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				if got := g.Acquire(context.Background(), far()); got != AdmittedOK {
					t.Errorf("acquire = %v, want AdmittedOK", got)
					return
				}
				mu.Lock()
				inflight++
				if inflight > peak {
					peak = inflight
				}
				mu.Unlock()

				time.Sleep(time.Millisecond)

				mu.Lock()
				inflight--
				mu.Unlock()
				g.Release()
			}
		}()
	}
	wg.Wait()

	if peak > limit {
		t.Errorf("peak in-flight = %d, want <= %d", peak, limit)
	}
	if peak < limit {
		t.Errorf("peak in-flight = %d, want the budget %d to be usable", peak, limit)
	}
	if got := g.TakeOverload(); got != 0 {
		t.Errorf("turned away %d operations, want 0 (every acquire had an unbounded deadline)", got)
	}
}

// A full budget turns an operation away at its deadline rather than running it
// late, and counts it so the heartbeat can explain the silence.
func TestProbeGateTurnsAwayPastTheDeadlineAndCounts(t *testing.T) {
	g := NewProbeGate(1)
	if got := g.Acquire(context.Background(), far()); got != AdmittedOK {
		t.Fatalf("first acquire = %v, want AdmittedOK", got)
	}

	start := time.Now()
	if got := g.Acquire(context.Background(), time.Now().Add(20*time.Millisecond)); got != AdmittedOverloaded {
		t.Fatalf("acquire on a full budget = %v, want AdmittedOverloaded", got)
	}
	if waited := time.Since(start); waited < 15*time.Millisecond {
		t.Errorf("gave up after %v, want it to have waited out its ~20ms budget", waited)
	}

	// An already-expired deadline does not wait at all.
	start = time.Now()
	if got := g.Acquire(context.Background(), time.Now().Add(-time.Second)); got != AdmittedOverloaded {
		t.Fatalf("acquire with an expired deadline = %v, want AdmittedOverloaded", got)
	}
	if waited := time.Since(start); waited > 50*time.Millisecond {
		t.Errorf("expired deadline waited %v, want an immediate refusal", waited)
	}

	if got := g.TakeOverload(); got != 2 {
		t.Errorf("TakeOverload = %d, want 2", got)
	}
	if got := g.TakeOverload(); got != 0 {
		t.Errorf("TakeOverload did not reset: second call = %d, want 0", got)
	}
	g.Release()
}

// A waiter admitted once a slot frees is not overload: it measured normally,
// just later, so it must not be counted.
func TestProbeGateAdmitsAWaiterWhenASlotFrees(t *testing.T) {
	g := NewProbeGate(1)
	if got := g.Acquire(context.Background(), far()); got != AdmittedOK {
		t.Fatalf("first acquire = %v, want AdmittedOK", got)
	}
	go func() {
		time.Sleep(10 * time.Millisecond)
		g.Release()
	}()
	if got := g.Acquire(context.Background(), time.Now().Add(2*time.Second)); got != AdmittedOK {
		t.Fatalf("waiting acquire = %v, want AdmittedOK", got)
	}
	if got := g.TakeOverload(); got != 0 {
		t.Errorf("turned away %d, want 0 — the operation did run", got)
	}
	g.Release()
}

// Shutdown and a superseded generation both cancel the run context. Neither is
// overload: the probe was withdrawn, not starved, and counting it would report a
// restart as a capacity problem.
func TestProbeGateCancellationIsNotOverload(t *testing.T) {
	g := NewProbeGate(1)
	if got := g.Acquire(context.Background(), far()); got != AdmittedOK {
		t.Fatalf("first acquire = %v, want AdmittedOK", got)
	}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(10 * time.Millisecond)
		cancel()
	}()
	if got := g.Acquire(ctx, time.Now().Add(2*time.Second)); got != AdmittedCanceled {
		t.Fatalf("acquire on a cancelled run = %v, want AdmittedCanceled", got)
	}

	// Already-cancelled is reported as cancellation even when the deadline has
	// also passed: shutdown wins over overload.
	if got := g.Acquire(ctx, time.Now().Add(-time.Second)); got != AdmittedCanceled {
		t.Fatalf("acquire with a cancelled ctx and expired deadline = %v, want AdmittedCanceled", got)
	}
	if got := g.TakeOverload(); got != 0 {
		t.Errorf("turned away %d, want 0 — cancellation is not overload", got)
	}
	g.Release()
}

// A free slot is taken without consulting the clock, so an agent inside its
// budget is unaffected by the gate even when its deadline has long passed. This
// is what keeps ping pacing identical to the pre-gate behavior.
func TestProbeGateFastPathIgnoresTheDeadline(t *testing.T) {
	g := NewProbeGate(4)
	for i := 0; i < 4; i++ {
		if got := g.Acquire(context.Background(), time.Now().Add(-time.Hour)); got != AdmittedOK {
			t.Fatalf("acquire %d within budget = %v, want AdmittedOK despite the stale deadline", i, got)
		}
	}
	for i := 0; i < 4; i++ {
		g.Release()
	}
	if got := g.TakeOverload(); got != 0 {
		t.Errorf("turned away %d, want 0", got)
	}
}
