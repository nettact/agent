package collector

import (
	"context"
	"sync"
	"testing"
	"time"
)

// Test support for the asynchronous, interval-spread ping cycle.
//
// Two things make a spread cycle awkward to unit-test: it waits most of a check
// interval in real time, and its result surfaces on a Collect after the one that
// started it. fakeCycleClock removes the first problem by advancing a synthetic
// clock instead of sleeping — which also lets a test assert the exact gaps the
// pacing asked for rather than inferring them from elapsed wall time — and
// collectSettled removes the second by draining once the cycles have finished.

// fakeCycleClock stands in for cycleNow/cycleSleep. Each sleep advances the
// clock by exactly the requested duration and records it.
type fakeCycleClock struct {
	mu    sync.Mutex
	now   time.Time
	slept []time.Duration
}

// stubCycleClock installs a synthetic clock for the duration of one test. It
// starts at real now so that NextDue values taken from schedState.claim (which
// uses the real clock) stay coherent with it.
func stubCycleClock(t *testing.T) *fakeCycleClock {
	t.Helper()
	c := &fakeCycleClock{now: time.Now()}
	oldNow, oldSleep := cycleNow, cycleSleep
	cycleNow = c.Now
	cycleSleep = func(ctx context.Context, d time.Duration) bool {
		if ctx.Err() != nil {
			return false
		}
		c.advance(d)
		return true
	}
	t.Cleanup(func() { cycleNow, cycleSleep = oldNow, oldSleep })
	return c
}

func (c *fakeCycleClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeCycleClock) advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.slept = append(c.slept, d)
	c.mu.Unlock()
}

// spend moves the clock without recording a pacing gap — what an echo's own
// round trip costs. Tests that leave it at zero exercise an infinitely fast
// link, which is exactly the regime where the pacing math is easiest to get
// right; give the fake platform an rtt to test the regime where it is not.
func (c *fakeCycleClock) spend(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

// gaps returns the pacing gaps requested so far, in order.
func (c *fakeCycleClock) gaps() []time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]time.Duration(nil), c.slept...)
}

// settledCollector is the shape both ping collectors share: start cycles, then
// hand their results back on a later pass.
type settledCollector interface {
	Collect(context.Context) (Result, error)
	WaitIdle()
}

// collectSettled runs one full round trip: the first Collect starts the due
// targets' cycles, WaitIdle lets them finish, and the second drains them. The
// second Collect starts nothing new — claim already pushed each target's
// next-due a full interval into real time.
func collectSettled(t *testing.T, ctx context.Context, c settledCollector) Result {
	t.Helper()
	if res, err := c.Collect(ctx); err != nil {
		t.Fatalf("Collect (start): %v", err)
	} else if !resultEmpty(res) {
		t.Fatalf("first Collect returned data before any cycle finished: %+v", res)
	}
	c.WaitIdle()
	res, err := c.Collect(ctx)
	if err != nil {
		t.Fatalf("Collect (drain): %v", err)
	}
	return res
}
