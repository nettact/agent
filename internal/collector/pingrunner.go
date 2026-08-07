package collector

import (
	"context"
	"sync"
	"time"
)

// pingRunner runs each due ping target's whole cycle on its own goroutine and
// buffers the finished per-target Results until the next Collect pass drains
// them. Shared by the public-ping and gateway collectors, which differ only in
// what one target's run does.
//
// Why the cycles cannot run inline any more: a healthy ICMP cycle now spreads
// its echoes across the target's entire check interval (see pingLoop), and every
// self-scheduled collector shares one sequential 1s poll loop in the scheduler.
// Run inline, a single 10s-interval ping target would hold that loop for ~10s
// and starve every other probe — DNS, HTTP, TCP, and the other ping targets —
// for its whole interval. Moving the run off the loop turns the old constraint
// ("keep a cycle shorter than its interval") into a much weaker one ("keep
// Collect from blocking").
//
// The cost is that a result surfaces on the tick after it completes rather than
// from the Collect that started it. That is deliberate: it keeps everything
// downstream of Collect unchanged — the scheduler still arms burst mode off a
// 100%-loss Result and still owns the only path to the WAL sink.
//
// Concurrency is bounded by the target list, not by the tick rate: schedState's
// in-flight guard means one goroutine per target at most, and each spends nearly
// all of it asleep between echoes. The platform pingers are built for this — a
// fresh ICMP handle (Windows) or socket with a random id/seq (unix) per echo.
//
// The goroutines themselves never touch the WAL. A cycle whose run context was
// cancelled discards its result outright (the shutdown contract: a pass cut
// short by shutdown must not fabricate loss that replays from the WAL as a
// false outage on the next start), and results finished but not yet drained at
// shutdown are simply dropped with the runner.
type pingRunner struct {
	sched *schedState

	mu   sync.Mutex
	done []Result

	wg sync.WaitGroup
}

func newPingRunner(fallback time.Duration) *pingRunner {
	return &pingRunner{sched: newSchedState(fallback)}
}

// collect drains the Results finished since the last pass and starts a cycle
// goroutine for every target that has come due, running it through run. It is
// the whole body of the embedding collector's Collect.
func (r *pingRunner) collect(ctx context.Context, run func(context.Context, scheduledProbe) Result) Result {
	res := r.drain()
	for _, sp := range r.sched.claim(time.Now()) {
		r.wg.Add(1)
		go func(sp scheduledProbe) {
			// The in-flight slot is released before wg.Done, so a WaitIdle that
			// returns can never be followed by a stale claim on this key. It
			// carries whether anything was actually reported, so a cycle that
			// produced nothing does not consume the target's first-run status.
			reported := false
			defer r.wg.Done()
			defer func() { r.sched.finish(sp.Key, reported) }()
			out := run(ctx, sp)
			if ctx.Err() != nil || resultEmpty(out) {
				return
			}
			reported = true
			r.mu.Lock()
			r.done = append(r.done, out)
			r.mu.Unlock()
		}(sp)
	}
	return res
}

// drain takes the finished Results and merges them into one. Per-target Results
// are independent, so concatenating them is the whole merge.
func (r *pingRunner) drain() Result {
	r.mu.Lock()
	done := r.done
	r.done = nil
	r.mu.Unlock()

	var res Result
	for _, d := range done {
		res.Metrics = append(res.Metrics, d.Metrics...)
		res.Events = append(res.Events, d.Events...)
		res.Blocked = append(res.Blocked, d.Blocked...)
	}
	return res
}

// WaitIdle blocks until every in-flight cycle has returned. The scheduler calls
// it once its poll loop has exited so Scheduler.Wait keeps its contract —
// nothing started by Run is still using the platform HAL or the proxy manager
// when the runtime tears them down. After the run context is cancelled a cycle
// unwinds within one per-echo timeout: the paced sleep aborts on cancellation
// and each platform call is bounded by its own timeout.
//
// The scheduler finds it through an optional interface, so these assertions are
// what keep a collector from losing the method without anything failing to
// build — the loss would only show up as a teardown race.
var (
	_ interface{ WaitIdle() } = (*PublicPingCollector)(nil)
	_ interface{ WaitIdle() } = (*GatewayPingCollector)(nil)
)

// Tests use it to make Collect deterministic (start the cycles, WaitIdle, then
// Collect again to drain).
func (r *pingRunner) WaitIdle() { r.wg.Wait() }

// SetMinInterval applies the local per-target probe-interval floor (stability limit).
func (r *pingRunner) SetMinInterval(d time.Duration) { r.sched.SetMinInterval(d) }

// resultEmpty reports whether a per-target run produced nothing at all — a
// target skipped this cycle (unreadable routes, a cancelled run). Buffering one
// would cost the scheduler an empty sink call for no data.
func resultEmpty(res Result) bool {
	return len(res.Metrics) == 0 && len(res.Events) == 0 && len(res.Blocked) == 0
}
