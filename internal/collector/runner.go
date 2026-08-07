package collector

import (
	"context"
	"sync"
	"time"

	pcfg "github.com/nettact/protocol/config"
)

// probeRunner runs each due target's whole probe on its own goroutine and
// buffers the finished per-target Results until the next Collect pass drains
// them. Every target-driven collector embeds one: the ping pair, and the
// single-shot kinds (DNS/HTTP/TCP/NAT). They differ only in what one target's
// run does.
//
// Why nothing runs inline any more: every self-scheduled collector shares one
// sequential 1s poll loop in the scheduler, so whatever a Collect does, every
// other probe on the agent waits for. That was survivable while each probe was a
// quick burst, and stopped being survivable twice over. A healthy ICMP cycle now
// spreads its echoes across the target's entire check interval (see pingLoop), so
// one 10s target would hold the loop for 10s. And a single-shot probe is bounded
// only by its own timeout — a dead HTTP target costs 10s, a NAT discovery 25s —
// which is exactly the moment when the probes queued behind it are the ones
// someone is waiting on. Moving every run off the loop turns "keep a probe
// shorter than its interval" into the much weaker "keep Collect from blocking".
//
// The cost is that a result surfaces on the tick after it completes rather than
// from the Collect that started it. That is deliberate: it keeps everything
// downstream of Collect unchanged — the scheduler still arms burst mode off a
// 100%-loss Result and still owns the only path to the WAL sink.
//
// # Why the goroutine count cannot run away
//
// Concurrency is bounded by the target list, not by the tick rate: schedState's
// in-flight guard means one goroutine per target at most. How much of it is
// actually PROBING at once is bounded separately and machine-wide by ProbeGate —
// the goroutines are cheap because each spends nearly all its life asleep
// (between a ping cycle's echoes) or blocked on I/O it already holds a slot for.
//
// A superseded generation does not accumulate either. set cancels the runs whose
// targets are gone, so a burst of config pushes leaves at most one live run per
// CURRENT target rather than one per push: a cancelled run drops out of a gate
// queue immediately, and unwinds within one operation timeout if it is already
// probing. Without that, edits during an outage — when every probe is at its
// slowest — would pile up runs that go on to spend budget on answers nobody can
// use any more.
//
// # What the goroutines may touch
//
// Never the WAL. A run whose context was cancelled discards its result outright
// (the shutdown contract: a pass cut short by shutdown must not fabricate a
// failure that replays from the WAL as a false outage on the next start), and
// results finished but not yet drained at shutdown are simply dropped with the
// runner. Everything else a run touches — the platform HAL, the guard, the proxy
// manager, its collector's own client caches — is safe for concurrent use.
type probeRunner struct {
	sched *schedState
	// gate is the machine-wide probe budget every run draws from. One instance is
	// shared by every collector of every server (see ProbeGate); nil is unlimited.
	gate *ProbeGate

	mu   sync.Mutex
	done []Result
	// running holds the cancel of every in-flight run, keyed the same way
	// schedState keys its claims, so set can withdraw the generations it drops.
	// The token disambiguates a key claimed again (an edit-then-restore) while
	// its previous run is still unwinding, so the old run's exit cannot delete
	// the new run's cancel and leave it unstoppable.
	running map[string]runHandle

	wg sync.WaitGroup
}

// runHandle is one in-flight run's cancel, tagged with the schedState token that
// identifies which run of that key it belongs to.
type runHandle struct {
	token  int64
	cancel context.CancelFunc
}

func newProbeRunner(fallback time.Duration, gate *ProbeGate) *probeRunner {
	return &probeRunner{sched: newSchedState(fallback), gate: gate, running: map[string]runHandle{}}
}

// Budget reports the concurrency budget this collector's probes draw from (nil
// when unlimited). It exists so the runtime assembly can be asserted to hand
// every collector of every server the SAME budget — a per-collector or
// per-server one would multiply the machine's allowance by the number of probe
// kinds and servers, which is no allowance at all.
func (r *probeRunner) Budget() *ProbeGate { return r.gate }

// setTargets replaces the target list from a DesiredState push and cancels the
// runs of the generations that push removed.
//
// Cancelling is what keeps a superseded run from competing with its own
// replacement. The replacement is claimable on the very next tick (schedState
// prunes the old in-flight mark), so without this both would be probing, and the
// obsolete one would hold a concurrency slot to produce samples the tracker is
// already committed to ignoring. A cancelled run discards its result rather than
// reporting a failure, so nothing it did halfway becomes telemetry.
func (r *probeRunner) setTargets(targets []pcfg.ProbeTarget) {
	dropped := r.sched.set(targets)
	if len(dropped) == 0 {
		return
	}
	r.mu.Lock()
	cancels := make([]context.CancelFunc, 0, len(dropped))
	for _, k := range dropped {
		if h, ok := r.running[k]; ok {
			cancels = append(cancels, h.cancel)
		}
	}
	r.mu.Unlock()
	// Outside the lock: a cancel wakes the run's goroutine, which takes the same
	// mutex on its way out.
	for _, cancel := range cancels {
		cancel()
	}
}

// collect drains the Results finished since the last pass and starts a goroutine
// for every target that has come due, running it through run. It is the whole
// body of the embedding collector's Collect.
// runFunc probes one target. It returns what the round produced and, optionally,
// a commit to run if — and only if — that Result is going to be published.
//
// The commit exists for side effects that must stay in step with what was
// actually reported. NAT's mapped-address change gate is the case that forced
// it: it decides "is this address different from the last one we told anyone
// about", so advancing it for a Result the runner then discards makes the NEXT
// round see no change and the real WAN IP change is never reported at all.
// Checking cancellation inside the run before committing only narrows that
// window — cancellation can still land between the check and the runner's own —
// so the decision and the commit have to be the same decision. That is what this
// hook makes them. It may append to the Result (the change event), which is why
// it takes a pointer and runs before the Result is handed on.
type runFunc func(context.Context, scheduledProbe) (Result, func(*Result))

// collect drains the Results finished since the last pass and starts a goroutine
// for every target that has come due, running it through run. It is the whole
// body of the embedding collector's Collect.
func (r *probeRunner) collect(ctx context.Context, run runFunc) Result {
	res := r.drain()
	r.startClaimed(ctx, r.sched.claim(time.Now()), run)
	return res
}

// startClaimed launches a goroutine for each already-claimed probe. It is split
// out of collect so a test can drive the window between the claim and the
// registration — the one this function has to close (see below).
func (r *probeRunner) startClaimed(ctx context.Context, claimed []scheduledProbe, run runFunc) {
	for _, sp := range claimed {
		// A per-run context so setTargets can withdraw this generation alone. It
		// derives from the run context, so shutdown still cancels everything.
		rctx, cancel := context.WithCancel(ctx)
		r.mu.Lock()
		r.running[sp.Key] = runHandle{token: sp.token, cancel: cancel}
		r.mu.Unlock()
		// Claiming and registering cannot be one atomic step — they are guarded by
		// schedState's mutex and the runner's. A push landing in the gap between
		// them prunes the claim while there is still nothing registered to cancel,
		// so setTargets finds no handle and the withdrawn run would probe on to
		// completion, holding a budget slot to produce samples the server will
		// discard. Re-checking after registering closes the gap from the other
		// side, and a doubled cancel is harmless.
		if !r.sched.holds(sp.Key, sp.token) {
			cancel()
		}

		r.wg.Add(1)
		go func(sp scheduledProbe) {
			// The in-flight slot is released before wg.Done, so a WaitIdle that
			// returns can never be followed by a stale claim on this key. It
			// carries whether anything was actually reported, so a run that
			// produced nothing does not consume the target's first-run status.
			reported := false
			defer r.wg.Done()
			defer func() {
				r.sched.finish(sp, reported)
				r.mu.Lock()
				// Only if this run still holds the key: a later generation
				// reusing it has already replaced the entry, and dropping that
				// one would leave the live run uncancellable.
				if h, ok := r.running[sp.Key]; ok && h.token == sp.token {
					delete(r.running, sp.Key)
				}
				r.mu.Unlock()
				cancel()
			}()
			out, commit := run(rctx, sp)
			if rctx.Err() != nil || resultEmpty(out) {
				return
			}
			// Past the discard decision: this Result WILL be published, so the
			// round's side effects may now be committed. Nothing re-checks
			// cancellation after this point, which is the whole guarantee — a
			// commit can never outlive the result it describes.
			if commit != nil {
				commit(&out)
			}
			reported = true
			r.mu.Lock()
			r.done = append(r.done, out)
			r.mu.Unlock()
		}(sp)
	}
}

// drain takes the finished Results and merges them into one. Per-target Results
// are independent, so concatenating them is the whole merge.
func (r *probeRunner) drain() Result {
	r.mu.Lock()
	done := r.done
	r.done = nil
	r.mu.Unlock()

	var res Result
	for _, d := range done {
		res.Metrics = append(res.Metrics, d.Metrics...)
		res.Events = append(res.Events, d.Events...)
		res.Blocked = append(res.Blocked, d.Blocked...)
		res.Inventory = append(res.Inventory, d.Inventory...)
	}
	return res
}

// WaitIdle blocks until every in-flight run has returned. The scheduler calls it
// once its poll loop has exited so Scheduler.Wait keeps its contract — nothing
// started by Run is still using the platform HAL or the proxy manager when the
// runtime tears them down. After the run context is cancelled a run unwinds
// within one operation timeout: a paced sleep and a queued gate acquire both
// abort on cancellation, and each platform/network call is bounded by its own
// timeout.
//
// The scheduler finds it through an optional interface, so these assertions are
// what keep a collector from losing the method without anything failing to
// build — the loss would only show up as a teardown race.
var (
	_ interface{ WaitIdle() } = (*PublicPingCollector)(nil)
	_ interface{ WaitIdle() } = (*GatewayPingCollector)(nil)
	_ interface{ WaitIdle() } = (*DNSCollector)(nil)
	_ interface{ WaitIdle() } = (*HTTPCollector)(nil)
	_ interface{ WaitIdle() } = (*TCPCollector)(nil)
	_ interface{ WaitIdle() } = (*NATCollector)(nil)
)

// Tests use it to make Collect deterministic (start the runs, WaitIdle, then
// Collect again to drain).
func (r *probeRunner) WaitIdle() { r.wg.Wait() }

// SetMinInterval applies the local per-target probe-interval floor (stability limit).
func (r *probeRunner) SetMinInterval(d time.Duration) { r.sched.SetMinInterval(d) }

// resultEmpty reports whether a per-target run produced nothing at all — a
// target skipped this cycle (unreadable routes, a cancelled run, a probe the
// concurrency budget could not admit). Buffering one would cost the scheduler an
// empty sink call for no data.
func resultEmpty(res Result) bool {
	return len(res.Metrics) == 0 && len(res.Events) == 0 && len(res.Blocked) == 0 &&
		len(res.Inventory) == 0
}
