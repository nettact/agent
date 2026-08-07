package collector

import (
	"context"
	"sync/atomic"
	"time"
)

// ProbeGate bounds how many probe operations run at once on this machine, and
// records the ones it had to turn away.
//
// It is created once and handed to every probe collector of every server, the
// same way the traceroute limiter is (see traceroute.Limiter). An agent
// reporting to several servers builds a collector pipeline per server — targets,
// permissions and the access guard are per server, so they have to be — but what
// this budget protects is not: the ICMP handles, sockets and file descriptors a
// probe holds are the machine's, and they do not become more plentiful because a
// second server asked for the same target. A per-pipeline budget would be no
// budget at all: public-ping and gateway would each get the full allowance, and
// then again per server.
//
// # What a slot means
//
// A slot is one concurrent probe OPERATION, not one socket and not one probe
// cycle:
//
//   - Not a socket, because the count would be a lie. A NAT discovery keeps its
//     primary UDP socket open while the filtering tests open a second one, and an
//     HTTP probe leaves pooled connections behind it. The budget is a bound on how
//     much probing happens at once, which is what a user setting it wants.
//   - Not a cycle, which is the important one. A healthy ICMP cycle spreads its
//     echoes across the target's whole check interval and holds nothing at all
//     between them (see pingcycle.go). Charging it a slot for its whole duration
//     would mean that with more targets than slots, the surplus targets simply
//     would not run until the next round — halving the real probe rate and
//     destroying the spread that the cycle exists to provide. So ping takes a slot
//     per echo, for the length of that echo, and gives it back while it sleeps.
//     The single-shot probes (DNS/HTTP/TCP/NAT) hold one for their whole run
//     because that IS one operation.
//
// # Waiting is bounded by the caller's own slack
//
// Acquire takes a deadline rather than blocking indefinitely, and every caller
// derives it the same way: the instant by which this operation must have STARTED
// for the rest of its cycle to still fit inside the budget the server derives for
// it (pcfg.CycleDeadline). A ping echo may wait only into the slack its pacing
// was already going to leave idle — never into the full per-echo timeout that
// spreadGap reserves for every echo still to come — so a queued echo still gets
// its whole timeout and a healthy target is never recorded as lost because the
// agent was busy. Past that instant the operation is not run late; it is not run.
//
// That is what keeps a queue from forming behind the gate: waiters are bounded in
// number (one in-flight round per target, enforced by schedState's claim) and in
// residency (the slack, after which they leave), so the budget can be
// oversubscribed without the backlog growing.
//
// # The turned-away count
//
// Acquire counts every operation it refuses. Nothing else can see that: an
// abandoned round produces no sample, so the monitor just goes quiet and the
// server marks it stale like any other silence. The count is what lets the agent
// say why — the heartbeat drains it into a rate-limited EventProbeOverload
// naming the limit to raise. A partially-run ICMP round is not silent but is not
// authoritative either; it reports how many echoes it actually sent
// (telemetry.ICMPSent) and the server refuses to move availability state on it.
//
// A nil *ProbeGate is a working gate with no limit at all: Acquire always admits
// immediately. That is what the collector tests use, and it is why every call
// site can be unconditional.
type ProbeGate struct {
	sem   chan struct{}
	limit int

	// turnedAway counts operations refused for want of a slot since the last
	// TakeOverload. Atomic because every probe goroutine on the machine writes it.
	turnedAway atomic.Int64
}

// Admission is the outcome of an Acquire.
type Admission int

const (
	// AdmittedOK means the caller holds a slot and must Release it.
	AdmittedOK Admission = iota
	// AdmittedCanceled means the run context ended (shutdown, or a superseded
	// config generation). The caller discards its work silently — a probe cut
	// short this way must never be reported as a network failure.
	AdmittedCanceled
	// AdmittedOverloaded means no slot came free inside the caller's budget. The
	// caller stops probing and reports honestly what it managed (nothing at all,
	// for a single-shot probe). It is already counted; the caller adds no
	// bookkeeping of its own.
	AdmittedOverloaded
)

// NewProbeGate builds the machine's probe-concurrency budget. A limit <= 0 means
// unlimited (a nil gate) — the agent runtime fills the configured value from
// DefaultLimits before it gets here, so that case is the in-process embedders and
// tests that never asked for a budget, not a misconfiguration to guess a default
// for.
func NewProbeGate(limit int) *ProbeGate {
	if limit <= 0 {
		return nil
	}
	return &ProbeGate{sem: make(chan struct{}, limit), limit: limit}
}

// Limit reports the configured budget (0 for an unlimited gate).
func (g *ProbeGate) Limit() int {
	if g == nil {
		return 0
	}
	return g.limit
}

// Acquire takes a slot, waiting no later than deadline. The caller must Release
// exactly one slot per AdmittedOK.
//
// A free slot is taken without ever consulting the clock, so an agent inside its
// budget behaves exactly as it did before the gate existed — no timer, no
// scheduling hop, and ping pacing that is identical instruction for instruction.
// Only a full budget reaches the waiting path.
func (g *ProbeGate) Acquire(ctx context.Context, deadline time.Time) Admission {
	if g == nil {
		return AdmittedOK
	}
	select {
	case g.sem <- struct{}{}:
		return AdmittedOK
	default:
	}
	// The budget is full. Cancellation is checked before the deadline so a
	// shutdown that races an expiring budget is reported as a shutdown: the
	// caller must not count a cancelled probe as overload.
	if ctx.Err() != nil {
		return AdmittedCanceled
	}
	wait := time.Until(deadline)
	if wait <= 0 {
		g.turnedAway.Add(1)
		return AdmittedOverloaded
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case g.sem <- struct{}{}:
		return AdmittedOK
	case <-ctx.Done():
		return AdmittedCanceled
	case <-timer.C:
		g.turnedAway.Add(1)
		return AdmittedOverloaded
	}
}

// Release returns a slot. It is a no-op on a nil gate, so callers can defer it
// unconditionally after an AdmittedOK.
func (g *ProbeGate) Release() {
	if g == nil {
		return
	}
	select {
	case <-g.sem:
	default:
		// Unreachable while every AdmittedOK is released exactly once. Dropping
		// the extra beats panicking in a probe goroutine, and beats blocking
		// forever on a channel receive that will never be satisfied.
	}
}

// TakeOverload returns how many operations the budget refused since the previous
// call, and resets the count. The heartbeat drains it; a zero means there is
// nothing to report and no event is emitted.
func (g *ProbeGate) TakeOverload() int {
	if g == nil {
		return 0
	}
	return int(g.turnedAway.Swap(0))
}

// gateWaitDeadline is the last instant at which an operation may still start:
// one timeout before the bound its whole probe must finish by, so an operation
// that queues and then runs still gets its full timeout and the probe still
// completes inside the deadline the server derives for it (pcfg.CycleDeadline).
//
// It can land in the past, and that is correct rather than a case to paper over.
// A target whose single operation already fills its own bound — a one-packet
// ping, a DNS monitor given a timeout as long as its interval — has no slack to
// spend, so it may not wait. It does not thereby go silent: Acquire takes a free
// slot without ever consulting the clock, so such a target still probes whenever
// the budget has room and only truncates when the machine is genuinely saturated
// at that instant. Best-effort-without-waiting is exactly the right behaviour for
// a probe with no room, and it is what keeps the derived deadline hard.
//
// An earlier version floored this at now+timeout to guarantee some wait budget.
// That was a mistake twice over: it was solving the silence problem the fast path
// already solves, and because it re-floored on EVERY operation it granted fresh
// slack per echo — so a contended cycle could overrun its deadline by a timeout
// per remaining packet and then start its already-due next cycle immediately.
func gateWaitDeadline(bound time.Time, timeout time.Duration) time.Time {
	return bound.Add(-timeout)
}
