package collector

import (
	"context"
	"time"

	pcfg "github.com/nettact/protocol/config"
)

// The shape of one ICMP probe cycle, shared by every ping path (platform and
// in-tunnel, public target and gateway).
//
// A cycle's echoes are spread across the target's check interval rather than
// sent as a burst: after each echo returns, the gap to the next one is
// recomputed as "time left before this target is due again, divided by the
// echoes still to send". Five packets on a 10s interval therefore leave at
// roughly 0 / 2.25 / 4.5 / 6.75 / 9s, and the loss and jitter the cycle reports
// describe the whole interval instead of a ~1s window at the top of it — which
// is the point: a burst cannot see a stall that begins one second after it ends.
//
// A lost or errored echo breaks the pacing and sends the next one immediately.
// That fail-fast is what keeps the spread from costing alert latency: a target
// that is fully down still finishes its cycle in count×perEcho (5s by default),
// so its 100%-loss round reaches the server no later than under the old
// fixed-spacing burst, and the availability detector's confirmation cadence is
// unchanged. Only a healthy target — the case where nothing is waiting on the
// result — pays the spread.

// cycleSleep and cycleNow are the cycle's only clock. They are package vars so
// the collector tests can substitute a synthetic one: a spread cycle waits most
// of a check interval in real time, which no unit test should sit through, and a
// fake clock also lets a test assert the exact gaps the pacing asked for rather
// than inferring them from elapsed wall time.
var (
	cycleSleep = sleepCtx
	cycleNow   = time.Now
)

// spreadGap is how long to wait before the next echo of a cycle. remaining
// counts the sends still to make including the next one, received reports
// whether the previous echo got a reply, and boundary is the instant the whole
// cycle must be finished by (see pingLoop).
//
// A lost echo returns 0 — the fail-fast above. Otherwise the gap is the smaller
// of two bounds:
//
//   - Spread evenly: share the time up to the last usable send instant
//     (boundary less one per-echo timeout) among the sends left.
//   - Stay feasible: after this send, every remaining echo must still fit its
//     FULL per-echo timeout before the boundary. Without this the pacing spends
//     budget it will need later, the tail runs back-to-back past the boundary,
//     and — under a GlobalTimeoutMs — the last echo gets a timeout shorter than
//     the link's own RTT and a healthy target is recorded as lost. Reserving
//     one timeout at the tail is not enough on its own: it ignores the time the
//     intermediate echoes themselves consume.
//
// The feasibility bound is what makes the spread self-correcting rather than
// optimistic. It holds inductively: if the next send leaves room for
// remaining×timeout, then after it completes (in at most timeout) there is room
// for (remaining−1)×timeout. So every echo of a cycle always gets its full
// timeout, and a cycle whose echoes fit at all finishes by the boundary.
//
// Both bounds go non-positive once the cycle is behind schedule (a slow link, or
// a packet count whose worst case does not fit the interval at all), and
// back-to-back sends are then the closest it can get to the intended cadence.
func spreadGap(now, boundary time.Time, timeout time.Duration, remaining int, received bool) time.Duration {
	if !received || remaining <= 0 {
		return 0
	}
	gap := boundary.Add(-timeout).Sub(now) / time.Duration(remaining)
	if slack := boundary.Sub(now) - time.Duration(remaining)*timeout; slack < gap {
		gap = slack
	}
	if gap <= 0 {
		return 0
	}
	return gap
}

// pacingDeadline is the instant a claimed probe's cycle paces its echoes
// against: normally the target's next due instant, so the cycle spreads across
// the whole check interval.
//
// A first cycle is the exception. Nothing has been reported for that target yet,
// so spreading over the interval would leave a newly created monitor with no
// data at all for one whole interval — five minutes on a five-minute target,
// which reads as a broken monitor rather than a slow one. A first cycle is
// therefore paced against its own worst case (count×perEcho), which still
// samples over a window instead of bursting, and every cycle after it uses the
// interval.
func pacingDeadline(sp scheduledProbe) time.Time {
	if !sp.First {
		return sp.NextDue
	}
	return cycleNow().Add(time.Duration(pcfg.PingCount(sp.Target.Params)) * pcfg.PingEchoTimeout(sp.Target.Params))
}

// echoFunc sends one echo of a cycle and waits for its reply, bounded by
// timeout. It reports the RTT when a reply came back, otherwise a classified
// telemetry.ProbeReason* plus the raw detail behind it — ProbeReasonNone when
// the sender could not classify the failure, since a class is never fabricated.
type echoFunc func(ctx context.Context, seq int, timeout time.Duration) (rtt time.Duration, reason int, detail string, received bool)

// pingLoop runs one ICMP cycle for a target and returns its loss percentage and
// the RTT distribution (avg/min/max/jitter) over the received echoes. It is the
// single implementation of the cycle contract described above, so the platform
// and in-tunnel paths cannot drift apart: a target's numbers mean the same thing
// whether or not it is proxied, which they must, or attaching a proxy would
// silently change the meaning of a monitor's whole availability history.
//
// Lost echoes contribute to loss only, never a zero-latency sample, so the
// distribution is computed over what actually returned.
//
// The packet count and per-echo timeout come from the shared protocol/config
// schedule helpers, and the pacing targets nextDue, so a cycle's real timing can
// never drift from the whole-cycle deadline the server derives for the same
// target (pcfg.CycleDeadline). A zero nextDue means the caller has no pacing
// budget to offer; the cycle then falls back to back-to-back echoes.
//
// GlobalTimeoutMs bounds the whole cycle regardless of how many packets are
// configured. It is enforced with a wall-clock deadline and by capping each
// echo's own timeout to the time remaining — context cancellation alone cannot
// interrupt a synchronous platform ping (Windows IcmpSendEcho honors only
// PingOptions.Timeout).
//
// # The concurrency budget, and why loss is a ratio over what was sent
//
// Every echo takes a slot from the machine-wide gate for the length of that echo
// and gives it back while the cycle sleeps — a cycle holds nothing between
// echoes, so charging it a slot for its whole span would starve the other
// targets for no resource (see ProbeGate). An echo may wait for a slot until one
// per-echo timeout before the cycle's bound, which is the last instant at which
// starting still leaves it its whole timeout: waiting cannot turn a healthy
// target into a lost one, and the cycle still finishes inside
// pcfg.CycleDeadline.
//
// Past that instant the echo is not sent late; it is not sent. Loss is therefore
// a ratio over the echoes actually SENT, and Sent is reported
// (telemetry.ICMPSent) so a truncated round is visible as such. Counting an
// unsent echo as lost would be the agent reporting its own busyness as the
// network's failure — and would do it in the worst possible way, since the count
// it would inflate is the one the availability detector reads. A cycle that sent
// nothing at all reports Sent 0 and its caller drops the whole Result: no sample
// beats a fabricated one, and the server's own staleness window is what surfaces
// the silence.
func pingLoop(ctx context.Context, params pcfg.ProbeParams, nextDue time.Time, gate *ProbeGate, echo echoFunc) pingCycleResult {
	count := pcfg.PingCount(params)
	timeout := pcfg.PingEchoTimeout(params)

	pctx := ctx
	var deadline time.Time
	if params.GlobalTimeoutMs > 0 {
		d := time.Duration(params.GlobalTimeoutMs) * time.Millisecond
		deadline = cycleNow().Add(d)
		var cancel context.CancelFunc
		pctx, cancel = context.WithTimeout(ctx, d)
		defer cancel()
	}

	// boundary is the instant the whole cycle must be finished by: the next due
	// instant, or the global deadline when that comes first. spreadGap paces
	// against it and guarantees every echo its full timeout inside it, so the
	// cycle can never spend its budget early and then report a healthy target as
	// lost on a truncated final echo.
	boundary := nextDue
	if !deadline.IsZero() && (boundary.IsZero() || deadline.Before(boundary)) {
		boundary = deadline
	}
	gateBound := gateBoundary(boundary, deadline, cycleNow(), count, timeout)

	rtts := make([]time.Duration, 0, count)
	reasons := make([]int, 0, count)    // per-echo failure reasons (lost echoes only)
	details := make([]string, 0, count) // parallel raw causes behind those reasons
	received := true                    // previous echo's outcome; the first send is never paced
	sent := 0                           // echoes actually attempted (see the doc above)
	for i := 0; i < count; i++ {
		if pctx.Err() != nil {
			break
		}
		if i > 0 {
			if gap := spreadGap(cycleNow(), boundary, timeout, count-i, received); gap > 0 && !cycleSleep(pctx, gap) {
				break
			}
		}
		// A slot first, then the clock: every timeout this echo runs under is
		// started after the wait, so queueing never eats the measurement's own
		// budget. Only THIS echo's timeout is reserved. Reserving the echoes after
		// it as well would be strictly worse: it cannot protect them (each
		// re-checks at its own acquire, and the round truncates honestly if the
		// room is gone), and on a target whose worst case already fills its
		// interval it computes a wait budget of zero for every echo.
		//
		// The bound is the CYCLE's, not this echo's, so the wait budget shrinks as
		// the cycle spends it. Once it is gone a free slot is still taken (Acquire's
		// fast path ignores the clock) but nothing waits, so the round truncates
		// rather than running past the deadline the server derives for it.
		if gate.Acquire(pctx, gateWaitDeadline(gateBound, timeout)) != AdmittedOK {
			break
		}
		rtt, reason, detail, ok, ran := oneEcho(pctx, gate, deadline, timeout, i, echo)
		if !ran {
			break
		}
		sent++
		received = ok
		if received {
			rtts = append(rtts, rtt)
			continue
		}
		reasons = append(reasons, reason)
		details = append(details, detail)
	}

	got := len(rtts)
	r := pingCycleResult{Sent: sent, Received: got}
	if sent > 0 {
		r.Loss = float64(sent-got) / float64(sent) * 100.0
	}
	r.Reason, r.Detail = cycleReason(got, reasons, details)
	r.AvgMs, r.MinMs, r.MaxMs, r.JitterMs, r.HaveJitter = pingStats(rtts)
	return r
}

// gateBoundary is the instant the cycle must be finished by for the whole-cycle
// deadline the SERVER derives (pcfg.CycleDeadline) to hold. It is what bounds how
// long an echo may wait for a concurrency slot.
//
// It is the pacing boundary, except when the echoes could not fit inside it even
// back-to-back. pcfg.CycleDeadline allows such a target max(interval,
// count×perEcho) rather than its interval, and the budget has to agree: bounded
// by the interval alone, a target whose worst case exceeds it (a 1s interval with
// 5 packets) could never wait for a slot at all and would go permanently silent
// on a busy agent — the one outcome worse than a late sample.
//
// A GlobalTimeoutMs is the exception that stays hard. The server derives exactly
// that when it is set, so the bound is never extended past it.
func gateBoundary(boundary, deadline, now time.Time, count int, timeout time.Duration) time.Time {
	out := boundary
	if worst := now.Add(time.Duration(count) * timeout); out.Before(worst) {
		out = worst
	}
	if !deadline.IsZero() && out.After(deadline) {
		out = deadline
	}
	return out
}

// oneEcho sends a single echo while holding a gate slot, releasing it whatever
// the outcome. ran is false when the global deadline left no time to run it at
// all, which ends the cycle without counting an attempt.
func oneEcho(ctx context.Context, gate *ProbeGate, deadline time.Time, timeout time.Duration, seq int, echo echoFunc) (rtt time.Duration, reason int, detail string, received, ran bool) {
	defer gate.Release()
	callTimeout := timeout
	if !deadline.IsZero() {
		remaining := deadline.Sub(cycleNow())
		if remaining <= 0 {
			return 0, 0, "", false, false
		}
		if remaining < callTimeout {
			callTimeout = remaining
		}
	}
	rtt, reason, detail, received = echo(ctx, seq, callTimeout)
	return rtt, reason, detail, received, true
}
