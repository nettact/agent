// Package clockmon tracks how wrong this process's wall clock is, so telemetry
// collected before the clock was fixed can be uploaded under the times it
// actually happened at.
//
// # The machine this is for
//
// A home router usually has no RTC. When the power is cut it comes back with no
// idea what time it is, and OpenWrt's sysfixtime sets the clock from the newest
// file mtime it can find — which, on a box running this agent, is the agent's own
// last write. That leaves the clock behind by roughly the length of the outage,
// and nothing can fix it until the network returns and NTP can be reached.
//
// This matters because of what the agent is doing during exactly that window. It
// has just been rebooted in the middle of an outage — the owner power-cycling the
// box is the most likely thing to happen after the internet stops working — and
// it is monitoring a network that is still down, writing the evidence to its
// outbox. Every one of those samples is stamped minutes early. When the link
// finally returns and the backlog uploads, the server folds them into detectors
// keyed on sample time and files an outage that began at the wrong moment, or
// rejects them as out-of-order stragglers and files nothing at all.
//
// # What it does, and what it deliberately does not
//
// One Monitor per process compares the wall clock against the monotonic clock a
// few times a minute. Those two only disagree when something SETS the wall clock,
// so a divergence is a step, and its size is exactly the error every stamp taken
// before it carries. NTP stepping the clock after the link returns is the event
// this is built to catch, and it catches it with no protocol, no configuration
// and no platform-specific code.
//
// A second, subordinate source is the server itself: the Date header of the
// session's own handshake, and the ServerTime on every acknowledgement. It covers
// the case the step detector cannot see — a clock that was wrong before this
// process started and that NTP never fixes, because NTP is blocked or
// misconfigured. It is subordinate because it is polluted by round-trip time and
// by the server's own clock, while the error being hunted is minutes wide.
//
// What this does NOT do is correct anything from a PREVIOUS process. That is not
// a simplification, it is the honest answer: the process that collected those
// samples never reached a server and never saw NTP fire, so it never learned its
// own error, and this process cannot derive it either — sysfixtime anchored the
// new clock to the old process's last write, which is a different unknown offset
// from the one that process was actually running with. Samples spilled by a
// process that died before it learned the time therefore keep sysfixtime's
// accuracy, which is bounded by how recently the agent last wrote to flash (at
// most one persist interval on the router builds). Everything this process
// stamps is corrected exactly.
//
// # The offset model
//
// Every correction is expressed through one function: offsetAt(m) is how much to
// ADD to a wall stamp that was taken at monotonic instant m.
//
//	offsetAt(m) = curErr + Σ{ step.delta : step.at > m }
//
// where curErr is the clock's error right now (true minus local) and each step is
// a wall-clock jump this process observed. The two event kinds update it in the
// only ways that keep the identity true:
//
//   - A step of +J at instant M means the clock just moved J closer to the truth,
//     so the error now is J smaller: curErr -= J. Stamps taken before M were made
//     by a clock that was J further out, which is what the sum restores.
//   - An anchor saying the server's time is S ahead of ours means the error IS S,
//     right now, for everything: curErr = S. Unlike a step it also applies to
//     stamps not yet taken, because a clock nobody has fixed stays wrong.
//
// Both are recorded in one append-only list, so a correction can be recomputed as
// of any earlier revision. The uploader needs that: a packet re-sent under its
// original sequence must carry the bytes it carried the first time, because the
// server dedups on (agent_id, sequence) and would swallow a differing retry
// rather than replace what it stored.
package clockmon

import (
	"log"
	"sync"
	"time"
)

const (
	// sampleInterval is how often the wall and monotonic clocks are compared. It
	// bounds how long a step can go unnoticed, which matters only for samples
	// taken inside that window — they are corrected as if the step happened at
	// the observation rather than at its true instant, so up to one interval of
	// samples can be misattributed by one interval. Ten seconds against an error
	// measured in minutes is noise; polling faster would buy accuracy nobody can
	// use and wake a router's CPU for it.
	sampleInterval = 10 * time.Second

	// stepThreshold is the wall-vs-monotonic divergence that counts as the clock
	// being SET rather than drifting. NTP's ordinary discipline slews at parts per
	// million and cannot approach this in one interval; the post-boot correction
	// this exists to catch is minutes. Two seconds sits far above the former and
	// far below the latter, and is also above any plausible scheduling delay
	// between the two clock reads.
	stepThreshold = 2 * time.Second

	// anchorThreshold is how far the server's clock must be from ours before the
	// subordinate anchor acts. It is an order of magnitude looser than
	// stepThreshold because the measurement is worse: it carries the request's
	// round trip, the server's own clock error, and — for the handshake header —
	// a value rounded to whole seconds. Thirty seconds is above all of that and
	// still far below the minutes-wide error it exists to catch.
	anchorThreshold = 30 * time.Second
)

// event is one observation that changed what this process believes about its own
// clock. curErr is the error AFTER applying it, so a correction can be recomputed
// as of any revision without replaying the whole list.
type event struct {
	at     int64         // monotonic nanoseconds since this process's epoch
	delta  time.Duration // wall-clock jump, zero for an anchor
	curErr time.Duration
}

// Monitor is one process's view of its own clock error. Safe for concurrent use;
// the WAL reads it on the session goroutine while the sampler writes it.
type Monitor struct {
	// epoch identifies this process instance. Groups tagged with a different
	// epoch — anything a previous run spilled — are never corrected, because this
	// process has no way to know what that one's error was. It is a process id,
	// deliberately not a boot id: a second agent started after this one exited
	// shares the machine's boot but not its clock observations, and treating its
	// groups as correctable would apply this process's steps to stamps taken by a
	// clock it never watched.
	epoch string
	start time.Time // monotonic reference; only differences are used

	// mono reads the monotonic elapsed nanoseconds. A field so tests can drive
	// both clocks independently — which is the only way to exercise a step
	// without waiting one out, since a step IS the two clocks disagreeing.
	mono func() int64

	mu     sync.Mutex
	events []event
	// haveAnchor records whether a server has ever told this process what the
	// error actually is. It decides what a step means: with no anchor the model
	// has no independent knowledge of the error, and the only sound reading of a
	// step is that whatever set the clock set it CORRECTLY — so the error after it
	// is zero, and everything stamped before it was out by the size of the jump.
	// Once a server has stated the error, a step is instead a move of that size
	// toward the truth, and what remains is the difference.
	haveAnchor bool
	// lastWall/lastMono are the previous sampler observation, the pair a step is
	// detected against.
	lastWall time.Time
	lastMono int64
	onChange func()
}

// New returns a Monitor for this process. Run must be called to start detecting
// steps; anchors work without it.
func New(epoch string) *Monitor {
	now := time.Now()
	m := &Monitor{
		epoch:    epoch,
		start:    now,
		lastWall: now,
		lastMono: 0,
	}
	m.mono = func() int64 { return int64(time.Since(m.start)) }
	return m
}

// Epoch is this process instance's id, stamped onto every WAL group so a
// correction is never applied across processes.
func (m *Monitor) Epoch() string { return m.epoch }

// Mono is the monotonic nanoseconds elapsed since this Monitor was created. It
// is what a WAL group records, and what OffsetAt is asked about.
//
// time.Since is monotonic on every platform Go supports: the reading is taken
// from the monotonic reading embedded in m.start, and is therefore immune to the
// very clock changes this package is watching for.
func (m *Monitor) Mono() int64 { return m.mono() }

// OnChange registers a callback fired after any observation that moves the
// offset model. The WAL uses it to persist the revision alongside its state.
// Called with no locks held; must not block.
func (m *Monitor) OnChange(fn func()) {
	m.mu.Lock()
	m.onChange = fn
	m.mu.Unlock()
}

// Revision is the number of observations recorded so far. A claim freezes it so
// a re-served packet reproduces its original timestamps exactly.
func (m *Monitor) Revision() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.events)
}

// OffsetAt returns how much to add to a wall stamp taken at monotonic instant
// mono during epoch, as the model stood at revision rev. A zero or negative rev
// means "as it stands now".
//
// An epoch that is not this process's yields zero: see the package comment for
// why a previous run's error is not recoverable rather than merely unrecorded.
func (m *Monitor) OffsetAt(epoch string, mono int64, rev int) time.Duration {
	if m == nil || epoch != m.epoch {
		return 0
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	n := len(m.events)
	if rev > 0 && rev < n {
		n = rev
	}
	if n == 0 {
		return 0
	}
	off := m.events[n-1].curErr
	for i := 0; i < n; i++ {
		if m.events[i].at > mono {
			off += m.events[i].delta
		}
	}
	return off
}

// Run samples the two clocks until ctx ends. One goroutine per process.
func (m *Monitor) Run(stop <-chan struct{}) {
	t := time.NewTicker(sampleInterval)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			m.sample(time.Now())
		}
	}
}

// sample folds one (wall, monotonic) observation into the model. Split from Run
// so tests can drive it without waiting out real intervals.
func (m *Monitor) sample(wall time.Time) {
	mono := m.Mono()

	m.mu.Lock()
	// The monotonic elapsed time is what SHOULD have passed; the wall difference
	// is what the clock claims did. Only setting the clock can separate them.
	wallDelta := wall.Sub(m.lastWall)
	monoDelta := time.Duration(mono - m.lastMono)
	jump := wallDelta - monoDelta
	m.lastWall, m.lastMono = wall, mono
	if jump < stepThreshold && jump > -stepThreshold {
		m.mu.Unlock()
		return
	}
	// A step moves the clock toward the truth by jump, so whatever error remains
	// is that much smaller. Stamps taken before this instant were made by a clock
	// that was jump further out, which OffsetAt restores by summing this delta.
	// With no anchor to measure against, the residual is taken to be zero: see
	// haveAnchor for why that is the only sound reading of an unattested step.
	cur := time.Duration(0)
	if m.haveAnchor {
		cur = m.curErrLocked() - jump
	}
	m.events = append(m.events, event{at: mono, delta: jump, curErr: cur})
	fn := m.onChange
	m.mu.Unlock()

	log.Printf("clockmon: the wall clock stepped by %s; telemetry stamped before it is uploaded at its true time",
		jump.Round(time.Millisecond))
	if fn != nil {
		fn()
	}
}

// Anchor folds one server-supplied time into the model: serverTime is what the
// server said the time was at the instant this agent observed localTime.
//
// It is ignored while the error it reports is inside anchorThreshold, and — being
// the subordinate source — it is ignored entirely once it agrees with what the
// step detector already established, so an ordinary healthy agent records nothing
// at all from the acks flowing past it.
func (m *Monitor) Anchor(serverTime, localTime time.Time) {
	if m == nil || serverTime.IsZero() {
		return
	}
	skew := serverTime.Sub(localTime)
	if skew < anchorThreshold && skew > -anchorThreshold {
		// The clock agrees with the server. If a previous anchor had claimed
		// otherwise, this is the observation that retires it.
		m.clearAnchor()
		return
	}
	mono := m.Mono()

	m.mu.Lock()
	if cur := m.curErrLocked(); cur != 0 && absDur(skew-cur) < anchorThreshold {
		// Already accounted for — by a step, or by an earlier anchor saying the
		// same thing. Recording it again would not change the offset and would
		// grow the event list on every ack.
		m.mu.Unlock()
		return
	}
	// An anchor states the error outright, for stamps already taken and for
	// stamps still to come: a clock nobody has stepped stays wrong.
	m.events = append(m.events, event{at: mono, curErr: skew})
	m.haveAnchor = true
	fn := m.onChange
	m.mu.Unlock()

	log.Printf("clockmon: this machine's clock is %s from the server's; correcting telemetry timestamps by that much "+
		"(NTP is not fixing it — check the time settings)", skew.Round(time.Second))
	if fn != nil {
		fn()
	}
}

// clearAnchor retires a standing anchor once the clock agrees with the server
// again, without disturbing the step history that may have been what fixed it.
func (m *Monitor) clearAnchor() {
	m.mu.Lock()
	cur := m.curErrLocked()
	if cur == 0 {
		m.mu.Unlock()
		return
	}
	m.events = append(m.events, event{at: m.Mono(), curErr: 0})
	m.haveAnchor = true
	fn := m.onChange
	m.mu.Unlock()
	if fn != nil {
		fn()
	}
}

// curErrLocked is the clock error as the model currently stands. Caller holds mu.
func (m *Monitor) curErrLocked() time.Duration {
	if len(m.events) == 0 {
		return 0
	}
	return m.events[len(m.events)-1].curErr
}

func absDur(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}
