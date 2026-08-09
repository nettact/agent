package clockmon

import (
	"testing"
	"time"
)

// testMonitor returns a Monitor whose two clocks the test drives independently.
// Driving both is the only way to model a step: a step IS the wall clock moving
// when the monotonic clock did not.
func testMonitor(t *testing.T) (*Monitor, *fakeClocks) {
	t.Helper()
	base := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)
	fc := &fakeClocks{wall: base}
	m := &Monitor{epoch: "proc-1", start: base, lastWall: base}
	m.mono = fc.monoNow
	return m, fc
}

type fakeClocks struct {
	wall time.Time
	mono int64
}

func (f *fakeClocks) monoNow() int64 { return f.mono }

// advance moves both clocks by d, as an untroubled machine would.
func (f *fakeClocks) advance(d time.Duration) {
	f.wall = f.wall.Add(d)
	f.mono += int64(d)
}

// step moves the wall clock only, which is what setting the clock looks like.
func (f *fakeClocks) step(d time.Duration) { f.wall = f.wall.Add(d) }

func TestNoStepMeansNoCorrection(t *testing.T) {
	m, fc := testMonitor(t)
	at := m.Mono()
	for i := 0; i < 5; i++ {
		fc.advance(sampleInterval)
		m.sample(fc.wall)
	}
	if got := m.OffsetAt("proc-1", at, 0); got != 0 {
		t.Fatalf("offset on a healthy clock = %s, want 0", got)
	}
	if m.Revision() != 0 {
		t.Fatalf("revision = %d, want 0 — a healthy agent records nothing", m.Revision())
	}
}

// The router case: samples are taken under a clock that is behind, NTP steps it
// forward, and everything stamped before the step needs that much added.
func TestStepCorrectsOnlyWhatCameBefore(t *testing.T) {
	m, fc := testMonitor(t)

	before := m.Mono()
	fc.advance(sampleInterval)
	m.sample(fc.wall)
	mid := m.Mono()

	// NTP arrives and moves the clock 20 minutes forward.
	fc.advance(sampleInterval)
	fc.step(20 * time.Minute)
	m.sample(fc.wall)

	fc.advance(sampleInterval)
	m.sample(fc.wall)
	after := m.Mono()

	if got := m.OffsetAt("proc-1", before, 0); got != 20*time.Minute {
		t.Fatalf("offset before the step = %s, want 20m", got)
	}
	if got := m.OffsetAt("proc-1", mid, 0); got != 20*time.Minute {
		t.Fatalf("offset mid-outage = %s, want 20m", got)
	}
	if got := m.OffsetAt("proc-1", after, 0); got != 0 {
		t.Fatalf("offset after the step = %s, want 0 — the clock is right now", got)
	}
}

func TestStepsCompose(t *testing.T) {
	m, fc := testMonitor(t)
	oldest := m.Mono()

	fc.advance(sampleInterval)
	fc.step(5 * time.Minute)
	m.sample(fc.wall)
	between := m.Mono()

	fc.advance(sampleInterval)
	fc.step(3 * time.Minute)
	m.sample(fc.wall)
	newest := m.Mono()

	if got := m.OffsetAt("proc-1", oldest, 0); got != 8*time.Minute {
		t.Fatalf("offset before both steps = %s, want 8m", got)
	}
	if got := m.OffsetAt("proc-1", between, 0); got != 3*time.Minute {
		t.Fatalf("offset between the steps = %s, want 3m", got)
	}
	if got := m.OffsetAt("proc-1", newest, 0); got != 0 {
		t.Fatalf("offset after both = %s, want 0", got)
	}
}

// Slew must not be mistaken for a step: ordinary NTP discipline moves the clock
// by microseconds, and recording that would churn the model forever.
func TestSubThresholdDriftIsIgnored(t *testing.T) {
	m, fc := testMonitor(t)
	at := m.Mono()
	for i := 0; i < 10; i++ {
		fc.advance(sampleInterval)
		fc.step(100 * time.Millisecond)
		m.sample(fc.wall)
	}
	if m.Revision() != 0 {
		t.Fatalf("revision = %d, want 0 — slew is not a step", m.Revision())
	}
	if got := m.OffsetAt("proc-1", at, 0); got != 0 {
		t.Fatalf("offset = %s, want 0", got)
	}
}

// A clock nobody steps stays wrong, so an anchor has to correct stamps not yet
// taken as well as those already taken.
func TestAnchorAppliesToPastAndFuture(t *testing.T) {
	m, fc := testMonitor(t)
	past := m.Mono()

	fc.advance(sampleInterval)
	m.Anchor(fc.wall.Add(9*time.Minute), fc.wall)

	fc.advance(sampleInterval)
	future := m.Mono()

	if got := m.OffsetAt("proc-1", past, 0); got != 9*time.Minute {
		t.Fatalf("offset before the anchor = %s, want 9m", got)
	}
	if got := m.OffsetAt("proc-1", future, 0); got != 9*time.Minute {
		t.Fatalf("offset after the anchor = %s, want 9m — nothing has fixed the clock", got)
	}
}

func TestAnchorInsideToleranceRecordsNothing(t *testing.T) {
	m, fc := testMonitor(t)
	m.Anchor(fc.wall.Add(2*time.Second), fc.wall)
	if m.Revision() != 0 {
		t.Fatalf("revision = %d, want 0 — a few seconds of RTT is not a clock error", m.Revision())
	}
}

// Every ack carries a ServerTime. Restating an error already accounted for must
// not grow the model, or a long session would accumulate an event per ack.
func TestRepeatedAnchorsDoNotAccumulate(t *testing.T) {
	m, fc := testMonitor(t)
	for i := 0; i < 5; i++ {
		fc.advance(time.Minute)
		m.Anchor(fc.wall.Add(9*time.Minute), fc.wall)
	}
	if m.Revision() != 1 {
		t.Fatalf("revision = %d, want 1 — the same error restated is not new information", m.Revision())
	}
}

// A step is the authoritative source. Once it has fixed the clock, the anchors
// that follow agree with the server and must retire the standing correction
// rather than adding to it.
func TestStepAfterAnchorRetiresTheStandingError(t *testing.T) {
	m, fc := testMonitor(t)
	early := m.Mono()

	// The clock is 20 minutes behind and only the server can tell us.
	m.Anchor(fc.wall.Add(20*time.Minute), fc.wall)
	if got := m.OffsetAt("proc-1", early, 0); got != 20*time.Minute {
		t.Fatalf("anchored offset = %s, want 20m", got)
	}

	// NTP finally fires and fixes it.
	fc.advance(sampleInterval)
	fc.step(20 * time.Minute)
	m.sample(fc.wall)
	fixed := m.Mono()

	if got := m.OffsetAt("proc-1", early, 0); got != 20*time.Minute {
		t.Fatalf("offset of pre-step samples = %s, want 20m still", got)
	}
	if got := m.OffsetAt("proc-1", fixed, 0); got != 0 {
		t.Fatalf("offset after the fix = %s, want 0 — not 20m twice over", got)
	}

	// A later ack now agrees with the server; the model must stay at zero.
	fc.advance(time.Minute)
	m.Anchor(fc.wall, fc.wall)
	if got := m.OffsetAt("proc-1", fixed, 0); got != 0 {
		t.Fatalf("offset after an agreeing anchor = %s, want 0", got)
	}
}

// A packet re-sent under its original sequence must carry the bytes it carried
// the first time: the server dedups on (agent_id, sequence) and would swallow a
// differing retry rather than replace what it stored.
func TestRevisionFreezesACorrection(t *testing.T) {
	m, fc := testMonitor(t)
	at := m.Mono()

	fc.advance(sampleInterval)
	fc.step(5 * time.Minute)
	m.sample(fc.wall)
	rev := m.Revision()
	frozen := m.OffsetAt("proc-1", at, rev)

	// A second step lands while the packet is still unacknowledged.
	fc.advance(sampleInterval)
	fc.step(7 * time.Minute)
	m.sample(fc.wall)

	if got := m.OffsetAt("proc-1", at, rev); got != frozen {
		t.Fatalf("frozen offset moved: %s, want %s", got, frozen)
	}
	if got := m.OffsetAt("proc-1", at, 0); got != 12*time.Minute {
		t.Fatalf("live offset = %s, want both steps (12m)", got)
	}
}

// Nothing a previous process stamped is ever corrected: this process cannot know
// what error that one was running with.
func TestForeignEpochIsNeverCorrected(t *testing.T) {
	m, fc := testMonitor(t)
	at := m.Mono()
	fc.advance(sampleInterval)
	fc.step(20 * time.Minute)
	m.sample(fc.wall)

	if got := m.OffsetAt("an-earlier-process", at, 0); got != 0 {
		t.Fatalf("offset for a previous process = %s, want 0", got)
	}
	if got := m.OffsetAt("", at, 0); got != 0 {
		t.Fatalf("offset for an untagged group = %s, want 0", got)
	}
}

func TestNilMonitorIsInert(t *testing.T) {
	var m *Monitor
	if got := m.OffsetAt("proc-1", 0, 0); got != 0 {
		t.Fatalf("nil monitor offset = %s, want 0", got)
	}
	m.Anchor(time.Now(), time.Now()) // must not panic
}

func TestOnChangeFiresForEveryRecordedObservation(t *testing.T) {
	m, fc := testMonitor(t)
	calls := 0
	m.OnChange(func() { calls++ })

	fc.advance(sampleInterval)
	m.sample(fc.wall) // healthy: no event
	if calls != 0 {
		t.Fatalf("OnChange fired %d times for a healthy sample", calls)
	}
	fc.advance(sampleInterval)
	fc.step(4 * time.Minute)
	m.sample(fc.wall)
	if calls != 1 {
		t.Fatalf("OnChange fired %d times for a step, want 1", calls)
	}
	m.Anchor(fc.wall.Add(-time.Hour), fc.wall)
	if calls != 2 {
		t.Fatalf("OnChange fired %d times after an anchor, want 2", calls)
	}
}
