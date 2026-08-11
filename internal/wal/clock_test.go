package wal

import (
	"testing"
	"time"

	"github.com/nettact/protocol/gamesense"
	"github.com/nettact/protocol/telemetry"
)

// fakeClock is a ClockSource a test can state outright, so the WAL's behaviour
// can be exercised without simulating a machine whose clock is wrong.
//
// Its model mirrors clockmon's: a list of corrections, each recorded at a
// monotonic instant, where the offset for a stamp is the sum of the corrections
// recorded after it. Untagged in the build sense on purpose — both stores share
// this behaviour and must be shown to.
type fakeClock struct {
	epoch string
	now   int64
	steps []fakeStep
	// standing is the clock's residual error, the way an anchor reports it: it
	// applies to every stamp this process has taken AND to every one it is about
	// to take, because nothing has corrected the clock. clockmon calls this
	// curErr; the offset is standing plus the steps recorded after a stamp.
	standing time.Duration
}

type fakeStep struct {
	at    int64
	delta time.Duration
}

func (c *fakeClock) Epoch() string { return c.epoch }
func (c *fakeClock) Mono() int64   { return c.now }
func (c *fakeClock) Revision() int { return len(c.steps) }

func (c *fakeClock) OffsetAt(epoch string, mono int64, rev int) time.Duration {
	if epoch != c.epoch {
		return 0
	}
	n := len(c.steps)
	if rev > 0 && rev < n {
		n = rev
	}
	var d time.Duration
	for i := 0; i < n; i++ {
		if c.steps[i].at > mono {
			d += c.steps[i].delta
		}
	}
	return c.standing + d
}

// advance moves the monotonic clock without any correction, as an untroubled
// machine would.
func (c *fakeClock) advance(d time.Duration) { c.now += int64(d) }

// step records a clock correction at the current instant: everything appended
// before it was stamped d too early.
func (c *fakeClock) step(d time.Duration) {
	c.steps = append(c.steps, fakeStep{at: c.now, delta: d})
}

// standingError models an anchor: the clock is wrong by d for everything this
// process has stamped and everything it is about to stamp, because nothing has
// corrected it.
func (c *fakeClock) standingError(d time.Duration) { c.standing = d }

const clockServer = "srv"

func openClockStore(t *testing.T, c ClockSource) *Store {
	t.Helper()
	s, err := Open(tempWALDir(t), []string{clockServer}, Options{Persist: true, Clock: c})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

var clockBase = time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)

func metricAt(ts time.Time, target string) Records {
	return Records{Metrics: []telemetry.Metric{{
		TS: ts, Kind: telemetry.ICMPRTTms, Target: target, Value: 1,
	}}}
}

// The router case, end to end through the outbox: samples are appended under a
// clock that is 20 minutes behind, the clock is then fixed, and what goes out
// carries the times the samples actually happened at.
func TestClockCorrectionIsAppliedToTheOutgoingBatch(t *testing.T) {
	c := &fakeClock{epoch: "proc-1"}
	s := openClockStore(t, c)

	// Collected while the clock was wrong.
	if _, err := s.Append(metricAt(clockBase, "1.1.1.1"), clockServer); err != nil {
		t.Fatalf("append: %v", err)
	}
	c.advance(time.Minute)
	c.step(20 * time.Minute)
	c.advance(time.Second)

	// Collected after it was fixed.
	if _, err := s.Append(metricAt(clockBase.Add(21*time.Minute), "8.8.8.8"), clockServer); err != nil {
		t.Fatalf("append: %v", err)
	}

	b, ok, err := s.NextBatch(clockServer, 100)
	if err != nil || !ok {
		t.Fatalf("next batch: ok=%v err=%v", ok, err)
	}
	if len(b.Metrics) != 2 {
		t.Fatalf("metrics = %d, want 2", len(b.Metrics))
	}
	if got, want := b.Metrics[0].TS.UTC(), clockBase.Add(20*time.Minute); !got.Equal(want) {
		t.Fatalf("pre-fix sample sent at %s, want %s", got, want)
	}
	if got, want := b.Metrics[1].TS.UTC(), clockBase.Add(21*time.Minute); !got.Equal(want) {
		t.Fatalf("post-fix sample sent at %s, want %s — it was already right", got, want)
	}
}

// The correction is applied to the copy that goes out, never to what is stored.
// If it were applied in place, a re-serve would shift the same records twice.
func TestCorrectionDoesNotMutateStoredRecords(t *testing.T) {
	c := &fakeClock{epoch: "proc-1"}
	s := openClockStore(t, c)
	if _, err := s.Append(metricAt(clockBase, "1.1.1.1"), clockServer); err != nil {
		t.Fatalf("append: %v", err)
	}
	c.advance(time.Minute)
	c.step(10 * time.Minute)

	first, ok, err := s.NextBatch(clockServer, 100)
	if err != nil || !ok {
		t.Fatalf("first batch: ok=%v err=%v", ok, err)
	}
	// The session dropped before the ack, so the same packet is served again.
	second, ok, err := s.NextBatch(clockServer, 100)
	if err != nil || !ok {
		t.Fatalf("re-serve: ok=%v err=%v", ok, err)
	}
	if second.Sequence != first.Sequence {
		t.Fatalf("re-serve sequence = %d, want the original %d", second.Sequence, first.Sequence)
	}
	if !second.Metrics[0].TS.Equal(first.Metrics[0].TS) {
		t.Fatalf("re-serve stamped %s, first attempt %s — the stored record was mutated",
			second.Metrics[0].TS, first.Metrics[0].TS)
	}
	if got, want := first.Metrics[0].TS.UTC(), clockBase.Add(10*time.Minute); !got.Equal(want) {
		t.Fatalf("correction = %s, want a single 10m shift", got)
	}
}

// A packet re-sent under its original sequence must carry the bytes it carried
// the first time: the server dedups on (agent_id, sequence) and would swallow a
// differing retry rather than replace what it already stored.
func TestReServeAfterANewStepReproducesTheOriginalTimestamps(t *testing.T) {
	c := &fakeClock{epoch: "proc-1"}
	s := openClockStore(t, c)
	// Two groups stamped by the same wrong clock. Claiming one at a time is what
	// puts a step between the first claim and the second.
	if _, err := s.Append(metricAt(clockBase, "1.1.1.1"), clockServer); err != nil {
		t.Fatalf("append: %v", err)
	}
	if _, err := s.Append(metricAt(clockBase, "8.8.8.8"), clockServer); err != nil {
		t.Fatalf("append: %v", err)
	}
	c.advance(time.Minute)
	c.step(5 * time.Minute)

	first, ok, err := s.NextBatch(clockServer, 1)
	if err != nil || !ok {
		t.Fatalf("first batch: ok=%v err=%v", ok, err)
	}
	if got := first.Metrics[0].TS.UTC(); !got.Equal(clockBase.Add(5 * time.Minute)) {
		t.Fatalf("first claim corrected by %s, want 5m", got.Sub(clockBase))
	}

	// The clock is corrected AGAIN while the packet is still unacknowledged.
	c.advance(time.Minute)
	c.step(7 * time.Minute)

	again, ok, err := s.NextBatch(clockServer, 1)
	if err != nil || !ok {
		t.Fatalf("re-serve: ok=%v err=%v", ok, err)
	}
	if !again.Metrics[0].TS.Equal(first.Metrics[0].TS) {
		t.Fatalf("re-serve stamped %s, first attempt %s — the frozen revision was not honoured",
			again.Metrics[0].TS, first.Metrics[0].TS)
	}

	// The second group was stamped by the same wrong clock but is claimed after
	// both corrections, so it carries both.
	if err := s.Ack(clockServer, first.Sequence); err != nil {
		t.Fatalf("ack: %v", err)
	}
	fresh, ok, err := s.NextBatch(clockServer, 1)
	if err != nil || !ok {
		t.Fatalf("fresh batch: ok=%v err=%v", ok, err)
	}
	if got := fresh.Metrics[0].TS.UTC(); !got.Equal(clockBase.Add(12 * time.Minute)) {
		t.Fatalf("a claim taken after both steps corrected by %s, want 12m", got.Sub(clockBase))
	}
}

// Nothing an earlier process stamped is corrected: this process cannot know what
// error that one was running with.
func TestGroupsFromAnEarlierProcessAreServedAsStored(t *testing.T) {
	dir := tempWALDir(t)
	old := &fakeClock{epoch: "proc-1"}
	s1, err := Open(dir, []string{clockServer}, Options{Persist: true, Clock: old})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := s1.Append(metricAt(clockBase, "1.1.1.1"), clockServer); err != nil {
		t.Fatalf("append: %v", err)
	}
	if err := s1.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// A new process with a clock that learns it is 20 minutes out.
	fresh := &fakeClock{epoch: "proc-2"}
	s2, err := Open(dir, []string{clockServer}, Options{Persist: true, Clock: fresh})
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer func() { _ = s2.Close() }()
	fresh.advance(time.Minute)
	fresh.step(20 * time.Minute)

	b, ok, err := s2.NextBatch(clockServer, 100)
	if err != nil || !ok {
		t.Fatalf("batch: ok=%v err=%v", ok, err)
	}
	if got := b.Metrics[0].TS.UTC(); !got.Equal(clockBase) {
		t.Fatalf("a previous process's sample was shifted to %s; it must be served as stored", got)
	}
}

// A group carries one monotonic reading, taken when it was appended. That
// describes a probe round or a tier sweep, not a game run spanning minutes of
// play or the span of a traceroute sweep — correcting part of one of those would
// produce a record whose end precedes its start. (The trigger instant a trace
// also carries is a single moment and IS corrected; see the slow-clock test.)
func TestLongSpanningPayloadsAreNotShifted(t *testing.T) {
	c := &fakeClock{epoch: "proc-1"}
	s := openClockStore(t, c)

	started := clockBase
	ended := clockBase.Add(30 * time.Minute)
	rec := Records{
		Metrics:  []telemetry.Metric{{TS: clockBase, Kind: telemetry.ICMPRTTms, Target: "1.1.1.1"}},
		GameRuns: []gamesense.Run{{ID: "run-1", StartedAt: started, LastSeenAt: ended, EndedAt: &ended}},
		TraceResults: []telemetry.TraceResult{{
			ReportID: "tr-1", StartedAt: started, CompletedAt: ended,
		}},
	}
	if _, err := s.Append(rec, clockServer); err != nil {
		t.Fatalf("append: %v", err)
	}
	c.advance(time.Minute)
	c.step(20 * time.Minute)

	b, ok, err := s.NextBatch(clockServer, 100)
	if err != nil || !ok {
		t.Fatalf("batch: ok=%v err=%v", ok, err)
	}
	if got := b.Metrics[0].TS.UTC(); !got.Equal(clockBase.Add(20 * time.Minute)) {
		t.Fatalf("metric was not corrected: %s", got)
	}
	if got := b.GameRuns[0].StartedAt.UTC(); !got.Equal(started) {
		t.Fatalf("game run start was shifted to %s; long-spanning payloads are left as collected", got)
	}
	if got := b.GameRuns[0].EndedAt.UTC(); !got.Equal(ended) {
		t.Fatalf("game run end was shifted to %s", got)
	}
	if got := b.TraceResults[0].StartedAt.UTC(); !got.Equal(started) {
		t.Fatalf("trace start was shifted to %s", got)
	}
}

// The acceptance case for WAL-002: an agent whose clock is SLOW still has its
// self-describing reports claimed by the incident they belong to.
//
// A trace's FirstFailedAt and a scene trigger's FirstFailedAt/DisconnectedAt are
// join keys, not decoration — server-side (incidentops) they are compared
// against fault_signals.observed_at, which is the SERVER's clock, with two
// minutes of slack. Left as collected by a clock twenty minutes behind, they sit
// far outside that gate: the report is stored, and the incident that caused it
// can never claim it.
//
// The direction is the whole test. The server's gate is one-sided — a trigger is
// refused for being too EARLY, never for being too late — so the same scenario
// with the clock set FAST passes with the correction removed. This one fails.
func TestTriggerInstantsAreCorrectedForASlowClock(t *testing.T) {
	c := &fakeClock{epoch: "proc-1"}
	s := openClockStore(t, c)

	// Everything below is stamped by a clock that is twenty minutes behind, so
	// the true instant of each is twenty minutes later than what is stored.
	const slow = 20 * time.Minute
	failed := clockBase
	started := clockBase.Add(10 * time.Second)
	completed := clockBase.Add(40 * time.Second)
	collected := clockBase.Add(45 * time.Second)
	dropped := clockBase.Add(5 * time.Second)

	rec := Records{
		TraceResults: []telemetry.TraceResult{{
			ReportID: "tr-1", DestKey: "ip:1.1.1.1",
			TriggerReason: telemetry.TraceTriggerConsecutiveFailures, TriggerStreak: 3,
			FirstFailedAt: failed, StartedAt: started, CompletedAt: completed,
		}},
		SceneReports: []telemetry.SceneReport{{
			ReportID: "sc-1", CollectedAt: collected,
			Triggers: []telemetry.SceneTrigger{
				{
					Kind: telemetry.SceneTriggerProbeFault, MonitorID: "probe_mon1",
					ConfigSerial: 7, TriggerStreak: 3, FirstFailedAt: failed,
				},
				{
					Kind: telemetry.SceneTriggerServerDisconnect, Reason: "network",
					EdgeCount: 1, DisconnectedAt: dropped,
				},
			},
		}},
	}
	if _, err := s.Append(rec, clockServer); err != nil {
		t.Fatalf("append: %v", err)
	}
	// The link comes back and NTP steps the clock forward onto the truth.
	c.advance(time.Minute)
	c.step(slow)

	b, ok, err := s.NextBatch(clockServer, 100)
	if err != nil || !ok {
		t.Fatalf("batch: ok=%v err=%v", ok, err)
	}

	// The server observed the same outage on its own clock, twenty minutes later
	// than the agent's stamps say. claimable mirrors incidentops' gate.
	observedAt := failed.Add(slow)
	if claimable(failed, observedAt) {
		t.Fatal("the fixture does not reproduce the bug: an uncorrected trigger " +
			"must fall outside the server's slack, or this test proves nothing")
	}

	tr := b.TraceResults[0]
	if !claimable(tr.FirstFailedAt.UTC(), observedAt) {
		t.Errorf("trace first-failure sent as %s; the incident observed at %s cannot claim it",
			tr.FirstFailedAt.UTC(), observedAt)
	}
	if got := tr.FirstFailedAt.UTC(); !got.Equal(failed.Add(slow)) {
		t.Errorf("trace first-failure = %s, want the corrected %s", got, failed.Add(slow))
	}
	// The sweep's own span is left as collected: one offset cannot be applied to
	// part of it without risking an end that precedes its start.
	if got := tr.StartedAt.UTC(); !got.Equal(started) {
		t.Errorf("trace start was shifted to %s; a span stays as collected", got)
	}
	if got := tr.CompletedAt.UTC(); !got.Equal(completed) {
		t.Errorf("trace completion was shifted to %s; a span stays as collected", got)
	}

	sc := b.SceneReports[0]
	probe, disc := sc.Triggers[0], sc.Triggers[1]
	if !claimable(probe.FirstFailedAt.UTC(), observedAt) {
		t.Errorf("scene probe edge sent as %s; the incident observed at %s cannot claim it",
			probe.FirstFailedAt.UTC(), observedAt)
	}
	if got := probe.FirstFailedAt.UTC(); !got.Equal(failed.Add(slow)) {
		t.Errorf("scene probe edge = %s, want the corrected %s", got, failed.Add(slow))
	}
	if got := disc.DisconnectedAt.UTC(); !got.Equal(dropped.Add(slow)) {
		t.Errorf("scene disconnect edge = %s, want the corrected %s", got, dropped.Add(slow))
	}
	// Exactly one instant is filled per trigger kind, and server-side an edge of
	// zero deliberately owns no outage. Shifting one would invent a placeable
	// timestamp two thousand years out of date.
	if !probe.DisconnectedAt.IsZero() {
		t.Errorf("a probe trigger's empty disconnect edge was given a time: %s", probe.DisconnectedAt)
	}
	if !disc.FirstFailedAt.IsZero() {
		t.Errorf("a disconnect trigger's empty first-failure was given a time: %s", disc.FirstFailedAt)
	}
	// CollectedAt is not a join key: the server stores it AS the agent's clock and
	// derives delivery lag and its clock-ahead flag from it, so correcting it
	// would erase the only record of what the agent thought the time was.
	if got := sc.CollectedAt.UTC(); !got.Equal(collected) {
		t.Errorf("scene collection time was shifted to %s; it is the agent's own clock by design", got)
	}
}

// claimable mirrors the server's one-sided time gate (incidentops.attachSlack):
// an agent-stamped trigger is refused when it lands more than two minutes before
// the signal's first observed failing round.
func claimable(edge, observedAt time.Time) bool {
	const attachSlack = 2 * time.Minute
	return !edge.Before(observedAt.Add(-attachSlack))
}

// A scene's Triggers live behind a slice, so the batch's copy of the report
// shares that array with the stored record. Shifting it in place would move the
// STORED edges, and a claim re-served after a session drop — same sequence,
// frozen revision, same offset — would move them a second time. The server
// dedups on (agent_id, sequence) and would swallow the differing retry.
func TestReServingASceneDoesNotShiftItsTriggersTwice(t *testing.T) {
	c := &fakeClock{epoch: "proc-1"}
	s := openClockStore(t, c)

	edge := clockBase
	rec := Records{SceneReports: []telemetry.SceneReport{{
		ReportID: "sc-1", CollectedAt: clockBase.Add(10 * time.Second),
		Triggers: []telemetry.SceneTrigger{{
			Kind: telemetry.SceneTriggerProbeFault, MonitorID: "probe_mon1",
			ConfigSerial: 7, TriggerStreak: 3, FirstFailedAt: edge,
		}},
	}}}
	if _, err := s.Append(rec, clockServer); err != nil {
		t.Fatalf("append: %v", err)
	}
	c.advance(time.Minute)
	c.step(15 * time.Minute)

	first, ok, err := s.NextBatch(clockServer, 100)
	if err != nil || !ok {
		t.Fatalf("first batch: ok=%v err=%v", ok, err)
	}
	// Read the value out NOW. The batch's Triggers header can alias the stored
	// array — that aliasing IS the bug — so holding the Batch and comparing the
	// two attempts field by field would compare the same memory with itself and
	// pass either way. A time.Time copy is what makes the two attempts
	// independent observations.
	want := edge.Add(15 * time.Minute)
	firstEdge := first.SceneReports[0].Triggers[0].FirstFailedAt
	if got := firstEdge.UTC(); !got.Equal(want) {
		t.Fatalf("first attempt sent %s, want %s", got, want)
	}
	// The session dropped before the ack, so the same packet is served again.
	again, ok, err := s.NextBatch(clockServer, 100)
	if err != nil || !ok {
		t.Fatalf("re-serve: ok=%v err=%v", ok, err)
	}
	if got := again.SceneReports[0].Triggers[0].FirstFailedAt.UTC(); !got.Equal(want) {
		t.Fatalf("re-serve sent %s, first attempt %s — the stored trigger was shifted in place",
			got, firstEdge.UTC())
	}
}

// Events, inventory and interface snapshots are stamped inside the same
// collection cycle as the metrics beside them, so they move together.
func TestSingleCycleSiblingsMoveWithTheMetrics(t *testing.T) {
	c := &fakeClock{epoch: "proc-1"}
	s := openClockStore(t, c)

	rec := Records{
		Metrics:   []telemetry.Metric{{TS: clockBase, Kind: telemetry.ICMPRTTms, Target: "1.1.1.1"}},
		Events:    []telemetry.Event{{ID: "ev-1", TS: clockBase}},
		Inventory: []telemetry.InventoryItem{{ID: "aa:bb", LastSeen: clockBase}},
		Snapshots: []telemetry.InterfaceSnapshot{{SampledAt: clockBase}},
	}
	if _, err := s.Append(rec, clockServer); err != nil {
		t.Fatalf("append: %v", err)
	}
	c.advance(time.Minute)
	c.step(15 * time.Minute)

	b, ok, err := s.NextBatch(clockServer, 100)
	if err != nil || !ok {
		t.Fatalf("batch: ok=%v err=%v", ok, err)
	}
	want := clockBase.Add(15 * time.Minute)
	if got := b.Events[0].TS.UTC(); !got.Equal(want) {
		t.Fatalf("event at %s, want %s", got, want)
	}
	if got := b.Inventory[0].LastSeen.UTC(); !got.Equal(want) {
		t.Fatalf("inventory last-seen at %s, want %s", got, want)
	}
	if got := b.Snapshots[0].SampledAt.UTC(); !got.Equal(want) {
		t.Fatalf("interface snapshot at %s, want %s", got, want)
	}
}

// A zero LastSeen means "not reported", not "the epoch"; shifting it would
// invent a timestamp.
func TestZeroTimestampsAreLeftZero(t *testing.T) {
	c := &fakeClock{epoch: "proc-1"}
	s := openClockStore(t, c)
	if _, err := s.Append(Records{Inventory: []telemetry.InventoryItem{{ID: "aa:bb"}}}, clockServer); err != nil {
		t.Fatalf("append: %v", err)
	}
	c.advance(time.Minute)
	c.step(15 * time.Minute)

	b, ok, err := s.NextBatch(clockServer, 100)
	if err != nil || !ok {
		t.Fatalf("batch: ok=%v err=%v", ok, err)
	}
	if !b.Inventory[0].LastSeen.IsZero() {
		t.Fatalf("a zero timestamp was shifted to %s", b.Inventory[0].LastSeen)
	}
}

// With no clock wired the store behaves exactly as it did before corrections
// existed.
func TestNoClockMeansNoCorrection(t *testing.T) {
	s := openClockStore(t, nil)
	if _, err := s.Append(metricAt(clockBase, "1.1.1.1"), clockServer); err != nil {
		t.Fatalf("append: %v", err)
	}
	b, ok, err := s.NextBatch(clockServer, 100)
	if err != nil || !ok {
		t.Fatalf("batch: ok=%v err=%v", ok, err)
	}
	if got := b.Metrics[0].TS.UTC(); !got.Equal(clockBase) {
		t.Fatalf("timestamp = %s, want it untouched", got)
	}
}

// Retention compares a stored time against the present, so BOTH have to be in
// the same clock domain. Correcting only the stored side turns a large standing
// error into silent data loss: a clock running days ahead pulls every group's
// time back past a cutoff that was not moved with it, and the backlog the
// correction exists to deliver is deleted instead.
func TestALargeStandingClockErrorDoesNotExpireFreshBacklog(t *testing.T) {
	c := &fakeClock{epoch: "proc-1"}
	s := openClockStore(t, c)

	if _, err := s.Append(metricAt(clockBase, "1.1.1.1"), clockServer); err != nil {
		t.Fatalf("append: %v", err)
	}
	// Retention only governs the durable tier, so the group has to reach it.
	// Both builds spill on Flush while the server is disconnected, which every
	// store is at Open.
	if err := s.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	// The server tells us this machine's clock is a week ahead — far more than
	// the retention window, and nothing has stepped it.
	c.advance(time.Second)
	c.standingError(-7 * 24 * time.Hour)

	b, ok, err := s.NextBatch(clockServer, 100)
	if err != nil {
		t.Fatalf("batch: %v", err)
	}
	if !ok {
		t.Fatal("the backlog was expired away: retention compared a corrected " +
			"stored time against an uncorrected now")
	}
	if len(b.Metrics) != 1 {
		t.Fatalf("metrics = %d, want the one appended row", len(b.Metrics))
	}
	if got, want := b.Metrics[0].TS.UTC(), clockBase.Add(-7*24*time.Hour); !got.Equal(want) {
		t.Fatalf("sample sent at %s, want the corrected %s", got, want)
	}
}

// A previous process's backlog is never deleted on the strength of a correction
// that cannot be applied to its stamps.
//
// The competing hazard is real — sysfixtime resets a no-RTC clock onto the
// agent's own last write, so week-old backlog can read as fresh and be uploaded
// past the window server-core prunes its dedup rows on — but the costs are not
// equal. This deletion is permanent and takes exactly the outage evidence the
// feature exists to preserve; the late replay is idempotent at the sample level
// and rejected by the detector watermark.
func TestAnEarlierProcessesBacklogIsNeverDeletedByThisProcessesCorrection(t *testing.T) {
	dir := tempWALDir(t)

	old := &fakeClock{epoch: "proc-1"}
	s1, err := Open(dir, []string{clockServer}, Options{Persist: true, Clock: old})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := s1.Append(metricAt(clockBase, "1.1.1.1"), clockServer); err != nil {
		t.Fatalf("append: %v", err)
	}
	if err := s1.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// The agent restarts seconds later on the same boot, and the handshake
	// reveals that this machine's clock is a week out — for a reason that has
	// nothing to do with downtime.
	fresh := &fakeClock{epoch: "proc-2"}
	s2, err := Open(dir, []string{clockServer}, Options{Persist: true, Clock: fresh})
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer func() { _ = s2.Close() }()
	fresh.advance(time.Second)
	fresh.standingError(7 * 24 * time.Hour)

	b, ok, err := s2.NextBatch(clockServer, 100)
	if err != nil {
		t.Fatalf("batch: %v", err)
	}
	if !ok {
		t.Fatal("a seconds-old segment from the previous process was deleted by a " +
			"correction that does not describe the clock that wrote it")
	}
	if got := b.Metrics[0].TS.UTC(); !got.Equal(clockBase) {
		t.Fatalf("sample sent at %s, want it served exactly as stored", got)
	}
}

// The same machinery must NOT expire the current process's own backlog, which is
// the case where both sides of the comparison are correctable and the answer is
// unambiguous.
func TestALargeStandingErrorDoesNotExpireThisProcessesBacklog(t *testing.T) {
	c := &fakeClock{epoch: "proc-1"}
	s := openClockStore(t, c)
	if _, err := s.Append(metricAt(clockBase, "1.1.1.1"), clockServer); err != nil {
		t.Fatalf("append: %v", err)
	}
	if err := s.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	c.advance(time.Second)
	c.standingError(7 * 24 * time.Hour)

	b, ok, err := s.NextBatch(clockServer, 100)
	if err != nil {
		t.Fatalf("batch: %v", err)
	}
	if !ok {
		t.Fatal("this process's own fresh backlog was expired: both its stamp and " +
			"the present are correctable, so the comparison has one right answer")
	}
	if got, want := b.Metrics[0].TS.UTC(), clockBase.Add(7*24*time.Hour); !got.Equal(want) {
		t.Fatalf("sample sent at %s, want the corrected %s", got, want)
	}
}
