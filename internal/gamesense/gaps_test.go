package gamesense

import (
	"fmt"
	"strings"
	"testing"
	"time"

	gs "github.com/nettact/protocol/gamesense"
)

// The frameless half of the contract: the seconds a game produced nothing, and
// the machine-level readings that keep arriving through them.
//
// These live apart from gamesense_test.go because they are about the records
// that exist when a run has nothing to say. The tests there drain runs and
// buckets through a narrowing helper for exactly that reason, and this file is
// where the two fields it drops are read.

// gapLine is one `gap` message: a second the tracked game presented nothing, and
// which of the two silences it was.
func gapLine(ts, proc string, pid int, reason string) string {
	return fmt.Sprintf(`{"type":"gap","ts":%q,"pid":%d,"proc":%q,"reason":%q}`, ts, pid, proc, reason)
}

func hostLine(ts, body string) string {
	return fmt.Sprintf(`{"type":"host","ts":%q,%s}`, ts, body)
}

// at formats an offset from fixtureStart as a sensor timestamp.
func at(d time.Duration) string { return fixtureStart.Add(d).UTC().Format(time.RFC3339Nano) }

// gapsByID indexes drained intervals, keeping the newest copy of each — the
// drain stream is an upsert stream, so a growing interval appears more than once.
func gapsByID(gaps []gs.Gap) map[string]gs.Gap {
	byID := map[string]gs.Gap{}
	for _, g := range gaps {
		byID[g.ID] = g
	}
	return byID
}

// tracking is the status line that opens a run for game.exe at pid 1.
const tracking = `{"type":"status","state":"tracking","pid":1,"proc":"game.exe"}`

// Consecutive frameless seconds with the same reason are one interruption, not
// sixty rows. A per-second record would be honest and unusable: the console
// shades a band per interval, so a minute alt-tabbed would arrive as sixty
// touching bands with sixty ids to merge.
func TestFramelessSecondsFoldIntoOneInterval(t *testing.T) {
	s := NewSupervisor("sensor", nil)
	fakeClock(s, fixtureStart)
	s.consume(strings.NewReader(strings.Join([]string{
		tracking,
		secLine(at(0), "game.exe", 1),
		gapLine(at(time.Second), "game.exe", 1, gs.GapBackground),
		gapLine(at(2*time.Second), "game.exe", 1, gs.GapBackground),
		gapLine(at(3*time.Second), "game.exe", 1, gs.GapBackground),
	}, "\n")))

	rec := s.Drain()
	byID := gapsByID(rec.Gaps)
	if len(byID) != 1 {
		t.Fatalf("recorded %d intervals, want one: %+v", len(byID), rec.Gaps)
	}
	for _, g := range byID {
		// The start reaches back to where the first frameless second BEGAN, so the
		// band covers the same axis a bucket's point sits on.
		if want := fixtureStart; !g.StartedAt.Equal(want) {
			t.Errorf("interval starts at %s, want %s", g.StartedAt, want)
		}
		if want := fixtureStart.Add(3 * time.Second); !g.EndedAt.Equal(want) {
			t.Errorf("interval ends at %s, want %s", g.EndedAt, want)
		}
		if g.Reason != gs.GapBackground {
			t.Errorf("reason = %q, want %q", g.Reason, gs.GapBackground)
		}
		if len(rec.Runs) == 0 || g.RunID != rec.Runs[0].ID {
			t.Errorf("interval run = %q, want the recorded run", g.RunID)
		}
	}
}

// The two reasons are opposite findings, so a stretch that changes from one to
// the other is two interruptions. Merging them would produce a band claiming the
// player was away for time they spent staring at a loading screen, or the
// reverse.
func TestAChangedReasonStartsANewInterval(t *testing.T) {
	s := NewSupervisor("sensor", nil)
	fakeClock(s, fixtureStart)
	s.consume(strings.NewReader(strings.Join([]string{
		tracking,
		secLine(at(0), "game.exe", 1),
		gapLine(at(time.Second), "game.exe", 1, gs.GapNoFrames),
		gapLine(at(2*time.Second), "game.exe", 1, gs.GapNoFrames),
		gapLine(at(3*time.Second), "game.exe", 1, gs.GapBackground),
	}, "\n")))

	byID := gapsByID(s.Drain().Gaps)
	if len(byID) != 2 {
		t.Fatalf("recorded %d intervals, want one per reason: %+v", len(byID), byID)
	}
	var loading, away gs.Gap
	for _, g := range byID {
		switch g.Reason {
		case gs.GapNoFrames:
			loading = g
		case gs.GapBackground:
			away = g
		}
	}
	if !loading.EndedAt.Equal(fixtureStart.Add(2 * time.Second)) {
		t.Errorf("the loading stretch ends at %s, want it closed where the reason changed", loading.EndedAt)
	}
	if !away.StartedAt.Equal(fixtureStart.Add(2 * time.Second)) {
		t.Errorf("the away stretch starts at %s, want it to begin where the other ended", away.StartedAt)
	}
}

// Frameless seconds far enough apart are two interruptions. The sensor SKIPS the
// boundaries a stall swallowed rather than publishing them, so a jump in the
// timestamps means seconds nobody observed — and stretching one interval across
// them would assert coverage of time that was never looked at.
func TestATimeJumpSplitsTheInterval(t *testing.T) {
	s := NewSupervisor("sensor", nil)
	fakeClock(s, fixtureStart)
	s.consume(strings.NewReader(strings.Join([]string{
		tracking,
		secLine(at(0), "game.exe", 1),
		gapLine(at(time.Second), "game.exe", 1, gs.GapBackground),
		// Exactly gapJoin later: still one interruption.
		gapLine(at(time.Second+gapJoin), "game.exe", 1, gs.GapBackground),
		// Past it: a discontinuity.
		gapLine(at(2*time.Second+2*gapJoin), "game.exe", 1, gs.GapBackground),
	}, "\n")))

	byID := gapsByID(s.Drain().Gaps)
	if len(byID) != 2 {
		t.Fatalf("recorded %d intervals, want the jump to split them: %+v", len(byID), byID)
	}
}

// The parking trap, and the reason gaps are attributed by session rather than by
// the run in progress.
//
// Thirty frameless seconds make the sensor report idle, which parks the run. The
// player is very often still there — coming back ten minutes later to the same
// game — and the seconds in between are the whole point of recording gaps. An
// implementation that required r.cur would discard every one of them past the
// thirtieth: exactly the stretch a reader stares at and cannot explain.
func TestGapsSurviveTheRunBeingParked(t *testing.T) {
	s := NewSupervisor("sensor", nil)
	advance := fakeClock(s, fixtureStart)

	s.consume(strings.NewReader(strings.Join([]string{
		tracking,
		secLine(at(0), "game.exe", 1),
	}, "\n")))
	drained := s.Drain().Runs
	if len(drained) == 0 {
		t.Fatal("no run was recorded")
	}
	firstRun := drained[0].ID

	// The sensor gives up on the silence and reports idle; the agent parks the run.
	advance(30 * time.Second)
	s.consume(strings.NewReader(`{"type":"status","state":"idle"}`))
	if s.cur != nil {
		t.Fatal("the run was not parked; this test is not exercising what it claims")
	}

	// Frameless seconds keep arriving, because the sensor is still tracking and the
	// game is still alive.
	var lines []string
	for i := 1; i <= 120; i++ {
		lines = append(lines, gapLine(at(time.Duration(i)*time.Second), "game.exe", 1, gs.GapBackground))
	}
	s.consume(strings.NewReader(strings.Join(lines, "\n")))

	byID := gapsByID(s.Drain().Gaps)
	if len(byID) != 1 {
		t.Fatalf("recorded %d intervals across the park, want one: %+v", len(byID), byID)
	}
	for _, g := range byID {
		if g.RunID != firstRun {
			t.Errorf("interval run = %q, want the parked run %q", g.RunID, firstRun)
		}
		if want := fixtureStart.Add(120 * time.Second); !g.EndedAt.Equal(want) {
			t.Errorf("interval ends at %s, want %s — the seconds past the park were discarded",
				g.EndedAt, want)
		}
	}
}

// The other half of the parking rule: a session nobody ever came back to stops
// being matchable, and its interval stops growing.
//
// This is the case the sweep is easy to miss on. A game left minimized produces
// nothing but gap lines from then on, so neither of the paths that normally
// sweep — switchTo and parkCurrent — ever runs again. Without a sweep here the
// parked session stays matchable for as long as the machine is on, and one
// interval grows across days, contradicting reviveWindow's own statement that
// the session is over.
func TestAGapStopsGrowingOnceItsSessionIsPastTheReviveWindow(t *testing.T) {
	s := NewSupervisor("sensor", nil)
	advance := fakeClock(s, fixtureStart)

	s.consume(strings.NewReader(strings.Join([]string{
		tracking,
		secLine(at(0), "game.exe", 1),
	}, "\n")))
	// The sensor gives up after thirty frameless seconds and the agent parks the
	// run. Everything after this arrives as gap lines against a PARKED session,
	// which is the state the sweep has to reach.
	advance(30 * time.Second)
	s.consume(strings.NewReader(`{"type":"status","state":"idle"}`))
	if s.parked[1] == nil {
		t.Fatal("the session was not parked; this test is not exercising what it claims")
	}

	s.consume(strings.NewReader(strings.Join([]string{
		// Inside the window: one interval, still growing.
		gapLine(at(time.Second), "game.exe", 1, gs.GapBackground),
		gapLine(at(2*time.Second), "game.exe", 1, gs.GapBackground),
	}, "\n")))
	byID := gapsByID(s.Drain().Gaps)
	if len(byID) != 1 {
		t.Fatalf("recorded %d intervals before the window elapsed, want one", len(byID))
	}
	var before gs.Gap
	for _, g := range byID {
		before = g
	}

	// Past reviveWindow, measured from the second the run was last SEEN. The
	// session is gone, so there is nothing to attribute these to.
	s.consume(strings.NewReader(strings.Join([]string{
		gapLine(at(reviveWindow+3*time.Second), "game.exe", 1, gs.GapBackground),
		gapLine(at(reviveWindow+4*time.Second), "game.exe", 1, gs.GapBackground),
	}, "\n")))

	if s.parked[1] != nil {
		t.Error("the session past its revive window is still parked")
	}
	after := s.Drain()
	if len(after.Gaps) != 0 {
		t.Fatalf("recorded %d interval(s) for a session that had expired: %+v", len(after.Gaps), after.Gaps)
	}
	// And the interval that was already recorded is untouched — it describes real
	// time and stands; it simply stops being extended.
	if !before.EndedAt.Equal(fixtureStart.Add(2 * time.Second)) {
		t.Errorf("the recorded interval ends at %s, want it left where the session ended", before.EndedAt)
	}
}

// The queue is bounded like the two second-buffers. An upload path that is
// failing leaves everything requeued, while a machine flipping between
// foreground and background can open a fresh interval every second — which is
// unbounded growth in a process meant to run for months.
func TestTheIntervalQueueIsBounded(t *testing.T) {
	s := NewSupervisor("sensor", nil)
	fakeClock(s, fixtureStart)
	s.consume(strings.NewReader(strings.Join([]string{
		tracking,
		secLine(at(0), "game.exe", 1),
	}, "\n")))

	// Alternate the reason every second, which is the fastest an interval can be
	// opened: each one closes the last and starts a new one.
	var lines []string
	for i := 1; i <= maxBuffered*2; i++ {
		reason := gs.GapBackground
		if i%2 == 0 {
			reason = gs.GapNoFrames
		}
		lines = append(lines, gapLine(at(time.Duration(i)*time.Second), "game.exe", 1, reason))
	}
	s.consume(strings.NewReader(strings.Join(lines, "\n")))

	rec := s.Drain()
	if len(rec.Gaps) > maxBuffered {
		t.Fatalf("queued %d intervals, want no more than %d", len(rec.Gaps), maxBuffered)
	}
	// The recent end is what survives, matching the rule the bucket buffer uses:
	// what a reader is coming back to is the newest data.
	newest := rec.Gaps[len(rec.Gaps)-1]
	if want := fixtureStart.Add(time.Duration(maxBuffered*2) * time.Second); !newest.EndedAt.Equal(want) {
		t.Errorf("newest interval ends at %s, want %s — eviction took the wrong end", newest.EndedAt, want)
	}
}

// Noticing a silence is not observing play. A gap must not advance the run's
// extent, must not reopen it, and must not mark it dirty: a game sitting
// minimized for an hour is a finished session, and advancing it would make it
// look alive to the server's abandoned-run reaper while stretching its duration
// across time no frame covered.
func TestGapsDoNotMutateTheRun(t *testing.T) {
	s := NewSupervisor("sensor", nil)
	advance := fakeClock(s, fixtureStart)

	s.consume(strings.NewReader(strings.Join([]string{
		tracking,
		secLine(at(0), "game.exe", 1),
	}, "\n")))
	advance(30 * time.Second)
	s.consume(strings.NewReader(`{"type":"status","state":"idle"}`))

	ended := s.Drain().Runs
	if len(ended) == 0 {
		t.Fatal("no run was drained")
	}
	before := ended[len(ended)-1]
	if before.EndedAt == nil {
		t.Fatalf("run = %+v, want it ended by the idle report", before)
	}

	s.consume(strings.NewReader(strings.Join([]string{
		gapLine(at(time.Second), "game.exe", 1, gs.GapBackground),
		gapLine(at(2*time.Second), "game.exe", 1, gs.GapBackground),
	}, "\n")))

	rec := s.Drain()
	if len(rec.Runs) != 0 {
		t.Fatalf("the gaps re-sent the run: %+v", rec.Runs)
	}
	if len(rec.Gaps) == 0 {
		t.Fatal("the gaps were not recorded at all")
	}
	// And the recorder's own copy is untouched, which is what a later drain would
	// carry if anything here had written to it.
	parked := s.parked[1]
	if parked == nil {
		t.Fatal("the session is no longer parked")
	}
	if parked.run.EndedAt == nil || !parked.run.EndedAt.Equal(*before.EndedAt) {
		t.Errorf("run ended_at = %v, want %v — a gap reopened it", parked.run.EndedAt, before.EndedAt)
	}
	if !parked.run.LastSeenAt.Equal(before.LastSeenAt) {
		t.Errorf("run last_seen_at = %s, want %s — a gap advanced it",
			parked.run.LastSeenAt, before.LastSeenAt)
	}
}

// Frames are the only thing that ends a silence.
func TestFramesCloseTheInterval(t *testing.T) {
	s := NewSupervisor("sensor", nil)
	fakeClock(s, fixtureStart)
	s.consume(strings.NewReader(strings.Join([]string{
		tracking,
		secLine(at(0), "game.exe", 1),
		gapLine(at(time.Second), "game.exe", 1, gs.GapNoFrames),
		gapLine(at(2*time.Second), "game.exe", 1, gs.GapNoFrames),
		secLine(at(3*time.Second), "game.exe", 1),
		gapLine(at(4*time.Second), "game.exe", 1, gs.GapNoFrames),
	}, "\n")))

	byID := gapsByID(s.Drain().Gaps)
	if len(byID) != 2 {
		t.Fatalf("recorded %d intervals, want the frames to have ended the first: %+v", len(byID), byID)
	}
	var first, second gs.Gap
	for _, g := range byID {
		if g.StartedAt.Equal(fixtureStart) {
			first = g
		} else {
			second = g
		}
	}
	if !first.EndedAt.Equal(fixtureStart.Add(2 * time.Second)) {
		t.Errorf("the first interval ends at %s, want it closed at the last frameless second", first.EndedAt)
	}
	if !second.StartedAt.Equal(fixtureStart.Add(3 * time.Second)) {
		t.Errorf("the second interval starts at %s, want it to begin after the frames", second.StartedAt)
	}
}

// A silence belonging to no recorded session is discarded rather than opening
// one. A run is a stretch of a game PRESENTING frames; a silence before the
// first frame is not a run beginning, and a run whose only content is that
// nothing happened in it would be worse than the blank it replaces.
func TestAGapWithNoSessionIsDiscarded(t *testing.T) {
	s := NewSupervisor("sensor", nil)
	fakeClock(s, fixtureStart)
	s.consume(strings.NewReader(gapLine(at(0), "game.exe", 1, gs.GapBackground)))

	rec := s.Drain()
	if len(rec.Gaps) != 0 || len(rec.Runs) != 0 {
		t.Fatalf("drained %d gap(s) and %d run(s), want nothing", len(rec.Gaps), len(rec.Runs))
	}
}

// Machine seconds ride the same stream and the same drain but hang off no run.
// They are recorded before any status, while a game is parked, and for seconds
// no bucket exists for — which is exactly when they are the only thing a reader
// has to look at.
func TestHostSecondsAreRecordedWithoutARun(t *testing.T) {
	s := NewSupervisor("sensor", nil)
	fakeClock(s, fixtureStart)
	s.consume(strings.NewReader(strings.Join([]string{
		hostLine(at(0), `"cpu":{"total_pct":41.5,"busiest_pct":99.25},"mem":{"used":12884901888,"total":34359738368}`),
		hostLine(at(time.Second), `"gpu":{"util_pct":87.5}`),
		// An idle machine: two measured zeros, which must survive as a block.
		hostLine(at(2*time.Second), `"cpu":{"total_pct":0,"busiest_pct":0}`),
		// Nothing readable and nothing to explain it. Dropped before it costs a row.
		hostLine(at(3*time.Second), `"quality":[]`),
	}, "\n")))

	rec := s.Drain()
	if len(rec.Runs) != 0 || len(rec.Buckets) != 0 {
		t.Fatalf("machine seconds opened a run: %+v / %+v", rec.Runs, rec.Buckets)
	}
	if len(rec.HostSeconds) != 3 {
		t.Fatalf("drained %d machine second(s), want the empty one dropped: %+v",
			len(rec.HostSeconds), rec.HostSeconds)
	}
	if c := rec.HostSeconds[0].CPU; c == nil || c.BusiestPct != 99.25 {
		t.Errorf("cpu = %+v", c)
	}
	if m := rec.HostSeconds[0].Mem; m == nil || m.Total != 34359738368 {
		t.Errorf("mem = %+v", m)
	}
	if g := rec.HostSeconds[1].GPU; g == nil || g.UtilPct == nil || *g.UtilPct != 87.5 {
		t.Errorf("gpu = %+v", g)
	}
	if rec.HostSeconds[1].CPU != nil {
		t.Errorf("an adapter-only second acquired a cpu block: %+v", rec.HostSeconds[1].CPU)
	}
	if c := rec.HostSeconds[2].CPU; c == nil || *c != (gs.HostCPU{}) {
		t.Errorf("an idle machine came back as %+v, want a zeroed block", c)
	}
}

// The clocks travel on the same second as the loads they explain: a frame rate
// that fell alongside the core clock is a card out of headroom, and one that fell
// while every clock held is not.
func TestClocksTravelWithTheMachineSecond(t *testing.T) {
	s := NewSupervisor("sensor", nil)
	fakeClock(s, fixtureStart)
	s.consume(strings.NewReader(strings.Join([]string{
		hostLine(at(0), `"cpu_clock":{"current_mhz":4900,"max_mhz":3600},"gpu":{"core_mhz":2610.5,"mem_mhz":1313.3}`),
		// A machine that reports its processor's clock and nothing about the card:
		// the ordinary case where the driver publishes no adapter telemetry.
		hostLine(at(time.Second), `"cpu_clock":{"current_mhz":3200,"max_mhz":3600}`),
	}, "\n")))

	rec := s.Drain()
	if len(rec.HostSeconds) != 2 {
		t.Fatalf("drained %d machine second(s), want 2", len(rec.HostSeconds))
	}
	// A boost clock above the nominal maximum is what boost IS, and nothing on
	// the way through may tidy it back down to the maximum.
	if c := rec.HostSeconds[0].CPUClock; c == nil || c.CurrentMHz != 4900 || c.MaxMHz != 3600 {
		t.Errorf("cpu clock = %+v, want 4900/3600", c)
	}
	if g := rec.HostSeconds[0].GPU; g == nil || g.CoreMHz == nil || *g.CoreMHz != 2610.5 || g.MemMHz == nil || *g.MemMHz != 1313.3 {
		t.Errorf("adapter clocks = %+v", g)
	}
	// The card said nothing here, and the processor's clock survives that.
	if rec.HostSeconds[1].GPU != nil {
		t.Errorf("a second with no adapter reading acquired one: %+v", rec.HostSeconds[1].GPU)
	}
	if c := rec.HostSeconds[1].CPUClock; c == nil || c.CurrentMHz != 3200 {
		t.Errorf("cpu clock = %+v, want it kept without any adapter reading", c)
	}
}

// A drain that could not be persisted comes back whole, every kind included.
// Without this a full disk for one upload cycle would take a hole out of the
// middle of a session rather than delaying it.
func TestRequeueRestoresEveryRecordKind(t *testing.T) {
	s := NewSupervisor("sensor", nil)
	fakeClock(s, fixtureStart)
	s.consume(strings.NewReader(strings.Join([]string{
		tracking,
		secLine(at(0), "game.exe", 1),
		gapLine(at(time.Second), "game.exe", 1, gs.GapBackground),
		hostLine(at(time.Second), `"cpu":{"total_pct":10,"busiest_pct":20}`),
	}, "\n")))

	first := s.Drain()
	if first.Empty() {
		t.Fatal("nothing was recorded")
	}
	s.Requeue(first)
	again := s.Drain()
	if len(again.Runs) != len(first.Runs) || len(again.Buckets) != len(first.Buckets) ||
		len(again.Gaps) != len(first.Gaps) || len(again.HostSeconds) != len(first.HostSeconds) {
		t.Fatalf("requeued drain = %d/%d/%d/%d, want %d/%d/%d/%d",
			len(again.Runs), len(again.Buckets), len(again.Gaps), len(again.HostSeconds),
			len(first.Runs), len(first.Buckets), len(first.Gaps), len(first.HostSeconds))
	}
	// The requeued interval is the live one, so a silence still growing keeps
	// growing rather than being frozen at the moment the write failed — and does
	// not reappear as a second interval alongside itself.
	s.consume(strings.NewReader(gapLine(at(2*time.Second), "game.exe", 1, gs.GapBackground)))
	byID := gapsByID(s.Drain().Gaps)
	if len(byID) != 1 {
		t.Fatalf("the requeued interval was duplicated: %+v", byID)
	}
	for _, g := range byID {
		if !g.EndedAt.Equal(fixtureStart.Add(2 * time.Second)) {
			t.Errorf("interval ends at %s, want it still growing", g.EndedAt)
		}
	}
}
