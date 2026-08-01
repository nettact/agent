package gamesense

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	gs "github.com/nettact/protocol/gamesense"
	"github.com/nettact/protocol/telemetry"
)

// The sensor is a separate, closed component that this repository never builds,
// so these tests stand in for it. TestMain turns the test binary itself into a
// mock sensor when the scenario variable is set (see mocksensor_windows_test.go),
// which makes the spawn path testable without a second toolchain — and makes the
// protocol the tests encode the actual contract the component must meet.

// secLine is one complete `sec` message, with every field a fully-capable sensor
// fills. Tests that care about lifecycle rather than payload use it so the
// lifecycle is exercised against realistic lines rather than minimal ones.
func secLine(ts, proc string, pid int) string {
	return fmt.Sprintf(`{"type":"sec","ts":%q,"pid":%d,"proc":%q,`+
		`"frames":{"presented":60,"displayed":59,"dropped":1,"app":60},`+
		`"ft":{"avg":16.667,"p50":16.6,"p95":19.2,"p99":22.1,"max":31.4,"sd":2.2},`+
		`"ft_hist":{"layout":"log24_v1","counts":[0,0,0,0,0,0,0,0,0,0,0,0,58,2,0,0,0,0,0,0,0,0,0,0]},`+
		`"disp_ft":{"avg":16.9,"p95":20.1},`+
		`"present":{"mode":"hardware_independent_flip","sync":0,"tearing":false,"api":"dxgi"}}`,
		ts, pid, proc)
}

func TestParseProbeLineAcceptsAWorkingSensor(t *testing.T) {
	got := parseProbeLine([]byte(`{"type":"probe","proto":2,"sensor_version":"0.2.0",` +
		`"ok":true,"pm_version":"2.3.0"}`))
	if !got.OK {
		t.Fatalf("probe = %+v, want OK", got)
	}
	if got.SensorVersion != "0.2.0" || got.Proto != ProtoVersion {
		t.Fatalf("probe = %+v, want proto %d version 0.2.0", got, ProtoVersion)
	}
	if got.PMVersion != "2.3.0" {
		t.Fatalf("PMVersion = %q, want the frame source's version", got.PMVersion)
	}
}

// A sensor that answers but cannot capture is the "blocked" state: not usable,
// but for a reason the operator can act on. The reason must survive.
func TestParseProbeLineKeepsBlockedReason(t *testing.T) {
	for _, want := range []string{
		ReasonPresentMonMissing,
		ReasonServiceUnavailable,
		ReasonVersionMismatch,
		ReasonUnsupportedOS,
	} {
		t.Run(want, func(t *testing.T) {
			got := parseProbeLine([]byte(fmt.Sprintf(
				`{"type":"probe","proto":2,"sensor_version":"0.2.0","ok":false,"reason":%q}`, want)))
			if got.OK {
				t.Fatalf("probe = %+v, want not OK", got)
			}
			if got.Reason != want {
				t.Fatalf("reason = %q, want %q", got.Reason, want)
			}
		})
	}
}

func TestParseProbeLineRejectsUnusableAnswers(t *testing.T) {
	tests := []struct {
		name, line, wantReason string
	}{
		{"garbage", `not json at all`, ReasonProbeFailed},
		{"wrong type", `{"type":"hello","proto":2}`, ReasonProbeFailed},
		{"empty", ``, ReasonProbeFailed},
		{"newer protocol", `{"type":"probe","proto":99,"ok":true}`, ReasonProtoMismatch},
		{"older protocol", `{"type":"probe","proto":1,"ok":true}`, ReasonProtoMismatch},
		// The sensor says it cannot capture but does not say why. Still blocked,
		// and still given a code rather than an empty reason.
		{"unexplained", `{"type":"probe","proto":2,"ok":false}`, ReasonProbeFailed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseProbeLine([]byte(tt.line))
			if got.OK {
				t.Fatalf("probe = %+v, want not OK", got)
			}
			if got.Reason != tt.wantReason {
				t.Fatalf("reason = %q, want %q", got.Reason, tt.wantReason)
			}
		})
	}
}

func TestConsumeBucketsSecondsAndSkipsNoise(t *testing.T) {
	s := NewSupervisor("sensor", nil)
	s.consume(strings.NewReader(strings.Join([]string{
		`{"type":"hello","proto":2,"sensor_version":"0.2.0","source":"presentmon_service",` +
			`"pm_version":"2.3.0","caps":["displayed","frame_type","present_meta","per_frame_complete"]}`,
		`{"type":"status","state":"tracking","pid":42,"proc":"game.exe","title":"Deep Rock Galactic"}`,
		secLine("2026-08-01T12:00:00.500Z", "game.exe", 42),
		`{"type":"sec"`, // truncated line: skipped, must not end the stream
		`this is not json`,
		// A message type this build does not know is ignored, not fatal.
		`{"type":"gpu","proto":2,"temp_c":71}`,
		secLine("2026-08-01T12:00:01.500Z", "game.exe", 42),
	}, "\n")))

	runs, buckets := s.Drain()
	if len(runs) != 1 {
		t.Fatalf("Drain() returned %d runs, want 1: %+v", len(runs), runs)
	}
	run := runs[0]
	if run.ID == "" || run.Proc != "game.exe" || run.Title != "Deep Rock Galactic" {
		t.Fatalf("run = %+v", run)
	}
	if run.Source != gs.SourcePresentMonService || len(run.Caps) != 4 {
		t.Fatalf("run = %+v, want the hello's source and capabilities", run)
	}
	if run.EndedAt != nil {
		t.Fatalf("run = %+v, want no end while the stream is still open", run)
	}

	if len(buckets) != 2 {
		t.Fatalf("Drain() returned %d buckets, want 2: %+v", len(buckets), buckets)
	}
	for _, b := range buckets {
		if b.RunID != run.ID {
			t.Errorf("bucket %+v does not belong to the run %q", b, run.ID)
		}
	}
	if want := time.Date(2026, 8, 1, 12, 0, 0, 500e6, time.UTC); !buckets[0].TS.Equal(want) {
		t.Errorf("first bucket TS = %v, want %v", buckets[0].TS, want)
	}
	if !run.LastSeenAt.Equal(buckets[1].TS) {
		t.Errorf("run LastSeenAt = %v, want the newest second %v", run.LastSeenAt, buckets[1].TS)
	}

	if runs, buckets := s.Drain(); runs != nil || buckets != nil {
		t.Fatalf("Drain() = %v, %v on the second call; want both cleared", runs, buckets)
	}
}

// The optional fields exist so "not measured" stays distinct from "measured
// zero". A bucket must carry through exactly what the sensor said, including the
// absences.
func TestBucketsCarryTheSampleUnchanged(t *testing.T) {
	s := NewSupervisor("sensor", nil)
	s.consume(strings.NewReader(strings.Join([]string{
		`{"type":"status","state":"tracking","pid":7,"proc":"game.exe"}`,
		// A source that sees only that frames were presented.
		`{"type":"sec","ts":"2026-08-01T12:00:00Z","pid":7,"proc":"game.exe",` +
			`"frames":{"presented":30},` +
			`"ft":{"avg":33.3,"p50":33.2,"p95":40.0,"p99":45.0,"max":51.0,"sd":4.0},` +
			`"ft_hist":{"layout":"log24_v1","counts":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,30,0,0,0,0,0,0,0,0]},` +
			`"quality":["hist_clipped"]}`,
		// A source that sees every frame through to the screen, dropping none.
		`{"type":"sec","ts":"2026-08-01T12:00:01Z","pid":7,"proc":"game.exe",` +
			`"frames":{"presented":30,"displayed":30,"dropped":0},` +
			`"ft":{"avg":33.3,"p50":33.2,"p95":40.0,"p99":45.0,"max":51.0,"sd":4.0},` +
			`"ft_hist":{"layout":"log24_v1","counts":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,30,0,0,0,0,0,0,0,0]}}`,
	}, "\n")))

	_, buckets := s.Drain()
	if len(buckets) != 2 {
		t.Fatalf("got %d buckets, want 2", len(buckets))
	}
	if buckets[0].Frames.Dropped != nil {
		t.Errorf("unmeasured dropped count became %d; absent must stay absent", *buckets[0].Frames.Dropped)
	}
	if buckets[0].Hist.Layout != gs.HistLayoutLog24V1 || len(buckets[0].Hist.Counts) != gs.HistBins {
		t.Errorf("histogram = %+v, want a full %s histogram", buckets[0].Hist, gs.HistLayoutLog24V1)
	}
	if len(buckets[0].Quality) != 1 || buckets[0].Quality[0] != gs.QualityHistClipped {
		t.Errorf("quality = %v, want the clipped flag preserved", buckets[0].Quality)
	}
	if buckets[1].Frames.Dropped == nil || *buckets[1].Frames.Dropped != 0 {
		t.Errorf("measured zero drops became %v; zero is an observation", buckets[1].Frames.Dropped)
	}
}

// A launcher hands the game a new pid partway through. The session the player is
// having does not restart, so neither does the run.
func TestRunSurvivesAPIDChange(t *testing.T) {
	s := NewSupervisor("sensor", nil)
	s.consume(strings.NewReader(strings.Join([]string{
		`{"type":"status","state":"tracking","pid":100,"proc":"game.exe"}`,
		secLine("2026-08-01T12:00:00Z", "game.exe", 100),
		`{"type":"status","state":"tracking","pid":200,"proc":"game.exe"}`,
		secLine("2026-08-01T12:00:01Z", "game.exe", 200),
	}, "\n")))

	runs, buckets := s.Drain()
	if len(runs) != 1 {
		t.Fatalf("got %d runs across a pid change, want 1: %+v", len(runs), runs)
	}
	for _, b := range buckets {
		if b.RunID != runs[0].ID {
			t.Fatalf("bucket %+v left the run when the pid changed", b)
		}
	}
}

// A different process is a different session, whatever the sensor was doing
// before.
func TestNewRunWhenTheProcessChanges(t *testing.T) {
	s := NewSupervisor("sensor", nil)
	s.consume(strings.NewReader(strings.Join([]string{
		`{"type":"status","state":"tracking","pid":1,"proc":"first.exe"}`,
		secLine("2026-08-01T12:00:00Z", "first.exe", 1),
		`{"type":"status","state":"tracking","pid":2,"proc":"second.exe"}`,
		secLine("2026-08-01T12:00:01Z", "second.exe", 2),
	}, "\n")))

	runs, buckets := s.Drain()
	if len(runs) != 2 {
		t.Fatalf("got %d runs for two games, want 2: %+v", len(runs), runs)
	}
	first, second := runs[0], runs[1]
	if first.Proc != "first.exe" || second.Proc != "second.exe" {
		t.Fatalf("runs = %+v, %+v", first, second)
	}
	// The displaced run is over, and its end is the last second it was seen.
	if first.EndedAt == nil {
		t.Fatal("the displaced run was left open")
	}
	if !first.EndedAt.Equal(first.LastSeenAt) {
		t.Errorf("EndedAt = %v, want the last observed second %v", first.EndedAt, first.LastSeenAt)
	}
	if second.EndedAt != nil {
		t.Errorf("the current run = %+v, want it still open", second)
	}
	if len(buckets) != 2 || buckets[0].RunID != first.ID || buckets[1].RunID != second.ID {
		t.Fatalf("buckets = %+v, want one per run", buckets)
	}
}

// The window title names the run for a human, and it changes as the player moves
// between menu and match. It updates the run in place; a run that started before
// a window existed still gets its name when one appears.
func TestTitleUpdatesTheCurrentRun(t *testing.T) {
	s := NewSupervisor("sensor", nil)
	s.consume(strings.NewReader(strings.Join([]string{
		// Mid-launch: no window title could be read yet.
		`{"type":"status","state":"tracking","pid":1,"proc":"game.exe"}`,
		secLine("2026-08-01T12:00:00Z", "game.exe", 1),
		`{"type":"status","state":"tracking","pid":1,"proc":"game.exe","title":"Main Menu"}`,
		secLine("2026-08-01T12:00:01Z", "game.exe", 1),
		`{"type":"status","state":"tracking","pid":1,"proc":"game.exe","title":"Hoxxes IV"}`,
	}, "\n")))

	runs, _ := s.Drain()
	if len(runs) != 1 {
		t.Fatalf("got %d runs, want 1: %+v", len(runs), runs)
	}
	if runs[0].Title != "Hoxxes IV" {
		t.Fatalf("title = %q, want the latest one", runs[0].Title)
	}
}

// An absent title is "no window could be read", not "the window has no name".
// Overwriting a known title with it would replace a fact with the lack of one.
func TestAbsentTitleDoesNotClearAKnownOne(t *testing.T) {
	s := NewSupervisor("sensor", nil)
	s.consume(strings.NewReader(strings.Join([]string{
		`{"type":"status","state":"tracking","pid":1,"proc":"game.exe","title":"Hoxxes IV"}`,
		`{"type":"status","state":"tracking","pid":2,"proc":"game.exe"}`,
	}, "\n")))

	runs, _ := s.Drain()
	if len(runs) != 1 || runs[0].Title != "Hoxxes IV" {
		t.Fatalf("runs = %+v, want the title kept", runs)
	}
}

// Idle is the ordinary end of a session. The run closes at the last second it
// was actually seen presenting, not at whenever the status happened to arrive.
func TestIdleEndsTheRun(t *testing.T) {
	s := NewSupervisor("sensor", nil)
	last := time.Date(2026, 8, 1, 12, 0, 5, 0, time.UTC)
	s.consume(strings.NewReader(strings.Join([]string{
		`{"type":"status","state":"tracking","pid":1,"proc":"game.exe"}`,
		secLine("2026-08-01T12:00:05Z", "game.exe", 1),
		`{"type":"status","state":"idle"}`,
	}, "\n")))

	runs, _ := s.Drain()
	if len(runs) != 1 {
		t.Fatalf("got %d runs, want 1: %+v", len(runs), runs)
	}
	if runs[0].EndedAt == nil {
		t.Fatal("an idle sensor left the run open")
	}
	if !runs[0].EndedAt.Equal(last) {
		t.Fatalf("EndedAt = %v, want the last captured second %v", runs[0].EndedAt, last)
	}
}

// Tracking that produced no seconds still has to end somewhere, and the agent's
// clock is the only moment there is.
func TestRunWithoutBucketsEndsAtTheAgentClock(t *testing.T) {
	s := NewSupervisor("sensor", nil)
	before := time.Now().UTC().Add(-time.Second)
	s.consume(strings.NewReader(strings.Join([]string{
		`{"type":"status","state":"tracking","pid":1,"proc":"game.exe"}`,
		`{"type":"status","state":"idle"}`,
	}, "\n")))

	runs, buckets := s.Drain()
	if len(runs) != 1 || len(buckets) != 0 {
		t.Fatalf("Drain() = %+v, %+v; want one run and no buckets", runs, buckets)
	}
	if runs[0].EndedAt == nil || runs[0].EndedAt.Before(before) {
		t.Fatalf("EndedAt = %v, want a recent time", runs[0].EndedAt)
	}
}

// The seconds are real whether or not a status announced them. A sec with no run
// to belong to starts one rather than being discarded — and does not invent a
// window title it was never told.
func TestSecWithoutStatusStartsARun(t *testing.T) {
	s := NewSupervisor("sensor", nil)
	s.consume(strings.NewReader(secLine("2026-08-01T12:00:00Z", "orphan.exe", 9)))

	runs, buckets := s.Drain()
	if len(runs) != 1 || len(buckets) != 1 {
		t.Fatalf("Drain() = %+v, %+v; want one run and one bucket", runs, buckets)
	}
	if runs[0].Proc != "orphan.exe" {
		t.Fatalf("run = %+v, want the process the second named", runs[0])
	}
	if runs[0].Title != "" {
		t.Fatalf("title = %q, want none — a sec line never carries one", runs[0].Title)
	}
	if !runs[0].StartedAt.Equal(buckets[0].TS) {
		t.Fatalf("StartedAt = %v, want the first captured second %v", runs[0].StartedAt, buckets[0].TS)
	}
}

// Moving between windows and back is one session per program, not one per move.
//
// This is what a desktop actually looks like: a person alternates between two
// things for an hour. Keyed on anything but the process id, that came back as a
// row per switch, each holding a fragment nobody played.
func TestReturningToTheSameProcessReopensItsRun(t *testing.T) {
	s := NewSupervisor("sensor", nil)
	s.consume(strings.NewReader(strings.Join([]string{
		`{"type":"status","state":"tracking","pid":100,"proc":"game.exe","title":"A Game"}`,
		secLine("2026-08-02T01:00:00Z", "game.exe", 100),
		`{"type":"status","state":"tracking","pid":200,"proc":"chrome.exe","title":"A Wiki"}`,
		secLine("2026-08-02T01:00:20Z", "chrome.exe", 200),
		`{"type":"status","state":"tracking","pid":100,"proc":"game.exe","title":"A Game"}`,
		secLine("2026-08-02T01:00:40Z", "game.exe", 100),
	}, "\n")))

	runs, buckets := s.Drain()
	byID := map[string]gs.Run{}
	for _, r := range runs {
		byID[r.ID] = r
	}
	if len(byID) != 2 {
		t.Fatalf("recorded %d runs, want one per program: %+v", len(byID), runs)
	}
	perRun := map[string]int{}
	for _, b := range buckets {
		perRun[b.RunID]++
	}
	var gameRun gs.Run
	for _, r := range byID {
		if r.Proc == "game.exe" {
			gameRun = r
		}
	}
	if gameRun.ID == "" {
		t.Fatalf("no run for the game: %+v", runs)
	}
	if perRun[gameRun.ID] != 2 {
		t.Fatalf("the game's run holds %d seconds, want both of its own", perRun[gameRun.ID])
	}
	// Reopened, so it is live again rather than stranded as finished.
	if gameRun.EndedAt != nil {
		t.Fatalf("the reopened run is still marked ended at %v", gameRun.EndedAt)
	}
	if !gameRun.LastSeenAt.Equal(time.Date(2026, 8, 2, 1, 0, 40, 0, time.UTC)) {
		t.Fatalf("last seen = %v, want the run to span the interruption", gameRun.LastSeenAt)
	}
}

// A pause long enough for the sensor to call the session over is still the same
// session if the same process comes back. A long loading screen, a game
// minimized over lunch, a sensor that crashed and restarted — all of them end up
// here, and all of them are one session to the person who played it.
func TestASessionResumesAfterBeingDeclaredOver(t *testing.T) {
	s := NewSupervisor("sensor", nil)
	s.consume(strings.NewReader(strings.Join([]string{
		`{"type":"status","state":"tracking","pid":100,"proc":"game.exe","title":"A Game"}`,
		secLine("2026-08-02T01:00:00Z", "game.exe", 100),
		`{"type":"status","state":"idle"}`,
		`{"type":"status","state":"tracking","pid":100,"proc":"game.exe","title":"A Game"}`,
		secLine("2026-08-02T01:02:00Z", "game.exe", 100),
	}, "\n")))

	runs, buckets := s.Drain()
	ids := map[string]bool{}
	for _, r := range runs {
		ids[r.ID] = true
	}
	if len(ids) != 1 {
		t.Fatalf("recorded %d runs, want the session resumed: %+v", len(ids), runs)
	}
	if len(buckets) != 2 {
		t.Fatalf("recorded %d seconds, want both under the one session", len(buckets))
	}
	last := runs[len(runs)-1]
	if last.EndedAt != nil {
		t.Fatalf("the resumed session is still marked ended at %v", last.EndedAt)
	}
	if !last.LastSeenAt.Equal(time.Date(2026, 8, 2, 1, 2, 0, 0, time.UTC)) {
		t.Fatalf("last seen = %v, want the session to span the pause", last.LastSeenAt)
	}
}

// The same program run twice is two sessions. Reusing by name would merge a
// second copy of a game — or a second browser window — into the first.
func TestADifferentProcessIdIsADifferentSession(t *testing.T) {
	s := NewSupervisor("sensor", nil)
	s.consume(strings.NewReader(strings.Join([]string{
		`{"type":"status","state":"tracking","pid":100,"proc":"game.exe"}`,
		secLine("2026-08-02T01:00:00Z", "game.exe", 100),
		`{"type":"status","state":"idle"}`,
		`{"type":"status","state":"tracking","pid":300,"proc":"game.exe"}`,
		secLine("2026-08-02T01:00:20Z", "game.exe", 300),
	}, "\n")))

	runs, _ := s.Drain()
	ids := map[string]bool{}
	for _, r := range runs {
		ids[r.ID] = true
	}
	if len(ids) != 2 {
		t.Fatalf("recorded %d runs, want one per launch: %+v", len(ids), runs)
	}
}

// A process quiet for longer than the window has ended, whatever it does later.
// The window runs from when the run was last SEEN, so a long session interrupted
// briefly is still reopenable however long it had been going.
func TestAProcessQuietPastTheWindowStartsFresh(t *testing.T) {
	s := NewSupervisor("sensor", nil)
	s.consume(strings.NewReader(strings.Join([]string{
		`{"type":"status","state":"tracking","pid":100,"proc":"game.exe"}`,
		secLine("2026-08-02T01:00:00Z", "game.exe", 100),
	}, "\n")))
	s.Drain()

	// Park it, then move the clock past the window before it returns.
	s.mu.Lock()
	s.parkCurrent(time.Now().UTC())
	for _, run := range s.parked {
		run.LastSeenAt = time.Now().UTC().Add(-2 * reviveWindow)
	}
	s.mu.Unlock()

	s.consume(strings.NewReader(strings.Join([]string{
		`{"type":"status","state":"tracking","pid":100,"proc":"game.exe"}`,
		secLine("2026-08-02T03:00:00Z", "game.exe", 100),
	}, "\n")))

	runs, _ := s.Drain()
	var live, finished int
	for _, r := range runs {
		if r.EndedAt == nil {
			live++
		} else {
			finished++
		}
	}
	if live != 1 || finished != 1 {
		t.Fatalf("drained %d live and %d finished runs, want the old one left ended and a new one started: %+v", live, finished, runs)
	}
}

// A second nobody could name is dropped rather than given a run of its own.
//
// A nameless run has nothing to identify it in a list, and the moment the name
// arrives on the next status the recorder would close it and open another —
// turning one session into two, which is the thing runs exist to prevent. Losing
// the first second of a session is the smaller harm.
func TestASecondWithNoProcessNameIsDiscarded(t *testing.T) {
	s := NewSupervisor("sensor", nil)
	s.consume(strings.NewReader(strings.Join([]string{
		secLine("2026-08-01T12:00:00Z", "", 9),
		`{"type":"status","state":"tracking","pid":9,"proc":"game.exe","title":"A Game"}`,
		secLine("2026-08-01T12:00:01Z", "game.exe", 9),
	}, "\n")))

	runs, buckets := s.Drain()
	if len(runs) != 1 {
		t.Fatalf("Drain() returned %d runs, want one session rather than a nameless one plus a real one", len(runs))
	}
	if runs[0].Proc != "game.exe" || runs[0].Title != "A Game" {
		t.Fatalf("run = %+v, want the named session", runs[0])
	}
	if len(buckets) != 1 {
		t.Fatalf("recorded %d buckets, want only the second that could be attributed", len(buckets))
	}
	if got := buckets[0].TS.Format(time.RFC3339); got != "2026-08-01T12:00:01Z" {
		t.Fatalf("bucket at %s, want the named second", got)
	}
}

// Draining empties the recorder, so a caller that cannot persist what it took
// must be able to give it back — otherwise one failed write takes a hole out of
// the middle of a session instead of delaying it.
func TestRequeuePutsUnpersistedRecordsBack(t *testing.T) {
	s := NewSupervisor("sensor", nil)
	s.consume(strings.NewReader(strings.Join([]string{
		`{"type":"status","state":"tracking","pid":1,"proc":"game.exe"}`,
		secLine("2026-08-01T12:00:00Z", "game.exe", 1),
		secLine("2026-08-01T12:00:01Z", "game.exe", 1),
	}, "\n")))

	runs, buckets := s.Drain()
	if len(runs) != 1 || len(buckets) != 2 {
		t.Fatalf("Drain() = %d runs, %d buckets", len(runs), len(buckets))
	}
	s.Requeue(runs, buckets)

	// A later second arrives before the retry.
	s.consume(strings.NewReader(secLine("2026-08-01T12:00:02Z", "game.exe", 1)))

	againRuns, againBuckets := s.Drain()
	if len(againRuns) != 1 || againRuns[0].ID != runs[0].ID {
		t.Fatalf("runs = %+v, want the same run offered again", againRuns)
	}
	if len(againBuckets) != 3 {
		t.Fatalf("buckets = %d, want the two returned plus the new one", len(againBuckets))
	}
	// Order still follows time: the returned seconds are older than the new one.
	for i := 1; i < len(againBuckets); i++ {
		if !againBuckets[i-1].TS.Before(againBuckets[i].TS) {
			t.Fatalf("buckets out of order at %d: %v then %v", i, againBuckets[i-1].TS, againBuckets[i].TS)
		}
	}
}

// An ending that failed to persist has to survive the retry, or the run stays
// open on the server forever.
func TestRequeueKeepsTheEndingOfAFinishedRun(t *testing.T) {
	s := NewSupervisor("sensor", nil)
	s.consume(strings.NewReader(strings.Join([]string{
		`{"type":"status","state":"tracking","pid":1,"proc":"game.exe"}`,
		secLine("2026-08-01T12:00:00Z", "game.exe", 1),
		`{"type":"status","state":"idle"}`,
	}, "\n")))

	runs, buckets := s.Drain()
	if len(runs) != 1 || runs[0].EndedAt == nil {
		t.Fatalf("runs = %+v, want one finished run", runs)
	}
	s.Requeue(runs, buckets)

	again, _ := s.Drain()
	if len(again) != 1 {
		t.Fatalf("runs = %d, want the finished run offered again", len(again))
	}
	if again[0].EndedAt == nil || !again[0].EndedAt.Equal(*runs[0].EndedAt) {
		t.Fatalf("run = %+v, want its ending preserved", again[0])
	}
}

// After an idle, seconds that keep arriving belong to a new session rather than
// to the one that was declared over.
func TestSecAfterIdleStartsAFreshRun(t *testing.T) {
	s := NewSupervisor("sensor", nil)
	s.consume(strings.NewReader(strings.Join([]string{
		`{"type":"status","state":"tracking","pid":1,"proc":"game.exe"}`,
		secLine("2026-08-01T12:00:00Z", "game.exe", 1),
		`{"type":"status","state":"idle"}`,
		secLine("2026-08-01T12:00:30Z", "game.exe", 1),
	}, "\n")))

	runs, buckets := s.Drain()
	if len(runs) != 2 {
		t.Fatalf("got %d runs, want 2: %+v", len(runs), runs)
	}
	if runs[0].ID == runs[1].ID {
		t.Fatal("the second run reused the ended run's id")
	}
	if len(buckets) != 2 || buckets[1].RunID != runs[1].ID {
		t.Fatalf("buckets = %+v, want the later second on the new run", buckets)
	}
}

// The sensor stopping ends the run even though no status said so: nothing is
// observing the game any more, and a restart must not stitch the seconds either
// side of the gap into one continuous session.
func TestAStoppedSensorEndsTheRun(t *testing.T) {
	restoreSchedule(t, time.Millisecond, time.Millisecond, time.Hour)

	s := NewSupervisor("sensor", nil)
	var once sync.Once
	fed := make(chan struct{})
	s.run = func(ctx context.Context) error {
		once.Do(func() {
			s.consume(strings.NewReader(strings.Join([]string{
				`{"type":"status","state":"tracking","pid":1,"proc":"game.exe"}`,
				secLine("2026-08-01T12:00:00Z", "game.exe", 1),
			}, "\n")))
			close(fed)
		})
		<-ctx.Done()
		return ctx.Err()
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); s.Run(ctx) }()
	<-fed
	cancel()
	<-done

	runs, _ := s.Drain()
	if len(runs) != 1 {
		t.Fatalf("got %d runs, want 1: %+v", len(runs), runs)
	}
	if runs[0].EndedAt == nil {
		t.Fatal("the run outlived the sensor that was producing it")
	}
}

// A line past the cap stops a Scanner for good. The cap exists to bound memory,
// but the reader behind it is a pipe the sensor keeps writing to — so the
// failure has to be reported rather than swallowed, or the run stalls with the
// sensor blocked on a full pipe and the supervisor none the wiser.
func TestConsumeReportsAnOversizedLine(t *testing.T) {
	s := NewSupervisor("sensor", nil)
	huge := `{"type":"sec","proc":"` + strings.Repeat("x", maxLineBytes) + `.exe"}`
	err := s.consume(strings.NewReader(strings.Join([]string{
		secLine("2026-08-01T12:00:00Z", "game.exe", 1),
		huge,
		secLine("2026-08-01T12:00:01Z", "game.exe", 1),
	}, "\n")))
	if err == nil {
		t.Fatal("consume() = nil for a line past the cap; the caller cannot know to restart")
	}
	// What arrived before the bad line is still real data that happened.
	if _, buckets := s.Drain(); len(buckets) != 1 {
		t.Fatalf("kept %d buckets from before the oversized line, want 1", len(buckets))
	}
}

func TestConsumeReturnsNilAtACleanEnd(t *testing.T) {
	s := NewSupervisor("sensor", nil)
	if err := s.consume(strings.NewReader(`{"type":"status","state":"idle"}`)); err != nil {
		t.Fatalf("consume() = %v at a clean end, want nil", err)
	}
}

// A second the sensor did not stamp still needs a timestamp, or it would land at
// the zero time and sort before every real point in the run.
func TestConsumeStampsUndatedSeconds(t *testing.T) {
	s := NewSupervisor("sensor", nil)
	before := time.Now().UTC().Add(-time.Second)
	s.consume(strings.NewReader(`{"type":"sec","proc":"game.exe","frames":{"presented":30},` +
		`"ft":{"avg":33.3,"p50":33.2,"p95":40,"p99":45,"max":51,"sd":4},` +
		`"ft_hist":{"layout":"log24_v1","counts":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,30,0,0,0,0,0,0,0,0]}}`))
	_, buckets := s.Drain()
	if len(buckets) != 1 {
		t.Fatalf("Drain() returned %d buckets, want 1", len(buckets))
	}
	if buckets[0].TS.Before(before) {
		t.Fatalf("TS = %v, want a recent time", buckets[0].TS)
	}
}

// The buffer exists so the sensor's per-second cadence and the upload cycle need
// not agree. It must be bounded, and when it overflows it must keep the newest
// seconds — a live chart shows the recent past, not the distant one.
func TestBufferDropsOldestWhenFull(t *testing.T) {
	s := NewSupervisor("sensor", nil)
	base := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	for i := 0; i < maxBuffered+10; i++ {
		s.sec(gs.Sec{
			Type: gs.TypeSec, TS: base.Add(time.Duration(i) * time.Second),
			PID: 1, Proc: "game.exe",
		})
	}
	_, buckets := s.Drain()
	if len(buckets) != maxBuffered {
		t.Fatalf("buffered %d buckets, want the cap %d", len(buckets), maxBuffered)
	}
	if want := base.Add(10 * time.Second); !buckets[0].TS.Equal(want) {
		t.Fatalf("oldest retained bucket = %v, want the 10 earliest dropped (%v)", buckets[0].TS, want)
	}
	if want := base.Add(time.Duration(maxBuffered+9) * time.Second); !buckets[len(buckets)-1].TS.Equal(want) {
		t.Fatalf("newest retained bucket = %v, want the last pushed (%v)", buckets[len(buckets)-1].TS, want)
	}
	if s.DroppedCount() != 10 {
		t.Fatalf("DroppedCount() = %d, want 10", s.DroppedCount())
	}
}

// The server upserts runs, so a run whose mutable state moved is handed out
// again. That is what completes a run whose ending happened after its buckets
// were already uploaded.
func TestRunIsResentWhileItChanges(t *testing.T) {
	s := NewSupervisor("sensor", nil)
	s.consume(strings.NewReader(strings.Join([]string{
		`{"type":"status","state":"tracking","pid":1,"proc":"game.exe"}`,
		secLine("2026-08-01T12:00:00Z", "game.exe", 1),
	}, "\n")))
	first, _ := s.Drain()
	if len(first) != 1 || first[0].EndedAt != nil {
		t.Fatalf("first drain = %+v, want one open run", first)
	}

	// Nothing happened since: there is nothing to upsert.
	if runs, _ := s.Drain(); len(runs) != 0 {
		t.Fatalf("second drain = %+v, want no runs for an unchanged run", runs)
	}

	s.consume(strings.NewReader(`{"type":"status","state":"idle"}`))
	ended, _ := s.Drain()
	if len(ended) != 1 || ended[0].ID != first[0].ID || ended[0].EndedAt == nil {
		t.Fatalf("third drain = %+v, want the same run, now ended", ended)
	}
}

// A sensor that keeps exiting quickly is reported once, not once per restart,
// and the report clears when it starts working again.
//
// The recovery half is the subtle one: a working sensor runs until the agent
// stops it, so the run that recovers never returns. Recovery therefore has to be
// recognised while the run is still going — waiting for it to end would mean an
// operator sees a failure event that never clears, on a machine that has been
// collecting normally for hours.
func TestSupervisorReportsPersistentFailureOnceThenRecovery(t *testing.T) {
	restoreSchedule(t, time.Millisecond, 5*time.Millisecond, 50*time.Millisecond)

	var mu sync.Mutex
	var events []telemetry.Event
	recovered := make(chan struct{})
	var once sync.Once
	s := NewSupervisor("sensor", func(ev telemetry.Event) {
		mu.Lock()
		events = append(events, ev)
		mu.Unlock()
		if ev.Type == telemetry.EventGameSensorRecovered {
			once.Do(func() { close(recovered) })
		}
	})

	attempts := 0
	s.run = func(ctx context.Context) error {
		mu.Lock()
		attempts++
		n := attempts
		mu.Unlock()
		if n <= 5 {
			return fmt.Errorf("attempt %d failed", n)
		}
		// From here the sensor works, which means it does not stop.
		<-ctx.Done()
		return ctx.Err()
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); s.Run(ctx) }()

	select {
	case <-recovered:
	case <-time.After(5 * time.Second):
		cancel()
		<-done
		t.Fatal("no recovery event while the sensor was running normally")
	}
	cancel()
	<-done

	mu.Lock()
	defer mu.Unlock()
	var failed, recoveredCount int
	for _, ev := range events {
		switch ev.Type {
		case telemetry.EventGameSensorFailed:
			failed++
			if ev.Attrs["reason"] == "" {
				t.Error("failure event carries no reason")
			}
			if ev.Attrs["path"] != "sensor" {
				t.Errorf("failure event path = %q, want the sensor path", ev.Attrs["path"])
			}
			if ev.Severity != telemetry.SeverityWarn {
				t.Errorf("failure severity = %q, want warn", ev.Severity)
			}
		case telemetry.EventGameSensorRecovered:
			recoveredCount++
		}
	}
	if failed != 1 {
		t.Errorf("emitted %d failure events, want exactly 1 for one failing streak", failed)
	}
	if recoveredCount != 1 {
		t.Errorf("emitted %d recovery events, want 1", recoveredCount)
	}
}

// A sensor that loses its capture session says so before exiting. That code is
// the only actionable part of the failure, so it must reach the event rather than
// being replaced by the exit status the agent happened to observe.
func TestFailureEventCarriesTheSensorsOwnReason(t *testing.T) {
	restoreSchedule(t, time.Millisecond, 5*time.Millisecond, time.Hour)

	var mu sync.Mutex
	var events []telemetry.Event
	failed := make(chan struct{})
	var once sync.Once
	s := NewSupervisor("sensor", func(ev telemetry.Event) {
		mu.Lock()
		events = append(events, ev)
		mu.Unlock()
		if ev.Type == telemetry.EventGameSensorFailed {
			once.Do(func() { close(failed) })
		}
	})

	s.run = func(context.Context) error {
		// What the sensor emits on its way out, then the exit the agent sees.
		s.consume(strings.NewReader(
			`{"type":"status","state":"error","reason":"session_lost"}`))
		return errors.New("sensor exited with code 4")
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); s.Run(ctx) }()
	select {
	case <-failed:
	case <-time.After(5 * time.Second):
		cancel()
		<-done
		t.Fatal("no failure event")
	}
	cancel()
	<-done

	mu.Lock()
	defer mu.Unlock()
	for _, ev := range events {
		if ev.Type != telemetry.EventGameSensorFailed {
			continue
		}
		if ev.Attrs["reason"] != ReasonSessionLost {
			t.Errorf("reason = %q, want the sensor's own %q", ev.Attrs["reason"], ReasonSessionLost)
		}
		// The observed exit is still worth keeping, just not in place of the reason.
		if ev.Attrs["detail"] == "" {
			t.Error("failure event dropped the observed exit")
		}
		return
	}
}

// Without a reason from the sensor the event still has to say something stable;
// an empty reason would read as "no information available" when the real
// information is "it stopped and did not say why".
func TestFailureEventFallsBackToAStableReason(t *testing.T) {
	restoreSchedule(t, time.Millisecond, 5*time.Millisecond, time.Hour)

	var mu sync.Mutex
	var got telemetry.Event
	failed := make(chan struct{})
	var once sync.Once
	s := NewSupervisor("sensor", func(ev telemetry.Event) {
		if ev.Type != telemetry.EventGameSensorFailed {
			return
		}
		mu.Lock()
		got = ev
		mu.Unlock()
		once.Do(func() { close(failed) })
	})
	s.run = func(context.Context) error { return errors.New("exit status 1") }

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); s.Run(ctx) }()
	select {
	case <-failed:
	case <-time.After(5 * time.Second):
		cancel()
		<-done
		t.Fatal("no failure event")
	}
	cancel()
	<-done

	mu.Lock()
	defer mu.Unlock()
	if got.Attrs["reason"] != ReasonSensorExited {
		t.Fatalf("reason = %q, want %q", got.Attrs["reason"], ReasonSensorExited)
	}
}

// A reason belongs to the run that produced it. Carrying it forward would
// attribute an old capture-session loss to a sensor that is now failing to start
// for an entirely different cause.
func TestReasonDoesNotCarryAcrossRuns(t *testing.T) {
	s := NewSupervisor("sensor", nil)
	s.consume(strings.NewReader(`{"type":"status","state":"error","reason":"session_lost"}`))
	if got := s.takeReason(); got != ReasonSessionLost {
		t.Fatalf("takeReason() = %q, want the recorded reason", got)
	}
	if got := s.takeReason(); got != "" {
		t.Fatalf("takeReason() = %q on the second call, want it cleared", got)
	}
	// A status that names no failure records nothing.
	s.consume(strings.NewReader(`{"type":"status","state":"idle"}`))
	if got := s.takeReason(); got != "" {
		t.Fatalf("takeReason() = %q after an idle status, want empty", got)
	}
}

// Two failures are ordinary — a game exiting, a driver reset. Only a streak is
// worth an operator's attention.
func TestSupervisorStaysQuietForOccasionalExits(t *testing.T) {
	restoreSchedule(t, time.Millisecond, 5*time.Millisecond, time.Millisecond)

	var mu sync.Mutex
	var events []telemetry.Event
	s := NewSupervisor("sensor", func(ev telemetry.Event) {
		mu.Lock()
		events = append(events, ev)
		mu.Unlock()
	})

	attempts := 0
	s.run = func(ctx context.Context) error {
		mu.Lock()
		attempts++
		n := attempts
		mu.Unlock()
		// Fail twice, then run long enough to be healthy, forever.
		if n <= 2 {
			return errors.New("short exit")
		}
		<-ctx.Done()
		return ctx.Err()
	}

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	s.Run(ctx)

	mu.Lock()
	defer mu.Unlock()
	for _, ev := range events {
		if ev.Type == telemetry.EventGameSensorFailed {
			t.Fatalf("reported a failure after %d exits, want silence below the threshold", failuresBeforeEvent)
		}
	}
}

func TestSupervisorStopsOnCancel(t *testing.T) {
	restoreSchedule(t, time.Millisecond, 5*time.Millisecond, time.Millisecond)

	s := NewSupervisor("sensor", nil)
	s.run = func(ctx context.Context) error {
		<-ctx.Done()
		return ctx.Err()
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); s.Run(ctx) }()
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after cancellation")
	}
}

// Locate must not claim a sensor that is not there: an agent shipped without one
// is the ordinary case, and a false positive would turn "unsupported" into a
// spawn failure on every restart.
func TestLocateHonoursTheDevelopmentOverride(t *testing.T) {
	if !platformSupported {
		t.Skip("no sensor component off Windows")
	}
	dir := t.TempDir()
	exe := filepath.Join(dir, ExeName)
	if err := os.WriteFile(exe, []byte("stub"), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Setenv(PathEnv, exe)
	got, ok := Locate(false)
	if !ok || got != exe {
		t.Fatalf("Locate() = %q, %v; want the override path", got, ok)
	}

	t.Setenv(PathEnv, filepath.Join(dir, "absent.exe"))
	if got, ok := Locate(false); ok {
		t.Fatalf("Locate() = %q, true; want false for a missing override", got)
	}

	// A directory at the sensor's name is not a sensor.
	subdir := filepath.Join(dir, "dir.exe")
	if err := os.Mkdir(subdir, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv(PathEnv, subdir)
	if _, ok := Locate(false); ok {
		t.Fatal("Locate() accepted a directory as the sensor")
	}
}

// `go run` puts the executable in a temp directory, so a developer would
// otherwise have to set the override on every run for the sensor to be found at
// all. A release build must not do this search: the file it finds is a program
// this agent spawns, and the working directory is not ours to trust.
func TestLocateSearchesTheWorkspaceOnlyForDevBuilds(t *testing.T) {
	if !platformSupported {
		t.Skip("no sensor component off Windows")
	}
	root := t.TempDir()
	// The workspace shape: the module being run is a sibling of the one whose
	// dist directory a locally built sensor lands in.
	cwd := filepath.Join(root, "agent")
	dist := filepath.Join(root, devBuildDir, "dist")
	if err := os.MkdirAll(cwd, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dist, 0o755); err != nil {
		t.Fatal(err)
	}
	sensor := filepath.Join(dist, ExeName)
	if err := os.WriteFile(sensor, []byte("stub"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(cwd)

	if got, ok := Locate(true); !ok || got != filepath.Clean(sensor) {
		t.Fatalf("Locate(dev) = %q, %v; want the workspace build %q", got, ok, sensor)
	}
	if got, ok := Locate(false); ok {
		t.Fatalf("Locate(release) = %q, true; a release build must not search the working directory", got)
	}

	// An explicit override still wins over the search, and a bad one still fails
	// rather than falling through to whatever the cwd happens to hold.
	t.Setenv(PathEnv, filepath.Join(root, "absent.exe"))
	if got, ok := Locate(true); ok {
		t.Fatalf("Locate() = %q, true; a broken override must not fall through to the workspace", got)
	}
}

func TestLocateFindsNothingOffWindows(t *testing.T) {
	if platformSupported {
		t.Skip("Windows ships a sensor")
	}
	if _, ok := Locate(true); ok {
		t.Fatal("Locate() found a sensor on a platform that has none")
	}
	if got := Probe(context.Background(), "sensor"); got.OK {
		t.Fatalf("Probe() = %+v, want not OK", got)
	}
}

// restoreSchedule compresses the restart schedule for a test and restores it
// afterwards.
func restoreSchedule(t *testing.T, min, max, healthy time.Duration) {
	t.Helper()
	oMin, oMax, oHealthy := backoffMin, backoffMax, healthyFor
	backoffMin, backoffMax, healthyFor = min, max, healthy
	t.Cleanup(func() { backoffMin, backoffMax, healthyFor = oMin, oMax, oHealthy })
}
