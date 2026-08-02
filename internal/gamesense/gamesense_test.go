package gamesense

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
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

// fixtureStart is the instant the lifecycle fixtures below stamp their first
// second at. Their later seconds are offsets from it, so naming it lets a test
// put the recorder's own clock in the same era as the sensor lines it is being
// fed — which is the relationship a real agent is always in, and the one the
// revive window is measured across.
var fixtureStart = time.Date(2026, 8, 2, 1, 0, 0, 0, time.UTC)

// restartGap is how far the fixtures' second half sits past their first. It is
// the length of a sensor restart as these tests model it: long enough to be a
// real interruption, far short of reviveWindow.
const restartGap = 10 * time.Second

// fakeClock points s at a hand-driven clock reading start, and returns the
// function that moves it.
//
// A test that involves parking a run must install one. The recorder decides
// whether a parked run is still revivable by comparing its own clock against the
// second the run was last seen at, so a fixture with fixed timestamps read
// against the real time.Now answers that question differently depending on when
// the suite is run: inside the window on the day the fixture was written, and
// outside it every day after. Driving the clock is what makes each test state
// the gap it means rather than inherit one from the calendar.
func fakeClock(s *Supervisor, start time.Time) func(time.Duration) {
	now := start
	s.now = func() time.Time { return now }
	return func(d time.Duration) { now = now.Add(d) }
}

func TestParseProbeLineAcceptsAWorkingSensor(t *testing.T) {
	got := parseProbeLine([]byte(`{"type":"probe","proto":3,"sensor_version":"0.2.0",` +
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

// The probe answers two questions, and the narrower one is not implied by the
// broader: a machine whose driver publishes no adapter telemetry still captures
// frames, and that is the common case rather than a fault. The one direction that
// is a contradiction — adapter telemetry on a sensor that cannot capture at all —
// is resolved here rather than passed on, since the GPU read is collected on the
// frame tick and cannot happen without it.
func TestParseProbeLineSeparatesTheGPUAnswer(t *testing.T) {
	tests := []struct {
		name, line      string
		wantOK, wantGPU bool
	}{
		{"frames and adapter", `{"type":"probe","proto":3,"ok":true,"gpu_ok":true}`, true, true},
		{"frames only", `{"type":"probe","proto":3,"ok":true}`, true, false},
		{"frames only, stated", `{"type":"probe","proto":3,"ok":true,"gpu_ok":false}`, true, false},
		{"adapter without capture", `{"type":"probe","proto":3,"ok":false,"reason":"service_unavailable","gpu_ok":true}`, false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseProbeLine([]byte(tt.line))
			if got.OK != tt.wantOK || got.GPUOK != tt.wantGPU {
				t.Fatalf("probe = %+v, want OK=%v GPUOK=%v", got, tt.wantOK, tt.wantGPU)
			}
		})
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
				`{"type":"probe","proto":3,"sensor_version":"0.2.0","ok":false,"reason":%q}`, want)))
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
		{"wrong type", `{"type":"hello","proto":3}`, ReasonProbeFailed},
		{"empty", ``, ReasonProbeFailed},
		{"newer protocol", `{"type":"probe","proto":99,"ok":true}`, ReasonProtoMismatch},
		{"older protocol", `{"type":"probe","proto":1,"ok":true}`, ReasonProtoMismatch},
		// The sensor says it cannot capture but does not say why. Still blocked,
		// and still given a code rather than an empty reason.
		{"unexplained", `{"type":"probe","proto":3,"ok":false}`, ReasonProbeFailed},
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
		`{"type":"hello","proto":3,"sensor_version":"0.2.0","source":"presentmon_service",` +
			`"pm_version":"2.3.0","caps":["displayed","frame_type","present_meta","per_frame_complete"]}`,
		`{"type":"status","state":"tracking","pid":42,"proc":"game.exe","title":"Deep Rock Galactic"}`,
		secLine("2026-08-01T12:00:00.500Z", "game.exe", 42),
		`{"type":"sec"`, // truncated line: skipped, must not end the stream
		`this is not json`,
		// A message type this build does not know is ignored, not fatal.
		`{"type":"gpu","proto":3,"temp_c":71}`,
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
	advance := fakeClock(s, fixtureStart)
	s.consume(strings.NewReader(`{"type":"status","state":"tracking","pid":1,"proc":"game.exe"}`))
	// Whatever the gap was, the ending is the moment the agent noticed — the one
	// piece of information it has, since the sensor never reported a second.
	advance(90 * time.Second)
	s.consume(strings.NewReader(`{"type":"status","state":"idle"}`))

	runs, buckets := s.Drain()
	if len(runs) != 1 || len(buckets) != 0 {
		t.Fatalf("Drain() = %+v, %+v; want one run and no buckets", runs, buckets)
	}
	want := fixtureStart.Add(90 * time.Second)
	if runs[0].EndedAt == nil || !runs[0].EndedAt.Equal(want) {
		t.Fatalf("EndedAt = %v, want the agent clock at the idle (%v)", runs[0].EndedAt, want)
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
	// The agent's clock moves with the seconds it is being shown, which is what a
	// real one does. Twenty seconds in another window is nowhere near reviveWindow,
	// so the game's run is still there to come back to.
	advance := fakeClock(s, fixtureStart)
	s.consume(strings.NewReader(strings.Join([]string{
		`{"type":"status","state":"tracking","pid":100,"proc":"game.exe","title":"A Game"}`,
		secLine("2026-08-02T01:00:00Z", "game.exe", 100),
	}, "\n")))
	advance(20 * time.Second)
	s.consume(strings.NewReader(strings.Join([]string{
		`{"type":"status","state":"tracking","pid":200,"proc":"chrome.exe","title":"A Wiki"}`,
		secLine("2026-08-02T01:00:20Z", "chrome.exe", 200),
	}, "\n")))
	advance(20 * time.Second)
	s.consume(strings.NewReader(strings.Join([]string{
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
	advance := fakeClock(s, fixtureStart)
	s.consume(strings.NewReader(strings.Join([]string{
		`{"type":"status","state":"tracking","pid":100,"proc":"game.exe","title":"A Game"}`,
		secLine("2026-08-02T01:00:00Z", "game.exe", 100),
		`{"type":"status","state":"idle"}`,
	}, "\n")))

	// Two minutes away — a loading screen, or a step out of the room. Well inside
	// reviveWindow, so the same process id is the same session coming back.
	advance(2 * time.Minute)
	s.consume(strings.NewReader(strings.Join([]string{
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
	// Inside the window, so the split is the identity rule doing its job and not
	// the first run having quietly aged out.
	advance := fakeClock(s, fixtureStart)
	s.consume(strings.NewReader(strings.Join([]string{
		`{"type":"status","state":"tracking","pid":100,"proc":"game.exe"}`,
		secLine("2026-08-02T01:00:00Z", "game.exe", 100),
		`{"type":"status","state":"idle"}`,
	}, "\n")))
	advance(20 * time.Second)
	s.consume(strings.NewReader(strings.Join([]string{
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
	advance := fakeClock(s, fixtureStart)
	s.consume(strings.NewReader(strings.Join([]string{
		`{"type":"status","state":"tracking","pid":100,"proc":"game.exe"}`,
		secLine("2026-08-02T01:00:00Z", "game.exe", 100),
	}, "\n")))
	s.Drain()
	s.endRun() // the sensor stopped; the run is parked, not forgotten

	// Two hours of silence — twice the window — before the same process returns.
	advance(2 * reviveWindow)
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

// reviveBases are the instants the window is measured from below. The rule is
// about a duration and nothing else, so it must hold identically at all three —
// and a test that passes at instants a century apart cannot be passing because
// of what today's date happens to be.
//
// That is what this table is here to prove. The wall clock used to supply these
// answers silently: fixtures stamped at a fixed moment sit inside reviveWindow on
// the day they are written and outside it every day after, which made the
// continuity tests go green for an afternoon and red every morning since.
var reviveBases = []struct {
	name string
	at   time.Time
}{
	{"2001", time.Date(2001, 3, 4, 5, 6, 7, 0, time.UTC)},
	{"2026", fixtureStart},
	{"2099", time.Date(2099, 12, 31, 23, 0, 0, 0, time.UTC)},
}

// reviveWindow is a boundary, and a boundary has two sides. A parked run whose
// process comes back at the last moment resumes; one that comes back a second
// later does not, and gets a session of its own.
//
// Both sides matter and neither was pinned before: the near side was asserted
// only by tests that happened to be inside the window, and the far side by a test
// that back-dated the run's own data rather than moving the clock. What was
// missing is the edge itself — the assertion that the window is exactly as wide
// as it says, rather than merely wide or narrow.
func TestTheReviveWindowIsAnEdge(t *testing.T) {
	cases := []struct {
		name     string
		away     time.Duration
		wantRuns int
	}{
		{"back at the last moment", reviveWindow, 1},
		{"back a second too late", reviveWindow + time.Second, 2},
	}
	for _, base := range reviveBases {
		for _, tc := range cases {
			t.Run(base.name+"/"+tc.name, func(t *testing.T) {
				back := base.at.Add(tc.away)
				s := NewSupervisor("sensor", nil)
				advance := fakeClock(s, base.at)
				s.consume(strings.NewReader(strings.Join([]string{
					`{"type":"status","state":"tracking","pid":100,"proc":"game.exe"}`,
					secLine(base.at.Format(time.RFC3339), "game.exe", 100),
					`{"type":"status","state":"idle"}`,
				}, "\n")))

				advance(tc.away)
				s.consume(strings.NewReader(strings.Join([]string{
					`{"type":"status","state":"tracking","pid":100,"proc":"game.exe"}`,
					secLine(back.Format(time.RFC3339), "game.exe", 100),
				}, "\n")))

				runs, buckets := s.Drain()
				byID := runsByID(runs)
				if len(byID) != tc.wantRuns {
					t.Fatalf("away %v from a run last seen at %v: recorded %d runs, want %d: %+v",
						tc.away, base.at, len(byID), tc.wantRuns, runs)
				}
				if len(buckets) != 2 {
					t.Fatalf("recorded %d seconds, want both: %+v", len(buckets), buckets)
				}

				if tc.wantRuns == 1 {
					var only gs.Run
					for _, r := range byID {
						only = r
					}
					if only.EndedAt != nil {
						t.Errorf("run = %+v, want the ending withdrawn by the revival", only)
					}
					if !only.LastSeenAt.Equal(back) {
						t.Errorf("last seen = %v, want the run to span the pause to %v", only.LastSeenAt, back)
					}
					if buckets[0].RunID != buckets[1].RunID {
						t.Errorf("buckets = %+v, want both seconds on the one run", buckets)
					}
					return
				}

				var ended, live gs.Run
				for _, r := range byID {
					if r.EndedAt != nil {
						ended = r
					} else {
						live = r
					}
				}
				if ended.ID == "" || live.ID == "" {
					t.Fatalf("runs = %+v, want the aged-out one ended and a new one open", runs)
				}
				if !ended.EndedAt.Equal(base.at) {
					t.Errorf("EndedAt = %v, want the last second it was seen (%v)", ended.EndedAt, base.at)
				}
				if !live.StartedAt.Equal(back) {
					t.Errorf("StartedAt = %v, want the moment the process came back (%v)", live.StartedAt, back)
				}
				if buckets[0].RunID != ended.ID || buckets[1].RunID != live.ID {
					t.Errorf("buckets = %+v, want each second on the session it was collected in", buckets)
				}
			})
		}
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

// Seconds that keep arriving after an idle belong to the session that was
// declared over. It is the revive rule reached through a sec line rather than a
// status: the sensor said nothing was presenting, and then the same process id
// was, which is one person coming back to one game. Only a gap past reviveWindow
// makes them a new session — see TestTheReviveWindowIsAnEdge.
//
// This asserted the opposite until the recorder's clock became injectable, and
// passed for a reason that had nothing to do with the rule: the fixture's seconds
// were far enough into the machine's past that the parked run was swept before
// the later second arrived, so the test was reading pre-revive behaviour off a
// stale wall clock.
func TestSecAfterIdleResumesTheParkedRun(t *testing.T) {
	s := NewSupervisor("sensor", nil)
	base := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	advance := fakeClock(s, base)
	s.consume(strings.NewReader(strings.Join([]string{
		`{"type":"status","state":"tracking","pid":1,"proc":"game.exe"}`,
		secLine("2026-08-01T12:00:00Z", "game.exe", 1),
		`{"type":"status","state":"idle"}`,
	}, "\n")))
	advance(30 * time.Second)
	s.consume(strings.NewReader(secLine("2026-08-01T12:00:30Z", "game.exe", 1)))

	runs, buckets := s.Drain()
	byID := runsByID(runs)
	if len(byID) != 1 {
		t.Fatalf("got %d runs, want the session resumed by its own seconds: %+v", len(byID), runs)
	}
	var only gs.Run
	for _, r := range byID {
		only = r
	}
	if only.EndedAt != nil {
		t.Errorf("run = %+v, want the ending withdrawn by the second that resumed it", only)
	}
	if want := base.Add(30 * time.Second); !only.LastSeenAt.Equal(want) {
		t.Errorf("last seen = %v, want the second that reopened it (%v)", only.LastSeenAt, want)
	}
	if len(buckets) != 2 || buckets[0].RunID != buckets[1].RunID {
		t.Fatalf("buckets = %+v, want both seconds on the one run", buckets)
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

	configure(s)
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
	fakeClock(s, fixtureStart)
	s.consume(strings.NewReader(`{"type":"sec","proc":"game.exe","frames":{"presented":30},` +
		`"ft":{"avg":33.3,"p50":33.2,"p95":40,"p99":45,"max":51,"sd":4},` +
		`"ft_hist":{"layout":"log24_v1","counts":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,30,0,0,0,0,0,0,0,0]}}`))
	_, buckets := s.Drain()
	if len(buckets) != 1 {
		t.Fatalf("Drain() returned %d buckets, want 1", len(buckets))
	}
	if !buckets[0].TS.Equal(fixtureStart) {
		t.Fatalf("TS = %v, want the agent clock (%v)", buckets[0].TS, fixtureStart)
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

	configure(s)
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

	configure(s)
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

	configure(s)
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

	configure(s)
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

	configure(s)
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
	if !PlatformSupported {
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
	if !PlatformSupported {
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
	if PlatformSupported {
		t.Skip("Windows ships a sensor")
	}
	if _, ok := Locate(true); ok {
		t.Fatal("Locate() found a sensor on a platform that has none")
	}
	if got := Probe(context.Background(), "sensor", true); got.OK {
		t.Fatalf("Probe() = %+v, want not OK", got)
	}
}

// configure gives the supervisor the first configuration, which is what releases
// it to spawn a sensor at all — the DesiredState push, in production. Tests
// about the restart policy rather than the gate use it to get past the gate.
func configure(s *Supervisor) {
	s.SetConfig(gs.Config{Mode: gs.ModeAll})
}

// Nothing is captured until the server has said what may be captured. A site
// that named its games and turned off "record everything else" would otherwise
// have every window on the machine recorded for the seconds — or, with the
// server unreachable, the hours — before the first push landed, and the WAL
// keeps whatever is recorded. This is the same posture as the probe side, where
// no target is persisted across restarts either.
func TestSupervisorCapturesNothingBeforeItIsConfigured(t *testing.T) {
	restoreSchedule(t, time.Millisecond, time.Millisecond, time.Hour)

	s := NewSupervisor("sensor", nil)
	var spawns atomic.Int32
	spawned := make(chan struct{}, 4)
	s.run = func(ctx context.Context) error {
		spawns.Add(1)
		spawned <- struct{}{}
		<-ctx.Done()
		return ctx.Err()
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); s.Run(ctx) }()
	defer func() {
		cancel()
		<-done
	}()

	select {
	case <-spawned:
		t.Fatal("the sensor was spawned before any configuration arrived")
	case <-time.After(300 * time.Millisecond):
	}

	s.SetConfig(gs.Config{
		Mode:     gs.ModeProfiles,
		Profiles: []gs.ConfigProfile{{ID: "p1", Exe: []string{"game.exe"}, Tier: gs.TierBase}},
	})
	select {
	case <-spawned:
	case <-time.After(2 * time.Second):
		t.Fatal("the sensor was not spawned once it was configured")
	}
	if got := s.currentConfig(); got.Mode != gs.ModeProfiles {
		t.Fatalf("spawned with %+v, want the configuration that released it", got)
	}
	if n := spawns.Load(); n != 1 {
		t.Fatalf("spawned %d times for one configuration, want 1", n)
	}
}

// An agent shut down before it was ever configured — a server that was
// unreachable for the whole session — must stop waiting and return, not leak the
// goroutine its caller is joining on.
func TestSupervisorStopsWhileWaitingForItsConfiguration(t *testing.T) {
	s := NewSupervisor("sensor", nil)
	s.run = func(context.Context) error {
		t.Error("the sensor was spawned by a supervisor that was never configured")
		return nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); s.Run(ctx) }()
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return while waiting for a configuration")
	}
}

// The configuration usually arrives before the supervisor is even started — the
// session applies a push as soon as it lands, and the sensor goroutine may not
// have been scheduled yet. It must run immediately rather than wait for a second
// push that may be an hour away.
func TestConfigurationBeforeRunIsPickedUpImmediately(t *testing.T) {
	restoreSchedule(t, time.Millisecond, time.Millisecond, time.Hour)

	s := NewSupervisor("sensor", nil)
	started := make(chan gs.Config, 4)
	s.run = func(ctx context.Context) error {
		started <- s.currentConfig()
		<-ctx.Done()
		return ctx.Err()
	}
	s.SetConfig(gs.Config{
		Mode:     gs.ModeProfiles,
		Profiles: []gs.ConfigProfile{{ID: "p1", Exe: []string{"game.exe"}, Tier: gs.TierDiag}},
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); s.Run(ctx) }()
	defer func() {
		cancel()
		<-done
	}()

	got := nextRun(t, started)
	if got.Mode != gs.ModeProfiles || len(got.Profiles) != 1 {
		t.Fatalf("first run started with %+v, want the configuration set before Run", got)
	}
}

// The sensor is configured once, at spawn, so the supervisor holds the
// configuration between runs.
func TestSupervisorStampsTheProtocolFieldsOnTheConfig(t *testing.T) {
	s := NewSupervisor("sensor", nil)

	// The protocol fields belong to this build, not to whoever assembled the
	// profiles, so they are stamped rather than trusted.
	s.SetConfig(gs.Config{Type: "nonsense", Proto: 99, Mode: gs.ModeProfiles})
	got := s.currentConfig()
	if got.Type != gs.TypeConfig || got.Proto != ProtoVersion {
		t.Fatalf("config = %+v, want the protocol fields restamped", got)
	}
	if got.Mode != gs.ModeProfiles {
		t.Fatalf("config = %+v, want the mode it was given", got)
	}

	// What a spawned sensor is actually handed: one JSON line, newline included.
	line, err := s.configLine()
	if err != nil {
		t.Fatalf("configLine() = %v", err)
	}
	if len(line) == 0 || line[len(line)-1] != '\n' {
		t.Fatalf("config line %q is not newline-terminated; the sensor reads one line", line)
	}
	var decoded gs.Config
	if err := json.Unmarshal(line, &decoded); err != nil {
		t.Fatalf("config line %q: %v", line, err)
	}
	if decoded.Type != gs.TypeConfig || decoded.Mode != gs.ModeProfiles {
		t.Fatalf("config line decoded to %+v", decoded)
	}
}

// Changing the configuration restarts the sensor, because that is the only way a
// sensor learns a new one. The restart is not a failure: it must not be counted
// toward the failure streak and must not wait out the backoff, or the agent would
// punish the sensor for doing what the agent asked and leave capture off for the
// backoff's length every time a profile is edited.
func TestConfigChangeRestartsTheSensorWithoutAFailurePenalty(t *testing.T) {
	// A backoff far longer than the test's patience, and a health window no run
	// reaches: if a configuration restart were treated like a crash, the
	// replacement would not start in time and the streak would be reported.
	restoreSchedule(t, 10*time.Second, 10*time.Second, time.Hour)

	var mu sync.Mutex
	var failures int
	s := NewSupervisor("sensor", func(ev telemetry.Event) {
		if ev.Type != telemetry.EventGameSensorFailed {
			return
		}
		mu.Lock()
		failures++
		mu.Unlock()
	})

	started := make(chan gs.Config, 16)
	s.run = func(ctx context.Context) error {
		started <- s.currentConfig()
		<-ctx.Done()
		return ctx.Err()
	}

	configure(s)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); s.Run(ctx) }()
	defer func() {
		cancel()
		<-done
	}()

	if got := nextRun(t, started); got.Mode != gs.ModeAll {
		t.Fatalf("first run started with %+v, want the default configuration", got)
	}

	// More restarts than the reporting threshold, so counting them as failures
	// could not stay invisible.
	for i := 0; i < failuresBeforeEvent+1; i++ {
		id := fmt.Sprintf("p%d", i)
		s.SetConfig(gs.Config{
			Mode:     gs.ModeProfiles,
			Profiles: []gs.ConfigProfile{{ID: id, Exe: []string{"game.exe"}, Tier: gs.TierBase}},
		})
		got := nextRun(t, started)
		if got.Type != gs.TypeConfig || got.Proto != ProtoVersion {
			t.Fatalf("restart %d ran with %+v, want the protocol fields stamped", i, got)
		}
		if len(got.Profiles) != 1 || got.Profiles[0].ID != id {
			t.Fatalf("restart %d ran with %+v, want the profile just installed", i, got)
		}
	}

	mu.Lock()
	defer mu.Unlock()
	if failures != 0 {
		t.Errorf("emitted %d failure events for %d configuration restarts, want none",
			failures, failuresBeforeEvent+1)
	}
}

// The server re-pushes the whole configuration on every reconnect and on every
// unrelated edit. Restarting for a configuration the sensor is already running
// would interrupt capture — and split nothing but the agent's own patience —
// for no change at all.
func TestAnUnchangedConfigurationDoesNotRestartTheSensor(t *testing.T) {
	restoreSchedule(t, time.Millisecond, time.Millisecond, time.Hour)

	s := NewSupervisor("sensor", nil)
	started := make(chan gs.Config, 8)
	s.run = func(ctx context.Context) error {
		started <- s.currentConfig()
		<-ctx.Done()
		return ctx.Err()
	}

	configure(s)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); s.Run(ctx) }()
	defer func() {
		cancel()
		<-done
	}()

	nextRun(t, started)
	cfg := gs.Config{
		Mode:     gs.ModeProfiles,
		Profiles: []gs.ConfigProfile{{ID: "p1", Exe: []string{"game.exe"}, Tier: gs.TierDiag}},
	}
	s.SetConfig(cfg)
	nextRun(t, started)

	// The same configuration again, twice, including the shape the caller passed
	// the first time.
	s.SetConfig(cfg)
	s.SetConfig(gs.Config{
		Type: gs.TypeConfig, Proto: ProtoVersion,
		Mode:     gs.ModeProfiles,
		Profiles: []gs.ConfigProfile{{ID: "p1", Exe: []string{"game.exe"}, Tier: gs.TierDiag}},
	})
	select {
	case got := <-started:
		t.Fatalf("the sensor restarted for an unchanged configuration: %+v", got)
	case <-time.After(200 * time.Millisecond):
	}
}

// nextRun waits for the supervisor to start a sensor and returns the
// configuration it started with. The wait is deliberately shorter than the
// backoff the callers set, so a restart that went through the failure path fails
// the test rather than merely being slow.
func nextRun(t *testing.T, started <-chan gs.Config) gs.Config {
	t.Helper()
	select {
	case cfg := <-started:
		return cfg
	case <-time.After(2 * time.Second):
		t.Fatal("the supervisor did not start a sensor")
		return gs.Config{}
	}
}

// Which game a run belongs to is the sensor's decision — it holds the profile
// list the run is being captured under — and the agent copies it rather than
// matching the process name again against a list it may hold a different
// generation of.
func TestRunCarriesTheProfileTheSensorMatched(t *testing.T) {
	s := NewSupervisor("sensor", nil)
	s.consume(strings.NewReader(strings.Join([]string{
		`{"type":"status","state":"tracking","pid":1,"proc":"cs2.exe","title":"CS2","profile_id":"prof-cs2"}`,
		secLine("2026-08-01T12:00:00Z", "cs2.exe", 1),
		// A process matching nothing is an "other process" run, which is a normal
		// record under the record-everything mode and simply carries no profile.
		`{"type":"status","state":"tracking","pid":2,"proc":"chrome.exe"}`,
		secLine("2026-08-01T12:00:01Z", "chrome.exe", 2),
	}, "\n")))

	runs, _ := s.Drain()
	if len(runs) != 2 {
		t.Fatalf("got %d runs, want one per process: %+v", len(runs), runs)
	}
	if runs[0].ProfileID != "prof-cs2" {
		t.Errorf("run = %+v, want the profile the sensor matched", runs[0])
	}
	if runs[1].ProfileID != "" {
		t.Errorf("run = %+v, want no profile for a process that matched none", runs[1])
	}
}

// A run's profile assignment never changes. It describes how the seconds already
// collected were captured, so moving it would file a whole session under a game
// it was not being recorded as; the session ends and a new one begins instead.
//
// The assignment can only change across a sensor restart — a running sensor's
// configuration is fixed — so these tests all go through the restart path:
// consume, endRun (park), then the next sensor's first status.
//
// restartWith replays that sequence and returns everything drained afterwards.
// The recorder's clock is anchored to the fixtures' own era and moved by the gap
// their second half is stamped at, so the restart is the ten-second interruption
// it is written as. Every case below turns on whether the run survives that
// interruption or is split by something else about the second sensor, and neither
// answer may depend on what today's date is.
func restartWith(t *testing.T, s *Supervisor, first, second string) ([]gs.Run, []gs.Bucket) {
	t.Helper()
	advance := fakeClock(s, fixtureStart)
	s.consume(strings.NewReader(first))
	s.endRun()
	advance(restartGap)
	s.consume(strings.NewReader(second))
	return s.Drain()
}

// profileOf indexes drained runs by id, keeping the newest copy of each — the
// drain stream is an upsert stream, so a run can appear more than once.
func runsByID(runs []gs.Run) map[string]gs.Run {
	byID := map[string]gs.Run{}
	for _, r := range runs {
		byID[r.ID] = r
	}
	return byID
}

// Reassigning an executable from one profile to another splits the session: the
// seconds recorded as the first game stay recorded as the first game.
func TestAReassignedProfileStartsANewRun(t *testing.T) {
	s := NewSupervisor("sensor", nil)
	runs, buckets := restartWith(t, s,
		strings.Join([]string{
			`{"type":"status","state":"tracking","pid":100,"proc":"game.exe","profile_id":"prof-a"}`,
			secLine("2026-08-02T01:00:00Z", "game.exe", 100),
		}, "\n"),
		strings.Join([]string{
			`{"type":"status","state":"tracking","pid":100,"proc":"game.exe","profile_id":"prof-b"}`,
			secLine("2026-08-02T01:00:10Z", "game.exe", 100),
		}, "\n"))

	byID := runsByID(runs)
	if len(byID) != 2 {
		t.Fatalf("recorded %d runs, want the session split at the reassignment: %+v", len(byID), runs)
	}
	var before, after gs.Run
	for _, r := range byID {
		switch r.ProfileID {
		case "prof-a":
			before = r
		case "prof-b":
			after = r
		default:
			t.Fatalf("run %+v carries neither profile", r)
		}
	}
	if before.EndedAt == nil {
		t.Errorf("run = %+v, want the first game's session ended at the reassignment", before)
	}
	if after.EndedAt != nil {
		t.Errorf("run = %+v, want the new session still open", after)
	}
	if len(buckets) != 2 || buckets[0].RunID != before.ID || buckets[1].RunID != after.ID {
		t.Fatalf("buckets = %+v, want each second on the run it was collected under", buckets)
	}
}

// Deleting the profile a running game matched leaves what was already recorded
// stamped with it, and records what follows as the unprofiled process it now is.
func TestLosingTheProfileStartsANewUnprofiledRun(t *testing.T) {
	s := NewSupervisor("sensor", nil)
	runs, _ := restartWith(t, s,
		strings.Join([]string{
			`{"type":"status","state":"tracking","pid":100,"proc":"game.exe","profile_id":"prof-a"}`,
			secLine("2026-08-02T01:00:00Z", "game.exe", 100),
		}, "\n"),
		strings.Join([]string{
			`{"type":"status","state":"tracking","pid":100,"proc":"game.exe"}`,
			secLine("2026-08-02T01:00:10Z", "game.exe", 100),
		}, "\n"))

	byID := runsByID(runs)
	if len(byID) != 2 {
		t.Fatalf("recorded %d runs, want the session split when the profile went away: %+v", len(byID), runs)
	}
	var stamped, plain int
	for _, r := range byID {
		if r.ProfileID == "prof-a" {
			stamped++
			if r.EndedAt == nil {
				t.Errorf("run = %+v, want the profiled session ended", r)
			}
		} else {
			plain++
		}
	}
	if stamped != 1 || plain != 1 {
		t.Fatalf("runs = %+v, want one still stamped and one unprofiled", runs)
	}
}

// The mirror: a process that was knowingly matching nothing, then matches a
// newly created profile. What was recorded as an ordinary process stays that way.
func TestGainingAProfileStartsANewRun(t *testing.T) {
	s := NewSupervisor("sensor", nil)
	runs, _ := restartWith(t, s,
		strings.Join([]string{
			`{"type":"status","state":"tracking","pid":100,"proc":"game.exe"}`,
			secLine("2026-08-02T01:00:00Z", "game.exe", 100),
		}, "\n"),
		strings.Join([]string{
			`{"type":"status","state":"tracking","pid":100,"proc":"game.exe","profile_id":"prof-a"}`,
			secLine("2026-08-02T01:00:10Z", "game.exe", 100),
		}, "\n"))

	byID := runsByID(runs)
	if len(byID) != 2 {
		t.Fatalf("recorded %d runs, want the session split when the profile appeared: %+v", len(byID), runs)
	}
	for _, r := range byID {
		if r.ProfileID == "prof-a" && r.EndedAt != nil {
			t.Errorf("run = %+v, want the newly profiled session open", r)
		}
		if r.ProfileID == "" && r.EndedAt == nil {
			t.Errorf("run = %+v, want the unprofiled session ended", r)
		}
	}
}

// A restart that does not change the assignment is the ordinary case — an
// unrelated profile was edited, or the sensor crashed — and must still resume the
// one session the player is having.
func TestAnUnchangedProfileResumesTheRun(t *testing.T) {
	s := NewSupervisor("sensor", nil)
	runs, buckets := restartWith(t, s,
		strings.Join([]string{
			`{"type":"status","state":"tracking","pid":100,"proc":"game.exe","profile_id":"prof-a"}`,
			secLine("2026-08-02T01:00:00Z", "game.exe", 100),
		}, "\n"),
		strings.Join([]string{
			`{"type":"status","state":"tracking","pid":100,"proc":"game.exe","profile_id":"prof-a"}`,
			secLine("2026-08-02T01:00:10Z", "game.exe", 100),
		}, "\n"))

	byID := runsByID(runs)
	if len(byID) != 1 {
		t.Fatalf("recorded %d runs, want the session resumed across the restart: %+v", len(byID), runs)
	}
	for _, r := range byID {
		if r.ProfileID != "prof-a" || r.EndedAt != nil {
			t.Fatalf("run = %+v, want it still open and still the same game", r)
		}
	}
	if len(buckets) != 2 || buckets[0].RunID != buckets[1].RunID {
		t.Fatalf("buckets = %+v, want both seconds on the one run", buckets)
	}
}

// A run opened by a sec line has no assignment yet — nothing has said what the
// process matched. The status that follows fills it in place: that is the first
// stamp, not a change, and splitting there would turn one session into two over
// its own first second.
func TestFirstStatusStampsARunOpenedByASecondLine(t *testing.T) {
	s := NewSupervisor("sensor", nil)
	s.consume(strings.NewReader(strings.Join([]string{
		secLine("2026-08-01T12:00:00Z", "game.exe", 1),
		`{"type":"status","state":"tracking","pid":1,"proc":"game.exe","title":"A Game","profile_id":"prof-a"}`,
		secLine("2026-08-01T12:00:01Z", "game.exe", 1),
	}, "\n")))

	runs, buckets := s.Drain()
	byID := runsByID(runs)
	if len(byID) != 1 {
		t.Fatalf("recorded %d runs, want the seconds and the status on one: %+v", len(byID), runs)
	}
	for _, r := range byID {
		if r.ProfileID != "prof-a" || r.Title != "A Game" {
			t.Fatalf("run = %+v, want the first status stamped onto it", r)
		}
	}
	if len(buckets) != 2 || buckets[0].RunID != buckets[1].RunID {
		t.Fatalf("buckets = %+v, want both seconds on the one run", buckets)
	}
}

// A sec line says nothing about the profile, so it can never split a run over
// one — neither while the run is current nor when it is what reopens a parked
// run whose game is already known.
func TestSecondsNeverSplitARunOverItsProfile(t *testing.T) {
	s := NewSupervisor("sensor", nil)
	runs, buckets := restartWith(t, s,
		strings.Join([]string{
			`{"type":"status","state":"tracking","pid":100,"proc":"game.exe","profile_id":"prof-a"}`,
			secLine("2026-08-02T01:00:00Z", "game.exe", 100),
			secLine("2026-08-02T01:00:01Z", "game.exe", 100),
		}, "\n"),
		// The replacement sensor's seconds arrive before its first status.
		secLine("2026-08-02T01:00:10Z", "game.exe", 100))

	byID := runsByID(runs)
	if len(byID) != 1 {
		t.Fatalf("recorded %d runs, want one: %+v", len(byID), runs)
	}
	for _, r := range byID {
		if r.ProfileID != "prof-a" {
			t.Fatalf("run = %+v, want its profile untouched by lines that never mention one", r)
		}
	}
	if len(buckets) != 3 {
		t.Fatalf("recorded %d seconds, want all three on the one run", len(buckets))
	}
}

// fullCapsHello is a sensor process that can measure everything. It is what
// makes the depth rules visible: with every capability declared, what a run
// carries is decided entirely by the tier its profile was configured with, which
// is the situation a mixed configuration puts a real sensor in.
const fullCapsHello = `{"type":"hello","proto":3,"sensor_version":"0.2.0",` +
	`"source":"presentmon_service","caps":["displayed","frame_type","present_meta",` +
	`"per_frame_complete","cpu_split","gpu_split","latency","gpu_tel","proc_vram","busiest_core"]}`

// tierConfig is a configuration naming game.exe at one tier.
func tierConfig(tier string) gs.Config {
	return gs.Config{
		Mode:     gs.ModeAll,
		Profiles: []gs.ConfigProfile{{ID: "prof-a", Exe: []string{"game.exe"}, Tier: tier}},
	}
}

// wantDepth checks that a run's capabilities describe exactly the depth it was
// captured at: the diag ones present only for a diag run, the base ones always.
func wantDepth(t *testing.T, run gs.Run, depth string) {
	t.Helper()
	hasCap := func(want string) bool {
		for _, c := range run.Caps {
			if c == want {
				return true
			}
		}
		return false
	}
	for _, c := range []string{
		gs.CapCPUSplit, gs.CapGPUSplit, gs.CapLatency,
		gs.CapGPUTel, gs.CapProcVRAM, gs.CapBusiestCore,
	} {
		if got, want := hasCap(c), depth == gs.TierDiag; got != want {
			t.Errorf("run %q caps = %v: %q present=%v, want %v for a %s-depth run",
				run.ProfileID, run.Caps, c, got, want, depth)
		}
	}
	// The base capabilities are what every run gets, whatever its depth — the
	// stripping is about the deeper measurements, not about the run.
	for _, c := range []string{gs.CapDisplayed, gs.CapFrameType, gs.CapPresentMeta, gs.CapPerFrameComplete} {
		if !hasCap(c) {
			t.Errorf("run %q caps = %v, want the base capability %q kept", run.ProfileID, run.Caps, c)
		}
	}
}

// One sensor process measures every game at once, each to the depth its own
// profile asked for. The hello therefore describes what the PROCESS can do, and
// copying it onto every run would tell the console that the site's browser was
// measured as deeply as the game it is diagnosing.
//
// The console draws its diagnostic charts from these capabilities, so a run that
// claims one it never fills renders as "measured, nothing was wrong" — the exact
// opposite of the truth, and worse than showing nothing.
func TestMixedTiersGiveEachRunItsOwnDepth(t *testing.T) {
	s := NewSupervisor("sensor", nil)
	s.SetConfig(gs.Config{Mode: gs.ModeAll, Profiles: []gs.ConfigProfile{
		{ID: "prof-diag", Exe: []string{"cs2.exe"}, Tier: gs.TierDiag},
		{ID: "prof-base", Exe: []string{"game.exe"}, Tier: gs.TierBase},
	}})
	s.consume(strings.NewReader(strings.Join([]string{
		fullCapsHello,
		`{"type":"status","state":"tracking","pid":1,"proc":"cs2.exe","profile_id":"prof-diag"}`,
		secLine("2026-08-01T12:00:00Z", "cs2.exe", 1),
		`{"type":"status","state":"tracking","pid":2,"proc":"game.exe","profile_id":"prof-base"}`,
		secLine("2026-08-01T12:00:01Z", "game.exe", 2),
		// Recorded under ModeAll without matching anything. Base, like every other
		// process the site never named.
		`{"type":"status","state":"tracking","pid":3,"proc":"chrome.exe"}`,
		secLine("2026-08-01T12:00:02Z", "chrome.exe", 3),
	}, "\n")))

	runs, _ := s.Drain()
	byProfile := map[string]gs.Run{}
	for _, r := range runs {
		byProfile[r.ProfileID] = r
	}
	if len(byProfile) != 3 {
		t.Fatalf("recorded %d runs, want one per process: %+v", len(byProfile), runs)
	}
	wantDepth(t, byProfile["prof-diag"], gs.TierDiag)
	wantDepth(t, byProfile["prof-base"], gs.TierBase)
	wantDepth(t, byProfile[""], gs.TierBase)
}

// A run opened by a sec line has no profile yet, so it starts at base depth —
// not because it was measured shallowly, but because nothing had said which game
// it was. The status that names the profile fills in the depth with it, in
// place: that is the first stamp rather than a change, and splitting a session
// over its own first second would be a worse answer than the moment of
// understatement it replaces.
func TestTheFirstStatusStampsTheDepthWithTheProfile(t *testing.T) {
	s := NewSupervisor("sensor", nil)
	s.SetConfig(tierConfig(gs.TierDiag))
	s.consume(strings.NewReader(strings.Join([]string{
		fullCapsHello,
		secLine("2026-08-01T12:00:00Z", "game.exe", 1),
		`{"type":"status","state":"tracking","pid":1,"proc":"game.exe","profile_id":"prof-a"}`,
		secLine("2026-08-01T12:00:01Z", "game.exe", 1),
	}, "\n")))

	runs, buckets := s.Drain()
	byID := runsByID(runs)
	if len(byID) != 1 {
		t.Fatalf("recorded %d runs, want the seconds and the status on one: %+v", len(byID), runs)
	}
	for _, r := range byID {
		if r.ProfileID != "prof-a" {
			t.Fatalf("run = %+v, want the profile the status named", r)
		}
		wantDepth(t, r, gs.TierDiag)
	}
	if len(buckets) != 2 || buckets[0].RunID != buckets[1].RunID {
		t.Fatalf("buckets = %+v, want both seconds on the one run", buckets)
	}
}

// Changing a game's tier changes what its seconds contain, so it splits the run
// exactly as reassigning its profile does. The seconds already collected keep
// describing the depth they were recorded at; stitching the two together would
// produce one run whose first half silently lacks the breakdowns its own
// capabilities promise.
//
// Like every configuration change, it can only reach the sensor through a
// restart, so the sequence is the restart path: consume, park, reconfigure,
// consume.
func TestATierEditSplitsTheRunAtTheDepthChange(t *testing.T) {
	tests := []struct {
		name          string
		before, after string
		wantRuns      int
	}{
		{"deepened", gs.TierBase, gs.TierDiag, 2},
		{"shallowed", gs.TierDiag, gs.TierBase, 2},
		// An unrelated edit re-pushes the same tier. The player is in the middle of
		// one session and must come back to it.
		{"unchanged", gs.TierDiag, gs.TierDiag, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewSupervisor("sensor", nil)
			// Same ten-second restart as restartWith models, so the only thing that
			// can split the run here is the tier.
			advance := fakeClock(s, fixtureStart)
			s.SetConfig(tierConfig(tt.before))
			s.consume(strings.NewReader(strings.Join([]string{
				fullCapsHello,
				`{"type":"status","state":"tracking","pid":100,"proc":"game.exe","profile_id":"prof-a"}`,
				secLine("2026-08-02T01:00:00Z", "game.exe", 100),
			}, "\n")))
			s.endRun()
			advance(restartGap)
			s.SetConfig(tierConfig(tt.after))
			s.consume(strings.NewReader(strings.Join([]string{
				fullCapsHello,
				`{"type":"status","state":"tracking","pid":100,"proc":"game.exe","profile_id":"prof-a"}`,
				secLine("2026-08-02T01:00:10Z", "game.exe", 100),
			}, "\n")))

			runs, buckets := s.Drain()
			byID := runsByID(runs)
			if len(byID) != tt.wantRuns {
				t.Fatalf("recorded %d runs, want %d: %+v", len(byID), tt.wantRuns, runs)
			}
			if tt.wantRuns == 1 {
				for _, r := range byID {
					if r.EndedAt != nil {
						t.Errorf("run = %+v, want the session resumed across the restart", r)
					}
					wantDepth(t, r, tt.after)
				}
				if len(buckets) != 2 || buckets[0].RunID != buckets[1].RunID {
					t.Fatalf("buckets = %+v, want both seconds on the one run", buckets)
				}
				return
			}

			var ended, open gs.Run
			for _, r := range byID {
				if r.EndedAt != nil {
					ended = r
				} else {
					open = r
				}
			}
			if ended.ID == "" || open.ID == "" {
				t.Fatalf("runs = %+v, want the old session ended and the new one open", runs)
			}
			// Each half keeps the depth it was recorded at. That is the whole point of
			// splitting: history describes what was actually measured then, not what
			// the site asked for afterwards.
			wantDepth(t, ended, tt.before)
			wantDepth(t, open, tt.after)
			if len(buckets) != 2 || buckets[0].RunID != ended.ID || buckets[1].RunID != open.ID {
				t.Fatalf("buckets = %+v, want each second on the run it was collected under", buckets)
			}
		})
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
