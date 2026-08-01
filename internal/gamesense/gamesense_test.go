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

	"github.com/nettact/protocol/telemetry"
)

// The sensor is a separate, closed component that this repository never builds,
// so these tests stand in for it. TestMain turns the test binary itself into a
// mock sensor when the scenario variable is set (see mocksensor_test.go), which
// makes the spawn path testable without a second toolchain — and makes the
// protocol the tests encode the actual contract the component must meet.

func TestParseProbeLineAcceptsAWorkingSensor(t *testing.T) {
	got := parseProbeLine([]byte(`{"type":"probe","proto":1,"sensor_version":"0.1.0",` +
		`"caps":{"presentmon":true,"etw_session":true},"reason":""}`))
	if !got.OK {
		t.Fatalf("probe = %+v, want OK", got)
	}
	if got.SensorVersion != "0.1.0" || got.Proto != 1 {
		t.Fatalf("probe = %+v, want proto 1 version 0.1.0", got)
	}
}

// A sensor that answers but cannot open a trace session is the "blocked" state:
// not usable, but for a reason the operator can act on. The reason must survive.
func TestParseProbeLineKeepsBlockedReason(t *testing.T) {
	got := parseProbeLine([]byte(`{"type":"probe","proto":1,"sensor_version":"0.1.0",` +
		`"caps":{"presentmon":true,"etw_session":false},"reason":"etw_access_denied"}`))
	if got.OK {
		t.Fatalf("probe = %+v, want not OK", got)
	}
	if got.Reason != ReasonETWAccessDenied {
		t.Fatalf("reason = %q, want %q", got.Reason, ReasonETWAccessDenied)
	}
}

func TestParseProbeLineRejectsUnusableAnswers(t *testing.T) {
	tests := []struct {
		name, line, wantReason string
	}{
		{"garbage", `not json at all`, ReasonProbeFailed},
		{"wrong type", `{"type":"hello","proto":1}`, ReasonProbeFailed},
		{"empty", ``, ReasonProbeFailed},
		{"newer protocol", `{"type":"probe","proto":2,"caps":{"presentmon":true,"etw_session":true}}`, ReasonProtoMismatch},
		{"older protocol", `{"type":"probe","proto":0,"caps":{"presentmon":true,"etw_session":true}}`, ReasonProtoMismatch},
		// A capability is missing but the sensor did not say which. Still blocked,
		// and still given a code rather than an empty reason.
		{"unexplained", `{"type":"probe","proto":1,"caps":{"presentmon":false,"etw_session":true}}`, ReasonProbeFailed},
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

func TestConsumeBuffersSamplesAndSkipsNoise(t *testing.T) {
	s := NewSupervisor("sensor", nil)
	s.consume(strings.NewReader(strings.Join([]string{
		`{"type":"hello","proto":1,"caps":{"presentmon":true,"etw_session":true}}`,
		`{"type":"status","state":"tracking","pid":42,"proc":"game.exe"}`,
		`{"type":"fps","ts":"2026-08-01T12:00:00.500Z","pid":42,"proc":"game.exe","fps":59.5,"frames":60,"ft_avg_ms":16.7,"ft_p95_ms":19.2,"presented":60,"dropped":0}`,
		`{"type":"fps"`, // truncated line: skipped, must not end the stream
		`this is not json`,
		// A sample with no process has no series to belong to.
		`{"type":"fps","ts":"2026-08-01T12:00:01.500Z","fps":10}`,
		// A message type this build does not know is ignored, not fatal.
		`{"type":"gpu","proto":1,"temp_c":71}`,
		`{"type":"fps","ts":"2026-08-01T12:00:02.500Z","pid":42,"proc":"game.exe","fps":60.1,"ft_avg_ms":16.6,"ft_p95_ms":17.0}`,
		`{"type":"status","state":"idle"}`,
	}, "\n")))

	got := s.Drain()
	if len(got) != 2 {
		t.Fatalf("Drain() returned %d samples, want 2: %+v", len(got), got)
	}
	if got[0].Proc != "game.exe" || got[0].PID != 42 || got[0].FPS != 59.5 {
		t.Fatalf("first sample = %+v", got[0])
	}
	if want := time.Date(2026, 8, 1, 12, 0, 0, 500e6, time.UTC); !got[0].TS.Equal(want) {
		t.Fatalf("first sample TS = %v, want %v", got[0].TS, want)
	}
	if got[1].FPS != 60.1 {
		t.Fatalf("second sample = %+v", got[1])
	}
	if s.Drain() != nil {
		t.Fatal("Drain() must empty the buffer")
	}
}

// A line past the cap stops a Scanner for good. The cap exists to bound memory,
// but the reader behind it is a pipe the sensor keeps writing to — so the
// failure has to be reported rather than swallowed, or the run stalls with the
// sensor blocked on a full pipe and the supervisor none the wiser.
func TestConsumeReportsAnOversizedLine(t *testing.T) {
	s := NewSupervisor("sensor", nil)
	huge := `{"type":"fps","proc":"` + strings.Repeat("x", maxLineBytes) + `.exe"}`
	err := s.consume(strings.NewReader(strings.Join([]string{
		`{"type":"fps","ts":"2026-08-01T12:00:00Z","pid":1,"proc":"game.exe","fps":60}`,
		huge,
		`{"type":"fps","ts":"2026-08-01T12:00:01Z","pid":1,"proc":"game.exe","fps":60}`,
	}, "\n")))
	if err == nil {
		t.Fatal("consume() = nil for a line past the cap; the caller cannot know to restart")
	}
	// What arrived before the bad line is still real data that happened.
	if got := s.Drain(); len(got) != 1 {
		t.Fatalf("kept %d samples from before the oversized line, want 1", len(got))
	}
}

func TestConsumeReturnsNilAtACleanEnd(t *testing.T) {
	s := NewSupervisor("sensor", nil)
	if err := s.consume(strings.NewReader(`{"type":"status","state":"idle"}`)); err != nil {
		t.Fatalf("consume() = %v at a clean end, want nil", err)
	}
}

// A sample whose second the sensor did not stamp still needs a timestamp, or it
// would land at the zero time and sort before every real point in the series.
func TestConsumeStampsUndatedSamples(t *testing.T) {
	s := NewSupervisor("sensor", nil)
	before := time.Now().UTC().Add(-time.Second)
	s.consume(strings.NewReader(`{"type":"fps","proc":"game.exe","fps":30}`))
	got := s.Drain()
	if len(got) != 1 {
		t.Fatalf("Drain() returned %d samples, want 1", len(got))
	}
	if got[0].TS.Before(before) {
		t.Fatalf("TS = %v, want a recent time", got[0].TS)
	}
}

// The buffer exists so the sensor's per-second cadence and the collection tier
// need not agree. It must be bounded, and when it overflows it must keep the
// newest seconds — a live chart shows the recent past, not the distant one.
func TestBufferDropsOldestWhenFull(t *testing.T) {
	s := NewSupervisor("sensor", nil)
	for i := 0; i < maxBuffered+10; i++ {
		s.push(Sample{Proc: "game.exe", FPS: float64(i)})
	}
	got := s.Drain()
	if len(got) != maxBuffered {
		t.Fatalf("buffered %d samples, want the cap %d", len(got), maxBuffered)
	}
	if got[0].FPS != 10 {
		t.Fatalf("oldest retained sample = %v, want the 10 earliest dropped", got[0].FPS)
	}
	if got[len(got)-1].FPS != float64(maxBuffered+9) {
		t.Fatalf("newest retained sample = %v, want the last pushed", got[len(got)-1].FPS)
	}
	if s.DroppedCount() != 10 {
		t.Fatalf("DroppedCount() = %d, want 10", s.DroppedCount())
	}
}

func TestCollectorEmitsThreeSeriesPerSample(t *testing.T) {
	s := NewSupervisor("sensor", nil)
	ts := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	s.push(Sample{TS: ts, Proc: "game.exe", FPS: 59.5, FrameAvgMs: 16.7, FrameP95Ms: 19.2})

	res, err := NewCollector(s).Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if len(res.Metrics) != 3 {
		t.Fatalf("Collect() produced %d metrics, want 3", len(res.Metrics))
	}
	want := map[telemetry.MetricKind]struct {
		value float64
		unit  string
	}{
		telemetry.GameFPS:          {59.5, telemetry.UnitFPS},
		telemetry.GameFrameTimeAvg: {16.7, telemetry.UnitMs},
		telemetry.GameFrameTimeP95: {19.2, telemetry.UnitMs},
	}
	for _, m := range res.Metrics {
		w, ok := want[m.Kind]
		if !ok {
			t.Fatalf("unexpected metric kind %q", m.Kind)
		}
		if m.Value != w.value || m.Unit != w.unit {
			t.Errorf("%s = %v %s, want %v %s", m.Kind, m.Value, m.Unit, w.value, w.unit)
		}
		if m.Target != "game.exe" {
			t.Errorf("%s target = %q, want the process name", m.Kind, m.Target)
		}
		if m.Layer != telemetry.LayerLocal {
			t.Errorf("%s layer = %q, want %q", m.Kind, m.Layer, telemetry.LayerLocal)
		}
		// Game series are not owned by a probe monitor; a monitor id would bind
		// them to a monitor's lifecycle and status.
		if m.MonitorID != "" {
			t.Errorf("%s carries monitor id %q, want none", m.Kind, m.MonitorID)
		}
		if !m.TS.Equal(ts) {
			t.Errorf("%s TS = %v, want the sample's own second %v", m.Kind, m.TS, ts)
		}
		delete(want, m.Kind)
	}
}

// Each sample keeps its own second, so a collection tier coarser than the
// sensor's cadence does not collapse ten seconds of data onto one timestamp.
func TestCollectorPreservesPerSecondTimestamps(t *testing.T) {
	s := NewSupervisor("sensor", nil)
	base := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	for i := 0; i < 10; i++ {
		s.push(Sample{TS: base.Add(time.Duration(i) * time.Second), Proc: "game.exe", FPS: 60})
	}
	res, _ := NewCollector(s).Collect(context.Background())
	seen := map[time.Time]bool{}
	for _, m := range res.Metrics {
		if m.Kind == telemetry.GameFPS {
			seen[m.TS] = true
		}
	}
	if len(seen) != 10 {
		t.Fatalf("got %d distinct FPS timestamps, want 10", len(seen))
	}
}

// An idle machine is not a machine rendering zero frames. The collector must
// leave a gap in the series rather than publish a value that claims otherwise.
func TestCollectorEmitsNothingWhenIdle(t *testing.T) {
	res, err := NewCollector(NewSupervisor("sensor", nil)).Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if len(res.Metrics) != 0 || len(res.Events) != 0 {
		t.Fatalf("Collect() = %+v, want an empty result", res)
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

// A sensor that loses its trace session says so before exiting. That code is the
// only actionable part of the failure, so it must reach the event rather than
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
			`{"type":"status","state":"error","reason":"etw_session_lost"}`))
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
		if ev.Attrs["reason"] != "etw_session_lost" {
			t.Errorf("reason = %q, want the sensor's own %q", ev.Attrs["reason"], "etw_session_lost")
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
// attribute an old trace-session loss to a sensor that is now failing to start
// for an entirely different cause.
func TestReasonDoesNotCarryAcrossRuns(t *testing.T) {
	s := NewSupervisor("sensor", nil)
	s.consume(strings.NewReader(`{"type":"status","state":"error","reason":"etw_session_lost"}`))
	if got := s.takeReason(); got != "etw_session_lost" {
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
	// The workspace shape: the module being run is a sibling of sensor-win.
	cwd := filepath.Join(root, "desktop")
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
