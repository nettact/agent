//go:build windows

package gamesense

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	gs "github.com/nettact/protocol/gamesense"
)

// This file is the contract test for the spawn path. The sensor component is
// closed and never built here, so the test binary impersonates it: TestMain sees
// the scenario variable, plays that scenario on stdout, and exits. Every message
// below is exactly what the real component must emit, which makes this file the
// executable half of the protocol documentation.
//
// The mock inherits the scenario from the environment because Probe and the
// supervisor deliberately expose no hook for shaping the child — the agent must
// be able to run a sensor it did not configure.

const mockEnv = "NETTACT_GAMESENSE_MOCK"

// mockConfigEnv names a file the mock writes the config line it was given to, so
// a test can assert on what the agent actually sent rather than only on the fact
// that the sensor accepted something.
const mockConfigEnv = "NETTACT_GAMESENSE_MOCK_CONFIG"

func TestMain(m *testing.M) {
	if scenario := os.Getenv(mockEnv); scenario != "" {
		os.Exit(runMockSensor(scenario, os.Args[1:]))
	}
	os.Exit(m.Run())
}

// mockBadStartup is the exit code the mock uses when the agent failed its half of
// the startup contract — wrong argv, or a missing or malformed config line.
const mockBadStartup = 3

// acceptConfig plays the sensor's side of run startup: check the argv, then read
// the one config line the agent must write to stdin before anything is captured.
// It returns the reader so the caller can go on waiting for the EOF that means
// stop.
//
// This is the strict half of the contract on purpose. A sensor that started
// capturing without a config would be guessing at the tracking mode, which is
// the difference between recording the games a site asked for and recording
// every window on the machine.
func acceptConfig(args []string) (*bufio.Reader, bool) {
	want := []string{"--run", "--proto", strconv.Itoa(gs.ProtoVersion)}
	if len(args) != len(want) {
		fmt.Fprintf(os.Stderr, "mock sensor: argv %v, want %v\n", args, want)
		return nil, false
	}
	for i, a := range args {
		if a != want[i] {
			fmt.Fprintf(os.Stderr, "mock sensor: argv %v, want %v\n", args, want)
			return nil, false
		}
	}

	stdin := bufio.NewReader(os.Stdin)
	line, err := stdin.ReadBytes('\n')
	if err != nil {
		fmt.Fprintf(os.Stderr, "mock sensor: no config line: %v\n", err)
		return nil, false
	}
	var cfg gs.Config
	if err := json.Unmarshal(line, &cfg); err != nil {
		fmt.Fprintf(os.Stderr, "mock sensor: unparseable config line: %v\n", err)
		return nil, false
	}
	if cfg.Type != gs.TypeConfig || cfg.Proto != gs.ProtoVersion {
		fmt.Fprintf(os.Stderr, "mock sensor: config line is %q/proto %d, want %q/proto %d\n",
			cfg.Type, cfg.Proto, gs.TypeConfig, gs.ProtoVersion)
		return nil, false
	}
	if path := os.Getenv(mockConfigEnv); path != "" {
		if err := os.WriteFile(path, line, 0o600); err != nil {
			fmt.Fprintf(os.Stderr, "mock sensor: record config line: %v\n", err)
			return nil, false
		}
	}
	return stdin, true
}

// acceptProbe plays the sensor's side of the probe argv contract: `--probe`
// alone, or `--probe --gpu` when the agent is also allowed to ask whether
// adapter telemetry is registrable. It returns whether the GPU question was
// asked.
//
// Strict, like acceptConfig, and for the same kind of reason: answering the GPU
// question means registering a query against the adapter, so a sensor that
// accepted an unrecognised argv — or answered a question nobody asked — would
// let the agent reach a protected source without the grant that authorises it.
func acceptProbe(args []string) (gpu bool, ok bool) {
	switch {
	case len(args) == 1:
		return false, true
	case len(args) == 2 && args[1] == "--gpu":
		return true, true
	}
	fmt.Fprintf(os.Stderr, "mock sensor: probe argv %v, want [--probe] or [--probe --gpu]\n", args)
	return false, false
}

// runMockSensor plays one scenario as if it were nettact-sensor.exe.
func runMockSensor(scenario string, args []string) int {
	probing := len(args) > 0 && args[0] == "--probe"

	switch scenario {
	case "ok":
		if probing {
			// This machine presents frames and publishes no adapter telemetry, so
			// gpu_ok is absent however it is asked — the ordinary machine.
			if _, ok := acceptProbe(args); !ok {
				return mockBadStartup
			}
			fmt.Println(`{"type":"probe","proto":4,"sensor_version":"0.2.0-mock","ok":true,"pm_version":"2.3.0"}`)
			return 0
		}
		stdin, ok := acceptConfig(args)
		if !ok {
			return mockBadStartup
		}
		// The capabilities are stated, not promised: hello is written once the
		// frame source is open and its query registered, so by here the sensor
		// knows which optional fields its seconds will carry.
		fmt.Println(`{"type":"hello","proto":4,"sensor_version":"0.2.0-mock","source":"presentmon_service",` +
			`"pm_version":"2.3.0","caps":["displayed","frame_type","present_meta","per_frame_complete"]}`)
		fmt.Println(`{"type":"status","state":"tracking","pid":4242,"proc":"mock.exe","title":"Mock Game"}`)
		for i := 0; i < 3; i++ {
			// A complete second: counts by outcome, within-second frame-time
			// statistics, and the full 24-bin histogram those statistics cannot
			// replace when the seconds are later merged into a whole run.
			fmt.Printf(`{"type":"sec","ts":"2026-08-01T12:00:0%dZ","pid":4242,"proc":"mock.exe",`+
				`"frames":{"presented":%d,"displayed":%d,"dropped":1,"app":%d,"generated":0},`+
				`"ft":{"avg":16.667,"p50":16.6,"p95":19.2,"p99":22.1,"max":31.4,"sd":2.2},`+
				`"ft_hist":{"layout":"log24_v1","counts":[0,0,0,0,0,0,0,0,0,0,0,0,%d,2,0,0,0,0,0,0,0,0,0,0]},`+
				`"disp_ft":{"avg":16.9,"p95":20.1},`+
				`"present":{"mode":"hardware_independent_flip","sync":0,"tearing":false,"api":"dxgi"}}`+"\n",
				i, 60+i, 59+i, 60+i, 58+i)
		}
		// Wait for the agent to close stdin — the documented stop signal, which is
		// why the pipe the config arrived on is kept open and read to its end.
		_, _ = io.Copy(io.Discard, stdin)
		return 0

	// A machine whose driver does publish adapter telemetry — and which still
	// only says so when asked, because registering that query is the read itself.
	// It plays the probe alone: what the flag changes is the answer, not the
	// capture that follows.
	case "ok-gpu":
		if !probing {
			fmt.Fprintln(os.Stderr, "mock sensor: scenario ok-gpu plays the probe only")
			return mockBadStartup
		}
		gpu, ok := acceptProbe(args)
		if !ok {
			return mockBadStartup
		}
		fmt.Printf(`{"type":"probe","proto":4,"sensor_version":"0.2.0-mock","ok":true,`+
			`"gpu_ok":%v,"pm_version":"2.3.0"}`+"\n", gpu)
		return 0

	case "blocked":
		if probing {
			if _, ok := acceptProbe(args); !ok {
				return mockBadStartup
			}
			fmt.Println(`{"type":"probe","proto":4,"sensor_version":"0.2.0-mock","ok":false,` +
				`"reason":"service_unavailable"}`)
			return 0
		}
		if _, ok := acceptConfig(args); !ok {
			return mockBadStartup
		}
		// A hello with no source is a run that failed to start; the status that
		// follows carries the reason, and the sensor gives up.
		fmt.Println(`{"type":"hello","proto":4,"sensor_version":"0.2.0-mock"}`)
		fmt.Println(`{"type":"status","state":"error","reason":"service_unavailable"}`)
		return 4

	case "future":
		fmt.Println(`{"type":"probe","proto":99,"sensor_version":"9.9.9","ok":true}`)
		return 0

	case "garbage":
		fmt.Println("this is not the protocol")
		return 0

	case "crash":
		return 4

	case "hang":
		time.Sleep(30 * time.Second)
		return 0

	case "runcrash":
		if _, ok := acceptConfig(args); !ok {
			return mockBadStartup
		}
		fmt.Println(`{"type":"hello","proto":4,"sensor_version":"0.2.0-mock","source":"presentmon_service",` +
			`"caps":["displayed"]}`)
		fmt.Println(`{"type":"status","state":"tracking","pid":1,"proc":"mock.exe","title":"Mock Game"}`)
		fmt.Println(`{"type":"sec","ts":"2026-08-01T12:00:00Z","pid":1,"proc":"mock.exe",` +
			`"frames":{"presented":42,"displayed":42,"dropped":0},` +
			`"ft":{"avg":23.8,"p50":23.5,"p95":25.0,"p99":27.0,"max":30.0,"sd":1.5},` +
			`"ft_hist":{"layout":"log24_v1","counts":[0,0,0,0,0,0,0,0,0,0,0,0,0,42,0,0,0,0,0,0,0,0,0,0]}}`)
		return 4

	default:
		fmt.Fprintf(os.Stderr, "unknown mock scenario %q\n", scenario)
		return 2
	}
}

// self returns the path used to spawn the mock, and arms the scenario.
func self(t *testing.T, scenario string) string {
	t.Helper()
	t.Setenv(mockEnv, scenario)
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return exe
}

func TestProbeAgainstMockSensor(t *testing.T) {
	tests := []struct {
		scenario   string
		wantOK     bool
		wantReason string
	}{
		{"ok", true, ""},
		{"blocked", false, ReasonServiceUnavailable},
		{"future", false, ReasonProtoMismatch},
		{"garbage", false, ReasonProbeFailed},
		{"crash", false, ReasonProbeFailed},
	}
	for _, tt := range tests {
		t.Run(tt.scenario, func(t *testing.T) {
			got := Probe(context.Background(), self(t, tt.scenario), false)
			if got.OK != tt.wantOK {
				t.Fatalf("Probe() = %+v, want OK=%v", got, tt.wantOK)
			}
			if got.Reason != tt.wantReason {
				t.Fatalf("reason = %q, want %q", got.Reason, tt.wantReason)
			}
		})
	}
}

// The adapter question is asked only when the caller says it may be. Answering
// it means registering a query against the GPU, so the flag is the agent's
// grant reaching the one place that acts on it: without it the sensor never
// touches the source and reports nothing about it, and the mock rejects the
// argv outright if the agent invents a flag of its own.
//
// The two rows for the capable machine are the whole point: same sensor, same
// machine, different answer — so a missing GPUOK cannot be read as "this
// machine cannot", only as "nobody asked".
func TestProbeAsksAboutTheAdapterOnlyWhenAllowed(t *testing.T) {
	tests := []struct {
		name     string
		scenario string
		gpu      bool
		want     bool
	}{
		{"capable machine, allowed to ask", "ok-gpu", true, true},
		{"capable machine, not allowed to ask", "ok-gpu", false, false},
		{"machine with no adapter telemetry", "ok", true, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Probe(context.Background(), self(t, tt.scenario), tt.gpu)
			if !got.OK {
				t.Fatalf("Probe() = %+v, want a sensor that can capture", got)
			}
			if got.GPUOK != tt.want {
				t.Fatalf("Probe() = %+v, want GPUOK=%v", got, tt.want)
			}
		})
	}
}

// A sensor that never answers must not hold up agent startup.
func TestProbeGivesUpOnAHangingSensor(t *testing.T) {
	exe := self(t, "hang")
	restoreProbeTimeout(t, 300*time.Millisecond)

	start := time.Now()
	got := Probe(context.Background(), exe, false)
	if got.OK {
		t.Fatalf("Probe() = %+v, want not OK", got)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("Probe() took %v, want it to give up promptly", elapsed)
	}
}

func TestProbeReportsAMissingExecutable(t *testing.T) {
	got := Probe(context.Background(), `C:\nettact-does-not-exist\nettact-sensor.exe`, false)
	if got.OK || got.Reason != ReasonProbeFailed {
		t.Fatalf("Probe() = %+v, want a failed probe", got)
	}
}

// The full spawn path: the agent starts the sensor, reads its stream, and stops
// it by closing stdin.
func TestRunOnceRecordsFromMockSensor(t *testing.T) {
	s := NewSupervisor(self(t, "ok"), nil)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- s.runOnce(ctx) }()

	deadline := time.After(10 * time.Second)
	for {
		if len(s.peek()) >= 3 {
			break
		}
		select {
		case err := <-done:
			t.Fatalf("sensor exited early (%v) with %d buckets", err, len(s.peek()))
		case <-deadline:
			t.Fatalf("timed out with %d buckets", len(s.peek()))
		case <-time.After(20 * time.Millisecond):
		}
	}

	cancel()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("runOnce did not return after cancellation")
	}

	runs, buckets := s.drainRB()
	if len(runs) != 1 {
		t.Fatalf("recorded %d runs, want 1: %+v", len(runs), runs)
	}
	if runs[0].Proc != "mock.exe" || runs[0].Title != "Mock Game" {
		t.Fatalf("run = %+v", runs[0])
	}
	if runs[0].Source != "presentmon_service" || len(runs[0].Caps) != 4 {
		t.Fatalf("run = %+v, want the hello's source and capabilities", runs[0])
	}
	if len(buckets) != 3 {
		t.Fatalf("recorded %d buckets, want 3", len(buckets))
	}
	if buckets[0].RunID != runs[0].ID || buckets[0].Frames.Presented != 60 {
		t.Fatalf("first bucket = %+v", buckets[0])
	}
	if buckets[0].Hist.Layout != "log24_v1" || len(buckets[0].Hist.Counts) != 24 {
		t.Fatalf("first bucket histogram = %+v", buckets[0].Hist)
	}
}

// The spawn path's other half: the sensor is handed its configuration on stdin
// before it captures anything, and the pipe stays open afterwards so closing it
// is still what stops the run.
func TestRunOnceSendsTheConfigurationOnStdin(t *testing.T) {
	s := NewSupervisor(self(t, "ok"), nil)
	recorded := filepath.Join(t.TempDir(), "config.json")
	t.Setenv(mockConfigEnv, recorded)

	s.SetConfig(gs.Config{
		GPU:  true,
		Mode: gs.ModeProfiles,
		Profiles: []gs.ConfigProfile{
			{ID: "p1", Exe: []string{"mock.exe"}, TargetFPS: 144, Tier: gs.TierDiag},
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.runOnce(ctx) }()

	deadline := time.After(10 * time.Second)
	for len(s.peek()) < 1 {
		select {
		case err := <-done:
			t.Fatalf("sensor exited early: %v", err)
		case <-deadline:
			t.Fatal("timed out waiting for the sensor to produce a second")
		case <-time.After(20 * time.Millisecond):
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("runOnce did not return after cancellation")
	}

	line, err := os.ReadFile(recorded)
	if err != nil {
		t.Fatalf("the sensor recorded no config line: %v", err)
	}
	var got gs.Config
	if err := json.Unmarshal(line, &got); err != nil {
		t.Fatalf("config line %q: %v", line, err)
	}
	if got.Type != gs.TypeConfig || got.Proto != ProtoVersion {
		t.Errorf("config = %+v, want %q at proto %d", got, gs.TypeConfig, ProtoVersion)
	}
	if got.Mode != gs.ModeProfiles || !got.GPU {
		t.Errorf("config = %+v, want the mode and gpu flag it was given", got)
	}
	if len(got.Profiles) != 1 || got.Profiles[0].ID != "p1" ||
		len(got.Profiles[0].Exe) != 1 || got.Profiles[0].Exe[0] != "mock.exe" ||
		got.Profiles[0].TargetFPS != 144 || got.Profiles[0].Tier != gs.TierDiag {
		t.Errorf("profiles = %+v, want the one it was given intact", got.Profiles)
	}
}

// A sensor that dies mid-stream keeps what it already produced: the seconds are
// real and discarding them would widen the chart gap for no reason.
func TestRunOnceKeepsBucketsFromACrashedSensor(t *testing.T) {
	s := NewSupervisor(self(t, "runcrash"), nil)

	err := s.runOnce(context.Background())
	if err == nil {
		t.Fatal("runOnce() = nil, want the non-zero exit reported")
	}
	runs, buckets := s.drainRB()
	if len(runs) != 1 || len(buckets) != 1 {
		t.Fatalf("recorded %+v / %+v, want the one run and second emitted before the crash", runs, buckets)
	}
	if buckets[0].Frames.Presented != 42 {
		t.Fatalf("bucket = %+v", buckets[0])
	}
}

func restoreProbeTimeout(t *testing.T, d time.Duration) {
	t.Helper()
	old := probeTimeout
	probeTimeout = d
	t.Cleanup(func() { probeTimeout = old })
}
