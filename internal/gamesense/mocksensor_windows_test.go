//go:build windows

package gamesense

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"
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

func TestMain(m *testing.M) {
	if scenario := os.Getenv(mockEnv); scenario != "" {
		os.Exit(runMockSensor(scenario, os.Args[1:]))
	}
	os.Exit(m.Run())
}

// runMockSensor plays one scenario as if it were nettact-sensor.exe.
func runMockSensor(scenario string, args []string) int {
	probing := len(args) > 0 && args[0] == "--probe"

	switch scenario {
	case "ok":
		if probing {
			fmt.Println(`{"type":"probe","proto":1,"sensor_version":"0.1.0-mock","caps":{"presentmon":true,"etw_session":true},"reason":""}`)
			return 0
		}
		fmt.Println(`{"type":"hello","proto":1,"sensor_version":"0.1.0-mock","caps":{"presentmon":true,"etw_session":true}}`)
		fmt.Println(`{"type":"status","state":"tracking","pid":4242,"proc":"mock.exe"}`)
		for i := 0; i < 3; i++ {
			fmt.Printf(`{"type":"fps","ts":"2026-08-01T12:00:0%dZ","pid":4242,"proc":"mock.exe","fps":%d,"frames":%d,"ft_avg_ms":16.7,"ft_p95_ms":19.2,"presented":%d,"dropped":0}`+"\n",
				i, 60+i, 60+i, 60+i)
		}
		// Wait for the agent to close stdin — the documented stop signal.
		_, _ = os.Stdin.Read(make([]byte, 1))
		return 0

	case "blocked":
		if probing {
			fmt.Println(`{"type":"probe","proto":1,"sensor_version":"0.1.0-mock","caps":{"presentmon":true,"etw_session":false},"reason":"etw_access_denied"}`)
			return 0
		}
		fmt.Println(`{"type":"hello","proto":1,"caps":{"presentmon":true,"etw_session":false}}`)
		fmt.Println(`{"type":"status","state":"error","reason":"etw_access_denied"}`)
		return 4

	case "future":
		fmt.Println(`{"type":"probe","proto":99,"sensor_version":"9.9.9","caps":{"presentmon":true,"etw_session":true}}`)
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
		fmt.Println(`{"type":"hello","proto":1,"caps":{"presentmon":true,"etw_session":true}}`)
		fmt.Println(`{"type":"fps","ts":"2026-08-01T12:00:00Z","pid":1,"proc":"mock.exe","fps":42,"ft_avg_ms":23.8,"ft_p95_ms":25.0}`)
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
		{"blocked", false, ReasonETWAccessDenied},
		{"future", false, ReasonProtoMismatch},
		{"garbage", false, ReasonProbeFailed},
		{"crash", false, ReasonProbeFailed},
	}
	for _, tt := range tests {
		t.Run(tt.scenario, func(t *testing.T) {
			got := Probe(context.Background(), self(t, tt.scenario))
			if got.OK != tt.wantOK {
				t.Fatalf("Probe() = %+v, want OK=%v", got, tt.wantOK)
			}
			if got.Reason != tt.wantReason {
				t.Fatalf("reason = %q, want %q", got.Reason, tt.wantReason)
			}
		})
	}
}

// A sensor that never answers must not hold up agent startup.
func TestProbeGivesUpOnAHangingSensor(t *testing.T) {
	exe := self(t, "hang")
	restoreProbeTimeout(t, 300*time.Millisecond)

	start := time.Now()
	got := Probe(context.Background(), exe)
	if got.OK {
		t.Fatalf("Probe() = %+v, want not OK", got)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("Probe() took %v, want it to give up promptly", elapsed)
	}
}

func TestProbeReportsAMissingExecutable(t *testing.T) {
	got := Probe(context.Background(), `C:\nettact-does-not-exist\nettact-sensor.exe`)
	if got.OK || got.Reason != ReasonProbeFailed {
		t.Fatalf("Probe() = %+v, want a failed probe", got)
	}
}

// The full spawn path: the agent starts the sensor, reads its stream, and stops
// it by closing stdin.
func TestRunOnceCollectsFromMockSensor(t *testing.T) {
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
			t.Fatalf("sensor exited early (%v) with %d samples", err, len(s.peek()))
		case <-deadline:
			t.Fatalf("timed out with %d samples", len(s.peek()))
		case <-time.After(20 * time.Millisecond):
		}
	}

	cancel()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("runOnce did not return after cancellation")
	}

	got := s.Drain()
	if len(got) != 3 {
		t.Fatalf("collected %d samples, want 3", len(got))
	}
	if got[0].Proc != "mock.exe" || got[0].PID != 4242 || got[0].FPS != 60 {
		t.Fatalf("first sample = %+v", got[0])
	}
}

// A sensor that dies mid-stream keeps what it already produced: the samples are
// real seconds that happened, and discarding them would widen the chart gap for
// no reason.
func TestRunOnceKeepsSamplesFromACrashedSensor(t *testing.T) {
	s := NewSupervisor(self(t, "runcrash"), nil)

	err := s.runOnce(context.Background())
	if err == nil {
		t.Fatal("runOnce() = nil, want the non-zero exit reported")
	}
	got := s.Drain()
	if len(got) != 1 || got[0].FPS != 42 {
		t.Fatalf("collected %+v, want the one sample emitted before the crash", got)
	}
}

func restoreProbeTimeout(t *testing.T, d time.Duration) {
	t.Helper()
	old := probeTimeout
	probeTimeout = d
	t.Cleanup(func() { probeTimeout = old })
}
