//go:build windows

package gamesense

import (
	"context"
	"os"
	"testing"
)

// The mock in mocksensor_windows_test.go encodes what the contract says. This
// test checks the other thing that matters: that a real build of the component
// actually emits it. The two can drift — the mock is written from the same
// document as the agent, so a shared misreading would pass both — and the only
// way to catch that is to run the real executable.
//
// It is opt-in because the component is closed and this repository never builds
// it. Point NETTACT_SENSOR_PATH at a published nettact-sensor.exe to run it:
//
//	$env:NETTACT_SENSOR_PATH = "...\desktop\dist\nettact-sensor.exe"
//	go test ./internal/gamesense/ -run TestRealSensor -v
func TestRealSensorSpeaksTheContract(t *testing.T) {
	path := os.Getenv(PathEnv)
	if path == "" {
		t.Skipf("set %s to a published sensor to run this", PathEnv)
	}
	if !fileExists(path) {
		t.Fatalf("%s=%q does not exist", PathEnv, path)
	}

	// Asked the full question, since this is the contract test: a real build has
	// to accept `--probe --gpu` and answer both halves.
	got := Probe(context.Background(), path, true)

	// Whatever this machine can or cannot do, the answer must be one the agent
	// understands: a parseable line at the protocol version it speaks.
	if got.Proto != ProtoVersion {
		t.Fatalf("probe = %+v; want proto %d — the agent would reject this sensor", got, ProtoVersion)
	}
	if got.SensorVersion == "" {
		t.Error("probe carries no sensor version")
	}
	// The three states are distinguishable, and a negative one always says why.
	// An empty reason on a not-OK probe is the failure mode this whole design
	// exists to avoid: unusable, with nothing to act on.
	if !got.OK && got.Reason == "" {
		t.Errorf("probe = %+v; a sensor that cannot collect must say why", got)
	}
	if got.OK && got.Reason != "" {
		t.Errorf("probe = %+v; a working sensor must not carry a failure reason", got)
	}
	// The other half of the argv contract: `--probe` alone must not register the
	// adapter query, so it can never come back with a GPU answer. A real sensor
	// that answers anyway would be reading a protected source for an agent that
	// was never granted it — invisible from the outside, which is why it is
	// checked against the real build rather than only against the mock.
	if plain := Probe(context.Background(), path, false); plain.GPUOK {
		t.Errorf("probe without --gpu = %+v; the adapter was queried without being asked", plain)
	}
	t.Logf("real sensor %s: ok=%v gpu_ok=%v pm_version=%q reason=%q",
		got.SensorVersion, got.OK, got.GPUOK, got.PMVersion, got.Reason)
}
