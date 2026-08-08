package collector

import (
	"context"
	"errors"
	"testing"

	"github.com/nettact/protocol/telemetry"
)

// countKind returns how many samples of a kind a result carries, and the value
// of the first one.
func countKind(res Result, kind telemetry.MetricKind) (int, telemetry.Metric) {
	var n int
	var first telemetry.Metric
	for _, m := range res.Metrics {
		if m.Kind == kind {
			if n == 0 {
				first = m
			}
			n++
		}
	}
	return n, first
}

// TestHostCoresFollowsCPUOrLoadGrant pins the one place where a host metric is
// NOT gated on a single permission: the core count is the denominator that makes
// a load average readable, so a load-only agent must still send it. The test also
// pins the converse — with neither family granted, nothing is read and nothing is
// sent, so an agent denied both never discloses its hardware shape.
func TestHostCoresFollowsCPUOrLoadGrant(t *testing.T) {
	cases := []struct {
		name       string
		cpuOn      bool
		loadOn     bool
		wantSample bool
	}{
		{"cpu only", true, false, true},
		{"load only", false, true, true},
		{"both", true, true, true},
		{"neither", false, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := NewHostMetricsCollector(tc.cpuOn, false, false, tc.loadOn, false, false, false)
			if c.coresOn != tc.wantSample {
				t.Fatalf("coresOn = %v, want %v", c.coresOn, tc.wantSample)
			}

			res, err := c.Collect(context.Background())
			if err != nil {
				t.Fatalf("Collect: %v", err)
			}
			n, m := countKind(res, telemetry.HostCPUCores)
			if !tc.wantSample {
				if n != 0 {
					t.Fatalf("host.cpu.cores emitted %d times without a grant", n)
				}
				return
			}
			if n != 1 {
				t.Fatalf("host.cpu.cores emitted %d times, want exactly 1", n)
			}
			if m.Target != "host" {
				t.Errorf("target = %q, want %q", m.Target, "host")
			}
			if m.Unit != telemetry.UnitCount {
				t.Errorf("unit = %q, want %q", m.Unit, telemetry.UnitCount)
			}
			if m.Layer != telemetry.LayerLocal {
				t.Errorf("layer = %q, want %q", m.Layer, telemetry.LayerLocal)
			}
			if m.Value < 1 || m.Value != float64(int(m.Value)) {
				t.Errorf("value = %v, want a positive whole core count", m.Value)
			}
			if m.MonitorID != "" {
				t.Errorf("MonitorID = %q, want empty: host metrics belong to no monitor", m.MonitorID)
			}
		})
	}
}

// TestHostCoresFollowsATopologyChange is the reason the count is read per cycle
// rather than cached at startup: a resized VM (or a laptop parking cores) changes
// it while the agent runs, and the server divides every later load average by it.
// The count source is stubbed because that change cannot be staged on the real
// host — and against an unchanged machine the assertion could not tell a fresh
// read from a cached one anyway.
func TestHostCoresFollowsATopologyChange(t *testing.T) {
	counts := []int{4, 16}
	var calls int
	orig := logicalCores
	logicalCores = func() (int, error) {
		n := counts[min(calls, len(counts)-1)]
		calls++
		return n, nil
	}
	t.Cleanup(func() { logicalCores = orig })

	c := NewHostMetricsCollector(true, false, false, false, false, false, false)
	for i, want := range counts {
		res, err := c.Collect(context.Background())
		if err != nil {
			t.Fatalf("Collect %d: %v", i, err)
		}
		n, m := countKind(res, telemetry.HostCPUCores)
		if n != 1 {
			t.Fatalf("Collect %d reported the count %d times, want 1", i, n)
		}
		if m.Value != float64(want) {
			t.Errorf("Collect %d reported %v cores, want %d — the count was cached", i, m.Value, want)
		}
	}
	if calls < len(counts) {
		t.Errorf("the count source was consulted %d times for %d collects", calls, len(counts))
	}
}

// A count the source cannot supply is not invented: nothing is reported, and the
// server declines to judge load rather than dividing by a guess.
func TestHostCoresAbsentWhenUnreadable(t *testing.T) {
	orig := logicalCores
	logicalCores = func() (int, error) { return 0, errors.New("no") }
	t.Cleanup(func() { logicalCores = orig })

	c := NewHostMetricsCollector(true, false, false, true, false, false, false)
	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if n, _ := countKind(res, telemetry.HostCPUCores); n != 0 {
		t.Errorf("reported a core count %d times despite an unreadable source", n)
	}
}
