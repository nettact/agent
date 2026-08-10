//go:build !lite

package wal

import (
	"testing"
	"time"

	"github.com/nettact/protocol/telemetry"
)

// An incident scene is in the outbox for a stronger version of the traceroute
// argument: one of the two things that triggers it IS this server's session
// dropping, so it is collected when there is provably no socket to answer on.
// Surviving a spill and a restart is the whole delivery mechanism.
func TestSceneReportSurvivesSpillAndRestart(t *testing.T) {
	s, dir := openTempFor(t, "alpha")
	cpu := 62.5
	scene := telemetry.SceneReport{
		ReportID:    "scene_1",
		CollectedAt: time.Unix(1700000000, 0).UTC(),
		Triggers: []telemetry.SceneTrigger{
			{
				Kind: telemetry.SceneTriggerProbeFault, MonitorID: "probe_mon1", ConfigSerial: 41,
				TriggerStreak: 3, FirstFailedAt: time.Unix(1699999970, 0).UTC(),
			},
			{
				Kind: telemetry.SceneTriggerServerDisconnect, Reason: "network", EdgeCount: 4,
				DisconnectedAt: time.Unix(1699999990, 0).UTC(),
			},
		},
		Groups: []telemetry.SnapshotGroupResult{
			{Group: telemetry.SnapshotGroupNetwork, Status: telemetry.ScopeCollected},
			{Group: telemetry.SnapshotGroupResources, Status: telemetry.ScopeDenied, Reason: "permission_denied"},
		},
		Network: &telemetry.SnapshotNetwork{
			Interfaces:   []telemetry.SnapshotInterface{{Name: "eth0", Addrs: []string{"10.0.0.2/24"}, Up: true}},
			DefaultRoute: &telemetry.SnapshotRoute{Gateway: "10.0.0.1", Interface: "eth0"},
			DNSServers:   []string{"1.1.1.1"},
		},
		Resources: &telemetry.SnapshotResources{CPUPercent: &cpu},
	}
	if _, err := s.Append(Records{SceneReports: []telemetry.SceneReport{scene}}, "alpha"); err != nil {
		t.Fatalf("append: %v", err)
	}
	if err := s.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	reopened, err := Open(dir, []string{"alpha"}, Options{})
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	t.Cleanup(func() { _ = reopened.Close() })

	b, ok, err := reopened.NextBatch("alpha", 100)
	if err != nil || !ok {
		t.Fatalf("NextBatch after restart: ok=%v err=%v", ok, err)
	}
	if len(b.SceneReports) != 1 {
		t.Fatalf("got %d scene reports after restart, want 1", len(b.SceneReports))
	}
	got := b.SceneReports[0]
	if got.ReportID != scene.ReportID {
		t.Fatalf("scene lost its report id across the spill: %+v", got)
	}
	// The triggers are what the server claims the scene by. A scene that survives
	// the outage but loses its identity is evidence nobody can file.
	if len(got.Triggers) != 2 {
		t.Fatalf("triggers = %+v, want both", got.Triggers)
	}
	if got.Triggers[0].MonitorID != "probe_mon1" || got.Triggers[0].ConfigSerial != 41 {
		t.Errorf("probe trigger lost its claim key: %+v", got.Triggers[0])
	}
	if got.Triggers[1].EdgeCount != 4 || got.Triggers[1].Reason != "network" {
		t.Errorf("disconnect trigger lost its count/reason: %+v", got.Triggers[1])
	}
	if got.Network == nil || got.Network.DefaultRoute == nil || got.Network.DefaultRoute.Gateway != "10.0.0.1" {
		t.Errorf("network payload did not round-trip: %+v", got.Network)
	}
	if got.Resources == nil || got.Resources.CPUPercent == nil || *got.Resources.CPUPercent != cpu {
		t.Errorf("resources payload did not round-trip: %+v", got.Resources)
	}
}

// A scene describes the machine as ONE server's pipeline saw it, gated by that
// server's grant. Serving it to another server would hand over evidence
// collected under permissions that server was never given.
func TestSceneReportIsServedOnlyToItsOwner(t *testing.T) {
	s, _ := openTempFor(t, "alpha", "beta")
	if _, err := s.Append(Records{SceneReports: []telemetry.SceneReport{{ReportID: "scene_alpha"}}}, "alpha"); err != nil {
		t.Fatalf("append: %v", err)
	}
	b, ok, err := s.NextBatch("beta", 100)
	if err != nil {
		t.Fatalf("NextBatch(beta): %v", err)
	}
	if ok && len(b.SceneReports) > 0 {
		t.Fatalf("beta was served alpha's scene: %+v", b.SceneReports)
	}
	b, ok, err = s.NextBatch("alpha", 100)
	if err != nil || !ok || len(b.SceneReports) != 1 {
		t.Fatalf("alpha did not get its own scene: ok=%v err=%v batch=%+v", ok, err, b)
	}
}
