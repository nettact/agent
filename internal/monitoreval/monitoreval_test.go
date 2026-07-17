package monitoreval

import (
	"testing"
	"time"

	"github.com/nettact/agent/internal/netguard"
	"github.com/nettact/agent/probepolicy"
	"github.com/nettact/protocol/config"
	"github.com/nettact/protocol/permission"
	"github.com/nettact/protocol/wire"
)

func TestRuntimeTransitionsRequireCurrentTargetGeneration(t *testing.T) {
	tracker := New(permission.All(), permission.All(), permission.All(),
		netguard.New(probepolicy.Policy{}, true), "policy", 45*time.Second)
	target := config.ProbeTarget{
		MonitorID: "monitor-a", Kind: "http", Target: "https://example.test",
		Params: config.ProbeParams{IntervalSeconds: 10, TimeoutMs: 2_000}, ConfigSerial: 7,
	}
	_, frame := tracker.ApplyDesired(3, []config.ProbeTarget{target})
	entry := frame.Statuses[0]
	if entry.TargetConfigSerial != 7 || entry.EffectiveIntervalSeconds != 45 || entry.CycleDeadlineMs != 2_000 {
		t.Fatalf("schedule/generation = %+v", entry)
	}

	tracker.RuntimeBlocked("monitor-a", 6, "scope:private", "resolved_denied")
	assertNoUpdate(t, tracker)
	tracker.RuntimeBlocked("monitor-a", 7, "scope:private", "resolved_denied")
	blocked := receiveUpdate(t, tracker)
	if got := blocked.Statuses[0]; got.Status != wire.MonitorStatusTargetBlocked || got.TargetConfigSerial != 7 {
		t.Fatalf("current block = %+v", got)
	}

	target.ConfigSerial = 8
	_, frame = tracker.ApplyDesired(4, []config.ProbeTarget{target})
	if frame.Statuses[0].Status != wire.MonitorStatusActive {
		t.Fatalf("new generation inherited runtime block: %+v", frame.Statuses[0])
	}
	tracker.RuntimeBlocked("monitor-a", 7, "scope:private", "resolved_denied")
	assertNoUpdate(t, tracker)
	tracker.RuntimeBlocked("monitor-a", 8, "scope:private", "resolved_denied")
	_ = receiveUpdate(t, tracker)
	tracker.RuntimeOK("monitor-a", 7)
	assertNoUpdate(t, tracker)
	tracker.RuntimeOK("monitor-a", 8)
	recovered := receiveUpdate(t, tracker)
	if got := recovered.Statuses[0]; got.Status != wire.MonitorStatusActive || got.TargetConfigSerial != 8 {
		t.Fatalf("current recovery = %+v", got)
	}
}

func assertNoUpdate(t *testing.T, tracker *Tracker) {
	t.Helper()
	select {
	case got := <-tracker.Updates():
		t.Fatalf("unexpected update: %+v", got)
	default:
	}
}

func receiveUpdate(t *testing.T, tracker *Tracker) wire.MonitorStatus {
	t.Helper()
	select {
	case got := <-tracker.Updates():
		return got
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for monitor update")
		return wire.MonitorStatus{}
	}
}
