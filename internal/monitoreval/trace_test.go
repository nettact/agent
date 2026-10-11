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

// A route monitor needs probe.traceroute and nothing else: without it the
// monitor is permission_blocked naming that permission, never scheduled.
func TestTraceMonitorRequiresTraceroutePermission(t *testing.T) {
	all := permission.All()
	without := permission.Set{}
	for id := range all {
		if id != permission.ProbeTraceroute {
			without.Add(id)
		}
	}
	tracker := New(without, without, all, netguard.New(probepolicy.Policy{}, true), nil, "p", 0, time.Second)
	runnable, frame := tracker.ApplyDesired(1, []config.ProbeTarget{
		{MonitorID: "m1", Kind: "trace", Target: "192.0.2.1"},
	})
	if len(runnable) != 0 {
		t.Fatalf("runnable = %+v, want none without probe.traceroute", runnable)
	}
	got := frame.Statuses[0]
	if got.Status != wire.MonitorStatusPermissionBlocked ||
		len(got.MissingPermissions) != 1 || got.MissingPermissions[0] != string(permission.ProbeTraceroute) {
		t.Fatalf("status = %+v, want permission_blocked on %s", got, permission.ProbeTraceroute)
	}

	// Granted but not supported (no traceroute mode on this machine) is
	// unsupported, the same split every other probe kind gets.
	tracker = New(without, all, without, netguard.New(probepolicy.Policy{}, true), nil, "p", 0, time.Second)
	_, frame = tracker.ApplyDesired(1, []config.ProbeTarget{{MonitorID: "m1", Kind: "trace", Target: "192.0.2.1"}})
	if s := frame.Statuses[0].Status; s != wire.MonitorStatusUnsupported {
		t.Fatalf("granted-but-unsupported status = %q, want unsupported", s)
	}

	tracker = newTracker(t, nil, probepolicy.Policy{}, true)
	runnable, frame = tracker.ApplyDesired(1, []config.ProbeTarget{{MonitorID: "m1", Kind: "trace", Target: "192.0.2.1"}})
	if len(runnable) != 1 || frame.Statuses[0].Status != wire.MonitorStatusActive {
		t.Fatalf("with the permission: runnable = %d status = %q, want active", len(runnable), frame.Statuses[0].Status)
	}
}

// A pinned route monitor is un-runnable whatever the proxy — present,
// absent, or of a transport that could carry other kinds — and is never
// downgraded to a host-stack sweep.
func TestPinnedTraceMonitorIsUnsupported(t *testing.T) {
	proxies := fakeProxySet{
		"prx_socks": {ID: "prx_socks", Type: config.ProxyTypeSOCKS5},
	}
	for _, pid := range []string{"prx_socks", "prx_gone"} {
		tracker := newTracker(t, proxies, probepolicy.Policy{}, true)
		runnable, frame := tracker.ApplyDesired(1, []config.ProbeTarget{
			{MonitorID: "m1", Kind: "trace", Target: "192.0.2.1", ProxyID: pid},
		})
		if len(runnable) != 0 {
			t.Fatalf("%s: a pinned trace monitor was scheduled", pid)
		}
		got := frame.Statuses[0]
		if got.Status != wire.MonitorStatusUnsupported || got.Reason != ReasonProxyUnsupported {
			t.Fatalf("%s: status = %q reason = %q, want unsupported/%s", pid, got.Status, got.Reason, ReasonProxyUnsupported)
		}
	}
}

// The target-access policy applies statically to a route monitor's
// destination, like any other directly dialed kind.
func TestTraceMonitorDestinationIsPolicyChecked(t *testing.T) {
	tracker := newTracker(t, nil, probepolicy.Default(), false)
	_, frame := tracker.ApplyDesired(1, []config.ProbeTarget{{MonitorID: "m1", Kind: "trace", Target: "127.0.0.1"}})
	if s := frame.Statuses[0].Status; s != wire.MonitorStatusTargetBlocked {
		t.Fatalf("loopback trace status = %q, want target_blocked", s)
	}
}

// The reported cadence honours the route-monitor floor even when the push
// asks for less.
func TestTraceMonitorScheduleStampIsFloored(t *testing.T) {
	tracker := newTracker(t, nil, probepolicy.Policy{}, true)
	_, frame := tracker.ApplyDesired(1, []config.ProbeTarget{
		{MonitorID: "m1", Kind: "trace", Target: "192.0.2.1", Params: config.ProbeParams{IntervalSeconds: 60}},
		{MonitorID: "m2", Kind: "trace", Target: "192.0.2.1"},
	})
	if got := frame.Statuses[0].EffectiveIntervalSeconds; got != int(config.MinTraceInterval/time.Second) {
		t.Fatalf("floored interval = %ds, want %v", got, config.MinTraceInterval)
	}
	if got := frame.Statuses[1].EffectiveIntervalSeconds; got != int(config.DefaultTraceInterval/time.Second) {
		t.Fatalf("default interval = %ds, want %v", got, config.DefaultTraceInterval)
	}
	if got := frame.Statuses[1].CycleDeadlineMs; got != int(config.DefaultTraceCycleDeadline/time.Millisecond) {
		t.Fatalf("cycle deadline = %dms, want %v", got, config.DefaultTraceCycleDeadline)
	}
}
