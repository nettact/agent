//go:build !lite

package scenetrigger

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/nettact/agent/internal/netguard"
	"github.com/nettact/agent/internal/tracetrigger"
	"github.com/nettact/agent/probepolicy"
	"github.com/nettact/protocol/permission"
	"github.com/nettact/protocol/telemetry"
)

// harness is a trigger wired to a recording sink. Collection itself runs for
// real — it is a handful of local reads with no permissions granted, so every
// group reports denied/unsupported and nothing touches the network.
type harness struct {
	trg *Trigger

	mu     sync.Mutex
	scenes []telemetry.SceneReport
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	h := &harness{}
	h.trg = New("test", Deps{
		Guard:     netguard.New(probepolicy.Default(), false),
		Effective: permission.NewSet(),
		Hostname:  "host-1",
	}, time.Second, func(s telemetry.SceneReport) {
		h.mu.Lock()
		h.scenes = append(h.scenes, s)
		h.mu.Unlock()
	})
	h.trg.Start(context.Background())
	return h
}

func (h *harness) collected() []telemetry.SceneReport {
	h.trg.wg.Wait()
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]telemetry.SceneReport(nil), h.scenes...)
}

func probeEdge(monitorID string, serial int) tracetrigger.FaultEdge {
	return tracetrigger.FaultEdge{
		MonitorID: monitorID, ConfigSerial: serial, Kind: "icmp", Target: "192.0.2.10",
		Streak: 3, FirstFailedAt: time.Now().Add(-30 * time.Second),
	}
}

// The report has to carry everything the server claims it by, because the server
// issued no request and holds nothing to match an unlabelled scene against.
func TestSceneCarriesItsTriggerIdentity(t *testing.T) {
	h := newHarness(t)
	h.trg.OnFaultEdge(probeEdge("mon_1", 41))

	got := h.collected()
	if len(got) != 1 {
		t.Fatalf("collected %d scenes, want 1", len(got))
	}
	if got[0].ReportID == "" {
		t.Error("scene has no report id; the server's idempotency key is (agent, report id)")
	}
	if got[0].CollectedAt.IsZero() {
		t.Error("scene has no collection time")
	}
	if len(got[0].Triggers) != 1 {
		t.Fatalf("triggers = %+v, want exactly the edge that caused it", got[0].Triggers)
	}
	trig := got[0].Triggers[0]
	if trig.Kind != telemetry.SceneTriggerProbeFault {
		t.Errorf("trigger kind = %q, want %q", trig.Kind, telemetry.SceneTriggerProbeFault)
	}
	if trig.MonitorID != "mon_1" || trig.ConfigSerial != 41 {
		t.Errorf("trigger identity = (%q, %d), want (mon_1, 41) — the server's claim key",
			trig.MonitorID, trig.ConfigSerial)
	}
	if trig.TriggerStreak != 3 || trig.FirstFailedAt.IsZero() {
		t.Errorf("trigger = %+v, want the streak and its beginning", trig)
	}
}

// A second edge inside the cooldown must not be dropped: a fault whose scene was
// silently skipped reads afterwards as a fault nobody collected evidence for. It
// is held and collected with the next one instead.
func TestCooldownDefersRatherThanDropping(t *testing.T) {
	h := newHarness(t)
	h.trg.OnFaultEdge(probeEdge("mon_1", 1))
	h.trg.wg.Wait()

	h.trg.OnFaultEdge(probeEdge("mon_2", 1))
	if got := h.collected(); len(got) != 1 {
		t.Fatalf("collected %d scenes, want 1 — the second edge is inside the cooldown", len(got))
	}

	h.trg.mu.Lock()
	held := len(h.trg.pending)
	armed := h.trg.timer != nil
	h.trg.mu.Unlock()
	if held != 1 || !armed {
		t.Fatalf("held = %d armed = %v, want the second edge held with a timer to collect it", held, armed)
	}

	// Fire what the timer would have.
	h.trg.drainPending()
	got := h.collected()
	if len(got) != 2 {
		t.Fatalf("collected %d scenes, want the deferred one to follow", len(got))
	}
	if len(got[1].Triggers) != 1 || got[1].Triggers[0].MonitorID != "mon_2" {
		t.Errorf("deferred scene triggers = %+v, want mon_2", got[1].Triggers)
	}
}

// Two monitors failing together describe one machine, so they share a scene —
// but both identities travel, because they are separate faults the server files
// under separate incidents.
func TestHeldEdgesMergeIntoOneScene(t *testing.T) {
	h := newHarness(t)
	h.trg.OnFaultEdge(probeEdge("mon_1", 1))
	h.trg.wg.Wait()

	h.trg.OnFaultEdge(probeEdge("mon_2", 1))
	h.trg.OnFaultEdge(probeEdge("mon_3", 1))
	h.trg.SessionLost("network", time.Now()) // unarmed: no session was ever up
	h.trg.drainPending()

	got := h.collected()
	if len(got) != 2 {
		t.Fatalf("collected %d scenes, want 2", len(got))
	}
	if len(got[1].Triggers) != 2 {
		t.Fatalf("second scene triggers = %+v, want both held monitors in one scene", got[1].Triggers)
	}
}

// The same monitor crossing again under the same generation is the same fault; a
// generation change is a different one and must stay separately claimable, or a
// scene collected after a target edit could be filed under the address the edit
// moved away from.
func TestMergeKeepsGenerationsApart(t *testing.T) {
	set := []telemetry.SceneTrigger{}
	add := func(monitor string, serial, streak int) {
		set = mergeTrigger(set, telemetry.SceneTrigger{
			Kind: telemetry.SceneTriggerProbeFault, MonitorID: monitor,
			ConfigSerial: serial, TriggerStreak: streak,
		})
	}
	add("mon_1", 41, 3)
	add("mon_1", 41, 7)
	add("mon_1", 42, 3)

	if len(set) != 2 {
		t.Fatalf("merged to %d triggers, want 2 (one per generation): %+v", len(set), set)
	}
	if set[0].TriggerStreak != 7 {
		t.Errorf("streak = %d, want the longer observed run 7", set[0].TriggerStreak)
	}
	if set[1].ConfigSerial != 42 {
		t.Errorf("second trigger serial = %d, want the new generation 42", set[1].ConfigSerial)
	}
}

// A flapping link produces disconnect edges faster than a scene is worth
// collecting, so they collapse — but the count travels, because one entry
// standing for six drops must not read as one clean drop.
func TestDisconnectEdgesCollapseButKeepTheirCount(t *testing.T) {
	set := []telemetry.SceneTrigger{}
	for i := 0; i < 4; i++ {
		set = mergeTrigger(set, telemetry.SceneTrigger{
			Kind: telemetry.SceneTriggerServerDisconnect, EdgeCount: 1, Reason: "network",
		})
	}
	if len(set) != 1 {
		t.Fatalf("merged to %d triggers, want 1", len(set))
	}
	if set[0].EdgeCount != 4 {
		t.Errorf("edge count = %d, want 4", set[0].EdgeCount)
	}
}

// The disconnect trigger is armed by an established session and spent by the
// first loss. Retries that never got a session collect nothing: the fiftieth
// failed dial against a server that is simply gone carries no fact the first did
// not, and each scene costs outbox space during an outage.
func TestDisconnectNeedsAnEstablishedSession(t *testing.T) {
	h := newHarness(t)
	h.trg.SessionLost("refused", time.Now())
	if got := h.collected(); len(got) != 0 {
		t.Fatalf("a dial that never connected collected %d scenes", len(got))
	}

	h.trg.SessionUp()
	h.trg.SessionLost("timeout", time.Now())
	got := h.collected()
	if len(got) != 1 {
		t.Fatalf("collected %d scenes after a real session dropped, want 1", len(got))
	}
	trig := got[0].Triggers[0]
	if trig.Kind != telemetry.SceneTriggerServerDisconnect || trig.Reason != "timeout" {
		t.Errorf("trigger = %+v, want a server_disconnect carrying its reason", trig)
	}
	if trig.DisconnectedAt.IsZero() {
		t.Error("disconnect trigger has no timestamp; it is the server's ordering gate")
	}

	// Still spent: a second loss without a new session must not collect again.
	h.trg.SessionLost("timeout", time.Now())
	if got := h.collected(); len(got) != 1 {
		t.Fatalf("collected %d scenes, want the edge to stay spent until a session is re-established", len(got))
	}
}

// A disconnect scene resolves no targets: the probes were healthy and only the
// uplink was not, so a target survey would answer a question nobody asked.
func TestDisconnectSceneSurveysNoTargets(t *testing.T) {
	h := newHarness(t)
	h.trg.SessionUp()
	h.trg.SessionLost("network", time.Now())

	got := h.collected()
	if len(got) != 1 {
		t.Fatalf("collected %d scenes, want 1", len(got))
	}
	if len(got[0].Targets) != 0 {
		t.Errorf("disconnect scene resolved %d targets", len(got[0].Targets))
	}
	for _, g := range got[0].Groups {
		if g.Group == telemetry.SnapshotGroupTargets {
			t.Errorf("disconnect scene reported a targets group: %+v", g)
		}
	}
}

// A session that ended terminally (superseded, revoked, schema mismatch) never
// reaches the retry hook, so nothing consumes the arm. The runtime spends it
// explicitly — otherwise the next enrollment's first failed dial would inherit
// it and file a disconnect scene for a session that never existed.
func TestDisarmSpendsTheEdgeWithoutCollecting(t *testing.T) {
	h := newHarness(t)
	h.trg.SessionUp()
	h.trg.Disarm()
	if got := h.collected(); len(got) != 0 {
		t.Fatalf("Disarm collected %d scenes", len(got))
	}

	// The stale arm must be gone: a later dial failure collects nothing.
	h.trg.SessionLost("refused", time.Now())
	if got := h.collected(); len(got) != 0 {
		t.Fatalf("a failed dial after a terminal close collected %d scenes", len(got))
	}

	// And a genuine session afterwards still works.
	h.trg.SessionUp()
	h.trg.SessionLost("timeout", time.Now())
	if got := h.collected(); len(got) != 1 {
		t.Fatalf("collected %d scenes for a real disconnect after re-enrollment, want 1", len(got))
	}
}

// Nothing is collected before Start or after Wait: both would append to an
// outbox outside the runtime's lifetime.
func TestNoCollectionOutsideTheRuntimeLifetime(t *testing.T) {
	var got int
	var mu sync.Mutex
	trg := New("test", Deps{Guard: netguard.New(probepolicy.Default(), false)}, time.Second,
		func(telemetry.SceneReport) { mu.Lock(); got++; mu.Unlock() })

	trg.OnFaultEdge(probeEdge("mon_1", 1))
	trg.wg.Wait()
	mu.Lock()
	before := got
	mu.Unlock()
	if before != 0 {
		t.Fatalf("collected %d scenes before Start", before)
	}

	trg.Start(context.Background())
	trg.Wait()
	trg.OnFaultEdge(probeEdge("mon_1", 1))
	trg.wg.Wait()
	mu.Lock()
	after := got
	mu.Unlock()
	if after != 0 {
		t.Fatalf("collected %d scenes after Wait", after)
	}
}
