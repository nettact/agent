package conn

import (
	"context"
	"sync"
	"testing"

	pcfg "github.com/nettact/protocol/config"
	"github.com/nettact/protocol/wire"
)

// The game configuration travels on the same DesiredState frame as the probe
// targets but on its own version axis, because the server bumps the two
// separately: editing a game profile leaves ConfigVersion alone, and editing a
// monitor leaves the game Version alone. A push is therefore routinely stale on
// one axis and fresh on the other, and each half has to be judged on its own —
// which is what these tests pin down.

// fakeGameApplier records every configuration the session handed it.
type fakeGameApplier struct {
	mu      sync.Mutex
	applied []pcfg.GameConfig
}

func (f *fakeGameApplier) ApplyGameConfig(cfg pcfg.GameConfig) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.applied = append(f.applied, cfg)
}

func (f *fakeGameApplier) calls() []pcfg.GameConfig {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]pcfg.GameConfig(nil), f.applied...)
}

// silentConn is a wire.Conn that is never expected to be used: these tests wire
// no tracker, so a DesiredState push produces no MonitorStatus frame.
type silentConn struct{ t *testing.T }

func (c *silentConn) ReadFrame(context.Context) (wire.Frame, error) {
	c.t.Fatal("the session read a frame while applying a push")
	return wire.Frame{}, nil
}

func (c *silentConn) WriteFrame(context.Context, wire.Frame) error {
	c.t.Fatal("the session wrote a frame while applying a push")
	return nil
}

func (*silentConn) Ping(context.Context) error         { return nil }
func (*silentConn) Close(wire.CloseCode, string) error { return nil }

// newGameRunner returns a runner wired with both axes' fakes, in the state a
// freshly connected session starts in.
func newGameRunner() (*runner, *fakeConfigurable, *fakeGameApplier) {
	configurable := &fakeConfigurable{}
	applier := &fakeGameApplier{}
	return &runner{
		deps: Deps{
			Configurables: []Configurable{configurable},
			Scheduler:     &fakeScheduler{},
			Game:          applier,
		},
		appliedConfigVersion: -1,
		appliedGameVersion:   -1,
	}, configurable, applier
}

func gamePush(configVersion int, game *pcfg.GameConfig, target string) wire.Frame {
	return wire.Frame{DesiredState: &pcfg.DesiredState{
		ConfigVersion: configVersion,
		ProbeTargets:  []pcfg.ProbeTarget{{Kind: "icmp", Target: target}},
		Intervals:     pcfg.Intervals{BaseSeconds: 5, RegularSeconds: 60},
		Game:          game,
	}}
}

func applyOrFail(t *testing.T, r *runner, f wire.Frame) {
	t.Helper()
	if err := r.applyPush(context.Background(), context.Background(), &silentConn{t}, f); err != nil {
		t.Fatalf("applyPush: %v", err)
	}
}

// A frame the probe axis has already moved past can still carry a game block
// nobody has seen. Skipping the whole push — which is what the single guard used
// to do — would strand the sensor on an old profile list until an unrelated
// monitor edit happened to bump ConfigVersion.
func TestStaleProbeVersionStillAppliesAFresherGameConfig(t *testing.T) {
	r, configurable, applier := newGameRunner()

	applyOrFail(t, r, gamePush(7, &pcfg.GameConfig{Version: 1}, "7.7.7.7"))
	applyOrFail(t, r, gamePush(5, &pcfg.GameConfig{
		Version:  2,
		Profiles: []pcfg.GameProfile{{ID: "p1", Name: "CS2", Exe: []string{"cs2.exe"}, Tier: "diag"}},
	}, "5.5.5.5"))

	if n := configurable.callCount(); n != 1 {
		t.Errorf("SetTargets calls = %d, want 1 — the stale probe half must be skipped", n)
	}
	if ts := configurable.lastTargets(); len(ts) != 1 || ts[0].Target != "7.7.7.7" {
		t.Errorf("targets = %+v, want the v7 generation kept", ts)
	}
	calls := applier.calls()
	if len(calls) != 2 {
		t.Fatalf("game configs applied = %d, want both", len(calls))
	}
	if len(calls[1].Profiles) != 1 || calls[1].Profiles[0].ID != "p1" {
		t.Errorf("second game config = %+v, want the profile it carried", calls[1])
	}
	if r.appliedGameVersion != 2 || r.appliedConfigVersion != 7 {
		t.Errorf("versions = config v%d / game v%d, want v7 / v2",
			r.appliedConfigVersion, r.appliedGameVersion)
	}
}

// The mirror image: a monitor edit re-pushes the game block unchanged, and an
// out-of-order frame can carry one older than what is installed. The sensor must
// not be restarted onto a profile list the server has already replaced.
func TestStaleGameVersionIsIgnoredWhileTheProbeHalfApplies(t *testing.T) {
	r, configurable, applier := newGameRunner()

	applyOrFail(t, r, gamePush(1, &pcfg.GameConfig{Version: 5}, "1.1.1.1"))
	applyOrFail(t, r, gamePush(2, &pcfg.GameConfig{Version: 3}, "2.2.2.2"))

	if n := configurable.callCount(); n != 2 {
		t.Errorf("SetTargets calls = %d, want 2 — the probe half is fresh both times", n)
	}
	if calls := applier.calls(); len(calls) != 1 || calls[0].Version != 5 {
		t.Errorf("game configs applied = %+v, want only v5", calls)
	}
	if r.appliedGameVersion != 5 {
		t.Errorf("appliedGameVersion = %d, want 5 (unmoved by the stale block)", r.appliedGameVersion)
	}
}

// Nil is "this push says nothing about game capture", which is different from an
// empty configuration ("no profiles, record everything"). Nothing is applied and
// the axis does not move, so the next real block still lands whatever its
// version.
func TestPushWithoutAGameBlockLeavesTheGameAxisUntouched(t *testing.T) {
	r, _, applier := newGameRunner()

	applyOrFail(t, r, gamePush(1, nil, "1.1.1.1"))
	if calls := applier.calls(); len(calls) != 0 {
		t.Fatalf("game configs applied = %+v, want none for a push with no game block", calls)
	}
	if r.appliedGameVersion != -1 {
		t.Fatalf("appliedGameVersion = %d, want it unmoved", r.appliedGameVersion)
	}

	applyOrFail(t, r, gamePush(2, &pcfg.GameConfig{Version: 0, RecordUnmatched: true}, "2.2.2.2"))
	if calls := applier.calls(); len(calls) != 1 || !calls[0].RecordUnmatched {
		t.Fatalf("game configs applied = %+v, want the empty-but-present block", calls)
	}
}

// The server re-pushes the whole DesiredState for reasons that have nothing to do
// with games — a reconnect, a monitor edit — so the same game version arrives
// again and again. Re-applying it must reach the applier rather than being
// filtered here: only the applier can tell whether the resulting sensor
// configuration actually changed, and it no-ops when it did not.
func TestEqualGameVersionsAreReapplied(t *testing.T) {
	r, _, applier := newGameRunner()

	cfg := &pcfg.GameConfig{
		Version:  4,
		Profiles: []pcfg.GameProfile{{ID: "p1", Name: "CS2", Exe: []string{"cs2.exe"}, Tier: "base"}},
	}
	applyOrFail(t, r, gamePush(1, cfg, "1.1.1.1"))
	applyOrFail(t, r, gamePush(1, cfg, "1.1.1.1"))
	applyOrFail(t, r, gamePush(1, cfg, "1.1.1.1"))

	calls := applier.calls()
	if len(calls) != 3 {
		t.Fatalf("game configs applied = %d, want every equal-version push handed on", len(calls))
	}
	for _, got := range calls {
		if got.Version != 4 || len(got.Profiles) != 1 {
			t.Fatalf("applied %+v, want the same configuration each time", got)
		}
	}
}

// An agent with no sensor to configure gets no applier, and a game block then
// has to be harmless rather than a nil dereference on the session goroutine.
func TestGameBlockIsIgnoredWithoutAnApplier(t *testing.T) {
	r, configurable, _ := newGameRunner()
	r.deps.Game = nil

	applyOrFail(t, r, gamePush(1, &pcfg.GameConfig{Version: 2}, "1.1.1.1"))

	if n := configurable.callCount(); n != 1 {
		t.Errorf("SetTargets calls = %d, want the probe half applied as usual", n)
	}
	if r.appliedGameVersion != -1 {
		t.Errorf("appliedGameVersion = %d, want it unmoved when nothing can apply it", r.appliedGameVersion)
	}
}
