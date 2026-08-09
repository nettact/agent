package conn

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nettact/agent/internal/desiredstate"
	"github.com/nettact/agent/internal/monitoreval"
	"github.com/nettact/agent/internal/netguard"
	"github.com/nettact/agent/probepolicy"
	pcfg "github.com/nettact/protocol/config"
	"github.com/nettact/protocol/permission"
	"github.com/nettact/protocol/wire"
)

const (
	persistServer = "home"
	persistToken  = "tok-home"
	persistAgent  = "agent_home"
	persistSite   = "site_home"
)

// fakeProxySet stands in for proxydial.Manager's Specs() view, so a test can
// model "the session has not supplied the proxies yet" (empty) and "it has"
// without building real tunnels.
type fakeProxySet struct{ specs map[string]pcfg.ProxySpec }

func (f *fakeProxySet) Specs() map[string]pcfg.ProxySpec { return f.specs }

// fakeDiagApplier records the last policy installed, so a restore can be checked
// to carry the operator's setting rather than falling back to built-in defaults.
type fakeDiagApplier struct{ policy *pcfg.DiagPolicy }

func (f *fakeDiagApplier) ApplyDiagPolicy(p *pcfg.DiagPolicy) { f.policy = p }
func (f *fakeDiagApplier) last() *pcfg.DiagPolicy             { return f.policy }

// discardConn accepts every frame; the persistence paths never read.
type discardConn struct{ frames []wire.Frame }

func (*discardConn) ReadFrame(context.Context) (wire.Frame, error) {
	return wire.Frame{}, errors.New("unused")
}
func (d *discardConn) WriteFrame(_ context.Context, f wire.Frame) error {
	d.frames = append(d.frames, f)
	return nil
}
func (*discardConn) Ping(context.Context) error         { return nil }
func (*discardConn) Close(wire.CloseCode, string) error { return nil }

func newTracker(proxies monitoreval.ProxySet) *monitoreval.Tracker {
	return monitoreval.New(permission.All(), permission.All(), permission.All(),
		netguard.New(probepolicy.Policy{}, true), proxies, "policy", 0, 5*time.Second)
}

// persistTempDir returns a directory for one test's cache, removed on a
// best-effort basis. t.TempDir is the wrong owner on Windows: its cleanup fails
// the test if RemoveAll errors, and a just-closed file can stay held a moment
// longer than Close suggests — so a test that asserted everything correctly
// still reports a failure on the unlink. internal/wal and internal/desiredstate
// carry the same helper for the same reason.
func persistTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "nettact-conn-desired-")
	if err != nil {
		t.Fatalf("temp dir: %v", err)
	}
	t.Cleanup(func() {
		for i := 0; i < 20; i++ {
			if os.RemoveAll(dir) == nil {
				return
			}
			time.Sleep(25 * time.Millisecond)
		}
	})
	return dir
}

// persistRunner builds a runner wired to a real on-disk cache in dir.
func persistRunner(dir string, cfgable *fakeConfigurable, sched *fakeScheduler, tracker *monitoreval.Tracker) *runner {
	return &runner{
		opts: Options{ServerName: persistServer},
		deps: Deps{
			Configurables: []Configurable{cfgable},
			Scheduler:     sched,
			Tracker:       tracker,
			Desired:       desiredstate.Bind(dir, persistServer, persistToken, persistAgent, persistSite),
		},
		appliedConfigVersion: -1,
		appliedGameVersion:   -1,
	}
}

func push(version int, targets ...pcfg.ProbeTarget) *pcfg.DesiredState {
	return &pcfg.DesiredState{
		ConfigVersion: version,
		ProbeTargets:  targets,
		Intervals:     pcfg.Intervals{BaseSeconds: 5, RegularSeconds: 60},
	}
}

func icmpTarget(id string) pcfg.ProbeTarget {
	return pcfg.ProbeTarget{MonitorID: id, Kind: "icmp", Target: "1.1.1.1", ConfigSerial: 3}
}

// The whole point of the cache: a process that starts while the server is
// unreachable must install targets and start probing anyway.
func TestRestoreInstallsCachedConfigWithoutASession(t *testing.T) {
	dir := persistTempDir(t)

	// First process: a push arrives and is applied.
	first := persistRunner(dir, &fakeConfigurable{}, &fakeScheduler{}, newTracker(nil))
	if _, ok := first.installProbeConfig(push(7, icmpTarget("mon-a"))); !ok {
		t.Fatal("first install was rejected as stale")
	}

	// Second process: no session at all, only the cache on disk.
	cfgable, sched := &fakeConfigurable{}, &fakeScheduler{}
	second := persistRunner(dir, cfgable, sched, newTracker(nil))
	second.restoreProbeConfig()

	targets := cfgable.lastTargets()
	if len(targets) != 1 || targets[0].MonitorID != "mon-a" {
		t.Fatalf("restored targets = %+v, want the cached monitor", targets)
	}
	if targets[0].ConfigSerial != 3 {
		t.Fatalf("restored ConfigSerial = %d, want 3 — the series identity must survive a restart", targets[0].ConfigSerial)
	}
	if base, regular := sched.intervals(); base != 5*time.Second || regular != 60*time.Second {
		t.Fatalf("restored intervals = %v/%v, want 5s/60s", base, regular)
	}
	if second.appliedConfigVersion != 7 {
		t.Fatalf("appliedConfigVersion = %d, want the cached 7", second.appliedConfigVersion)
	}
}

// The restored version must not lock out the server: the guard ignores only
// strictly LOWER versions, and the equal-version on-connect push is what
// re-supplies the proxies the cache never stored.
func TestEqualVersionPushAfterRestoreStillApplies(t *testing.T) {
	dir := persistTempDir(t)
	// HTTP rather than ICMP: a SOCKS5 proxy can carry TCP but not raw echo, so an
	// ICMP monitor pinned to one is un-runnable for a reason that has nothing to
	// do with the cache.
	pinned := pcfg.ProbeTarget{
		MonitorID: "mon-proxied", Kind: "http", Target: "https://example.test",
		ConfigSerial: 3, ProxyID: "px-1",
	}

	seed := persistRunner(dir, &fakeConfigurable{}, &fakeScheduler{}, newTracker(nil))
	if _, ok := seed.installProbeConfig(push(11, icmpTarget("mon-a"), pinned)); !ok {
		t.Fatal("seed install rejected")
	}

	// Restart with no proxies known: the pinned monitor must fail closed rather
	// than silently become a direct dial.
	proxies := &fakeProxySet{}
	cfgable := &fakeConfigurable{}
	r := persistRunner(dir, cfgable, &fakeScheduler{}, newTracker(proxies))
	r.restoreProbeConfig()
	if got := cfgable.lastTargets(); len(got) != 1 || got[0].MonitorID != "mon-a" {
		t.Fatalf("restored runnable = %+v, want only the unpinned monitor", got)
	}

	// The session comes up and pushes the same version, now carrying the proxies.
	proxies.specs = map[string]pcfg.ProxySpec{"px-1": {ID: "px-1", Type: pcfg.ProxyTypeSOCKS5}}
	ds := push(11, icmpTarget("mon-a"), pinned)
	ds.Proxies = []pcfg.ProxySpec{{ID: "px-1", Type: pcfg.ProxyTypeSOCKS5}}
	if err := r.applyProbeConfig(context.Background(), &discardConn{}, ds); err != nil {
		t.Fatalf("equal-version push: %v", err)
	}
	if got := cfgable.lastTargets(); len(got) != 2 {
		t.Fatalf("after the equal-version push runnable = %+v, want both monitors", got)
	}
}

// The cache is written on a payload change, not on a version change: the same
// ConfigVersion can carry different targets for different agents, and a save
// that failed once must be retried rather than assumed done.
func TestCacheWritesTrackPayloadAndRetryAfterFailure(t *testing.T) {
	dir := persistTempDir(t)
	r := persistRunner(dir, &fakeConfigurable{}, &fakeScheduler{}, newTracker(nil))
	file := filepath.Join(dir, "desired.json")

	if _, ok := r.installProbeConfig(push(4, icmpTarget("mon-a"))); !ok {
		t.Fatal("install rejected")
	}
	firstStat, err := os.Stat(file)
	if err != nil {
		t.Fatalf("cache not written: %v", err)
	}

	// An identical re-push must not rewrite the file — this is what keeps a
	// router's flash out of the reconnect path.
	before, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := r.installProbeConfig(push(4, icmpTarget("mon-a"))); !ok {
		t.Fatal("identical re-push rejected")
	}
	after, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("an identical configuration rewrote the cache")
	}
	if r.persistedDigest == "" {
		t.Fatal("digest not recorded after a successful save")
	}
	_ = firstStat

	// Same version, different payload: must be persisted.
	if _, ok := r.installProbeConfig(push(4, icmpTarget("mon-b"))); !ok {
		t.Fatal("same-version different-payload push rejected")
	}
	cached, ok := r.deps.Desired.Load()
	if !ok || len(cached.ProbeTargets) != 1 || cached.ProbeTargets[0].MonitorID != "mon-b" {
		t.Fatalf("cache = %+v, want the changed payload of the same version", cached)
	}

	// A failed save must not advance the digest, so the next push retries.
	r.persistedDigest = ""
	broken := persistRunner(t.TempDir(), &fakeConfigurable{}, &fakeScheduler{}, newTracker(nil))
	broken.deps.Desired = desiredstate.Bind(filepath.Join(dir, "desired.json", "not-a-dir"),
		persistServer, persistToken, persistAgent, persistSite)
	if _, ok := broken.installProbeConfig(push(1, icmpTarget("mon-a"))); !ok {
		t.Fatal("install rejected")
	}
	if broken.persistedDigest != "" {
		t.Fatal("a failed save advanced the digest; the next push would never retry")
	}
}

// A cache written under one credential must not be restored under another: the
// staleness guard would let an old high version permanently suppress the new
// server's pushes.
func TestRestoreRefusesAForeignCredential(t *testing.T) {
	dir := persistTempDir(t)
	seed := persistRunner(dir, &fakeConfigurable{}, &fakeScheduler{}, newTracker(nil))
	if _, ok := seed.installProbeConfig(push(50, icmpTarget("mon-old"))); !ok {
		t.Fatal("seed install rejected")
	}

	cfgable := &fakeConfigurable{}
	r := persistRunner(dir, cfgable, &fakeScheduler{}, newTracker(nil))
	r.deps.Desired = desiredstate.Bind(dir, persistServer, "a-different-token", persistAgent, persistSite)
	r.restoreProbeConfig()

	if cfgable.callCount() != 0 {
		t.Fatalf("SetTargets called %d times; a foreign credential's targets were installed", cfgable.callCount())
	}
	if r.appliedConfigVersion != -1 {
		t.Fatalf("appliedConfigVersion = %d, want -1 so the new server's v1 still applies", r.appliedConfigVersion)
	}
	// The decisive part: a fresh low version from the new server must install.
	if _, ok := r.installProbeConfig(push(1, icmpTarget("mon-new"))); !ok {
		t.Fatal("the new server's v1 was rejected as stale")
	}
}

// An identity verdict must stop this server's monitoring — and must not let a
// restart bring it back.
func TestQuiesceStopsProbingAndForgetsTheCache(t *testing.T) {
	dir := persistTempDir(t)
	cfgable := &fakeConfigurable{}
	r := persistRunner(dir, cfgable, &fakeScheduler{}, newTracker(nil))
	if _, ok := r.installProbeConfig(push(9, icmpTarget("mon-a"))); !ok {
		t.Fatal("install rejected")
	}
	if len(cfgable.lastTargets()) != 1 {
		t.Fatal("setup did not install a target")
	}

	r.quiesce("test")

	if got := cfgable.lastTargets(); len(got) != 0 {
		t.Fatalf("targets after quiesce = %+v, want none", got)
	}
	if r.appliedConfigVersion != -1 || r.persistedDigest != "" {
		t.Fatalf("quiesce left state behind: v=%d digest=%q", r.appliedConfigVersion, r.persistedDigest)
	}
	if _, ok := r.deps.Desired.Load(); ok {
		t.Fatal("quiesce left the cache on disk; a restart would resume the old targets")
	}
	// A restart must now find nothing to restore.
	restarted := persistRunner(dir, &fakeConfigurable{}, &fakeScheduler{}, newTracker(nil))
	restarted.restoreProbeConfig()
	if restarted.appliedConfigVersion != -1 {
		t.Fatalf("restart restored v%d after a quiesce", restarted.appliedConfigVersion)
	}
}

// An identity verdict must stop game capture too. Only the game owner is given
// an applier at all, so a runner that has one IS the owner — and with the cache
// restoring game configuration before the first dial, leaving the sensor running
// would have a server-side-deleted agent resume capturing what people play after
// every reboot.
func TestQuiesceStopsGameCapture(t *testing.T) {
	dir := persistTempDir(t)
	game := &fakeGameApplier{}
	r := persistRunner(dir, &fakeConfigurable{}, &fakeScheduler{}, newTracker(nil))
	r.deps.Game = game
	r.applyGameConfig(&pcfg.GameConfig{Version: 3, RecordUnmatched: true, Profiles: []pcfg.GameProfile{{ID: "p1"}}})
	if len(game.calls()) != 1 {
		t.Fatalf("setup did not install a game config: %+v", game.calls())
	}

	r.quiesce("test")

	calls := game.calls()
	if len(calls) != 2 {
		t.Fatalf("game applier called %d times, want a stop after the verdict", len(calls))
	}
	stop := calls[len(calls)-1]
	// "No profiles and no unmatched recording" is how this configuration says
	// capture nothing; a stop expressed any other way would be a new sensor verb.
	if stop.RecordUnmatched || len(stop.Profiles) != 0 {
		t.Fatalf("stop config = %+v, want no profiles and no unmatched recording", stop)
	}
	if r.appliedGame != nil {
		t.Fatal("quiesce left an applied game config behind")
	}
}

// …but a refusal that arrives before anything was ever captured must not START
// the sensor. The applier is wired for the game owner whether or not it has been
// configured, and its supervisor treats the first configuration as the signal to
// spawn the child — so an unconditional stop would launch the process in order
// to silence it, on an agent that had never been told to capture anything.
func TestQuiesceDoesNotStartAnUnconfiguredSensor(t *testing.T) {
	dir := persistTempDir(t)
	game := &fakeGameApplier{}
	r := persistRunner(dir, &fakeConfigurable{}, &fakeScheduler{}, newTracker(nil))
	r.deps.Game = game

	// The first dial is refused before any push or restore installed a config.
	r.quiesce("credential refused before anything was configured")

	if n := len(game.calls()); n != 0 {
		t.Fatalf("game applier called %d times on an unconfigured agent; the "+
			"supervisor's first SetConfig is what starts the sensor", n)
	}
}

// The three configuration axes are guarded independently and can arrive out of
// order, so the cache must store what is INSTALLED — not whatever game/diag
// block happened to ride along with the last accepted probe push.
func TestCacheStoresAppliedAxesNotThePushThatCarriedThem(t *testing.T) {
	dir := persistTempDir(t)
	game, diag := &fakeGameApplier{}, &fakeDiagApplier{}
	r := persistRunner(dir, &fakeConfigurable{}, &fakeScheduler{}, newTracker(nil))
	r.deps.Game, r.deps.Diag = game, diag

	// A push installs game v5 and diag serial 9 alongside probe v1.
	fresh := push(1, icmpTarget("mon-a"))
	fresh.Game = &pcfg.GameConfig{Version: 5}
	fresh.Diag = &pcfg.DiagPolicy{Serial: 9}
	r.applyGameConfig(fresh.Game)
	r.deps.Diag.ApplyDiagPolicy(fresh.Diag)
	r.appliedDiagSerial, r.haveDiagSerial, r.appliedDiag = 9, true, fresh.Diag
	if _, ok := r.installProbeConfig(fresh); !ok {
		t.Fatal("first install rejected")
	}

	// A LATER probe generation arrives carrying stale game/diag blocks — routine,
	// since the axes are built and pushed independently.
	stale := push(2, icmpTarget("mon-b"))
	stale.Game = &pcfg.GameConfig{Version: 2}
	stale.Diag = &pcfg.DiagPolicy{Serial: 3}
	r.applyGameConfig(stale.Game)            // rejected by the game guard
	if r.deps.Diag != nil && stale.Diag != nil { // rejected by the diag guard
		if stale.Diag.Serial > r.appliedDiagSerial {
			t.Fatal("test setup: the diag block should be stale")
		}
	}
	if _, ok := r.installProbeConfig(stale); !ok {
		t.Fatal("the fresh probe generation was rejected")
	}

	cached, ok := r.deps.Desired.Load()
	if !ok {
		t.Fatal("nothing cached")
	}
	if cached.ConfigVersion != 2 {
		t.Fatalf("cached probe version = %d, want the fresh 2", cached.ConfigVersion)
	}
	if cached.Game == nil || cached.Game.Version != 5 {
		t.Fatalf("cached game = %+v, want the applied v5 — not the stale v2 that rode along", cached.Game)
	}
	if cached.Diag == nil || cached.Diag.Serial != 9 {
		t.Fatalf("cached diag = %+v, want the applied serial 9", cached.Diag)
	}
}

// With no cache wired (tests, and any build that cannot write one) the session
// must behave exactly as it did before the cache existed.
func TestNoCacheWiredIsUnchangedBehaviour(t *testing.T) {
	cfgable := &fakeConfigurable{}
	r := &runner{
		opts:                 Options{ServerName: persistServer},
		deps:                 Deps{Configurables: []Configurable{cfgable}, Scheduler: &fakeScheduler{}, Tracker: newTracker(nil)},
		appliedConfigVersion: -1,
	}
	r.restoreProbeConfig() // must be a no-op, not a panic
	if cfgable.callCount() != 0 {
		t.Fatal("restore installed something with no cache wired")
	}
	if _, ok := r.installProbeConfig(push(2, icmpTarget("mon-a"))); !ok {
		t.Fatal("install rejected")
	}
	if len(cfgable.lastTargets()) != 1 {
		t.Fatal("push did not install")
	}
	r.quiesce("test") // must also be safe with no cache
}

// The game and diagnostic axes are restored with their own serials, so an
// install that turned diagnostics down does not come back up with the agent's
// built-in defaults after a reboot.
func TestRestoreCarriesGameAndDiagSerials(t *testing.T) {
	dir := persistTempDir(t)
	game := &fakeGameApplier{}
	diag := &fakeDiagApplier{}

	seed := persistRunner(dir, &fakeConfigurable{}, &fakeScheduler{}, newTracker(nil))
	ds := push(3, icmpTarget("mon-a"))
	ds.Game = &pcfg.GameConfig{Version: 5}
	ds.Diag = &pcfg.DiagPolicy{Serial: 12}
	seed.deps.Game, seed.deps.Diag = game, diag
	seed.applyGameConfig(ds.Game)
	seed.deps.Diag.ApplyDiagPolicy(ds.Diag)
	seed.appliedDiagSerial, seed.haveDiagSerial = ds.Diag.Serial, true
	seed.appliedDiag = ds.Diag // what applyPush records when the guard accepts
	if _, ok := seed.installProbeConfig(ds); !ok {
		t.Fatal("seed install rejected")
	}

	game2, diag2 := &fakeGameApplier{}, &fakeDiagApplier{}
	r := persistRunner(dir, &fakeConfigurable{}, &fakeScheduler{}, newTracker(nil))
	r.deps.Game, r.deps.Diag = game2, diag2
	r.restoreProbeConfig()

	if got := diag2.last(); got == nil || got.Serial != 12 {
		t.Fatalf("restored diag policy = %+v, want the cached serial 12", got)
	}
	if r.appliedDiagSerial != 12 || !r.haveDiagSerial {
		t.Fatalf("diag serial guard = %d/%v, want 12/true", r.appliedDiagSerial, r.haveDiagSerial)
	}
	if r.appliedGameVersion != 5 {
		t.Fatalf("game version = %d, want the cached 5", r.appliedGameVersion)
	}
	_ = game
}
