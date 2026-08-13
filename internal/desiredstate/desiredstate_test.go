package desiredstate

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	pcfg "github.com/nettact/protocol/config"
)

const (
	tokA = "token-alpha"
	tokB = "token-beta"
)

// tempDir returns a directory for one test's cache, removed on a best-effort
// basis when it ends.
//
// t.TempDir is the wrong owner for it on Windows: its cleanup FAILS the test if
// RemoveAll errors, and Windows can hold a just-closed file a fraction longer
// than Close suggests — so a test that asserted everything correctly still
// reports a failure on the unlink. (internal/wal and server-core's storetest
// have the same helper for the same reason.) Retry briefly and never fail: a
// leftover directory under the OS temp root is the operating system's to reap.
func tempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "nettact-desired-")
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

func bindA(t *testing.T, dir string) *Binding {
	t.Helper()
	return Bind(dir, "alpha", tokA, "agent_a", "site_a")
}

func sampleConfig(version int, target string) Config {
	return Config{
		ConfigVersion: version,
		ProbeTargets: []pcfg.ProbeTarget{{
			MonitorID: "mon_1", Kind: "icmp", Target: target, ConfigSerial: 7,
			Params: pcfg.ProbeParams{IntervalSeconds: 10},
		}},
		Intervals: pcfg.Intervals{BaseSeconds: 10, RegularSeconds: 60},
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	dir := tempDir(t)
	b := bindA(t, dir)
	want := sampleConfig(42, "1.1.1.1")
	if err := b.Save(want); err != nil {
		t.Fatalf("save: %v", err)
	}
	got, ok := b.Load()
	if !ok {
		t.Fatal("load missed a configuration that was just saved")
	}
	if got.ConfigVersion != 42 || len(got.ProbeTargets) != 1 {
		t.Fatalf("load = %+v, want v42 with one target", got)
	}
	// ConfigSerial is part of metric series identity; a round trip that loses it
	// would fork every series on restart.
	if got.ProbeTargets[0].ConfigSerial != 7 {
		t.Fatalf("ConfigSerial = %d, want 7", got.ProbeTargets[0].ConfigSerial)
	}
	if got.Intervals.BaseSeconds != 10 || got.Intervals.RegularSeconds != 60 {
		t.Fatalf("intervals = %+v, want 10/60", got.Intervals)
	}
}

// A snapshot written under one credential must never be restored under another:
// the staleness guard would then let an old high ConfigVersion permanently
// suppress the new server's pushes.
func TestLoadRejectsForeignCredential(t *testing.T) {
	dir := tempDir(t)
	if err := bindA(t, dir).Save(sampleConfig(50, "1.1.1.1")); err != nil {
		t.Fatalf("save: %v", err)
	}
	for _, tc := range []struct {
		name string
		b    *Binding
	}{
		{"different token", Bind(dir, "alpha", tokB, "agent_a", "site_a")},
		{"different agent id", Bind(dir, "alpha", tokA, "agent_z", "site_a")},
		{"different site id", Bind(dir, "alpha", tokA, "agent_a", "site_z")},
		{"no token yet", Bind(dir, "alpha", "", "agent_a", "site_a")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, ok := tc.b.Load(); ok {
				t.Fatal("restored a configuration bound to a different credential")
			}
		})
	}
}

func TestLoadTolerantOfUnusableFile(t *testing.T) {
	for _, tc := range []struct {
		name  string
		write func(t *testing.T, dir string)
	}{
		{"missing", func(*testing.T, string) {}},
		{"corrupt", func(t *testing.T, dir string) {
			if err := os.WriteFile(filepath.Join(dir, stateFile), []byte("{not json"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"wrong version", func(t *testing.T, dir string) {
			b, _ := json.Marshal(stateDoc{V: stateFormat + 1, Servers: map[string]snapshot{
				"alpha": {CredFingerprint: Fingerprint(tokA), AgentID: "agent_a", SiteID: "site_a"},
			}})
			if err := os.WriteFile(filepath.Join(dir, stateFile), b, 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"unbindable entry", func(t *testing.T, dir string) {
			b, _ := json.Marshal(stateDoc{V: stateFormat, Servers: map[string]snapshot{
				"alpha": {AgentID: "agent_a", SiteID: "site_a"},
			}})
			if err := os.WriteFile(filepath.Join(dir, stateFile), b, 0o600); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := tempDir(t)
			tc.write(t, dir)
			b := bindA(t, dir)
			if _, ok := b.Load(); ok {
				t.Fatal("load reported a usable configuration")
			}
			// An unusable file must not wedge the store: the next save has to work.
			if err := b.Save(sampleConfig(1, "9.9.9.9")); err != nil {
				t.Fatalf("save after %s file: %v", tc.name, err)
			}
			if _, ok := b.Load(); !ok {
				t.Fatal("save after an unusable file did not take")
			}
		})
	}
}

// Two servers' runners save independently; neither may erase the other.
func TestSavePreservesOtherServers(t *testing.T) {
	dir := tempDir(t)
	a := bindA(t, dir)
	bb := Bind(dir, "beta", tokB, "agent_b", "site_b")
	if err := a.Save(sampleConfig(1, "1.1.1.1")); err != nil {
		t.Fatalf("save alpha: %v", err)
	}
	if err := bb.Save(sampleConfig(2, "8.8.8.8")); err != nil {
		t.Fatalf("save beta: %v", err)
	}
	got, ok := a.Load()
	if !ok || got.ConfigVersion != 1 {
		t.Fatalf("alpha after beta's save: %+v ok=%v, want v1", got, ok)
	}
	got, ok = bb.Load()
	if !ok || got.ConfigVersion != 2 {
		t.Fatalf("beta: %+v ok=%v, want v2", got, ok)
	}
}

func TestForgetAndPrune(t *testing.T) {
	dir := tempDir(t)
	a := bindA(t, dir)
	bb := Bind(dir, "beta", tokB, "agent_b", "site_b")
	if err := a.Save(sampleConfig(1, "1.1.1.1")); err != nil {
		t.Fatal(err)
	}
	if err := bb.Save(sampleConfig(2, "8.8.8.8")); err != nil {
		t.Fatal(err)
	}

	if err := a.Forget(); err != nil {
		t.Fatalf("forget: %v", err)
	}
	if _, ok := a.Load(); ok {
		t.Fatal("forget left the entry behind")
	}
	if _, ok := bb.Load(); !ok {
		t.Fatal("forget removed an unrelated server's entry")
	}
	// Forgetting an absent entry is not an error.
	if err := a.Forget(); err != nil {
		t.Fatalf("second forget: %v", err)
	}

	if err := a.Save(sampleConfig(3, "1.1.1.1")); err != nil {
		t.Fatal(err)
	}
	n, err := Prune(dir, []string{"beta"})
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if n != 1 {
		t.Fatalf("prune removed %d, want 1", n)
	}
	if _, ok := a.Load(); ok {
		t.Fatal("prune kept an unconfigured server")
	}
	if _, ok := bb.Load(); !ok {
		t.Fatal("prune dropped a configured server")
	}
	if n, err := Prune(dir, []string{"beta"}); err != nil || n != 0 {
		t.Fatalf("idempotent prune = %d, %v", n, err)
	}
}

// The digest is the persistence trigger: it must move when the payload moves,
// including when the version does not.
func TestDigestTracksPayloadNotJustVersion(t *testing.T) {
	base := sampleConfig(5, "1.1.1.1")
	if Digest(base) != Digest(sampleConfig(5, "1.1.1.1")) {
		t.Fatal("identical configs digested differently")
	}
	if Digest(base) == Digest(sampleConfig(5, "9.9.9.9")) {
		t.Fatal("same version with different targets shares a digest")
	}
	if Digest(base) == Digest(sampleConfig(6, "1.1.1.1")) {
		t.Fatal("different versions share a digest")
	}
	withDiag := base
	withDiag.Diag = &pcfg.DiagPolicy{Serial: 3}
	if Digest(base) == Digest(withDiag) {
		t.Fatal("adding a diag policy did not move the digest")
	}
}

// The game and diagnostic axes carry their serials inside themselves, so a round
// trip has to restore the applied generation of each without extra bookkeeping.
func TestGameAndDiagRoundTrip(t *testing.T) {
	dir := tempDir(t)
	b := bindA(t, dir)
	c := sampleConfig(9, "1.1.1.1")
	c.Game = &pcfg.GameConfig{Version: 4, RecordUnmatched: true}
	c.Diag = &pcfg.DiagPolicy{Serial: 11}
	if err := b.Save(c); err != nil {
		t.Fatal(err)
	}
	got, ok := b.Load()
	if !ok {
		t.Fatal("load missed")
	}
	if got.Game == nil || got.Game.Version != 4 || !got.Game.RecordUnmatched {
		t.Fatalf("game = %+v, want v4 record-unmatched", got.Game)
	}
	if got.Diag == nil || got.Diag.Serial != 11 {
		t.Fatalf("diag = %+v, want serial 11", got.Diag)
	}
}

// Proxies are never persisted. This is a promise about credentials, so it is
// asserted against the bytes on disk rather than against the Go type.
func TestFileNeverContainsProxyMaterial(t *testing.T) {
	dir := tempDir(t)
	b := bindA(t, dir)
	c := sampleConfig(1, "1.1.1.1")
	c.ProbeTargets[0].ProxyID = "px_1"
	if err := b.Save(c); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, stateFile))
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, ok := doc["proxies"]; ok {
		t.Fatal("top-level proxies key on disk")
	}
	// The Config type has no Proxies field at all, so the only way one could
	// reach the file is by someone adding it; this asserts the shape stays that
	// way for the whole persisted document.
	srv := doc["servers"].(map[string]any)["alpha"].(map[string]any)
	cfg := srv["config"].(map[string]any)
	if _, ok := cfg["proxies"]; ok {
		t.Fatal("persisted config carries a proxies block")
	}
	// The pinned target itself is kept — it is what makes the monitor report as
	// proxy-missing rather than silently vanishing.
	targets := cfg["probe_targets"].([]any)
	if got := targets[0].(map[string]any)["proxy_id"]; got != "px_1" {
		t.Fatalf("proxy_id = %v, want the pin preserved", got)
	}
}

// TestBindingRebindUpdatesLiveFingerprint pins the rotation fix: the live
// binding's Rebind flips its fingerprint in memory so the NEXT Save re-keys the
// on-disk cache under the new token — the lazy re-key that keeps an offline
// restart restorable without ever rewriting the cache mid-rotation.
func TestBindingRebindUpdatesLiveFingerprint(t *testing.T) {
	dir := tempDir(t)
	const server = "default"

	b := Bind(dir, server, "old-token", "agent_a", "site_default")
	if err := b.Save(Config{ConfigVersion: 7, ProbeTargets: []pcfg.ProbeTarget{{Target: "192.168.1.1"}}}); err != nil {
		t.Fatalf("save: %v", err)
	}
	b.Rebind("new-token")
	// The next Save writes under the new bearer: a fresh binding for the new
	// token restores it, and the old token no longer matches.
	if err := b.Save(Config{ConfigVersion: 8}); err != nil {
		t.Fatalf("re-save after rebind: %v", err)
	}
	if _, ok := Bind(dir, server, "old-token", "agent_a", "site_default").Load(); ok {
		t.Fatal("old-token binding still restores after the live re-key")
	}
	cfg, ok := Bind(dir, server, "new-token", "agent_a", "site_default").Load()
	if !ok || cfg.ConfigVersion != 8 {
		t.Fatalf("new-token binding = %+v, ok=%v; want the re-keyed snapshot", cfg, ok)
	}
}

// TestBindingSetPrevAdmitsOldCache pins the crash-recovery half: after a
// rotation's credential write but before the cache re-key, a fresh binding for
// the new token with SetPrev(old fingerprint) must still restore the cache the
// old token wrote.
func TestBindingSetPrevAdmitsOldCache(t *testing.T) {
	dir := tempDir(t)
	const server = "default"

	old := Bind(dir, server, "old-token", "agent_a", "site_default")
	if err := old.Save(Config{ConfigVersion: 7, ProbeTargets: []pcfg.ProbeTarget{{Target: "192.168.1.1"}}}); err != nil {
		t.Fatalf("save: %v", err)
	}

	// A restart with the rotated credential: the new binding must accept the
	// old-fingerprint cache via SetPrev.
	nb := Bind(dir, server, "new-token", "agent_a", "site_default")
	nb.SetPrev(Fingerprint("old-token"))
	cfg, ok := nb.Load()
	if !ok || cfg.ConfigVersion != 7 {
		t.Fatalf("prev-admitting load = %+v, ok=%v; want the old cache", cfg, ok)
	}
	// Without the prev hint the same cache is foreign and refused.
	if _, ok := Bind(dir, server, "new-token", "agent_a", "site_default").Load(); ok {
		t.Fatal("new-token binding restores a foreign cache without the prev hint")
	}
}

// TestRebindReKeysByIdentityAcrossGenerations pins the drift fix: a cache left
// on an old token (a crash window, or a digest-gated Save that never re-keyed
// it) is still re-keyed by a later rotation because Rebind matches the agent's
// own identity, not the token fingerprint — so consecutive rotations cannot
// strand the cache out of the admissible set.
func TestRebindReKeysByIdentityAcrossGenerations(t *testing.T) {
	dir := tempDir(t)
	const server = "default"

	// The cache the agent's oldest credential wrote.
	if err := Bind(dir, server, "token-A", "agent_a", "site_default").Save(Config{ConfigVersion: 7}); err != nil {
		t.Fatalf("save: %v", err)
	}
	// Simulate a crash window: the new binding admits the old cache via prev,
	// and no Save re-keyed it (digest unchanged).
	b := Bind(dir, server, "token-B", "agent_a", "site_default")
	b.SetPrev(Fingerprint("token-A"))
	if _, ok := b.Load(); !ok {
		t.Fatal("prev-admitting load did not restore the old cache")
	}
	// A second rotation B -> C must re-key the still-A-keyed cache by identity.
	if err := b.Rebind("token-C"); err != nil {
		t.Fatalf("rebind: %v", err)
	}
	// A fresh C binding (no prev hint) restores it — the cache is no longer
	// stranded on A.
	cfg, ok := Bind(dir, server, "token-C", "agent_a", "site_default").Load()
	if !ok || cfg.ConfigVersion != 7 {
		t.Fatalf("C binding = %+v, ok=%v; want the re-keyed cache", cfg, ok)
	}
	// A foreign-identity snapshot is never re-keyed: a snapshot owned by a
	// different agent_id is left on its own fingerprint.
	if err := Bind(dir, server, "token-A", "someone_else", "site_default").Save(Config{ConfigVersion: 99}); err != nil {
		t.Fatalf("save foreign: %v", err)
	}
	if err := Bind(dir, server, "token-C", "agent_a", "site_default").Rebind("token-D"); err != nil {
		t.Fatalf("rebind over foreign: %v", err)
	}
	// The foreign snapshot is still restorable under its own (token-A,
	// someone_else) binding — Rebind did not touch it.
	if _, ok := Bind(dir, server, "token-A", "someone_else", "site_default").Load(); !ok {
		t.Fatal("foreign snapshot was dropped by an unrelated Rebind")
	}
	// And it was NOT re-keyed to token-D.
	if _, ok := Bind(dir, server, "token-D", "someone_else", "site_default").Load(); ok {
		t.Fatal("foreign snapshot was re-keyed by an unrelated Rebind")
	}
}
