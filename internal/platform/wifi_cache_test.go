package platform

import (
	"testing"
	"time"
)

// The cache is exercised through scripted scenarios with a fake clock: events
// in, Snapshot out, gated refreshes simulated by Claim/Apply pairs. No OS, no
// goroutines — this is the logic every platform watcher shares, so it runs on
// every host and under -tags lite.

type wifiClock struct{ t time.Time }

func newWiFiClock() *wifiClock {
	return &wifiClock{t: time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)}
}
func (c *wifiClock) now() time.Time          { return c.t }
func (c *wifiClock) advance(d time.Duration) { c.t = c.t.Add(d) }

func winCacheCfg() wifiCacheConfig {
	return wifiCacheConfig{MinRefreshInterval: 5 * time.Second}
}

func macCacheCfg() wifiCacheConfig {
	return wifiCacheConfig{
		MinRefreshInterval:             5 * time.Second,
		SSIDDemandWindow:               90 * time.Second,
		ReasonPermissionWhenSSIDAbsent: true,
	}
}

func intp(v int) *int         { return &v }
func f64p(v float64) *float64 { return &v }

func connObs(id string) wifiObs { return wifiObs{ID: id, Name: id, Connected: true} }

func connFacts(ssid string, band string, ch int, dbm, q int) wifiGatedFacts {
	return wifiGatedFacts{
		Connected: true, SSIDRaw: []byte(ssid), HasSSID: true,
		Band: band, Channel: ch, SignalDBm: intp(dbm), Quality: intp(q),
	}
}

// applyNow performs a full claim→apply cycle, seeding the entry if the scenario
// has not created one yet. Scenarios that care about the claim/apply race drive
// the two halves themselves.
func applyNow(t *testing.T, c *wifiCache, id string, f wifiGatedFacts) {
	t.Helper()
	c.NoteConnect(id)
	claim, ok := c.ClaimRefresh(id)
	if !ok {
		t.Fatalf("claim %s", id)
	}
	if !c.ApplyRefresh(claim, f) {
		t.Fatalf("apply %s", id)
	}
}

func TestWiFiCacheStartupSeeding(t *testing.T) {
	clk := newWiFiClock()
	c := newWiFiCache(winCacheCfg(), clk.now)

	// First tick: connected adapter, no facts yet → connected row with absent
	// categorical fields, and a refresh request.
	rows, need := c.Snapshot([]wifiObs{connObs("a")}, true)
	if len(rows) != 1 || rows[0].State != "connected" {
		t.Fatalf("rows=%+v", rows)
	}
	if rows[0].SSID != "" || rows[0].Band != "" || rows[0].SignalDBm != nil {
		t.Fatalf("pre-refresh row must not invent data: %+v", rows[0])
	}
	if len(need) != 1 || need[0] != "a" {
		t.Fatalf("need=%v", need)
	}

	claim, ok := c.ClaimRefresh("a")
	if !ok {
		t.Fatal("claim should succeed")
	}
	if !c.ApplyRefresh(claim, connFacts("home", "5", 44, -52, 96)) {
		t.Fatal("apply")
	}
	rows, need = c.Snapshot([]wifiObs{connObs("a")}, true)
	if len(need) != 0 {
		t.Fatalf("clean entry still wants refresh: %v", need)
	}
	r := rows[0]
	if r.SSID != "home" || r.Band != "5" || r.Channel != 44 ||
		r.SignalDBm == nil || *r.SignalDBm != -52 || r.Quality == nil || *r.Quality != 96 {
		t.Fatalf("row=%+v", r)
	}
}

func TestWiFiCacheDisconnectIsImmediateAndFree(t *testing.T) {
	clk := newWiFiClock()
	c := newWiFiCache(winCacheCfg(), clk.now)
	applyNow(t, c, "a", connFacts("home", "5", 44, -52, 96))

	c.NoteDisconnect("a")
	rows, need := c.Snapshot([]wifiObs{{ID: "a", Name: "a"}}, true)
	if rows[0].State != "disconnected" || rows[0].SSID != "" {
		t.Fatalf("row=%+v", rows[0])
	}
	if len(need) != 0 {
		t.Fatalf("disconnect must not request a gated refresh: %v", need)
	}
	if _, ok := c.ClaimRefresh("a"); ok {
		t.Fatal("nothing to refresh on a down link")
	}
}

func TestWiFiCacheRoamRefreshesIdentity(t *testing.T) {
	clk := newWiFiClock()
	c := newWiFiCache(winCacheCfg(), clk.now)
	applyNow(t, c, "a", connFacts("home", "2.4", 6, -60, 80))

	clk.advance(30 * time.Second)
	c.NoteRoamEnd("a")
	claim, ok := c.ClaimRefresh("a")
	if !ok {
		t.Fatal("roam should open a refresh")
	}
	if !c.ApplyRefresh(claim, connFacts("home", "5", 44, -50, 100)) {
		t.Fatal("apply")
	}
	rows, _ := c.Snapshot([]wifiObs{connObs("a")}, true)
	if rows[0].Band != "5" || rows[0].Channel != 44 {
		t.Fatalf("row=%+v", rows[0])
	}
}

func TestWiFiCacheSignalEventsGoLiveAndStaleDBm(t *testing.T) {
	clk := newWiFiClock()
	c := newWiFiCache(winCacheCfg(), clk.now)
	applyNow(t, c, "a", connFacts("home", "5", 44, -52, 96))

	// Event-pushed quality diverges from the refresh-time reading: the row must
	// follow the event and derive dBm rather than serve the stale native value.
	c.NoteSignalQuality("a", 60)
	rows, need := c.Snapshot([]wifiObs{connObs("a")}, true)
	r := rows[0]
	if r.Quality == nil || *r.Quality != 60 {
		t.Fatalf("quality=%v", r.Quality)
	}
	if r.SignalDBm == nil || *r.SignalDBm != dbmFromQuality(60) {
		t.Fatalf("dBm=%v want derived %d", r.SignalDBm, dbmFromQuality(60))
	}
	if len(need) != 0 {
		t.Fatalf("signal update must not request a refresh: %v", need)
	}

	// A tick-native dBm observation (ungated OS read) outranks derivation.
	rows, _ = c.Snapshot([]wifiObs{{ID: "a", Name: "a", Connected: true, SignalDBm: intp(-71)}}, true)
	if rows[0].SignalDBm == nil || *rows[0].SignalDBm != -71 {
		t.Fatalf("dBm=%v", rows[0].SignalDBm)
	}

	// A signal event for an adapter the cache has never seen implies a missed
	// connect → seeded dirty.
	c.NoteSignalQuality("b", 70)
	_, need = c.Snapshot([]wifiObs{connObs("a"), connObs("b")}, true)
	if len(need) != 1 || need[0] != "b" {
		t.Fatalf("need=%v", need)
	}
}

func TestWiFiCacheReconcileStateMismatch(t *testing.T) {
	clk := newWiFiClock()
	c := newWiFiCache(winCacheCfg(), clk.now)
	applyNow(t, c, "a", connFacts("home", "5", 44, -52, 96))

	// Missed disconnect: observation says down → row down immediately, facts
	// folded to disconnected locally, no gated refresh.
	rows, need := c.Snapshot([]wifiObs{{ID: "a", Name: "a"}}, true)
	if rows[0].State != "disconnected" || len(need) != 0 {
		t.Fatalf("rows=%+v need=%v", rows, need)
	}

	// Missed connect: observation says up while facts say down → refresh, and
	// until it lands the row must NOT leak the previous network's identity.
	clk.advance(10 * time.Second)
	rows, need = c.Snapshot([]wifiObs{connObs("a")}, true)
	if rows[0].State != "connected" || rows[0].SSID != "" || rows[0].Band != "" {
		t.Fatalf("stale identity leaked: %+v", rows[0])
	}
	if len(need) != 1 {
		t.Fatalf("need=%v", need)
	}
}

func TestWiFiCacheReconcileChannelDrift(t *testing.T) {
	clk := newWiFiClock()
	c := newWiFiCache(winCacheCfg(), clk.now)
	applyNow(t, c, "a", connFacts("home", "5", 44, -52, 96))

	ob := connObs("a")
	ob.Channel = 44
	if _, need := c.Snapshot([]wifiObs{ob}, true); len(need) != 0 {
		t.Fatalf("matching channel dirtied: %v", need)
	}
	clk.advance(30 * time.Second)
	ob.Channel = 149 // channel switch with no notification observed
	if _, need := c.Snapshot([]wifiObs{ob}, true); len(need) != 1 {
		t.Fatal("channel drift must trigger a refresh")
	}
	// An unknown (0) channel this tick is "don't know", never a change signal.
	applyNow(t, c, "a", connFacts("home", "5", 149, -52, 96))
	ob.Channel = 0
	if _, need := c.Snapshot([]wifiObs{ob}, true); len(need) != 0 {
		t.Fatalf("unknown channel dirtied: %v", need)
	}
}

func TestWiFiCacheRefreshRateLimit(t *testing.T) {
	clk := newWiFiClock()
	c := newWiFiCache(winCacheCfg(), clk.now)

	// A connect burst collapses into one gated attempt.
	c.NoteConnect("a")
	c.NoteRoamEnd("a")
	if _, ok := c.ClaimRefresh("a"); !ok {
		t.Fatal("first claim")
	}
	if _, ok := c.ClaimRefresh("a"); ok {
		t.Fatal("burst must be rate-limited")
	}
	// The refresh FAILED (no Apply): dirty persists but the window still holds —
	// stamping per attempt is what stops a hot loop against a failing API.
	clk.advance(2 * time.Second)
	if _, ok := c.ClaimRefresh("a"); ok {
		t.Fatal("failed attempt must not reopen early")
	}
	clk.advance(4 * time.Second)
	if _, ok := c.ClaimRefresh("a"); !ok {
		t.Fatal("window elapsed, dirty entry must be claimable again")
	}
}

func TestWiFiCacheSSIDDemandWindow(t *testing.T) {
	clk := newWiFiClock()
	c := newWiFiCache(macCacheCfg(), clk.now)

	if c.WantSSID() {
		t.Fatal("no demand yet")
	}
	c.Snapshot([]wifiObs{connObs("a")}, true)
	if !c.WantSSID() {
		t.Fatal("demand stamped")
	}
	applyNow(t, c, "a", connFacts("home", "5", 44, -52, 96))

	// Every server revokes ssid-read: demand expires, cached SSID is dropped and
	// the OS reads stop.
	clk.advance(2 * time.Minute)
	rows, need := c.Snapshot([]wifiObs{connObs("a")}, false)
	if c.WantSSID() {
		t.Fatal("demand must expire")
	}
	if rows[0].SSID != "" {
		t.Fatalf("row still discloses SSID: %+v", rows[0])
	}
	if len(need) != 0 {
		t.Fatalf("expired demand must not refresh: %v", need)
	}

	// Demand returns: the SSID-less facts must be re-read.
	clk.advance(10 * time.Second)
	_, need = c.Snapshot([]wifiObs{connObs("a")}, true)
	if len(need) != 1 {
		t.Fatal("renewed demand must trigger a refresh")
	}
}

func TestWiFiCachePermissionSemantics(t *testing.T) {
	clk := newWiFiClock()
	c := newWiFiCache(winCacheCfg(), clk.now)

	// Windows: the OS location policy denied the gated read. The row is built
	// from ungated observations and marked permission. Claim precedes Apply as
	// in the real refresh flow, so the attempt is stamped.
	c.NoteConnect("a")
	claim, ok := c.ClaimRefresh("a")
	if !ok {
		t.Fatal("claim")
	}
	if !c.ApplyRefresh(claim, wifiGatedFacts{Connected: true, Permission: true}) {
		t.Fatal("apply")
	}
	ob := connObs("a")
	ob.Channel = 6
	ob.RxMbps, ob.TxMbps = f64p(400), f64p(300)
	rows, need := c.Snapshot([]wifiObs{ob}, true)
	r := rows[0]
	if r.State != "connected" || r.Reason != "permission" {
		t.Fatalf("row=%+v", r)
	}
	if r.Band != "2.4" || r.Channel != 6 || *r.RxMbps != 400 || *r.TxMbps != 300 {
		t.Fatalf("ungated fields lost: %+v", r)
	}
	if len(need) != 0 {
		t.Fatalf("denied verdict must not retry eagerly: %v", need)
	}

	// ...but it retries on the slow clock, so a user re-enabling location does
	// not need a reconnect to be noticed.
	clk.advance(wifiPermissionRetryInterval + time.Second)
	if _, need = c.Snapshot([]wifiObs{ob}, true); len(need) != 1 {
		t.Fatal("permission verdict must retry slowly")
	}
}

func TestWiFiCacheReasonPermissionWhenSSIDAbsent(t *testing.T) {
	clk := newWiFiClock()
	c := newWiFiCache(macCacheCfg(), clk.now)
	c.Snapshot([]wifiObs{connObs("a")}, true) // establish demand
	applyNow(t, c, "a", connFacts("home", "5", 44, -52, 96))

	// macOS semantics: a connected row that does not disclose an SSID to THIS
	// caller carries reason=permission (historical normalizeCW behavior)...
	rows, _ := c.Snapshot([]wifiObs{connObs("a")}, false)
	if rows[0].Reason != "permission" || rows[0].SSID != "" {
		t.Fatalf("row=%+v", rows[0])
	}
	// ...and a disclosing row does not.
	rows, _ = c.Snapshot([]wifiObs{connObs("a")}, true)
	if rows[0].Reason != "" || rows[0].SSID != "home" {
		t.Fatalf("row=%+v", rows[0])
	}
}

func TestWiFiCacheNeverDecodesWithoutGrant(t *testing.T) {
	clk := newWiFiClock()
	c := newWiFiCache(winCacheCfg(), clk.now)
	applyNow(t, c, "a", connFacts("secret", "5", 44, -52, 96))
	rows, _ := c.Snapshot([]wifiObs{connObs("a")}, false)
	if rows[0].SSID != "" {
		t.Fatalf("SSID disclosed to ungranted caller: %+v", rows[0])
	}
	if rows[0].Band != "5" { // non-identifying fields still flow
		t.Fatalf("row=%+v", rows[0])
	}
}

func TestWiFiCacheRemovalAndPrune(t *testing.T) {
	clk := newWiFiClock()
	c := newWiFiCache(winCacheCfg(), clk.now)
	applyNow(t, c, "a", connFacts("home", "5", 44, -52, 96))
	applyNow(t, c, "b", connFacts("attic", "2.4", 6, -70, 60))

	c.NoteAdapterRemoved("b")
	rows, _ := c.Snapshot([]wifiObs{connObs("a")}, true)
	if len(rows) != 1 {
		t.Fatalf("rows=%+v", rows)
	}
	// An adapter that silently vanished from the observation set is pruned; if
	// it comes back it re-seeds as dirty.
	c.Snapshot([]wifiObs{}, true)
	_, need := c.Snapshot([]wifiObs{connObs("a")}, true)
	if len(need) != 1 {
		t.Fatal("re-appearing adapter must re-seed dirty")
	}
}

func TestWiFiCacheNoteChangeAll(t *testing.T) {
	clk := newWiFiClock()
	c := newWiFiCache(macCacheCfg(), clk.now)
	c.Snapshot([]wifiObs{connObs("a"), {ID: "b", Name: "b"}}, true)
	applyNow(t, c, "a", connFacts("home", "5", 44, -52, 96))

	// Coarse change event: everything goes dirty, but a down adapter is cleaned
	// up by reconcile rather than gated-refreshed.
	c.NoteChangeAll()
	clk.advance(10 * time.Second)
	_, need := c.Snapshot([]wifiObs{connObs("a"), {ID: "b", Name: "b"}}, true)
	if len(need) != 1 || need[0] != "a" {
		t.Fatalf("need=%v want only the connected adapter", need)
	}
}

func TestWiFiCacheDirtyFactsNeverSupplyIdentity(t *testing.T) {
	clk := newWiFiClock()
	c := newWiFiCache(winCacheCfg(), clk.now)
	applyNow(t, c, "a", connFacts("home", "5", 44, -52, 96))

	// A roam marks the entry dirty. Until the refresh lands, the row must not
	// present the PREVIOUS network as the current one — even though the link
	// never went down and the observation looks unchanged.
	c.NoteRoamEnd("a")
	rows, _ := c.Snapshot([]wifiObs{connObs("a")}, true)
	if rows[0].State != "connected" {
		t.Fatalf("row=%+v", rows[0])
	}
	if rows[0].SSID != "" || rows[0].Band != "" || rows[0].Channel != 0 {
		t.Fatalf("stale identity served while dirty: %+v", rows[0])
	}

	// A permission verdict is about our access, not about the association, so it
	// survives the slow re-dirty rather than flickering away for a tick.
	c2 := newWiFiCache(winCacheCfg(), clk.now)
	applyNow(t, c2, "a", wifiGatedFacts{Connected: true, Permission: true})
	clk.advance(wifiPermissionRetryInterval + time.Second)
	rows, need := c2.Snapshot([]wifiObs{connObs("a")}, true)
	if len(need) != 1 {
		t.Fatalf("permission verdict must retry: %v", need)
	}
	if rows[0].Reason != "permission" {
		t.Fatalf("reason lost while re-dirtied: %+v", rows[0])
	}
}

func TestWiFiCacheApplyRejectsOvertakenClaim(t *testing.T) {
	clk := newWiFiClock()
	c := newWiFiCache(winCacheCfg(), clk.now)

	// The OS read runs outside the lock, so events can land mid-flight. Each of
	// these must invalidate the in-flight refresh rather than be overwritten by
	// it — the tick reconcile cannot catch a same-channel reconnect, so a
	// wrongly-applied refresh would leave the old SSID cached and looking clean.
	for _, tc := range []struct {
		name  string
		event func()
	}{
		{"disconnect", func() { c.NoteDisconnect("a") }},
		{"reconnect", func() { c.NoteDisconnect("a"); c.NoteConnect("a") }},
		{"roam", func() { c.NoteRoamEnd("a") }},
		{"adapter removed", func() { c.NoteAdapterRemoved("a") }},
		{"watcher reset", func() { c.Reset() }},
	} {
		c.NoteConnect("a")
		claim, ok := c.ClaimRefresh("a")
		if !ok {
			t.Fatalf("%s: claim", tc.name)
		}
		tc.event() // …arrives while the OS read is in flight
		if c.ApplyRefresh(claim, connFacts("stale", "5", 44, -52, 96)) {
			t.Fatalf("%s: overtaken refresh was applied", tc.name)
		}
		rows, _ := c.Snapshot([]wifiObs{connObs("a")}, true)
		if rows[0].SSID != "" {
			t.Fatalf("%s: stale SSID published: %+v", tc.name, rows[0])
		}
		clk.advance(10 * time.Second) // clear the rate limit for the next case
		c.Reset()
	}

	// The uncontested case still applies.
	c.NoteConnect("a")
	claim, ok := c.ClaimRefresh("a")
	if !ok {
		t.Fatal("claim")
	}
	if !c.ApplyRefresh(claim, connFacts("home", "5", 44, -52, 96)) {
		t.Fatal("uncontested refresh must apply")
	}
}

func TestWiFiCacheReconcileRetiresInFlightClaim(t *testing.T) {
	clk := newWiFiClock()
	c := newWiFiCache(winCacheCfg(), clk.now)
	applyNow(t, c, "a", connFacts("home", "5", 44, -52, 96))
	ob := connObs("a")
	ob.Channel = 44
	c.Snapshot([]wifiObs{ob}, true) // establish lastObsChannel

	// A roam is noticed by the tick, not by an event: the claim is taken, and
	// while the OS read is in flight the NEXT tick observes the new channel.
	clk.advance(30 * time.Second)
	c.NoteRoamEnd("a")
	claim, ok := c.ClaimRefresh("a")
	if !ok {
		t.Fatal("claim")
	}
	ob.Channel = 149
	c.Snapshot([]wifiObs{ob}, true)

	// The in-flight read describes the PRE-roam association. Applying it would
	// clear dirty, and the channel detector has already moved lastObsChannel to
	// 149 — it will not fire again, so the stale SSID would never be corrected.
	if c.ApplyRefresh(claim, connFacts("home", "5", 44, -52, 96)) {
		t.Fatal("a refresh overtaken by reconcile must not apply")
	}
	rows, _ := c.Snapshot([]wifiObs{ob}, true)
	if rows[0].SSID != "" {
		t.Fatalf("stale identity survived: %+v", rows[0])
	}
	clk.advance(30 * time.Second) // next tick, past the claim rate limit
	_, need := c.Snapshot([]wifiObs{ob}, true)
	if len(need) != 1 {
		t.Fatalf("entry must still want a refresh: %v", need)
	}

	// A pending refresh that nothing overtakes still lands — the invalidation
	// must fire on transitions only, or the entry could never go clean.
	claim, ok = c.ClaimRefresh("a")
	if !ok {
		t.Fatal("reclaim")
	}
	c.Snapshot([]wifiObs{ob}, true) // same observation: no new information
	if !c.ApplyRefresh(claim, connFacts("attic", "5", 149, -50, 90)) {
		t.Fatal("an unchallenged refresh must apply")
	}
	rows, _ = c.Snapshot([]wifiObs{ob}, true)
	if rows[0].SSID != "attic" {
		t.Fatalf("row=%+v", rows[0])
	}
}

func TestWiFiCacheSnapshotPruneRetiresInFlightClaim(t *testing.T) {
	clk := newWiFiClock()
	c := newWiFiCache(winCacheCfg(), clk.now)
	c.NoteConnect("a")
	claim, ok := c.ClaimRefresh("a")
	if !ok {
		t.Fatal("claim")
	}

	// The adapter vanishes from the enumeration and comes back before the read
	// returns. Both entries are generation zero, so only the cache epoch can
	// tell the claim it is answering about a different association.
	c.Snapshot(nil, true)
	c.Snapshot([]wifiObs{connObs("a")}, true)
	if c.ApplyRefresh(claim, connFacts("home", "5", 44, -52, 96)) {
		t.Fatal("a claim from a pruned entry must not apply to its replacement")
	}
	rows, _ := c.Snapshot([]wifiObs{connObs("a")}, true)
	if rows[0].SSID != "" {
		t.Fatalf("facts from the departed adapter published: %+v", rows[0])
	}
}

func TestWiFiCacheDownRetiresPendingReconnectClaim(t *testing.T) {
	clk := newWiFiClock()
	c := newWiFiCache(winCacheCfg(), clk.now)
	// Cached facts already say disconnected…
	c.Snapshot([]wifiObs{{ID: "a", Name: "a"}}, true)

	// …a tick observes the link back up and a refresh is claimed…
	clk.advance(30 * time.Second)
	c.Snapshot([]wifiObs{connObs("a")}, true)
	claim, ok := c.ClaimRefresh("a")
	if !ok {
		t.Fatal("reconnect must open a refresh")
	}

	// …and it is gone again before the read returns. The facts were already
	// "disconnected", so nothing about them changes here — but the claim is
	// still answering about the association that just ended.
	clk.advance(30 * time.Second)
	c.Snapshot([]wifiObs{{ID: "a", Name: "a"}}, true)
	if c.ApplyRefresh(claim, connFacts("home", "5", 44, -52, 96)) {
		t.Fatal("a refresh overtaken by a disconnect must not apply")
	}
	rows, _ := c.Snapshot([]wifiObs{{ID: "a", Name: "a"}}, true)
	if rows[0].State != "disconnected" || rows[0].SSID != "" {
		t.Fatalf("row=%+v", rows[0])
	}
	// And the departed identity must not resurface on a same-channel reconnect,
	// which the tick has no way to distinguish from a link that never left.
	clk.advance(30 * time.Second)
	rows, need := c.Snapshot([]wifiObs{connObs("a")}, true)
	if rows[0].SSID != "" {
		t.Fatalf("departed identity resurfaced: %+v", rows[0])
	}
	if len(need) != 1 {
		t.Fatalf("reconnect must ask for a fresh read: %v", need)
	}
}

func TestWiFiCacheReset(t *testing.T) {
	clk := newWiFiClock()
	c := newWiFiCache(macCacheCfg(), clk.now)
	c.Snapshot([]wifiObs{connObs("a")}, true)
	applyNow(t, c, "a", connFacts("home", "5", 44, -52, 96))

	c.Reset()
	rows, need := c.Snapshot([]wifiObs{connObs("a")}, true)
	if rows[0].SSID != "" {
		t.Fatalf("reset must drop facts: %+v", rows[0])
	}
	if len(need) != 1 {
		t.Fatal("reset must re-seed dirty")
	}
	if !c.WantSSID() {
		t.Fatal("demand stamp survives a reset — it describes callers, not OS state")
	}
}
