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

	if !c.ClaimRefresh("a") {
		t.Fatal("claim should succeed")
	}
	c.ApplyRefresh("a", connFacts("home", "5", 44, -52, 96))
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
	c.ApplyRefresh("a", connFacts("home", "5", 44, -52, 96))

	c.NoteDisconnect("a")
	rows, need := c.Snapshot([]wifiObs{{ID: "a", Name: "a"}}, true)
	if rows[0].State != "disconnected" || rows[0].SSID != "" {
		t.Fatalf("row=%+v", rows[0])
	}
	if len(need) != 0 {
		t.Fatalf("disconnect must not request a gated refresh: %v", need)
	}
	if c.ClaimRefresh("a") {
		t.Fatal("nothing to refresh on a down link")
	}
}

func TestWiFiCacheRoamRefreshesIdentity(t *testing.T) {
	clk := newWiFiClock()
	c := newWiFiCache(winCacheCfg(), clk.now)
	c.ApplyRefresh("a", connFacts("home", "2.4", 6, -60, 80))

	clk.advance(30 * time.Second)
	c.NoteRoamEnd("a")
	if !c.ClaimRefresh("a") {
		t.Fatal("roam should open a refresh")
	}
	c.ApplyRefresh("a", connFacts("home", "5", 44, -50, 100))
	rows, _ := c.Snapshot([]wifiObs{connObs("a")}, true)
	if rows[0].Band != "5" || rows[0].Channel != 44 {
		t.Fatalf("row=%+v", rows[0])
	}
}

func TestWiFiCacheSignalEventsGoLiveAndStaleDBm(t *testing.T) {
	clk := newWiFiClock()
	c := newWiFiCache(winCacheCfg(), clk.now)
	c.ApplyRefresh("a", connFacts("home", "5", 44, -52, 96))

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
	c.ApplyRefresh("a", connFacts("home", "5", 44, -52, 96))

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
	c.ApplyRefresh("a", connFacts("home", "5", 44, -52, 96))

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
	c.ApplyRefresh("a", connFacts("home", "5", 149, -52, 96))
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
	if !c.ClaimRefresh("a") {
		t.Fatal("first claim")
	}
	if c.ClaimRefresh("a") {
		t.Fatal("burst must be rate-limited")
	}
	// The refresh FAILED (no Apply): dirty persists but the window still holds —
	// stamping per attempt is what stops a hot loop against a failing API.
	clk.advance(2 * time.Second)
	if c.ClaimRefresh("a") {
		t.Fatal("failed attempt must not reopen early")
	}
	clk.advance(4 * time.Second)
	if !c.ClaimRefresh("a") {
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
	c.ApplyRefresh("a", connFacts("home", "5", 44, -52, 96))

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
	if !c.ClaimRefresh("a") {
		t.Fatal("claim")
	}
	c.ApplyRefresh("a", wifiGatedFacts{Connected: true, Permission: true})
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
	c.ApplyRefresh("a", connFacts("home", "5", 44, -52, 96))

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
	c.ApplyRefresh("a", connFacts("secret", "5", 44, -52, 96))
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
	c.ApplyRefresh("a", connFacts("home", "5", 44, -52, 96))
	c.ApplyRefresh("b", connFacts("attic", "2.4", 6, -70, 60))

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
	c.ApplyRefresh("a", connFacts("home", "5", 44, -52, 96))

	// Coarse change event: everything goes dirty, but a down adapter is cleaned
	// up by reconcile rather than gated-refreshed.
	c.NoteChangeAll()
	clk.advance(10 * time.Second)
	_, need := c.Snapshot([]wifiObs{connObs("a"), {ID: "b", Name: "b"}}, true)
	if len(need) != 1 || need[0] != "a" {
		t.Fatalf("need=%v want only the connected adapter", need)
	}
}

func TestWiFiCacheReset(t *testing.T) {
	clk := newWiFiClock()
	c := newWiFiCache(macCacheCfg(), clk.now)
	c.Snapshot([]wifiObs{connObs("a")}, true)
	c.ApplyRefresh("a", connFacts("home", "5", 44, -52, 96))

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
