package platform

import (
	"sync"
	"time"
)

// Event-driven Wi-Fi cache shared by the OS watchers (Windows wlanapi
// notifications, macOS CoreWLAN events). It exists because reading the fields
// that identify a network (SSID, BSS data) is location-gated on both OSes:
// every such OS read is logged as a location access the user can see, and the
// 30-second regular tick — multiplied by one collector pipeline per server —
// turned that log into a permanent stream of location-access entries. The fix
// is to split the read path in two:
//
//   - gated facts (SSID, band, real dBm) are read ONLY when the network
//     actually changes — connect, roam, watcher (re)start, or a reconcile
//     mismatch — and cached here;
//   - everything the OS exposes ungated (link state, channel, link rates,
//     event-pushed signal quality) is observed fresh each tick and merged with
//     the cached facts into the same WiFiStatus rows the collector always saw.
//
// The obvious alternative — throttling the full gated read to a longer
// interval — was rejected: it still produces a periodic location-access stream,
// just a slower one, and the user-visible complaint is the periodicity itself.
//
// The cache is pure state-machine logic: injected clock, events in, snapshot
// out, no OS calls and no goroutines, guarded by one mutex. That keeps it
// build-tag-free (compiled and unit-tested on every host, lite included) and
// lets the per-OS watchers stay thin translation layers. It is owned by a
// package-level singleton in the watcher, deliberately process-lifetime: the
// desktop app restarts agentrt when its external-server list changes, and one
// process must keep exactly one OS notification registration and one cache no
// matter how many per-server pipelines call WiFi().
type wifiCacheConfig struct {
	// MinRefreshInterval rate-limits gated refresh attempts per adapter. A
	// connect delivers a burst of OS notifications (connection start / associated
	// / connected / complete plus signal updates); this collapses the burst into
	// one gated read. Stamped per ATTEMPT, not per success, so a failing refresh
	// cannot hot-loop the gated API.
	MinRefreshInterval time.Duration
	// SSIDDemandWindow guards platforms where reading the SSID is itself the
	// gated OS call (macOS -[CWInterface ssid]): a gated refresh may read the
	// SSID only if some caller passed includeSSID=true within this window, so
	// when every server's ssid grant is revoked the OS reads stop and the cached
	// SSID is dropped. Zero disables the guard for platforms where the SSID
	// bytes arrive embedded in a struct that must be fetched anyway (Windows
	// wlanConnectionAttributes) — there the disclosure gate is decode-time, per
	// caller, exactly as it was before the cache existed.
	SSIDDemandWindow time.Duration
	// ReasonPermissionWhenSSIDAbsent preserves the historical macOS telemetry
	// semantics: a connected row whose SSID is not disclosed to THIS caller
	// carries Reason "permission" (normalizeCW did this for both OS-withheld
	// SSIDs and includeSSID=false callers). Windows keeps it false — there
	// Reason "permission" means the OS location policy actually denied the read.
	ReasonPermissionWhenSSIDAbsent bool
}

// wifiPermissionRetryInterval bounds how stale a Permission verdict can get:
// after the OS denied a gated read, no WLAN event fires when the user later
// re-enables location access, so the cache re-marks the adapter dirty at this
// cadence. While denied the retry logs nothing (a denied read is not a location
// access), so the only cost is one cheap failing call per interval.
const wifiPermissionRetryInterval = 15 * time.Minute

// wifiGatedFacts is the product of one gated refresh of one adapter: the
// location-gated identity of the current association. SSIDRaw is kept as raw
// bytes and decoded per Snapshot caller, so servers with different ssid-read
// grants see different disclosures of the same cached fact.
type wifiGatedFacts struct {
	Connected bool
	SSIDRaw   []byte
	HasSSID   bool // SSIDRaw was captured (an empty hidden-network SSID still counts)
	Band      string
	Channel   int
	SignalDBm *int
	Quality   *int
	// Permission records that the OS location policy denied the gated read; the
	// row is then assembled from ungated observations with Reason "permission".
	Permission bool
	// RxMbps/TxMbps ride along for the non-cached fallback path only (they are
	// read in the same gated call there). The cache itself never serves them —
	// link rates change continuously, so a cached rate would be a stale number
	// masquerading as current; Snapshot takes rates exclusively from the
	// per-tick ungated observation.
	RxMbps *float64
	TxMbps *float64
}

// wifiObs is one adapter's ungated per-tick observation, assembled by the OS
// watcher from calls that are not location-gated. Zero values mean "this tick
// does not know" and defer to cached facts — never "known to be absent".
type wifiObs struct {
	ID        string
	Name      string
	Connected bool
	Band      string
	Channel   int
	SignalDBm *int
	Quality   *int
	RxMbps    *float64
	TxMbps    *float64
}

type wifiCacheEntry struct {
	facts     wifiGatedFacts
	haveFacts bool
	// dirty means the cached facts are missing or suspected stale and a gated
	// refresh should run (subject to the rate limit).
	dirty       bool
	lastAttempt time.Time
	// liveQuality is the most recent event-pushed signal quality. Once it
	// diverges from the refresh-time reading, the refresh-time native dBm no
	// longer describes the current signal either, so dbmStale flips and the
	// snapshot derives dBm from quality instead of serving a stale native value.
	liveQuality *int
	dbmStale    bool
	// last tick's ungated channel/band observations; a change is the ungated
	// signature of a roam or channel switch and triggers a refresh.
	lastObsBand    string
	lastObsChannel int
}

type wifiCache struct {
	mu             sync.Mutex
	cfg            wifiCacheConfig
	now            func() time.Time
	entries        map[string]*wifiCacheEntry
	lastSSIDDemand time.Time
}

func newWiFiCache(cfg wifiCacheConfig, now func() time.Time) *wifiCache {
	return &wifiCache{cfg: cfg, now: now, entries: make(map[string]*wifiCacheEntry)}
}

func (c *wifiCache) entry(id string) *wifiCacheEntry {
	e := c.entries[id]
	if e == nil {
		e = &wifiCacheEntry{}
		c.entries[id] = e
	}
	return e
}

// NoteConnect marks an adapter as newly connected: its gated facts are unknown
// until a refresh runs.
func (c *wifiCache) NoteConnect(id string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entry(id).dirty = true
}

// NoteDisconnect is authoritative without any OS call: a disconnected adapter
// has no gated facts worth fetching, so the entry is overwritten in place and
// NOT marked dirty — scheduling a gated refresh just to learn "disconnected"
// would log a location access for nothing.
func (c *wifiCache) NoteDisconnect(id string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e := c.entry(id)
	e.facts = wifiGatedFacts{}
	e.haveFacts = true
	e.dirty = false
	e.liveQuality = nil
	e.dbmStale = false
}

// NoteRoamEnd marks a completed roam: still connected, but the BSS (and so
// band/channel/SSID on an ESS boundary) may have changed.
func (c *wifiCache) NoteRoamEnd(id string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entry(id).dirty = true
}

// NoteChangeAll marks every entry dirty — for platforms whose change callback
// deliberately does no per-event work (the macOS delegate IMP runs on a
// CoreWLAN dispatch thread and just signals a channel, so which interface
// changed is never extracted). Coarse is fine: Macs have one Wi-Fi interface,
// and reconcile clears the flag for anything actually down.
func (c *wifiCache) NoteChangeAll() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, e := range c.entries {
		e.dirty = true
	}
}

// NoteSignalQuality records an event-pushed quality reading (0-100). For an
// unknown adapter it implies a missed connect, so the fresh entry starts dirty.
func (c *wifiCache) NoteSignalQuality(id string, quality int) {
	if quality < 0 {
		quality = 0
	}
	if quality > 100 {
		quality = 100
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	known := c.entries[id] != nil
	e := c.entry(id)
	if !known {
		e.dirty = true
	}
	q := quality
	e.liveQuality = &q
	e.dbmStale = true
}

func (c *wifiCache) NoteAdapterRemoved(id string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, id)
}

// Reset drops every entry — used when the watcher (re)starts or its OS handle
// is rebuilt, after which nothing cached is trustworthy. The SSID demand stamp
// survives: demand describes the callers, not the OS state.
func (c *wifiCache) Reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = make(map[string]*wifiCacheEntry)
}

// ClaimRefresh reports whether a gated refresh of id should run now, stamping
// the attempt when it says yes. Split from ApplyRefresh so the state machine
// stays pure while the actual OS read happens outside the lock; the stamp-on-
// claim (not on apply) is what prevents a failing refresh from hot-looping.
func (c *wifiCache) ClaimRefresh(id string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	e := c.entries[id]
	if e == nil || !e.dirty {
		return false
	}
	if !e.lastAttempt.IsZero() && c.now().Sub(e.lastAttempt) < c.cfg.MinRefreshInterval {
		return false
	}
	e.lastAttempt = c.now()
	return true
}

// entryDirty reports whether id currently wants a refresh — used by the eager
// event paths to decide whether a rate-limited claim is worth a retry timer.
func (c *wifiCache) entryDirty(id string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	e := c.entries[id]
	return e != nil && e.dirty
}

// ApplyRefresh stores the product of a gated refresh.
func (c *wifiCache) ApplyRefresh(id string, f wifiGatedFacts) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e := c.entry(id)
	e.facts = f
	e.haveFacts = true
	e.dirty = false
	e.dbmStale = false
	if f.Quality != nil {
		q := *f.Quality
		e.liveQuality = &q
	} else {
		e.liveQuality = nil
	}
}

// WantSSID reports whether a gated refresh is currently allowed to read the
// SSID from the OS (see SSIDDemandWindow).
func (c *wifiCache) WantSSID() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.wantSSIDLocked()
}

func (c *wifiCache) wantSSIDLocked() bool {
	if c.cfg.SSIDDemandWindow == 0 {
		return true
	}
	return !c.lastSSIDDemand.IsZero() && c.now().Sub(c.lastSSIDDemand) <= c.cfg.SSIDDemandWindow
}

// Snapshot merges this tick's ungated observations with the cached gated facts
// into WiFiStatus rows, and returns the adapters that want a gated refresh.
// obs must be the COMPLETE current adapter set — entries for absent adapters
// are pruned (a watcher whose enumeration failed must not call Snapshot).
//
// Merging never invents data: a categorical field this tick cannot observe and
// the cache does not know stays empty, and a connected row whose refresh is
// still pending (or rate-limited) goes out with absent categorical fields for
// that tick — nil/empty means unknown, exactly the WiFiStatus contract.
func (c *wifiCache) Snapshot(obs []wifiObs, includeSSID bool) ([]WiFiStatus, []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()

	if includeSSID {
		c.lastSSIDDemand = now
	} else if c.cfg.SSIDDemandWindow > 0 && !c.wantSSIDLocked() {
		// Every caller's ssid grant is gone: drop the cached SSIDs so a stale
		// network name cannot outlive the demand that justified reading it.
		for _, e := range c.entries {
			e.facts.SSIDRaw = nil
			e.facts.HasSSID = false
		}
	}

	rows := make([]WiFiStatus, 0, len(obs))
	seen := make(map[string]bool, len(obs))
	var need []string
	for _, ob := range obs {
		seen[ob.ID] = true
		e := c.entries[ob.ID]
		if e == nil {
			e = c.entry(ob.ID)
			e.dirty = true // startup / arrival: facts unknown
		}
		c.reconcileLocked(e, ob, now)
		rows = append(rows, c.assembleLocked(e, ob, includeSSID))
		if e.dirty && (e.lastAttempt.IsZero() || now.Sub(e.lastAttempt) >= c.cfg.MinRefreshInterval) {
			need = append(need, ob.ID)
		}
	}
	for id := range c.entries {
		if !seen[id] {
			delete(c.entries, id)
		}
	}
	return rows, need
}

// reconcileLocked compares the ungated observation against the cached facts and
// marks the entry dirty when they disagree — the safety net for dropped or
// missed OS notifications (the event channel sheds load rather than blocking
// the OS callback, so the tick must be able to repair any resulting drift).
func (c *wifiCache) reconcileLocked(e *wifiCacheEntry, ob wifiObs, now time.Time) {
	if !ob.Connected {
		// Observation is authoritative for "down" and down needs no gated data:
		// fold it in as if the disconnect event had arrived, without a refresh.
		// dirty always clears — whatever suspicion was raised, a down link never
		// justifies a gated read (it re-arms via the facts mismatch on reconnect).
		if !e.haveFacts || e.facts.Connected {
			e.facts = wifiGatedFacts{}
			e.haveFacts = true
			e.liveQuality = nil
			e.dbmStale = false
		}
		e.dirty = false
		e.lastObsBand, e.lastObsChannel = "", 0
		return
	}

	if !e.haveFacts || !e.facts.Connected {
		e.dirty = true // connected but facts missing or describing a down link
	}
	// An ungated channel/band change is the observable signature of a roam or
	// channel switch that produced no (or a lost) notification.
	if ob.Channel != 0 && e.lastObsChannel != 0 && ob.Channel != e.lastObsChannel {
		e.dirty = true
	}
	if ob.Band != "" && e.lastObsBand != "" && ob.Band != e.lastObsBand {
		e.dirty = true
	}
	if ob.Channel != 0 {
		e.lastObsChannel = ob.Channel
	}
	if ob.Band != "" {
		e.lastObsBand = ob.Band
	}
	// SSID demand appeared after the last refresh ran without it (demand-gated
	// platforms only). Permission facts are excluded — retrying those every tick
	// would be a hot loop against a policy denial (they retry slowly below).
	if c.cfg.SSIDDemandWindow > 0 && c.wantSSIDLocked() &&
		e.haveFacts && e.facts.Connected && !e.facts.HasSSID && !e.facts.Permission {
		e.dirty = true
	}
	// A Permission verdict never clears itself: no OS event fires when the user
	// re-enables location access, so retry on a slow clock.
	if e.haveFacts && e.facts.Permission &&
		!e.lastAttempt.IsZero() && now.Sub(e.lastAttempt) >= wifiPermissionRetryInterval {
		e.dirty = true
	}
}

// assembleLocked builds one adapter's WiFiStatus row from the observation plus
// cached facts. Facts contribute categorical fields only while they describe a
// connected link — after a state mismatch the stale identity of the PREVIOUS
// network must not leak onto the new one, so those fields go absent for the
// tick it takes the refresh to land.
//
// Note what this changes for a gated read that keeps failing: the row now says
// connected with the categorical fields absent, where the old direct read said
// unreadable(driver). That is the more honest verdict — the ungated half of the
// read establishes that the link IS up and how strong it is, and only the
// network's identity is unknown — but it means a persistently broken
// current_connection query no longer produces a chart gap in wifi.up.
func (c *wifiCache) assembleLocked(e *wifiCacheEntry, ob wifiObs, includeSSID bool) WiFiStatus {
	st := WiFiStatus{ID: ob.ID, Name: ob.Name}
	if !ob.Connected {
		st.State = "disconnected"
		return st
	}
	st.State = "connected"

	factsUsable := e.haveFacts && e.facts.Connected
	if factsUsable && e.facts.Permission {
		st.Reason = "permission"
	}
	if includeSSID && factsUsable && e.facts.HasSSID {
		st.SSID = string(e.facts.SSIDRaw)
	}

	st.Band = ob.Band
	if st.Band == "" && factsUsable {
		st.Band = e.facts.Band
	}
	st.Channel = ob.Channel
	if st.Channel == 0 && factsUsable {
		st.Channel = e.facts.Channel
	}
	// Only 2.4 GHz channel numbers are unambiguous; 5/6 GHz overlap, so band is
	// never guessed there (same rule the direct read path always applied).
	if st.Band == "" && st.Channel > 0 && st.Channel <= 14 {
		st.Band = "2.4"
	}

	quality := ob.Quality
	if quality == nil {
		quality = e.liveQuality
	}
	if quality == nil && factsUsable {
		quality = e.facts.Quality
	}
	if quality != nil {
		q := *quality
		st.Quality = &q
	}

	switch {
	case ob.SignalDBm != nil:
		v := *ob.SignalDBm
		st.SignalDBm = &v
	case factsUsable && !e.dbmStale && e.facts.SignalDBm != nil:
		v := *e.facts.SignalDBm
		st.SignalDBm = &v
	case quality != nil:
		// The refresh-time native dBm no longer matches the event-updated quality
		// (or was never read): derive it rather than serve a stale native value.
		v := dbmFromQuality(*quality)
		st.SignalDBm = &v
	}

	if ob.RxMbps != nil {
		v := *ob.RxMbps
		st.RxMbps = &v
	}
	if ob.TxMbps != nil {
		v := *ob.TxMbps
		st.TxMbps = &v
	}

	if c.cfg.ReasonPermissionWhenSSIDAbsent && st.SSID == "" && st.Reason == "" {
		st.Reason = "permission"
	}
	return st
}
