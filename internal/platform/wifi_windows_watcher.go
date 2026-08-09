//go:build windows

package platform

import (
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Windows event-driven Wi-Fi watcher: the OS side of the wifiCache split (see
// wifi_cache.go for why the split exists). One long-lived WlanSvc handle with a
// WlanRegisterNotification subscription replaces the per-tick location-gated
// reads: notifications and per-tick UNGATED calls keep the rows live, and the
// gated pair (current_connection + BSS list) runs only when the cache demands a
// refresh.
//
// Which wlanapi reads are location-gated is undocumented, so the split was
// settled empirically against the per-exe location consent store (Settings →
// Privacy → Location → Recent activity) — see TestWinWiFiLocationGatingIT,
// which is a live regression guard for exactly this line, not a one-off
// experiment. Verdict on Windows 11 26100 / Intel AX200:
//
//	gated:   WlanQueryInterface(current_connection), WlanGetNetworkBssList
//	ungated: WlanOpenHandle, WlanEnumInterfaces, WlanQueryInterface(rssi),
//	         WlanQueryInterface(channel_number), GetAdaptersAddresses
//
// So the steady-state tick reads state, channel, native dBm and link rates
// every round and touches nothing gated; only SSID and the frequency-derived
// band come from the cached refresh.
//
// The watcher is a package-level process-lifetime singleton: WlanSvc registers
// the notification callback per handle, windows.NewCallback slots are a finite
// process resource, and every per-server pipeline must share one cache for the
// location-access dedup to work at all. Failure to start (no WlanSvc: stripped
// -down VMs, wlan-less servers) falls back to the legacy full-read path —
// correct data, per-call location logs — retrying once a minute in case
// WlanSvc simply started after the agent.

const (
	wlanNotificationSourceACM = 0x00000008
	wlanNotificationSourceMSM = 0x00000010

	// WLAN_NOTIFICATION_ACM codes (wlanapi.h, sequential from 0).
	acmConnectionComplete = 10
	acmInterfaceRemoval   = 14
	acmDisconnected       = 21

	// WLAN_NOTIFICATION_MSM codes (wlanapi.h, sequential from 0).
	msmConnected           = 4
	msmRoamingEnd          = 6
	msmSignalQualityChange = 8 // pData → ULONG WLAN_SIGNAL_QUALITY 0-100
	msmDisconnected        = 10
	msmAdapterRemoval      = 13

	// ERROR_INVALID_STATE: a state-dependent query (current_connection, rssi,
	// channel) against a disconnected adapter. Not in x/sys zerrors by name.
	errorInvalidState = 5023
)

// wlanNotificationData mirrors WLAN_NOTIFICATION_DATA (amd64/arm64: the 4-byte
// implicit padding before pData comes from Go's natural alignment, matching C).
type wlanNotificationData struct {
	NotificationSource uint32
	NotificationCode   uint32
	InterfaceGUID      windows.GUID
	DataSize           uint32
	Data               unsafe.Pointer
}

// winWlanEvent is the tiny value copied OUT of the notification callback. The
// callback runs on a WlanSvc RPC thread where nothing may block, no WlanXxx
// call may be made (documented deadlock), and no pointer may outlive the
// return — so only these fields cross into Go land.
type winWlanEvent struct {
	Source  uint32
	Code    uint32
	GUID    windows.GUID
	Quality int // valid only for msmSignalQualityChange
}

// wlanNotificationEvent filters and copies one notification into a value event,
// reporting ok=false for sources/codes the watcher does not consume. Pure so
// the callback contract (minimal, no-panic) is testable without WlanSvc.
func wlanNotificationEvent(d *wlanNotificationData) (winWlanEvent, bool) {
	if d == nil {
		return winWlanEvent{}, false
	}
	ev := winWlanEvent{Source: d.NotificationSource, Code: d.NotificationCode, GUID: d.InterfaceGUID}
	switch d.NotificationSource {
	case wlanNotificationSourceACM:
		switch d.NotificationCode {
		case acmConnectionComplete, acmInterfaceRemoval, acmDisconnected:
			return ev, true
		}
	case wlanNotificationSourceMSM:
		switch d.NotificationCode {
		case msmConnected, msmRoamingEnd, msmDisconnected, msmAdapterRemoval:
			return ev, true
		case msmSignalQualityChange:
			if d.DataSize >= 4 && d.Data != nil {
				ev.Quality = int(*(*uint32)(d.Data))
				return ev, true
			}
		}
	}
	return winWlanEvent{}, false
}

// winWiFiWatcher owns the long-lived handle, the notification subscription, the
// event pump goroutine and the shared cache. All WlanSvc calls are handle-safe
// concurrently; only the handle SWAP (rebuild after WlanSvc restart) is
// serialized under mu.
type winWiFiWatcher struct {
	cache  *wifiCache
	events chan winWlanEvent

	mu          sync.Mutex
	handle      windows.Handle
	handleOK    bool
	lastRebuild time.Time

	retryMu      sync.Mutex
	retryPending map[windows.GUID]bool
	retryTimer   *time.Timer
}

var (
	winWatcherMu       sync.Mutex
	winWatcherInst     *winWiFiWatcher
	winWatcherLastFail time.Time

	// winWatcherCallback is created once per process: NewCallback slots are never
	// released, and one callback serves every handle generation (context unused —
	// state lives in the package singleton).
	winWatcherCallback = sync.OnceValue(func() uintptr {
		return windows.NewCallback(func(data *wlanNotificationData, _ uintptr) uintptr {
			if w := currentWinWatcher(); w != nil {
				if ev, ok := wlanNotificationEvent(data); ok {
					select {
					case w.events <- ev:
					default: // shed rather than block WlanSvc; the tick reconcile self-heals
					}
				}
			}
			return 0
		})
	})
)

func currentWinWatcher() *winWiFiWatcher {
	winWatcherMu.Lock()
	defer winWatcherMu.Unlock()
	return winWatcherInst
}

// getWinWatcher returns the process watcher, lazily starting it. A start
// failure is remembered for a minute so a wlan-less host does not pay an open
// attempt per tick per pipeline.
func getWinWatcher() *winWiFiWatcher {
	winWatcherMu.Lock()
	defer winWatcherMu.Unlock()
	if winWatcherInst != nil {
		return winWatcherInst
	}
	if !winWatcherLastFail.IsZero() && time.Since(winWatcherLastFail) < time.Minute {
		return nil
	}
	w, ok := startWinWatcher()
	if !ok {
		winWatcherLastFail = time.Now()
		return nil
	}
	winWatcherInst = w
	return w
}

func startWinWatcher() (*winWiFiWatcher, bool) {
	handle, ok := wlanOpen()
	if !ok {
		return nil, false
	}
	w := &winWiFiWatcher{
		cache: newWiFiCache(wifiCacheConfig{
			MinRefreshInterval: 5 * time.Second,
			// The gated query returns the SSID bytes whether we want them or
			// not, but the cache must not RETAIN a name no caller is entitled to
			// read. 90s of slack keeps a brief gap in grants (a server
			// reconnecting) from costing a re-read.
			SSIDDemandWindow: 90 * time.Second,
		}, time.Now),
		events:       make(chan winWlanEvent, 64),
		handle:       handle,
		handleOK:     true,
		retryPending: make(map[windows.GUID]bool),
	}
	if !wlanSubscribe(handle) {
		procWlanCloseHandle.Call(uintptr(handle), 0)
		return nil, false
	}
	go w.pump()
	return w, true
}

func wlanOpen() (windows.Handle, bool) {
	var handle windows.Handle
	var negotiated uint32
	r, _, _ := procWlanOpenHandle.Call(uintptr(wlanClientVersion2), 0,
		uintptr(unsafe.Pointer(&negotiated)), uintptr(unsafe.Pointer(&handle)))
	return handle, r == 0
}

func wlanSubscribe(handle windows.Handle) bool {
	var prev uint32
	r, _, _ := procWlanRegisterNotification.Call(
		uintptr(handle),
		uintptr(wlanNotificationSourceACM|wlanNotificationSourceMSM),
		1, // bIgnoreDuplicate
		winWatcherCallback(),
		0, 0,
		uintptr(unsafe.Pointer(&prev)),
	)
	return r == 0
}

// pump consumes callback events off the channel, translating them into cache
// state and eager gated refreshes — so SSID/band land ~seconds after a connect
// instead of waiting for the next 30s tick.
//
// A single reconnect legitimately costs up to two gated refreshes, not one:
// WlanSvc reports the connection in stages (MSM connected, then ACM
// connection_complete), the second arrives inside the 5s claim window, and the
// queued catch-up then re-reads. That is deliberate — the association details
// can still change between those stages — and the price is two location-log
// entries per network change against the ~2880/day the per-tick read produced.
func (w *winWiFiWatcher) pump() {
	for ev := range w.events {
		id := guidKey(ev.GUID)
		switch {
		case ev.Source == wlanNotificationSourceACM && ev.Code == acmConnectionComplete,
			ev.Source == wlanNotificationSourceMSM && ev.Code == msmConnected:
			w.cache.NoteConnect(id)
			w.eagerRefresh(ev.GUID)
		case ev.Source == wlanNotificationSourceMSM && ev.Code == msmRoamingEnd:
			w.cache.NoteRoamEnd(id)
			w.eagerRefresh(ev.GUID)
		case ev.Source == wlanNotificationSourceACM && ev.Code == acmDisconnected,
			ev.Source == wlanNotificationSourceMSM && ev.Code == msmDisconnected:
			w.cache.NoteDisconnect(id)
		case ev.Source == wlanNotificationSourceACM && ev.Code == acmInterfaceRemoval,
			ev.Source == wlanNotificationSourceMSM && ev.Code == msmAdapterRemoval:
			w.cache.NoteAdapterRemoved(id)
		case ev.Source == wlanNotificationSourceMSM && ev.Code == msmSignalQualityChange:
			w.cache.NoteSignalQuality(id, ev.Quality)
		}
	}
}

// eagerRefresh runs a gated refresh now if the rate limit allows, otherwise
// queues the adapter for one retry after the window — a connect burst becomes
// exactly one gated read plus at most one catch-up.
func (w *winWiFiWatcher) eagerRefresh(guid windows.GUID) {
	id := guidKey(guid)
	claim, ok := w.cache.ClaimRefresh(id)
	if !ok {
		if w.cache.entryDirty(id) {
			w.queueRetry(guid)
		}
		return
	}
	h, hok := w.currentHandle()
	if !hok {
		return // tick will rebuild; the entry stays dirty
	}
	if facts, rok := refreshWinAdapter(h, &guid, w.cache.WantSSID()); rok {
		w.cache.ApplyRefresh(claim, facts)
	}
}

func (w *winWiFiWatcher) queueRetry(guid windows.GUID) {
	w.retryMu.Lock()
	defer w.retryMu.Unlock()
	w.retryPending[guid] = true
	if w.retryTimer == nil {
		w.retryTimer = time.AfterFunc(w.cache.cfg.MinRefreshInterval+200*time.Millisecond, w.drainRetries)
	}
}

func (w *winWiFiWatcher) drainRetries() {
	w.retryMu.Lock()
	pending := w.retryPending
	w.retryPending = make(map[windows.GUID]bool)
	w.retryTimer = nil
	w.retryMu.Unlock()
	for guid := range pending {
		w.eagerRefresh(guid)
	}
}

func (w *winWiFiWatcher) currentHandle() (windows.Handle, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.handle, w.handleOK
}

// rebuild replaces a dead handle (WlanSvc restart: calls return
// ERROR_INVALID_HANDLE and the callback goes silent). failed names the handle
// the caller saw fail so concurrent tick goroutines rebuild once, not once
// each; rate-limited so a down WlanSvc costs one open attempt per window.
func (w *winWiFiWatcher) rebuild(failed windows.Handle) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.handleOK && w.handle != failed {
		return true // someone else already rebuilt
	}
	if time.Since(w.lastRebuild) < 5*time.Second {
		return w.handleOK
	}
	w.lastRebuild = time.Now()
	if w.handleOK {
		procWlanCloseHandle.Call(uintptr(w.handle), 0)
		w.handleOK = false
	}
	handle, ok := wlanOpen()
	if !ok {
		return false
	}
	if !wlanSubscribe(handle) {
		procWlanCloseHandle.Call(uintptr(handle), 0)
		return false
	}
	w.handle, w.handleOK = handle, true
	// Everything cached predates the blackout between handles: re-seed.
	w.cache.Reset()
	return true
}

// tick is the steady-state WiFi() implementation: ungated observations merged
// with cached gated facts. It performs a location-gated read only when the
// cache demands one (dirty + rate limit), which in the steady state is never.
func (w *winWiFiWatcher) tick(includeSSID bool) WiFiResult {
	for attempt := 0; attempt < 2; attempt++ {
		h, ok := w.currentHandle()
		if !ok {
			if !w.rebuild(h) {
				return WiFiResult{State: "unreadable", Reason: "driver"}
			}
			continue
		}
		res, invalid := w.tickWith(h, includeSSID)
		if !invalid {
			return res
		}
		if !w.rebuild(h) {
			return WiFiResult{State: "unreadable", Reason: "driver"}
		}
	}
	return WiFiResult{State: "unreadable", Reason: "driver"}
}

func (w *winWiFiWatcher) tickWith(handle windows.Handle, includeSSID bool) (WiFiResult, bool) {
	infos, r := wlanEnumAdapters(handle)
	if r == uintptr(windows.ERROR_INVALID_HANDLE) {
		return WiFiResult{}, true
	}
	if r != 0 {
		return WiFiResult{State: "unreadable", Reason: "driver"}, false
	}
	if len(infos) == 0 {
		w.cache.Snapshot(nil, includeSSID) // prune state for departed adapters
		return WiFiResult{State: "ok"}, false
	}

	speeds := winWirelessLinkSpeeds()
	obs := make([]wifiObs, 0, len(infos))
	guids := make(map[string]windows.GUID, len(infos))
	for i := range infos {
		id := guidKey(infos[i].InterfaceGUID)
		guids[id] = infos[i].InterfaceGUID
		ob := wifiObs{
			ID:        id,
			Name:      windows.UTF16ToString(infos[i].strInterfaceDescription[:]),
			Connected: infos[i].isState == wlanInterfaceStateConnected,
		}
		if ob.Connected {
			ob.Channel = queryChannelNumber(handle, &infos[i].InterfaceGUID) // ungated
			// Native live dBm, and quality derived from that same reading so the
			// two series can never disagree. Both are per-tick fresh; the
			// event-pushed quality in the cache only matters if this query fails
			// on some driver, and then it supplies the pair the other way round.
			if dbm, ok := queryRSSI(handle, &infos[i].InterfaceGUID); ok { // ungated
				ob.SignalDBm = &dbm
				q := qualityFromDBm(dbm)
				ob.Quality = &q
			}
			if sp, ok := speeds[id]; ok {
				ob.RxMbps, ob.TxMbps = sp.rx, sp.tx
			}
		}
		obs = append(obs, ob)
	}

	rows, need := w.cache.Snapshot(obs, includeSSID)
	if len(need) > 0 {
		withSSID := w.cache.WantSSID()
		applied := false
		for _, id := range need {
			guid, gok := guids[id]
			if !gok {
				continue
			}
			claim, cok := w.cache.ClaimRefresh(id)
			if !cok {
				continue
			}
			if facts, rok := refreshWinAdapter(handle, &guid, withSSID); rok {
				if w.cache.ApplyRefresh(claim, facts) {
					applied = true
				}
			}
		}
		if applied {
			rows, _ = w.cache.Snapshot(obs, includeSSID)
		}
	}
	return WiFiResult{State: "ok", Adapters: rows}, false
}

type winLinkSpeed struct{ rx, tx *float64 }

// winWirelessLinkSpeeds reads the current negotiated link rates of every
// wireless adapter from GetAdaptersAddresses — the ungated replacement for the
// association attributes' ulRx/TxRate (whose containing query is the gated
// one). NDIS updates these with rate adaptation, same source Task Manager
// shows; a skip-everything flag set keeps the walk cheap and address-blind.
func winWirelessLinkSpeeds() map[string]winLinkSpeed {
	flags := uint32(gaaFlagSkipUnicast | gaaFlagSkipAnycast | gaaFlagSkipMulticast | gaaFlagSkipDNSServer)
	size := uint32(15000)
	var buf []byte
	var head *windows.IpAdapterAddresses
	for attempt := 0; attempt < 4; attempt++ {
		buf = make([]byte, size)
		head = (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0]))
		err := windows.GetAdaptersAddresses(windows.AF_UNSPEC, flags, 0, head, &size)
		if err == nil {
			break
		}
		if err == windows.ERROR_BUFFER_OVERFLOW {
			continue
		}
		return nil
	}
	out := make(map[string]winLinkSpeed)
	for aa := head; aa != nil; aa = aa.Next {
		if aa.IfType != ifTypeIEEE80211 {
			continue
		}
		var sp winLinkSpeed
		// ^uint64(0) is NDIS "unknown"; 0 is unreported. Both stay nil — the
		// contract is absent, never a synthetic zero.
		if v := aa.ReceiveLinkSpeed; v != 0 && v != ^uint64(0) {
			rx := round1(float64(v) / 1e6)
			sp.rx = &rx
		}
		if v := aa.TransmitLinkSpeed; v != 0 && v != ^uint64(0) {
			tx := round1(float64(v) / 1e6)
			sp.tx = &tx
		}
		out[strings.ToUpper(windows.BytePtrToString(aa.AdapterName))] = sp
	}
	return out
}
