//go:build darwin

package platform

import (
	"errors"
	"fmt"
	"runtime"
	"sync"
	"unsafe"

	"github.com/ebitengine/purego"
	"github.com/ebitengine/purego/objc"

	"github.com/nettact/protocol/permission"
)

// macOS Wi-Fi status via a thin read-only CoreWLAN bridge over purego/objc
// (CGO-free; no qualifying maintained Go binding exists — see
// planning/library-evidence.md). We only READ current-connection state from
// CWInterface: interfaceName, powerOn, rssiValue, transmitRate and the current
// CWChannel (number + band). CoreWLAN exposes no RX link rate, so that field is
// omitted on macOS. No scanning, no BSSID, no association/config APIs, no keys.
// Runs under normal user privileges.
//
// Of those reads exactly one is location-gated: -[CWInterface ssid], which
// macOS both withholds without location permission and logs as a location
// access when granted. The 30-second tick therefore never calls it — the SSID
// lives in the shared wifiCache (wifi_cache.go) and is re-read only when the
// network actually changes, signaled by CWWiFiClient delegate events
// (wifi_darwin_watcher.go) with the cache's ungated-transition reconcile
// (link state, channel, band) as the event-less fallback. Every other field
// stays a fresh ungated per-tick read, exactly as before.

func wifiPermissions() []permission.ID {
	return []permission.ID{permission.NetWiFiStatusRead, permission.NetWiFiSSIDRead}
}

// On macOS a netdev is marked wireless during snapshot assembly when a CoreWLAN
// adapter name matches it (the join in the collector), not via a per-name hook.
func ifaceIsWireless(string) bool { return false }

// cwAdapter is one CWInterface's raw UNGATED readings; the gated SSID travels
// separately through cwClient.ssid so a caller cannot fetch it by accident.
// Kept as a plain struct so tests can drive the tick with a fake cwClient (no
// CoreWLAN required).
type cwAdapter struct {
	Name       string
	PoweredOn  bool
	HasChannel bool   // -[CWInterface wlanChannel] != nil ⇒ associated
	Band       string // "2.4" | "5" | "6" | ""
	Channel    int
	RSSI       int
	HasRSSI    bool
	TxRateMbps float64
	HasTxRate  bool
}

// cwClient is the fake-able CoreWLAN seam, split along the location-gating
// line: adapters() performs only ungated reads and is safe every tick; ssid()
// is THE gated call and is invoked solely by the cache-driven refresh.
type cwClient interface {
	adapters() ([]cwAdapter, error)
	// ssid returns the current SSID of the named interface. known=false with a
	// nil error means CoreWLAN returned nil — disconnected, or the SSID withheld
	// by the location privacy policy (indistinguishable at this API).
	ssid(ifname string) (s string, known bool, err error)
}

// newCWClient is a package var so tests can substitute a fake without CoreWLAN.
var newCWClient = func() (cwClient, error) { return openCoreWLAN() }

func (darwinPlatform) WiFi(includeSSID bool) WiFiResult {
	w, err := getDarwinWatcher()
	if err != nil {
		// dlopen / class-resolution / shared-client failure — the subsystem is
		// unreadable; never misreported as "no adapter".
		return WiFiResult{State: "unreadable", Reason: "driver"}
	}
	return darwinWiFiTick(w.cl, w.cache, includeSSID)
}

// darwinWiFiTick is one WiFi() round: ungated observations for every adapter,
// merged with the cached gated facts; a gated ssid() read runs only when the
// cache demands a refresh. Free function so tests drive it with a fake client
// and clock without the watcher singleton.
func darwinWiFiTick(cl cwClient, cache *wifiCache, includeSSID bool) WiFiResult {
	ads, err := cl.adapters()
	if err != nil {
		return WiFiResult{State: "unreadable", Reason: "driver"}
	}
	obs := make([]wifiObs, 0, len(ads))
	for _, a := range ads {
		obs = append(obs, cwObs(a))
	}
	rows, need := cache.Snapshot(obs, includeSSID)
	if len(need) > 0 {
		applied := false
		for _, id := range need {
			claim, ok := cache.ClaimRefresh(id)
			if !ok {
				continue
			}
			if facts, rok := refreshDarwinAdapter(cl, cache, id); rok {
				if cache.ApplyRefresh(claim, facts) {
					applied = true
				}
			}
		}
		if applied {
			rows, _ = cache.Snapshot(obs, includeSSID)
		}
	}
	return WiFiResult{State: "ok", Adapters: rows}
}

// cwObs converts one adapter's ungated readings into the tick observation.
// The historical normalization rules carry over: powered-off or channel-less
// means disconnected, RSSI 0 is "driver did not report" rather than a value,
// and rates are never inferred zeros.
func cwObs(a cwAdapter) wifiObs {
	ob := wifiObs{ID: a.Name, Name: a.Name, Connected: a.PoweredOn && a.HasChannel}
	if !ob.Connected {
		return ob
	}
	ob.Band = a.Band
	ob.Channel = a.Channel
	if a.HasRSSI && a.RSSI != 0 {
		dbm := a.RSSI
		ob.SignalDBm = &dbm
		q := qualityFromDBm(dbm)
		ob.Quality = &q
	}
	if a.HasTxRate && a.TxRateMbps > 0 {
		tx := round1(a.TxRateMbps)
		ob.TxMbps = &tx
	}
	return ob
}

// refreshDarwinAdapter is the gated refresh executor. The SSID is read from
// the OS only while some caller's ssid grant is live (cache.WantSSID) — on
// macOS the read itself is the location access, so unlike Windows there is no
// "fetch the struct, decode on demand" middle ground.
func refreshDarwinAdapter(cl cwClient, cache *wifiCache, ifname string) (wifiGatedFacts, bool) {
	if !cache.WantSSID() {
		return wifiGatedFacts{Connected: true}, true
	}
	s, known, err := cl.ssid(ifname)
	if err != nil {
		return wifiGatedFacts{}, false // transient — stay dirty, retry later
	}
	if !known {
		// Connected (the caller checked the ungated state) but CoreWLAN returned
		// nil: the location privacy policy withheld the name. Permission verdicts
		// retry on the slow clock only — never per tick.
		return wifiGatedFacts{Connected: true, Permission: true}, true
	}
	return wifiGatedFacts{Connected: true, SSIDRaw: []byte(s), HasSSID: true}, true
}

// ---- real CoreWLAN implementation (objc messaging) ----

const coreWLANPath = "/System/Library/Frameworks/CoreWLAN.framework/CoreWLAN"

// cwSelectors caches every Objective-C selector we send, resolved once (each
// objc.RegisterName grabs the global runtime lock, so per-round registration is
// avoided).
type cwSelectors struct {
	interfaces, count, objectAtIndex, name, powerOn, ssid,
	rssi, tx, wlanChannel, channelNumber, channelBand, utf8 objc.SEL
}

// coreWLAN holds the one-time CoreWLAN setup: the shared client, cached
// selectors, and the autorelease-pool push/pop functions bound from libobjc
// (purego/objc supplies no pool helper). Populated exactly once by loadCoreWLAN.
type coreWLAN struct {
	shared   objc.ID
	sel      cwSelectors
	poolPush func() unsafe.Pointer
	poolPop  func(unsafe.Pointer)
}

var (
	coreWLANOnce sync.Once
	coreWLANInst *coreWLAN
	coreWLANErr  error
)

// loadCoreWLAN performs the one-time dynamic load, class/shared-client
// resolution, selector caching, and autorelease-pool binding. Any failure
// (including an unexpected purego panic) is captured as an error so the caller
// reports collection-level unreadable(driver) rather than panicking or leaking.
func loadCoreWLAN() (*coreWLAN, error) {
	coreWLANOnce.Do(func() {
		defer func() {
			if r := recover(); r != nil {
				coreWLANInst = nil
				coreWLANErr = fmt.Errorf("CoreWLAN init failed: %v", r)
			}
		}()

		if _, err := purego.Dlopen(coreWLANPath, purego.RTLD_GLOBAL|purego.RTLD_NOW); err != nil {
			coreWLANErr = err
			return
		}

		cw := &coreWLAN{}
		// objc_autoreleasePoolPush/Pop live in libobjc, already loaded by the objc
		// package; RTLD_DEFAULT resolves them without re-dlopening. A missing
		// symbol makes RegisterLibFunc panic, caught by the recover above.
		purego.RegisterLibFunc(&cw.poolPush, purego.RTLD_DEFAULT, "objc_autoreleasePoolPush")
		purego.RegisterLibFunc(&cw.poolPop, purego.RTLD_DEFAULT, "objc_autoreleasePoolPop")
		if cw.poolPush == nil || cw.poolPop == nil {
			coreWLANErr = errors.New("CoreWLAN: autorelease pool functions unavailable")
			return
		}

		cls := objc.GetClass("CWWiFiClient")
		if cls == 0 {
			coreWLANErr = errors.New("CoreWLAN: CWWiFiClient class unavailable")
			return
		}
		cw.shared = objc.ID(cls).Send(objc.RegisterName("sharedWiFiClient"))
		if cw.shared == 0 {
			coreWLANErr = errors.New("CoreWLAN: sharedWiFiClient returned nil")
			return
		}

		cw.sel = cwSelectors{
			interfaces:    objc.RegisterName("interfaces"),
			count:         objc.RegisterName("count"),
			objectAtIndex: objc.RegisterName("objectAtIndex:"),
			name:          objc.RegisterName("interfaceName"),
			powerOn:       objc.RegisterName("powerOn"),
			ssid:          objc.RegisterName("ssid"),
			rssi:          objc.RegisterName("rssiValue"),
			tx:            objc.RegisterName("transmitRate"),
			wlanChannel:   objc.RegisterName("wlanChannel"),
			channelNumber: objc.RegisterName("channelNumber"),
			channelBand:   objc.RegisterName("channelBand"),
			utf8:          objc.RegisterName("UTF8String"),
		}
		coreWLANInst = cw
	})
	return coreWLANInst, coreWLANErr
}

type coreWLANClient struct{ cw *coreWLAN }

func openCoreWLAN() (cwClient, error) {
	cw, err := loadCoreWLAN()
	if err != nil {
		return nil, err
	}
	return &coreWLANClient{cw: cw}, nil
}

// adapters reads every CWInterface's UNGATED fields for one collection round.
// All CoreWLAN / Foundation message sends run on a locked OS thread inside a
// pushed autorelease pool: Cocoa convenience getters (-interfaces,
// -interfaceName, -wlanChannel) return autoreleased (+0) objects, and without a
// pool in place the Objective-C runtime leaks them ("autoreleased with no pool
// in place"). Results are copied into Go-owned values before the pool is
// drained, so nothing dangles. Thread pinning keeps the pool push/pop on the
// same thread (pools are thread-local) and the pop/unlock run on every return
// path via defer. The -ssid selector is deliberately never sent here.
func (c *coreWLANClient) adapters() ([]cwAdapter, error) {
	cw := c.cw
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	pool := cw.poolPush()
	defer cw.poolPop(pool)

	arr := cw.shared.Send(cw.sel.interfaces)
	if arr == 0 {
		return nil, nil
	}
	count := int(objc.Send[uint64](arr, cw.sel.count))
	out := make([]cwAdapter, 0, count)
	for i := 0; i < count; i++ {
		iface := arr.Send(cw.sel.objectAtIndex, uint64(i))
		if iface == 0 {
			continue
		}
		a := cwAdapter{
			Name:      nsStringToGo(iface.Send(cw.sel.name), cw.sel.utf8),
			PoweredOn: objc.Send[bool](iface, cw.sel.powerOn),
		}
		if ch := iface.Send(cw.sel.wlanChannel); ch != 0 {
			a.HasChannel = true
			a.Channel = objc.Send[int](ch, cw.sel.channelNumber)
			a.Band = cwBand(objc.Send[int](ch, cw.sel.channelBand))
		}
		a.RSSI = objc.Send[int](iface, cw.sel.rssi)
		a.HasRSSI = true
		a.TxRateMbps = objc.Send[float64](iface, cw.sel.tx)
		a.HasTxRate = true
		out = append(out, a)
	}
	return out, nil
}

// ssid performs THE location-gated CoreWLAN read: -[CWInterface ssid] on the
// named interface. Same thread/pool discipline as adapters. The interface is
// found by walking -interfaces and matching the name locally, which avoids
// having to construct an NSString for -interfaceWithName:.
func (c *coreWLANClient) ssid(ifname string) (string, bool, error) {
	cw := c.cw
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	pool := cw.poolPush()
	defer cw.poolPop(pool)

	arr := cw.shared.Send(cw.sel.interfaces)
	if arr == 0 {
		return "", false, nil
	}
	count := int(objc.Send[uint64](arr, cw.sel.count))
	for i := 0; i < count; i++ {
		iface := arr.Send(cw.sel.objectAtIndex, uint64(i))
		if iface == 0 || nsStringToGo(iface.Send(cw.sel.name), cw.sel.utf8) != ifname {
			continue
		}
		ssid := iface.Send(cw.sel.ssid)
		if ssid == 0 {
			return "", false, nil
		}
		return nsStringToGo(ssid, cw.sel.utf8), true, nil
	}
	return "", false, nil
}

// cwBand maps CWChannelBand to the band string. CWChannelBandUnknown=0,
// 2GHz=1, 5GHz=2, 6GHz=3.
func cwBand(b int) string {
	switch b {
	case 1:
		return "2.4"
	case 2:
		return "5"
	case 3:
		return "6"
	default:
		return ""
	}
}

// nsStringToGo copies an NSString into a Go string via -UTF8String (which must be
// read while the NSString is still alive, i.e. before the enclosing pool drains).
// Returns "" for a nil NSString.
func nsStringToGo(s objc.ID, selUTF8 objc.SEL) string {
	if s == 0 {
		return ""
	}
	ptr := objc.Send[unsafe.Pointer](s, selUTF8)
	if ptr == nil {
		return ""
	}
	n := 0
	for *(*byte)(unsafe.Add(ptr, n)) != 0 {
		n++
	}
	return string(unsafe.Slice((*byte)(ptr), n))
}
