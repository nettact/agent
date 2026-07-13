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

	"github.com/nettact/protocol/capability"
)

// macOS Wi-Fi status via a thin read-only CoreWLAN bridge over purego/objc
// (CGO-free; no qualifying maintained Go binding exists — see
// planning/library-evidence.md). We only READ current-connection state from
// CWInterface: interfaceName, powerOn, ssid, rssiValue, transmitRate and the
// current CWChannel (number + band). CoreWLAN exposes no RX link rate, so that
// field is omitted on macOS. No scanning, no BSSID, no association/config APIs,
// no keys. Runs under normal user privileges; when macOS location policy
// withholds the SSID we report connected + reason=permission and keep every
// other readable field.

func wifiCapability() capability.Capability { return capability.NetWiFiRead }

// On macOS a netdev is marked wireless during snapshot assembly when a CoreWLAN
// adapter name matches it (the join in the collector), not via a per-name hook.
func ifaceIsWireless(string) bool { return false }

// cwAdapter is one CWInterface's raw readings, normalized into a WiFiStatus by
// normalizeCW. Kept as a plain struct so tests can drive normalization with a
// fake cwClient (no CoreWLAN required).
type cwAdapter struct {
	Name       string
	PoweredOn  bool
	HasChannel bool   // -[CWInterface wlanChannel] != nil ⇒ associated
	Band       string // "2.4" | "5" | "6" | ""
	Channel    int
	SSID       string
	SSIDKnown  bool // false when -ssid returned nil (disconnected OR privacy withheld)
	RSSI       int
	HasRSSI    bool
	TxRateMbps float64
	HasTxRate  bool
}

// cwClient is the fake-able CoreWLAN seam.
type cwClient interface {
	adapters() ([]cwAdapter, error)
}

// newCWClient is a package var so tests can substitute a fake without CoreWLAN.
var newCWClient = func() (cwClient, error) { return openCoreWLAN() }

func (genericPlatform) WiFi() WiFiResult {
	cl, err := newCWClient()
	if err != nil {
		// dlopen / class-resolution / shared-client failure — the subsystem is
		// unreadable; never misreported as "no adapter".
		return WiFiResult{State: "unreadable", Reason: "driver"}
	}
	ads, err := cl.adapters()
	if err != nil {
		return WiFiResult{State: "unreadable", Reason: "driver"}
	}
	adapters := make([]WiFiStatus, 0, len(ads))
	for _, a := range ads {
		adapters = append(adapters, normalizeCW(a))
	}
	return WiFiResult{State: "ok", Adapters: adapters}
}

func normalizeCW(a cwAdapter) WiFiStatus {
	st := WiFiStatus{ID: a.Name, Name: a.Name}
	if !a.PoweredOn || !a.HasChannel {
		st.State = "disconnected"
		return st
	}
	st.State = "connected"
	if a.SSIDKnown {
		st.SSID = a.SSID
	} else {
		st.Reason = "permission" // connected but SSID withheld by privacy policy
	}
	st.Band = a.Band
	st.Channel = a.Channel
	if a.HasRSSI && a.RSSI != 0 {
		dbm := a.RSSI
		st.SignalDBm = &dbm
		q := qualityFromDBm(dbm)
		st.Quality = &q
	}
	if a.HasTxRate && a.TxRateMbps > 0 {
		tx := round1(a.TxRateMbps)
		st.TxMbps = &tx
	}
	// RX link rate is not exposed by CoreWLAN → omitted (allowed per-field absence).
	return st
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

// adapters reads every CWInterface for one collection round. All CoreWLAN /
// Foundation message sends run on a locked OS thread inside a pushed autorelease
// pool: Cocoa convenience getters (-interfaces, -interfaceName, -ssid,
// -wlanChannel) return autoreleased (+0) objects, and without a pool in place
// the Objective-C runtime leaks them ("autoreleased with no pool in place").
// Results are copied into Go-owned values before the pool is drained, so nothing
// dangles. Thread pinning keeps the pool push/pop on the same thread (pools are
// thread-local) and the pop/unlock run on every return path via defer.
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
		if ssid := iface.Send(cw.sel.ssid); ssid != 0 {
			a.SSID = nsStringToGo(ssid, cw.sel.utf8)
			a.SSIDKnown = true
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
