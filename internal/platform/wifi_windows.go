//go:build windows

package platform

import (
	"fmt"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/nettact/protocol/permission"
)

// Windows Wi-Fi status via a thin wlanapi.dll adapter (no qualifying maintained
// Go library exists; see planning/library-evidence.md). CGO-free, lazy-DLL, no
// Administrator required — the same pattern as the existing iphlpapi code. We
// only READ current-connection state (SSID, state, quality, rx/tx rate, dBm,
// band/channel). No scanning trigger, no BSSID storage, no profile/key APIs, no
// connect/disconnect.
//
// Since Windows 10 1809 the reads that identify a network —
// WlanQueryInterface(current_connection) and WlanGetNetworkBssList — are
// location-gated: every call is logged as a location access the user can see.
// WiFi() therefore routes through the event-driven watcher
// (wifi_windows_watcher.go + wifi_cache.go), which confines those two calls to
// actual network changes; the direct full read below survives as the fallback
// for hosts where the watcher cannot start (no WlanSvc) and as the refresh
// executor the watcher itself invokes.

func wifiPermissions() []permission.ID {
	return []permission.ID{permission.NetWiFiStatusRead, permission.NetWiFiSSIDRead}
}

// On Windows IsWireless is set from the adapter IfType during the
// GetAdaptersAddresses walk (see platform_windows.go), not from a per-name hook.
func ifaceIsWireless(string) bool { return false }

var (
	wlanapi                      = windows.NewLazySystemDLL("wlanapi.dll")
	procWlanOpenHandle           = wlanapi.NewProc("WlanOpenHandle")
	procWlanCloseHandle          = wlanapi.NewProc("WlanCloseHandle")
	procWlanEnumInterfaces       = wlanapi.NewProc("WlanEnumInterfaces")
	procWlanQueryInterface       = wlanapi.NewProc("WlanQueryInterface")
	procWlanGetNetworkBssList    = wlanapi.NewProc("WlanGetNetworkBssList")
	procWlanRegisterNotification = wlanapi.NewProc("WlanRegisterNotification")
	procWlanFreeMemory           = wlanapi.NewProc("WlanFreeMemory")
)

const (
	wlanClientVersion2 = 2

	wlanIntfOpcodeCurrentConnection = 7          // WLAN_INTF_OPCODE.current_connection
	wlanIntfOpcodeChannelNumber     = 8          // WLAN_INTF_OPCODE.channel_number
	wlanIntfOpcodeRSSI              = 0x10000102 // WLAN_INTF_OPCODE.rssi → LONG dBm

	// WLAN_INTERFACE_STATE
	wlanInterfaceStateNotReady       = 0
	wlanInterfaceStateConnected      = 1
	wlanInterfaceStateAdHocFormed    = 2
	wlanInterfaceStateDisconnecting  = 3
	wlanInterfaceStateDisconnected   = 4
	wlanInterfaceStateAssociating    = 5
	wlanInterfaceStateDiscovering    = 6
	wlanInterfaceStateAuthenticating = 7

	dot11BssTypeAny = 3 // DOT11_BSS_TYPE.dot11_BSS_type_any
)

// ---- mirrored wlanapi structs (amd64/arm64 natural alignment matches C) ----

type dot11SSID struct {
	uSSIDLength uint32
	ucSSID      [32]byte
}

type dot11MacAddress [6]byte

type wlanInterfaceInfo struct {
	InterfaceGUID           windows.GUID
	strInterfaceDescription [256]uint16
	isState                 uint32 // WLAN_INTERFACE_STATE
}

type wlanInterfaceInfoList struct {
	dwNumberOfItems uint32
	dwIndex         uint32
	interfaceInfo   [1]wlanInterfaceInfo
}

type wlanAssociationAttributes struct {
	dot11Ssid         dot11SSID
	dot11BssType      uint32
	dot11Bssid        dot11MacAddress
	dot11PhyType      uint32
	uDot11PhyIndex    uint32
	wlanSignalQuality uint32 // 0-100
	ulRxRate          uint32 // kbps
	ulTxRate          uint32 // kbps
}

type wlanSecurityAttributes struct {
	bSecurityEnabled     int32
	bOneXEnabled         int32
	dot11AuthAlgorithm   uint32
	dot11CipherAlgorithm uint32
}

type wlanConnectionAttributes struct {
	isState                   uint32
	wlanConnectionMode        uint32
	strProfileName            [256]uint16
	wlanAssociationAttributes wlanAssociationAttributes
	wlanSecurityAttributes    wlanSecurityAttributes
}

type wlanRateSet struct {
	uRateSetLength uint32
	usRateSet      [126]uint16
}

type wlanBssEntry struct {
	dot11Ssid               dot11SSID
	uPhyID                  uint32
	dot11Bssid              dot11MacAddress
	dot11BssType            uint32
	dot11BssPhyType         uint32
	lRssi                   int32  // dBm
	uLinkQuality            uint32 // 0-100
	bInRegDomain            uint8  // BOOLEAN
	usBeaconPeriod          uint16
	ullTimestamp            uint64
	ullHostTimestamp        uint64
	usCapabilityInformation uint16
	ulChCenterFrequency     uint32 // kHz
	wlanRateSet             wlanRateSet
	ulIeOffset              uint32
	ulIeSize                uint32
}

type wlanBssList struct {
	dwTotalSize     uint32
	dwNumberOfItems uint32
	wlanBssEntries  [1]wlanBssEntry
}

// wifiFullReadFn is the fallback taken when the watcher cannot start; a var so
// the routing decision is testable without a WlanSvc-less host.
var wifiFullReadFn = wifiFullRead

func (winPlatform) WiFi(includeSSID bool) WiFiResult {
	if w := getWinWatcher(); w != nil {
		return w.tick(includeSSID)
	}
	return wifiFullReadFn(includeSSID)
}

// wifiFullRead is the legacy direct read: open, enumerate, gated-query every
// adapter, close. Correct data, but each call logs a location access — which is
// why it only runs when the event-driven watcher is unavailable.
func wifiFullRead(includeSSID bool) WiFiResult {
	handle, ok := wlanOpen()
	if !ok {
		// WlanSvc unavailable / open failed — the whole subsystem is unreadable.
		return WiFiResult{State: "unreadable", Reason: "driver"}
	}
	defer procWlanCloseHandle.Call(uintptr(handle), 0)

	infos, r := wlanEnumAdapters(handle)
	if r != 0 {
		return WiFiResult{State: "unreadable", Reason: "driver"}
	}
	if len(infos) == 0 {
		return WiFiResult{State: "ok"}
	}
	adapters := make([]WiFiStatus, 0, len(infos))
	for i := range infos {
		adapters = append(adapters, readWinAdapter(handle, &infos[i], includeSSID))
	}
	return WiFiResult{State: "ok", Adapters: adapters}
}

// wlanEnumAdapters returns a Go-owned copy of every WLAN interface (GUID,
// description, state — all ungated) or the wlanapi error code.
func wlanEnumAdapters(handle windows.Handle) ([]wlanInterfaceInfo, uintptr) {
	var listPtr *wlanInterfaceInfoList
	r, _, _ := procWlanEnumInterfaces.Call(uintptr(handle), 0, uintptr(unsafe.Pointer(&listPtr)))
	if r != 0 || listPtr == nil {
		if r == 0 {
			r = uintptr(windows.ERROR_INVALID_DATA)
		}
		return nil, r
	}
	defer procWlanFreeMemory.Call(uintptr(unsafe.Pointer(listPtr)))
	n := int(listPtr.dwNumberOfItems)
	if n == 0 {
		return nil, 0
	}
	out := make([]wlanInterfaceInfo, n)
	copy(out, unsafe.Slice(&listPtr.interfaceInfo[0], n))
	return out, 0
}

// readWinAdapter assembles one adapter's status for the fallback path: state
// from the ungated enumeration, everything else via the same gated refresh the
// watcher uses.
func readWinAdapter(handle windows.Handle, info *wlanInterfaceInfo, includeSSID bool) WiFiStatus {
	st := WiFiStatus{
		ID:   guidKey(info.InterfaceGUID),
		Name: windows.UTF16ToString(info.strInterfaceDescription[:]),
	}

	if info.isState != wlanInterfaceStateConnected {
		// not_ready / disconnected / associating / etc. all collapse to
		// disconnected with empty categorical fields.
		st.State = "disconnected"
		return st
	}

	facts, ok := refreshWinAdapter(handle, &info.InterfaceGUID)
	if !ok {
		st.State, st.Reason = "unreadable", "driver"
		return st
	}
	if !facts.Connected {
		st.State = "disconnected"
		return st
	}
	st.State = "connected"
	if facts.Permission {
		// The OS location policy withheld the identity of the network, not the
		// existence of the link: report connected with the ungated remainder
		// (channel; 2.4 GHz inferable from channel numbers ≤ 14) instead of the
		// old unreadable(driver) verdict, which blamed hardware for policy.
		st.Reason = "permission"
		st.Channel = queryChannelNumber(handle, &info.InterfaceGUID)
		if st.Channel > 0 && st.Channel <= 14 {
			st.Band = "2.4"
		}
		return st
	}
	if includeSSID && facts.HasSSID {
		// The SSID is decoded from the cached bytes only when
		// network.wifi.ssid.read is granted (no read-then-redact disclosure).
		st.SSID = string(facts.SSIDRaw)
	}
	st.Band, st.Channel = facts.Band, facts.Channel
	if facts.Quality != nil {
		q := *facts.Quality
		st.Quality = &q
	}
	switch {
	case facts.SignalDBm != nil:
		v := *facts.SignalDBm
		st.SignalDBm = &v
	case facts.Quality != nil:
		v := dbmFromQuality(*facts.Quality) // fallback: quality/2 − 100
		st.SignalDBm = &v
	}
	if facts.RxMbps != nil {
		v := *facts.RxMbps
		st.RxMbps = &v
	}
	if facts.TxMbps != nil {
		v := *facts.TxMbps
		st.TxMbps = &v
	}
	return st
}

// refreshWinAdapter performs the location-gated read of one adapter — the ONLY
// place current_connection and the BSS list are queried. ok=false means a
// transient failure the caller should retry later (the cache keeps the entry
// dirty); every classified outcome, including "the OS denied us", is ok=true.
func refreshWinAdapter(handle windows.Handle, guid *windows.GUID) (wifiGatedFacts, bool) {
	conn, r := queryCurrentConnection(handle, guid)
	switch r {
	case 0:
	case uintptr(windows.ERROR_ACCESS_DENIED):
		// Location policy denied the read; the link itself is up (callers check
		// ungated state first).
		return wifiGatedFacts{Connected: true, Permission: true}, true
	case errorInvalidState:
		return wifiGatedFacts{}, true // raced a disconnect: authoritatively down
	default:
		return wifiGatedFacts{}, false
	}
	if conn.isState != wlanInterfaceStateConnected {
		return wifiGatedFacts{}, true
	}

	assoc := conn.wlanAssociationAttributes
	if assoc.dot11Bssid == (dot11MacAddress{}) {
		// Documented alternative deny behavior: the query succeeds but SSID/BSSID
		// come back zeroed. A real association always has a BSSID, so all-zero
		// means the identity was withheld, not that the network is nameless.
		return wifiGatedFacts{Connected: true, Permission: true}, true
	}

	facts := wifiGatedFacts{
		Connected: true,
		SSIDRaw:   []byte(decodeDot11SSID(assoc.dot11Ssid)),
		HasSSID:   true,
	}
	q := int(assoc.wlanSignalQuality)
	if q > 100 {
		q = 100
	}
	facts.Quality = &q
	if assoc.ulRxRate > 0 {
		rx := round1(float64(assoc.ulRxRate) / 1000.0) // kbps → Mbps
		facts.RxMbps = &rx
	}
	if assoc.ulTxRate > 0 {
		tx := round1(float64(assoc.ulTxRate) / 1000.0)
		facts.TxMbps = &tx
	}

	channel := queryChannelNumber(handle, guid)

	// Real dBm and center frequency from the connected BSS (matched by BSSID).
	if entry, ok := findConnectedBSS(handle, guid, assoc.dot11Bssid); ok {
		dbm := int(entry.lRssi)
		facts.SignalDBm = &dbm
		freqMHz := int(entry.ulChCenterFrequency / 1000) // kHz → MHz
		if b := bandFromFrequencyMHz(freqMHz); b != "" {
			facts.Band = b
		}
		if channel == 0 {
			channel = channelFromFrequencyMHz(freqMHz)
		}
	}
	// Ambiguous band from channel number alone: only 2.4 GHz channels (≤14) are
	// unambiguous; 5/6 GHz channel numbers overlap, so leave band empty there.
	if facts.Band == "" && channel > 0 && channel <= 14 {
		facts.Band = "2.4"
	}
	facts.Channel = channel
	return facts, true
}

func queryCurrentConnection(handle windows.Handle, guid *windows.GUID) (*wlanConnectionAttributes, uintptr) {
	var dataSize uint32
	var dataPtr unsafe.Pointer
	r, _, _ := procWlanQueryInterface.Call(
		uintptr(handle),
		uintptr(unsafe.Pointer(guid)),
		uintptr(wlanIntfOpcodeCurrentConnection),
		0,
		uintptr(unsafe.Pointer(&dataSize)),
		uintptr(unsafe.Pointer(&dataPtr)),
		0,
	)
	if r != 0 || dataPtr == nil {
		if r == 0 {
			r = uintptr(windows.ERROR_INVALID_DATA)
		}
		return nil, r
	}
	defer procWlanFreeMemory.Call(uintptr(dataPtr))
	cp := *(*wlanConnectionAttributes)(dataPtr) // value copy before free
	return &cp, 0
}

func queryChannelNumber(handle windows.Handle, guid *windows.GUID) int {
	var dataSize uint32
	var dataPtr unsafe.Pointer
	r, _, _ := procWlanQueryInterface.Call(
		uintptr(handle),
		uintptr(unsafe.Pointer(guid)),
		uintptr(wlanIntfOpcodeChannelNumber),
		0,
		uintptr(unsafe.Pointer(&dataSize)),
		uintptr(unsafe.Pointer(&dataPtr)),
		0,
	)
	if r != 0 || dataPtr == nil {
		return 0
	}
	defer procWlanFreeMemory.Call(uintptr(dataPtr))
	return int(*(*uint32)(dataPtr))
}

// queryRSSI reads the current signal strength in dBm. Unlike
// current_connection this opcode is NOT location-gated (proven on real
// hardware by TestWinWiFiLocationGatingIT, which fails if that ever changes),
// which is what lets the steady-state tick report a live native dBm instead of
// deriving one. A 0 reading means the driver did not report — 0 dBm at the
// antenna is not a value a real association produces.
func queryRSSI(handle windows.Handle, guid *windows.GUID) (int, bool) {
	var dataSize uint32
	var dataPtr unsafe.Pointer
	r, _, _ := procWlanQueryInterface.Call(
		uintptr(handle),
		uintptr(unsafe.Pointer(guid)),
		uintptr(wlanIntfOpcodeRSSI),
		0,
		uintptr(unsafe.Pointer(&dataSize)),
		uintptr(unsafe.Pointer(&dataPtr)),
		0,
	)
	if r != 0 || dataPtr == nil {
		return 0, false
	}
	defer procWlanFreeMemory.Call(uintptr(dataPtr))
	v := int(*(*int32)(dataPtr))
	return v, v != 0
}

// findConnectedBSS returns the BSS entry matching the associated BSSID. The full
// list is requested (pDot11Ssid=NULL, type=any) and matched locally, which
// avoids the SSID/security filtering pitfalls of the filtered form.
func findConnectedBSS(handle windows.Handle, guid *windows.GUID, bssid dot11MacAddress) (*wlanBssEntry, bool) {
	var listPtr *wlanBssList
	r, _, _ := procWlanGetNetworkBssList.Call(
		uintptr(handle),
		uintptr(unsafe.Pointer(guid)),
		0, // pDot11Ssid = NULL → all networks
		uintptr(dot11BssTypeAny),
		0, // bSecurityEnabled (ignored when SSID is NULL)
		0,
		uintptr(unsafe.Pointer(&listPtr)),
	)
	if r != 0 || listPtr == nil {
		return nil, false
	}
	defer procWlanFreeMemory.Call(uintptr(unsafe.Pointer(listPtr)))
	n := int(listPtr.dwNumberOfItems)
	if n == 0 {
		return nil, false
	}
	entries := unsafe.Slice(&listPtr.wlanBssEntries[0], n)
	for i := range entries {
		if entries[i].dot11Bssid == bssid {
			cp := entries[i]
			return &cp, true
		}
	}
	return nil, false
}

func decodeDot11SSID(s dot11SSID) string {
	n := int(s.uSSIDLength)
	if n > len(s.ucSSID) {
		n = len(s.ucSSID)
	}
	return string(s.ucSSID[:n])
}

// guidKey formats a GUID as the uppercase braced string GetAdaptersAddresses
// reports in IpAdapterAddresses.AdapterName, so Wi-Fi status joins the right
// interface row by ID.
func guidKey(g windows.GUID) string {
	return strings.ToUpper(fmt.Sprintf("{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
		g.Data1, g.Data2, g.Data3,
		g.Data4[0], g.Data4[1], g.Data4[2], g.Data4[3],
		g.Data4[4], g.Data4[5], g.Data4[6], g.Data4[7]))
}
