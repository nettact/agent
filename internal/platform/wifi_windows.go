//go:build windows

package platform

import (
	"fmt"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/nettact/protocol/capability"
)

// Windows Wi-Fi status via a thin wlanapi.dll adapter (no qualifying maintained
// Go library exists; see planning/library-evidence.md). CGO-free, lazy-DLL, no
// Administrator required — the same pattern as the existing iphlpapi code. We
// only READ current-connection state (SSID, state, quality, rx/tx rate, dBm,
// band/channel). No scanning trigger, no BSSID storage, no profile/key APIs, no
// connect/disconnect.

func wifiCapability() capability.Capability { return capability.NetWiFiRead }

// On Windows IsWireless is set from the adapter IfType during the
// GetAdaptersAddresses walk (see platform_windows.go), not from a per-name hook.
func ifaceIsWireless(string) bool { return false }

var (
	wlanapi                   = windows.NewLazySystemDLL("wlanapi.dll")
	procWlanOpenHandle        = wlanapi.NewProc("WlanOpenHandle")
	procWlanCloseHandle       = wlanapi.NewProc("WlanCloseHandle")
	procWlanEnumInterfaces    = wlanapi.NewProc("WlanEnumInterfaces")
	procWlanQueryInterface    = wlanapi.NewProc("WlanQueryInterface")
	procWlanGetNetworkBssList = wlanapi.NewProc("WlanGetNetworkBssList")
	procWlanFreeMemory        = wlanapi.NewProc("WlanFreeMemory")
)

const (
	wlanClientVersion2 = 2

	wlanIntfOpcodeCurrentConnection = 7 // WLAN_INTF_OPCODE.current_connection
	wlanIntfOpcodeChannelNumber     = 8 // WLAN_INTF_OPCODE.channel_number

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

func (winPlatform) WiFi() WiFiResult {
	var handle windows.Handle
	var negotiated uint32
	r, _, _ := procWlanOpenHandle.Call(uintptr(wlanClientVersion2), 0,
		uintptr(unsafe.Pointer(&negotiated)), uintptr(unsafe.Pointer(&handle)))
	if r != 0 {
		// WlanSvc unavailable / open failed — the whole subsystem is unreadable.
		return WiFiResult{State: "unreadable", Reason: "driver"}
	}
	defer procWlanCloseHandle.Call(uintptr(handle), 0)

	var listPtr *wlanInterfaceInfoList
	r, _, _ = procWlanEnumInterfaces.Call(uintptr(handle), 0, uintptr(unsafe.Pointer(&listPtr)))
	if r != 0 || listPtr == nil {
		return WiFiResult{State: "unreadable", Reason: "driver"}
	}
	defer procWlanFreeMemory.Call(uintptr(unsafe.Pointer(listPtr)))

	n := int(listPtr.dwNumberOfItems)
	if n == 0 {
		return WiFiResult{State: "ok"}
	}
	infos := unsafe.Slice(&listPtr.interfaceInfo[0], n)
	adapters := make([]WiFiStatus, 0, n)
	for i := range infos {
		adapters = append(adapters, readWinAdapter(handle, &infos[i]))
	}
	return WiFiResult{State: "ok", Adapters: adapters}
}

func readWinAdapter(handle windows.Handle, info *wlanInterfaceInfo) WiFiStatus {
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

	conn, ok := queryCurrentConnection(handle, &info.InterfaceGUID)
	if !ok {
		st.State, st.Reason = "unreadable", "driver"
		return st
	}
	if conn.isState != wlanInterfaceStateConnected {
		st.State = "disconnected"
		return st
	}

	assoc := conn.wlanAssociationAttributes
	st.State = "connected"
	st.SSID = decodeDot11SSID(assoc.dot11Ssid)
	q := int(assoc.wlanSignalQuality)
	if q > 100 {
		q = 100
	}
	st.Quality = &q
	if assoc.ulRxRate > 0 {
		rx := round1(float64(assoc.ulRxRate) / 1000.0) // kbps → Mbps
		st.RxMbps = &rx
	}
	if assoc.ulTxRate > 0 {
		tx := round1(float64(assoc.ulTxRate) / 1000.0)
		st.TxMbps = &tx
	}

	channel := queryChannelNumber(handle, &info.InterfaceGUID)

	// Real dBm and center frequency from the connected BSS (matched by BSSID).
	if entry, ok := findConnectedBSS(handle, &info.InterfaceGUID, assoc.dot11Bssid); ok {
		dbm := int(entry.lRssi)
		st.SignalDBm = &dbm
		freqMHz := int(entry.ulChCenterFrequency / 1000) // kHz → MHz
		if b := bandFromFrequencyMHz(freqMHz); b != "" {
			st.Band = b
		}
		if channel == 0 {
			channel = channelFromFrequencyMHz(freqMHz)
		}
	}
	if st.SignalDBm == nil {
		dbm := dbmFromQuality(q) // fallback: quality/2 − 100
		st.SignalDBm = &dbm
	}
	// Ambiguous band from channel number alone: only 2.4 GHz channels (≤14) are
	// unambiguous; 5/6 GHz channel numbers overlap, so leave band empty there.
	if st.Band == "" && channel > 0 && channel <= 14 {
		st.Band = "2.4"
	}
	st.Channel = channel
	return st
}

func queryCurrentConnection(handle windows.Handle, guid *windows.GUID) (*wlanConnectionAttributes, bool) {
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
		return nil, false
	}
	defer procWlanFreeMemory.Call(uintptr(dataPtr))
	cp := *(*wlanConnectionAttributes)(dataPtr) // value copy before free
	return &cp, true
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
