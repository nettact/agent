//go:build linux

package platform

import (
	"errors"
	"os"
	"syscall"

	"github.com/mdlayher/wifi"

	"github.com/nettact/protocol/permission"
)

// Linux Wi-Fi status via nl80211 (github.com/mdlayher/wifi) — pure Go netlink,
// no CGO, no external commands, unprivileged reads (same access as `iw dev X
// link` as a normal user). We only READ current-connection state: interface
// list, associated BSS (SSID/frequency), and station info (signal, bitrates).
// No scanning, no BSSID storage, no connect/disconnect, no keys.

func wifiPermissions() []permission.ID {
	return []permission.ID{permission.NetWiFiStatusRead, permission.NetWiFiSSIDRead}
}

// ifaceIsWireless reports whether a netdev is backed by Wi-Fi hardware, using the
// kernel's /sys/class/net/<name>/wireless marker. This is independent of nl80211
// so wireless hardware is recognized even when its status is unreadable.
func ifaceIsWireless(name string) bool {
	_, err := os.Stat("/sys/class/net/" + name + "/wireless")
	return err == nil
}

// hasWirelessHardware reports whether any netdev has the /sys wireless marker.
// Used to distinguish "no adapter" from "unreadable(driver)" when nl80211 itself
// is missing/unreadable (per the approved Linux classification correction).
func hasWirelessHardware() bool {
	entries, err := os.ReadDir("/sys/class/net")
	if err != nil {
		return false
	}
	for _, e := range entries {
		if _, err := os.Stat("/sys/class/net/" + e.Name() + "/wireless"); err == nil {
			return true
		}
	}
	return false
}

func isPermErr(err error) bool {
	return errors.Is(err, os.ErrPermission) || errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES)
}

func (genericPlatform) WiFi(includeSSID bool) WiFiResult {
	cl, err := wifi.New()
	if err != nil {
		return classifyLinuxWiFiOpenErr(err)
	}
	defer cl.Close()

	ifis, err := cl.Interfaces()
	if err != nil {
		return classifyLinuxWiFiOpenErr(err)
	}

	var adapters []WiFiStatus
	for _, ifi := range ifis {
		// Only managed client interfaces represent a user's Wi-Fi link. AP,
		// monitor, mesh and P2P virtual interfaces are not "the machine's Wi-Fi".
		if ifi.Name == "" || (ifi.Type != wifi.InterfaceTypeStation && ifi.Type != wifi.InterfaceTypeUnspecified) {
			continue
		}
		adapters = append(adapters, readLinuxAdapter(cl, ifi, includeSSID))
	}
	return WiFiResult{State: "ok", Adapters: adapters}
}

// classifyLinuxWiFiOpenErr maps a family-open / enumeration failure to a
// collection verdict: EPERM ⇒ permission; otherwise driver only if independent
// enumeration finds wireless hardware, else genuinely no adapter.
func classifyLinuxWiFiOpenErr(err error) WiFiResult {
	if isPermErr(err) {
		return WiFiResult{State: "unreadable", Reason: "permission"}
	}
	if hasWirelessHardware() {
		return WiFiResult{State: "unreadable", Reason: "driver"}
	}
	return WiFiResult{State: "ok"} // missing nl80211 family + no hardware ⇒ no adapter
}

func readLinuxAdapter(cl *wifi.Client, ifi *wifi.Interface, includeSSID bool) WiFiStatus {
	st := WiFiStatus{ID: ifi.Name, Name: ifi.Name}

	bss, err := cl.BSS(ifi)
	if err != nil {
		switch {
		case errors.Is(err, os.ErrNotExist):
			st.State = "disconnected" // not associated
		case isPermErr(err):
			st.State, st.Reason = "unreadable", "permission"
		default:
			st.State, st.Reason = "unreadable", "driver"
		}
		return st
	}
	if bss == nil || (bss.Status != wifi.BSSStatusAssociated && bss.Status != wifi.BSSStatusAuthenticated) {
		st.State = "disconnected"
		return st
	}

	st.State = "connected"
	// The SSID is retained only when network.wifi.ssid.read is granted; the BSS
	// netlink response is not kept otherwise (no read-then-redact into WiFiStatus).
	if includeSSID {
		st.SSID = bss.SSID
	}
	freq := bss.Frequency
	if freq == 0 {
		freq = ifi.Frequency
	}
	st.Band = bandFromFrequencyMHz(freq)
	st.Channel = channelFromFrequencyMHz(freq)

	// Prefer native per-station dBm and link bitrates; fall back to the BSS
	// signal. Numeric fields are set only when the driver actually reports them.
	if stations, serr := cl.StationInfo(ifi); serr == nil {
		for _, s := range stations {
			if s == nil {
				continue
			}
			if s.Signal != 0 {
				dbm := s.Signal
				st.SignalDBm = &dbm
			}
			if s.ReceiveBitrate > 0 {
				rx := round1(float64(s.ReceiveBitrate) / 1e6)
				st.RxMbps = &rx
			}
			if s.TransmitBitrate > 0 {
				tx := round1(float64(s.TransmitBitrate) / 1e6)
				st.TxMbps = &tx
			}
			break // the first station is the associated AP
		}
	}
	if st.SignalDBm == nil && bss.Signal != 0 {
		dbm := int(bss.Signal / 100) // mBm → dBm
		st.SignalDBm = &dbm
	}
	if st.SignalDBm != nil {
		q := qualityFromDBm(*st.SignalDBm)
		st.Quality = &q
	} else if bss.SignalUnspecified > 0 {
		q := int(bss.SignalUnspecified)
		if q > 100 {
			q = 100
		}
		st.Quality = &q
	}
	return st
}
