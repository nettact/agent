//go:build windows

package platform

import (
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// TestWinWiFiLocationGatingIT is the live regression guard for the assumption
// the steady-state tick is built on: that wlan_intf_opcode_rssi and
// channel_number are NOT location-gated while current_connection is. Windows
// documents none of this, so it is settled empirically — Windows records every
// gated access under the CapabilityAccessManager consent store keyed by the
// calling exe, so the test reads its own entry's LastUsedTimeStop around each
// API batch, with the known-gated current_connection query as the positive
// control. If a future Windows build starts gating rssi, this fails and the
// tick must stop calling it.
//
// Requirements: NETTACT_WIFI_IT=1, a CONNECTED Wi-Fi adapter, and location
// access enabled for desktop apps. It is excluded from `go test ./...` runs by
// the env gate (same pattern as TestNATBindingSmoke).
func TestWinWiFiLocationGatingIT(t *testing.T) {
	if os.Getenv("NETTACT_WIFI_IT") == "" {
		t.Skip("set NETTACT_WIFI_IT=1 to run the live location-gating probe")
	}

	handle, ok := wlanOpen()
	if !ok {
		t.Skip("WlanSvc unavailable")
	}
	defer procWlanCloseHandle.Call(uintptr(handle), 0)
	infos, r := wlanEnumAdapters(handle)
	if r != 0 {
		t.Fatalf("enum failed: %d", r)
	}
	var guid *windows.GUID
	for i := range infos {
		if infos[i].isState == wlanInterfaceStateConnected {
			guid = &infos[i].InterfaceGUID
			break
		}
	}
	if guid == nil {
		t.Skip("no connected Wi-Fi adapter — connect one and rerun")
	}

	stamp := locationStamp(t)
	settle := func() { time.Sleep(3 * time.Second) } // consent-store writes are async

	base := stamp()

	// Candidate: opcode_rssi + channel_number, 20 rounds. These are what the
	// steady-state tick calls every round, so they must not log.
	for i := 0; i < 20; i++ {
		if v, ok := queryRSSI(handle, guid); !ok {
			t.Logf("opcode_rssi round %d: unreadable", i)
		} else if i == 0 {
			t.Logf("opcode_rssi = %d dBm", v)
		}
		queryChannelNumber(handle, guid)
	}
	settle()
	afterCandidate := stamp()

	// Positive control: one known-gated read must move the stamp, or the
	// detection method itself is broken and nothing can be concluded.
	if _, r := queryCurrentConnection(handle, guid); r != 0 {
		t.Logf("current_connection err=%d (location off? then no verdict on rssi either)", r)
	}
	settle()
	afterControl := stamp()

	t.Logf("stamps: base=%d afterCandidate=%d afterControl=%d", base, afterCandidate, afterControl)
	if afterControl == afterCandidate {
		t.Skip("positive control did not move the location stamp — method inconclusive on this machine")
	}
	if afterCandidate != base {
		t.Fatal("opcode_rssi/channel_number DID log a location access — the tick must NOT use them beyond current usage")
	}
	t.Log("verdict: opcode_rssi + channel_number are NOT location-gated on this machine")
}

// locationStamp returns a reader of this test binary's LastUsedTimeStop in the
// per-exe location consent store — the machine-readable form of Settings →
// Privacy → Location → "Recent activity". Windows updates it on every gated
// access, so a stamp that does not move across a batch of calls is proof none
// of them was logged as a location access. Zero means the exe has no entry at
// all (never logged).
func locationStamp(t *testing.T) func() uint64 {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	key := `Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location\NonPackaged\` +
		strings.ReplaceAll(exe, `\`, `#`)
	return func() uint64 {
		k, err := registry.OpenKey(registry.CURRENT_USER, key, registry.QUERY_VALUE)
		if err != nil {
			return 0
		}
		defer k.Close()
		v, _, err := k.GetIntegerValue("LastUsedTimeStop")
		if err != nil {
			return 0
		}
		return v
	}
}

// TestWinWiFiTickSoakIT is the end-to-end proof of the whole change: it drives
// WiFi() the way the collector does (a tick every few seconds, standing in for
// the 30s regular tier) and asserts the location consent stamp does not move
// after the initial seeding refresh. Before this change every one of those
// ticks logged a location access.
//
// Requires NETTACT_WIFI_IT=1. Most meaningful with a CONNECTED adapter — that
// is the case where the old code performed the gated reads; it still runs
// disconnected, where it proves the down path stays gated-read-free.
func TestWinWiFiTickSoakIT(t *testing.T) {
	if os.Getenv("NETTACT_WIFI_IT") == "" {
		t.Skip("set NETTACT_WIFI_IT=1 to run the live tick soak")
	}
	stamp := locationStamp(t)
	p := winPlatform{}

	// Seeding tick: on a connected adapter this performs the one legitimate
	// gated refresh, so its location access is expected and excluded below.
	first := p.WiFi(true)
	t.Logf("seed: state=%s adapters=%d", first.State, len(first.Adapters))
	for _, a := range first.Adapters {
		t.Logf("  seed %s state=%s reason=%q ssid=%q band=%q ch=%d dbm=%v q=%v rx=%v tx=%v",
			a.Name, a.State, a.Reason, a.SSID, a.Band, a.Channel,
			derefInt(a.SignalDBm), derefInt(a.Quality), derefF64(a.RxMbps), derefF64(a.TxMbps))
	}
	time.Sleep(5 * time.Second)
	base := stamp()

	const ticks = 12
	for i := 0; i < ticks; i++ {
		res := p.WiFi(true)
		for _, a := range res.Adapters {
			t.Logf("tick %2d: %s state=%s reason=%q ssid=%q band=%q ch=%d dbm=%v q=%v rx=%v tx=%v",
				i, a.Name, a.State, a.Reason, a.SSID, a.Band, a.Channel,
				derefInt(a.SignalDBm), derefInt(a.Quality), derefF64(a.RxMbps), derefF64(a.TxMbps))
		}
		time.Sleep(2 * time.Second)
	}
	time.Sleep(5 * time.Second)
	after := stamp()

	t.Logf("location stamp: base=%d after=%d (%d steady-state ticks)", base, after, ticks)
	if after != base {
		t.Fatalf("steady-state ticks logged a location access (stamp %d → %d)", base, after)
	}
}

func derefInt(p *int) any {
	if p == nil {
		return "nil"
	}
	return *p
}

// TestWinWiFiChangeSoakIT exercises the notification path end to end: it ticks
// for NETTACT_WIFI_SOAK_SEC seconds while the operator disconnects and
// reconnects the adapter (`netsh wlan disconnect` / `netsh wlan connect
// name=<profile>`). What it proves cannot be unit-tested: that WlanSvc actually
// delivers ACM/MSM notifications to the registered callback, that the event
// pump turns them into an eager gated refresh, and that a reconnect restores
// SSID/band within seconds rather than at the next tick.
//
// It asserts only the invariants (no gated read while nothing changes; the
// SSID comes back after a reconnect); the per-tick log plus the location-stamp
// deltas are the evidence to read.
func TestWinWiFiChangeSoakIT(t *testing.T) {
	if os.Getenv("NETTACT_WIFI_IT") == "" {
		t.Skip("set NETTACT_WIFI_IT=1 to run the live change soak")
	}
	secs := 90
	if v := os.Getenv("NETTACT_WIFI_SOAK_SEC"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			secs = n
		}
	}
	stamp := locationStamp(t)
	p := winPlatform{}

	start := time.Now()
	prev := stamp()
	var sawDisconnected, sawSSIDAfterDisconnect bool
	var stampMoves int
	for time.Since(start) < time.Duration(secs)*time.Second {
		res := p.WiFi(true)
		now := stamp()
		moved := ""
		if now != prev {
			stampMoves++
			moved = "  <-- LOCATION ACCESS"
			prev = now
		}
		for _, a := range res.Adapters {
			t.Logf("%4.0fs %s reason=%q ssid=%q band=%q ch=%d dbm=%v q=%v rx=%v tx=%v%s",
				time.Since(start).Seconds(), a.State, a.Reason, a.SSID, a.Band, a.Channel,
				derefInt(a.SignalDBm), derefInt(a.Quality), derefF64(a.RxMbps), derefF64(a.TxMbps), moved)
			if a.State == "disconnected" {
				sawDisconnected = true
			} else if a.State == "connected" && a.SSID != "" && sawDisconnected {
				sawSSIDAfterDisconnect = true
			}
		}
		time.Sleep(2 * time.Second)
	}

	t.Logf("summary: location accesses during soak=%d disconnect seen=%v ssid recovered=%v",
		stampMoves, sawDisconnected, sawSSIDAfterDisconnect)
	if !sawDisconnected {
		t.Skip("adapter never disconnected during the soak — nothing to conclude about the event path")
	}
	if !sawSSIDAfterDisconnect {
		t.Fatal("reconnect did not restore the SSID: the notification → eager-refresh path is broken")
	}
	// One refresh per reconnect is the design; anything near the tick count means
	// the gated read leaked back into the steady state.
	if stampMoves > 4 {
		t.Fatalf("%d location accesses for one disconnect/reconnect cycle", stampMoves)
	}
}

func derefF64(p *float64) any {
	if p == nil {
		return "nil"
	}
	return *p
}
