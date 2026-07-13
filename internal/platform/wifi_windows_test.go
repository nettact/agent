//go:build windows

package platform

import (
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestWindowsWiFiStructLayouts(t *testing.T) {
	for name, gotWant := range map[string][2]uintptr{
		"dot11SSID":                 {unsafe.Sizeof(dot11SSID{}), 36},
		"wlanInterfaceInfo":         {unsafe.Sizeof(wlanInterfaceInfo{}), 532},
		"wlanAssociationAttributes": {unsafe.Sizeof(wlanAssociationAttributes{}), 68},
		"wlanConnectionAttributes":  {unsafe.Sizeof(wlanConnectionAttributes{}), 604},
		"wlanBssEntry":              {unsafe.Sizeof(wlanBssEntry{}), 360},
	} {
		if gotWant[0] != gotWant[1] {
			t.Errorf("%s size=%d want %d", name, gotWant[0], gotWant[1])
		}
	}
}

func TestWindowsWiFiDecodingHelpers(t *testing.T) {
	g := windows.GUID{Data1: 0x12345678, Data2: 0x9abc, Data3: 0xdef0, Data4: [8]byte{1, 2, 3, 4, 5, 6, 7, 8}}
	if got, want := guidKey(g), "{12345678-9ABC-DEF0-0102-030405060708}"; got != want {
		t.Fatalf("guidKey=%q want %q", got, want)
	}

	var ssid dot11SSID
	ssid.uSSIDLength = 4
	copy(ssid.ucSSID[:], []byte("wifi"))
	if got := decodeDot11SSID(ssid); got != "wifi" {
		t.Fatalf("decodeDot11SSID=%q", got)
	}
	ssid.uSSIDLength = 99
	if got := decodeDot11SSID(ssid); len(got) != len(ssid.ucSSID) {
		t.Fatalf("oversized SSID decoded length=%d want %d", len(got), len(ssid.ucSSID))
	}
}
