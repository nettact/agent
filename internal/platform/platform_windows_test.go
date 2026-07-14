//go:build windows

package platform

import "testing"

func TestIsHiddenVirtualWirelessAdapter(t *testing.T) {
	cases := []struct {
		desc string
		want bool
	}{
		// Hidden virtual adapters Windows synthesizes off the physical Wi-Fi NIC.
		{"Microsoft Wi-Fi Direct Virtual Adapter", true},
		{"Microsoft Wi-Fi Direct Virtual Adapter #3", true},
		{"Microsoft Hosted Network Virtual Adapter", true},
		{"Microsoft Virtual WiFi Miniport Adapter", true},
		// Real / unrelated hardware must never match.
		{"Intel(R) Wi-Fi 6 AX200 160MHz", false},
		{"Realtek Gaming 2.5GbE Family Controller", false},
		{"Bluetooth Device (Personal Area Network)", false},
		{"TAP-Windows Adapter V9", false},
		{"Hyper-V Virtual Ethernet Adapter", false},
		{"Tailscale Tunnel", false},
		{"", false},
	}
	for _, c := range cases {
		if got := isHiddenVirtualWirelessAdapter(c.desc); got != c.want {
			t.Errorf("isHiddenVirtualWirelessAdapter(%q) = %v, want %v", c.desc, got, c.want)
		}
	}
}
