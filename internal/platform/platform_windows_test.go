//go:build windows

package platform

import (
	"testing"

	"github.com/nettact/protocol/telemetry"
)

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

func TestMapWinIPStatus(t *testing.T) {
	cases := []struct {
		status uint32
		want   int
	}{
		{0, telemetry.ProbeReasonNone}, // IP_SUCCESS
		{ipReqTimedOut, telemetry.ProbeReasonTimeout},
		{ipDestNetUnreachable, telemetry.ProbeReasonUnreachable},
		{ipDestHostUnreachable, telemetry.ProbeReasonUnreachable},
		{ipDestProtUnreachable, telemetry.ProbeReasonUnreachable},
		{ipDestPortUnreachable, telemetry.ProbeReasonUnreachable},
		{11013, telemetry.ProbeReasonOther}, // IP_TTL_EXPIRED_TRANSIT
		{11050, telemetry.ProbeReasonOther}, // IP_GENERAL_FAILURE
	}
	for _, c := range cases {
		if got := mapWinIPStatus(c.status); got != c.want {
			t.Errorf("mapWinIPStatus(%d) = %d, want %d", c.status, got, c.want)
		}
	}
}

func TestWinIPStatusName(t *testing.T) {
	cases := []struct {
		status uint32
		want   string
	}{
		{ipDestHostUnreachable, "IP_DEST_HOST_UNREACHABLE (11003)"},
		{ipDestProtUnreachable, "IP_DEST_PROT_UNREACHABLE (11004)"},
		{ipDestPortUnreachable, "IP_DEST_PORT_UNREACHABLE (11005)"},
		{ipReqTimedOut, "IP_REQ_TIMED_OUT (11010)"},
		// Outside the named set the bare number is still the machine truth.
		{12345, "IP_STATUS 12345"},
	}
	for _, c := range cases {
		if got := winIPStatusName(c.status); got != c.want {
			t.Errorf("winIPStatusName(%d) = %q, want %q", c.status, got, c.want)
		}
	}
}
