//go:build linux || darwin

package traceroute

import (
	"net"
	"net/netip"
	"testing"
)

// TestResponderFromAddrAcceptsBothSocketShapes is the regression guarding the
// datagram fallback's quietest failure mode: x/net/icmp reports a raw socket's
// source as *net.IPAddr and a datagram socket's as *net.UDPAddr, and dropping
// the latter would not error — every hop would normalize to a timeout and a
// perfectly good trace would render as a column of stars.
func TestResponderFromAddrAcceptsBothSocketShapes(t *testing.T) {
	want := netip.MustParseAddr("192.168.88.1")
	for _, tc := range []struct {
		name string
		from net.Addr
		want netip.Addr
	}{
		{"raw socket", &net.IPAddr{IP: net.IPv4(192, 168, 88, 1)}, want},
		{"datagram socket", &net.UDPAddr{IP: net.IPv4(192, 168, 88, 1)}, want},
		{"datagram carries a meaningless port", &net.UDPAddr{IP: net.IPv4(192, 168, 88, 1), Port: 0}, want},
		{"unrelated address type", &net.TCPAddr{IP: net.IPv4(192, 168, 88, 1)}, netip.Addr{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := responderFromAddr(tc.from)
			if got != tc.want {
				t.Fatalf("responderFromAddr(%v) = %v, want %v", tc.from, got, tc.want)
			}
			// pickResponder is what turns an unrecognized source into a timeout;
			// pin that consequence too, since it is the visible symptom.
			out := pickResponder(probeOutcome{responder: got})
			if tc.want.IsValid() == out.timeout {
				t.Fatalf("pickResponder timeout=%v for responder %v", out.timeout, got)
			}
		})
	}
}

// TestICMPSocketKindMapping pins the per-kind socket spelling. The datagram
// address must be *net.UDPAddr: a raw *net.IPAddr on a datagram socket is
// rejected at WriteTo, which would surface as a send failure rather than a
// hop.
func TestICMPSocketKindMapping(t *testing.T) {
	dest := netip.MustParseAddr("1.1.1.1")
	for _, tc := range []struct {
		kind    icmpSocketKind
		network string
		udp     bool
	}{
		{icmpSocketRaw, "ip4:icmp", false},
		{icmpSocketDatagram, "udp4", true},
	} {
		if got := icmpListenNetwork(tc.kind); got != tc.network {
			t.Errorf("icmpListenNetwork(%d) = %q, want %q", tc.kind, got, tc.network)
		}
		addr := icmpDestAddr(tc.kind, dest)
		if _, isUDP := addr.(*net.UDPAddr); isUDP != tc.udp {
			t.Errorf("icmpDestAddr(%d) = %T, want UDP=%v", tc.kind, addr, tc.udp)
		}
		if host, _, _ := net.SplitHostPort(addr.String() + ":0"); host != "" && addr.String() != "1.1.1.1" &&
			addr.String() != "1.1.1.1:0" {
			t.Errorf("icmpDestAddr(%d) addressed %s, want 1.1.1.1", tc.kind, addr)
		}
	}
}

// TestDatagramFallbackIsPlatformGated pins the rule that keeps Linux honest:
// only Darwin may resolve to a datagram socket, because only Darwin delivers
// ICMP errors on one. A Linux build reporting a capability it cannot deliver
// would file traces of pure silence instead of declining.
func TestDatagramFallbackIsPlatformGated(t *testing.T) {
	kind := resolveICMPSocket()
	if kind == icmpSocketDatagram && !datagramICMPUsable {
		t.Fatal("resolved a datagram ICMP socket on a platform that disallows it")
	}
	caps := detectCapabilities()
	if (kind == icmpSocketNone) == (caps.ICMP || caps.TCP) {
		t.Fatalf("kind=%d but capabilities=%+v; the two must agree", kind, caps)
	}
	if caps.ICMP != caps.TCP {
		t.Fatalf("capabilities=%+v; both modes hang off the one socket check", caps)
	}
	t.Logf("resolved kind=%d datagramICMPUsable=%v caps=%+v", kind, datagramICMPUsable, caps)
}
