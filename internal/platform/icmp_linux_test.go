//go:build linux

package platform

import (
	"context"
	"testing"
	"time"

	"github.com/nettact/protocol/permission"
)

// quotedEcho builds the quotation an ICMP error carries: a 20-byte IPv4 header
// followed by the first 8 bytes of the original echo request.
func quotedEcho(id, seq int) []byte {
	q := make([]byte, 28)
	q[0] = 0x45 // IPv4, IHL 5
	q[9] = 1    // protocol ICMP
	q[20] = 8   // echo request
	q[24], q[25] = byte(id>>8), byte(id)
	q[26], q[27] = byte(seq>>8), byte(seq)
	return q
}

// TestQuotesEchoAttributesRepliesToTheRightProbe: a raw socket sees every ICMP
// packet on the host, so without this check a concurrent probe's unreachable
// would be reported against the wrong target.
func TestQuotesEchoAttributesRepliesToTheRightProbe(t *testing.T) {
	if !quotesEcho(quotedEcho(0x1234, 0x0007), icmpRaw, 0x1234, 0x0007) {
		t.Fatal("our own echo quotation must match")
	}
	if quotesEcho(quotedEcho(0x9999, 0x0007), icmpRaw, 0x1234, 0x0007) {
		t.Fatal("another probe's id must not match on a raw socket")
	}
	if quotesEcho(quotedEcho(0x1234, 0x0008), icmpRaw, 0x1234, 0x0007) {
		t.Fatal("a different sequence must not match")
	}
	// On a ping socket the kernel rewrites the id, so only the sequence is
	// comparable — requiring the id there would drop every real reply.
	if !quotesEcho(quotedEcho(0x9999, 0x0007), icmpDatagram, 0x1234, 0x0007) {
		t.Fatal("datagram mode must match on sequence alone")
	}
	if quotesEcho(quotedEcho(0x9999, 0x0008), icmpDatagram, 0x1234, 0x0007) {
		t.Fatal("datagram mode must still reject a different sequence")
	}
}

func TestQuotesEchoRejectsMalformed(t *testing.T) {
	for name, q := range map[string][]byte{
		"empty":            nil,
		"short":            make([]byte, 10),
		"bad IHL":          {0x40, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0},
		"truncated inner":  make([]byte, 20),
		"not echo request": append(append([]byte{0x45}, make([]byte, 19)...), 3, 0, 0, 0, 0, 0, 0, 0),
	} {
		if quotesEcho(q, icmpRaw, 1, 1) {
			t.Fatalf("%s must not match", name)
		}
	}
}

func TestDstUnreachNameCoversCommonCodes(t *testing.T) {
	if got := dstUnreachName(1); got != "HostUnreachable" {
		t.Fatalf("code 1 → %q", got)
	}
	if got := dstUnreachName(99); got == "" {
		t.Fatal("an unknown code must still render a detail string")
	}
}

// TestSupportsReflectsRuntimeCapability: the whole point of probing at startup is
// that `supported` describes THIS process. The test adapts to whatever privilege
// it runs with rather than asserting a fixed set, so it is meaningful both in CI
// (unprivileged) and in a root shell.
func TestSupportsReflectsRuntimeCapability(t *testing.T) {
	s := linuxPlatform{}.Supports()

	// Interface reads never depend on privilege.
	if !s.Has(permission.NetIfaceStatusRead) || !s.Has(permission.NetIfaceAddressRead) {
		t.Fatalf("interface reads must always be supported, got %v", s.Strings())
	}
	// ICMP echo and gateway probing move together: gateway probing IS an echo.
	if s.Has(permission.ProbeICMP) != s.Has(permission.NetworkGatewayProbe) {
		t.Fatalf("probe.icmp and network.gateway.probe must agree, got %v", s.Strings())
	}
	if got, want := s.Has(permission.ProbeICMP), icmpCapability() != icmpNone; got != want {
		t.Fatalf("probe.icmp supported = %v, want %v for mode %v", got, want, icmpCapability())
	}
	// Traceroute is the engine's call, never advertised by the platform layer.
	if s.Has(permission.DiagnosticTracerouteICMP) || s.Has(permission.DiagnosticTracerouteTCP) {
		t.Fatalf("platform must not advertise traceroute permissions, got %v", s.Strings())
	}
}

// TestPingAgainstLoopback exercises the real socket path end to end. It skips
// when the environment allows no ICMP at all, which is a legitimate state (and
// exactly the one Supports() reports honestly).
func TestPingAgainstLoopback(t *testing.T) {
	if icmpCapability() == icmpNone {
		t.Skip("no ICMP socket available in this environment")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	res, err := linuxPlatform{}.Ping(ctx, "127.0.0.1", PingOptions{Timeout: 2 * time.Second})
	if err != nil {
		t.Fatalf("ping loopback: %v", err)
	}
	if !res.Received {
		t.Fatalf("loopback echo not received: %+v", res)
	}
	if res.RTT <= 0 {
		t.Fatalf("received echo must carry an RTT, got %+v", res)
	}
}

// TestPingRejectsIPv6 pins parity with the Windows implementation: IPv4 only, and
// an IPv6 target is a clear error rather than a silent non-result.
func TestPingRejectsIPv6(t *testing.T) {
	if _, err := (linuxPlatform{}).Ping(context.Background(), "::1", PingOptions{}); err == nil {
		t.Fatal("an IPv6 target must be rejected")
	}
}
