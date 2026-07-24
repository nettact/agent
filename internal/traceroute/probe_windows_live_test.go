//go:build windows

package traceroute

// Live diagnostics for the Windows TCP traceroute path. These need Administrator
// (raw ICMP socket) and a real network, so they are skipped unless
// NETTACT_TRACE_LIVE=1. Destination defaults to 1.1.1.1:443; override with
// NETTACT_TRACE_DEST (ip or hostname) / NETTACT_TRACE_PORT.

import (
	"context"
	"net"
	"net/netip"
	"os"
	"strconv"
	"testing"
	"time"
)

func liveDest(t *testing.T) (netip.Addr, int) {
	t.Helper()
	if os.Getenv("NETTACT_TRACE_LIVE") == "" {
		t.Skip("set NETTACT_TRACE_LIVE=1 (requires Administrator + network)")
	}
	dest := netip.MustParseAddr("1.1.1.1")
	if v := os.Getenv("NETTACT_TRACE_DEST"); v != "" {
		if a, err := netip.ParseAddr(v); err == nil {
			dest = a
		} else {
			ips, lerr := net.LookupIP(v)
			if lerr != nil {
				t.Fatalf("resolve %s: %v", v, lerr)
			}
			found := false
			for _, ip := range ips {
				if ip4 := ip.To4(); ip4 != nil {
					dest = netip.AddrFrom4([4]byte(ip4))
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("no IPv4 for %s", v)
			}
			t.Logf("resolved %s -> %v", v, dest)
		}
	}
	port := 443
	if v := os.Getenv("NETTACT_TRACE_PORT"); v != "" {
		p, err := strconv.Atoi(v)
		if err != nil {
			t.Fatalf("bad NETTACT_TRACE_PORT: %v", err)
		}
		port = p
	}
	return dest, port
}

// TestLiveTCPProbe runs the real tcpProbe over increasing TTLs and logs each
// outcome, mirroring what the engine's walk would record.
func TestLiveTCPProbe(t *testing.T) {
	dest, port := liveDest(t)
	for ttl := 1; ttl <= 10; ttl++ {
		start := time.Now()
		out, err := tcpProbe(context.Background(), dest, port, ttl, 2*time.Second)
		t.Logf("ttl=%d responder=%v reached=%v timeout=%v rtt=%.1fms err=%v elapsed=%v",
			ttl, out.responder, out.reached, out.timeout, out.rttMs, err, time.Since(start))
		if err != nil || out.reached {
			return
		}
	}
}
