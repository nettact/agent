package collector

import (
	"bytes"
	"context"
	"net/netip"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"

	"github.com/nettact/agent/internal/proxydial"
	pcfg "github.com/nettact/protocol/config"
	"github.com/nettact/protocol/telemetry"
)

// ICMP echo inside a WireGuard tunnel.
//
// The platform pingers (IcmpSendEcho on Windows, raw/DGRAM sockets elsewhere) send
// from the HOST's stack, so they cannot reach a tunnel-only destination and would
// silently measure the wrong path. A tunnelled monitor therefore builds its own
// echoes and writes them to the netstack "ping4"/"ping6" socket the tunnel exposes.
//
// Only the sending of one echo differs from the host path: the cycle itself —
// packet count, spread pacing and its fail-fast, per-echo timeout, global
// deadline, and the rule that a lost echo contributes to loss and NEVER to the
// latency distribution — is pingLoop, shared with pingCycle. That sharing is the
// point: a target's numbers must mean the same thing whether or not it is
// proxied, or the availability history of a monitor would change meaning the
// moment a proxy is attached.

// icmpEchoPayload is the fixed echo payload. It is matched on the reply (together
// with the sequence number) because a netstack ping socket assigns the ICMP id
// itself, so the payload is the only other thing we control.
var icmpEchoPayload = []byte("nettact-probe")

// tunnelPingCycle runs one ICMP cycle against target through a tunnel dialer,
// paced to land its last echo before nextDue. target must already be a vetted
// literal IP — same contract as the platform path, where handing over a raw
// hostname would let it be re-resolved outside the guard.
func tunnelPingCycle(ctx context.Context, d *proxydial.Dialer, target string, params pcfg.ProbeParams, nextDue time.Time, gate *ProbeGate) pingCycleResult {
	addr, err := netip.ParseAddr(target)
	if err != nil {
		return pingCycleResult{
			Loss: 100, Sent: pcfg.PingCount(params),
			Reason: telemetry.ProbeReasonProxyConfig, Detail: "tunnel ping needs a literal IP: " + target,
		}
	}
	network, proto, echoType := "ping4", ipv4.ICMPTypeEcho.Protocol(), icmp.Type(ipv4.ICMPTypeEcho)
	if !addr.Is4() {
		network, proto, echoType = "ping6", ipv6.ICMPTypeEchoRequest.Protocol(), icmp.Type(ipv6.ICMPTypeEchoRequest)
	}

	return pingLoop(ctx, params, nextDue, gate, func(ectx context.Context, seq int, timeout time.Duration) (time.Duration, int, string, bool) {
		// A size-sweeping cycle derives the echo's payload from its sequence
		// number (round-robin across the swept sizes); otherwise the fixed
		// PacketSize. The reply is matched on sequence + payload, so the payload
		// must be built per-echo here, not once for the cycle.
		payload := tunnelPayload(sweepSize(params, seq))
		rtt, reason, detail := tunnelPingOnce(ectx, d, network, proto, echoType, addr.String(), seq, payload, timeout)
		return rtt, reason, detail, reason == telemetry.ProbeReasonNone
	})
}

// tunnelPayload is the echo payload for a tunnel ping of the given size: the
// probe marker repeated (and truncated) to EXACTLY size bytes, so a size-sensitive
// path (MTU, fragmentation) is exercised the same way the platform pinger would.
// The exact-size guarantee matters for a size-sweeping cycle: the reply is matched
// on sequence + payload, and the sweep labels describe the bytes actually on the
// wire — a configured size below the marker length must produce a payload of that
// size, not the full marker. The marker is never mutated; the result is a fresh
// slice.
func tunnelPayload(size int) []byte {
	if size <= 0 {
		size = len(icmpEchoPayload)
	}
	if size > 65500 { // IPv4 datagram ceiling, mirroring the platform pinger
		size = 65500
	}
	buf := make([]byte, size)
	for i := 0; i < size; i++ {
		buf[i] = icmpEchoPayload[i%len(icmpEchoPayload)]
	}
	return buf
}

// tunnelPingOnce sends one echo and waits for its reply. A fresh socket per echo
// keeps replies from bleeding between echoes, which matters because the netstack
// ping socket owns the ICMP id: without a fresh socket a late reply to echo N could
// be counted as the reply to echo N+1 and understate the loss.
func tunnelPingOnce(ctx context.Context, d *proxydial.Dialer, network string, proto int, echoType icmp.Type,
	addr string, seq int, payload []byte, timeout time.Duration) (time.Duration, int, string) {
	conn, err := d.DialPing(ctx, network, addr)
	if err != nil {
		// The tunnel could not give us an ICMP channel at all: an egress failure, so it
		// keeps its proxy_* reason rather than being reported as target loss.
		if reason, atTarget, ok := proxydial.ProxyReason(err); ok && !atTarget {
			return 0, reason, errText(err)
		}
		return 0, telemetry.ProbeReasonProxyConnect, errText(err)
	}
	defer conn.Close()

	req := icmp.Message{Type: echoType, Code: 0, Body: &icmp.Echo{Seq: seq, Data: payload}}
	wire, err := req.Marshal(nil)
	if err != nil {
		return 0, telemetry.ProbeReasonOther, errText(err)
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))
	start := time.Now()
	if _, err := conn.Write(wire); err != nil {
		return 0, classifyNetError(err), errText(err)
	}
	// The reply is at most the request size plus the ICMP header; a generous buffer
	// avoids truncating a padded payload.
	buf := make([]byte, len(wire)+512)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return 0, classifyNetError(err), errText(err)
		}
		msg, perr := icmp.ParseMessage(proto, buf[:n])
		if perr != nil {
			continue // not a parsable ICMP message; keep waiting within the deadline
		}
		echo, ok := msg.Body.(*icmp.Echo)
		// The stack picks the ICMP id, so the reply is matched on sequence + payload —
		// the two fields we control. A mismatch means it belongs to a different echo.
		if !ok || echo.Seq != seq || !bytes.Equal(echo.Data, payload) {
			continue
		}
		return time.Since(start), telemetry.ProbeReasonNone, ""
	}
}
