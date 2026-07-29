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
// The cycle semantics deliberately mirror pingCycle exactly — same packet count,
// spacing, per-echo timeout and global deadline, and the same rule that a lost echo
// contributes to loss and NEVER to the latency distribution — so a target's numbers
// mean the same thing whether or not it is proxied. Anything else would make the
// availability history of a monitor change meaning the moment a proxy is attached.

// icmpEchoPayload is the fixed echo payload. It is matched on the reply (together
// with the sequence number) because a netstack ping socket assigns the ICMP id
// itself, so the payload is the only other thing we control.
var icmpEchoPayload = []byte("nettact-probe")

// tunnelPingCycle runs one ICMP cycle against target through a tunnel dialer.
// target must already be a vetted literal IP — same contract as the platform path,
// where handing over a raw hostname would let it be re-resolved outside the guard.
func tunnelPingCycle(ctx context.Context, d *proxydial.Dialer, target string, params pcfg.ProbeParams) pingCycleResult {
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

	count := pcfg.PingCount(params)
	timeout := pcfg.PingEchoTimeout(params)
	payload := icmpEchoPayload
	if params.PacketSize > len(payload) {
		// Pad to the requested payload size so a size-sensitive path (MTU, fragmentation)
		// is exercised the same way the platform pinger would.
		payload = append(append([]byte(nil), payload...), make([]byte, params.PacketSize-len(payload))...)
	}

	pctx := ctx
	var cancel context.CancelFunc
	var deadline time.Time
	if params.GlobalTimeoutMs > 0 {
		dur := time.Duration(params.GlobalTimeoutMs) * time.Millisecond
		deadline = time.Now().Add(dur)
		pctx, cancel = context.WithTimeout(ctx, dur)
	}
	if cancel != nil {
		defer cancel()
	}

	rtts := make([]time.Duration, 0, count)
	reasons := make([]int, 0, count)
	details := make([]string, 0, count)
	for i := 0; i < count; i++ {
		if pctx.Err() != nil {
			break
		}
		if i > 0 && !sleepCtx(pctx, pingSpacing) {
			break
		}
		echoTimeout := timeout
		if !deadline.IsZero() {
			remaining := time.Until(deadline)
			if remaining <= 0 {
				break
			}
			if remaining < echoTimeout {
				echoTimeout = remaining
			}
		}
		rtt, reason, detail := tunnelPingOnce(pctx, d, network, proto, echoType, addr.String(), i, payload, echoTimeout)
		if reason == telemetry.ProbeReasonNone {
			rtts = append(rtts, rtt)
			continue
		}
		reasons = append(reasons, reason)
		details = append(details, detail)
	}

	received := len(rtts)
	r := pingCycleResult{
		Loss:     float64(count-received) / float64(count) * 100.0,
		Sent:     count,
		Received: received,
	}
	r.Reason, r.Detail = cycleReason(received, reasons, details)
	r.AvgMs, r.MinMs, r.MaxMs, r.JitterMs, r.HaveJitter = pingStats(rtts)
	return r
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
