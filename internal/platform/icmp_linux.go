//go:build linux

package platform

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"sync"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"

	"github.com/nettact/protocol/telemetry"
)

// Linux offers two ways to send an ICMP echo, and which one a process gets is a
// runtime fact, not a build fact:
//
//   - a RAW ICMP socket (CAP_NET_RAW, which root has) sees every ICMP packet on
//     the host, including the Time-Exceeded and Destination-Unreachable errors
//     that classify a failed probe and drive traceroute;
//   - an unprivileged "ping socket" (SOCK_DGRAM/IPPROTO_ICMP) needs no
//     capability but is only enabled when net.ipv4.ping_group_range covers the
//     process's gid, and the kernel delivers ICMP errors for it to the socket
//     error queue rather than as readable messages — so echoes work, but a
//     failure can only be reported as "no answer".
//
// The agent probes for both once at startup and reports the outcome through
// Supports(), so a host that can only do one, or neither, says so honestly
// instead of failing every probe at collection time.

type icmpMode int

const (
	icmpNone     icmpMode = iota // no ICMP echo possible in this process
	icmpDatagram                 // unprivileged ping socket
	icmpRaw                      // raw ICMP socket (CAP_NET_RAW / root)
)

// icmpCapability is probed once per process: the answer cannot change without a
// restart (capabilities are fixed at exec, and the sysctl is read at socket
// creation), and Supports() must stay stable for the reported policy's lifetime.
var icmpCapability = sync.OnceValue(detectICMPCapability)

func detectICMPCapability() icmpMode {
	if c, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0"); err == nil {
		_ = c.Close()
		return icmpRaw
	}
	if c, err := icmp.ListenPacket("udp4", "0.0.0.0"); err == nil {
		_ = c.Close()
		return icmpDatagram
	}
	return icmpNone
}

// errNoICMP is returned when neither socket type is available. It is a probe
// error, not a silent failure: the permission is not in `supported` either, so
// the server should never have scheduled an ICMP monitor for this agent.
var errNoICMP = errors.New("icmp echo unavailable: no raw ICMP socket (CAP_NET_RAW) and no unprivileged ping socket (net.ipv4.ping_group_range)")

// Ping sends one ICMP echo and classifies the outcome. IPv4 only, matching the
// Windows implementation.
func (linuxPlatform) Ping(ctx context.Context, target string, opts PingOptions) (PingResult, error) {
	res := PingResult{Target: target}

	ip := net.ParseIP(target)
	if ip == nil {
		ips, err := net.DefaultResolver.LookupIP(ctx, "ip4", target)
		if err != nil || len(ips) == 0 {
			return res, errors.New("cannot resolve target: " + target)
		}
		ip = ips[0]
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return res, errors.New("only IPv4 ICMP is supported in P0")
	}

	mode := icmpCapability()
	if mode == icmpNone {
		return res, errNoICMP
	}

	network := "udp4"
	var dst net.Addr = &net.UDPAddr{IP: ip4}
	if mode == icmpRaw {
		network = "ip4:icmp"
		dst = &net.IPAddr{IP: ip4}
	}
	conn, err := icmp.ListenPacket(network, "0.0.0.0")
	if err != nil {
		return res, err
	}
	defer conn.Close()

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = time.Second
	}
	deadline := time.Now().Add(timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return res, err
	}

	// A raw socket receives every ICMP packet the host gets, so concurrent probes
	// (the agent runs up to 16) would otherwise steal each other's replies. A
	// random id+seq per echo makes each reply attributable. On a ping socket the
	// kernel rewrites the id to the socket's port, so only the sequence matches.
	id := int(rand.Uint32() & 0xffff)
	seq := int(rand.Uint32() & 0xffff)
	wm := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Body: &icmp.Echo{ID: id, Seq: seq, Data: pingPayload(opts.PayloadSize)},
	}
	wb, err := wm.Marshal(nil)
	if err != nil {
		return res, err
	}

	start := time.Now()
	if _, err := conn.WriteTo(wb, dst); err != nil {
		// A send that the kernel rejects outright (no route, network down) is a
		// classified failure, not a transport error the caller must handle.
		res.Reason = telemetry.ProbeReasonUnreachable
		res.Detail = "send: " + err.Error()
		return res, nil
	}

	rb := make([]byte, 1500)
	for {
		n, _, err := conn.ReadFrom(rb)
		if err != nil {
			// Deadline reached with nothing attributable to this echo.
			res.Reason = telemetry.ProbeReasonTimeout
			return res, nil
		}
		rm, perr := icmp.ParseMessage(ipv4.ICMPTypeEchoReply.Protocol(), rb[:n])
		if perr != nil {
			continue
		}
		switch body := rm.Body.(type) {
		case *icmp.Echo:
			if rm.Type != ipv4.ICMPTypeEchoReply || !echoMatches(mode, body.ID, body.Seq, id, seq) {
				continue
			}
			res.Received = true
			res.RTT = time.Since(start)
			return res, nil
		case *icmp.DstUnreach:
			if !quotesEcho(body.Data, mode, id, seq) {
				continue
			}
			res.Reason = telemetry.ProbeReasonUnreachable
			res.Detail = dstUnreachName(rm.Code)
			return res, nil
		case *icmp.TimeExceeded:
			if !quotesEcho(body.Data, mode, id, seq) {
				continue
			}
			// TTL ran out before the destination: not a timeout (something did
			// answer) and not unreachable in the routing sense.
			res.Reason = telemetry.ProbeReasonOther
			res.Detail = "TimeExceeded"
			return res, nil
		}
	}
}

// echoMatches reports whether a received echo reply belongs to this probe. A
// ping socket's replies carry the kernel's own id, so only the sequence is
// comparable there.
func echoMatches(mode icmpMode, gotID, gotSeq, wantID, wantSeq int) bool {
	if gotSeq != wantSeq {
		return false
	}
	return mode != icmpRaw || gotID == wantID
}

// quotesEcho reports whether an ICMP error quotes this probe's echo request. The
// quotation is the original IP header plus the first 8 bytes of its payload,
// which for an echo is exactly type/code/checksum/id/seq.
func quotesEcho(quoted []byte, mode icmpMode, wantID, wantSeq int) bool {
	if len(quoted) < 20 {
		return false
	}
	ihl := int(quoted[0]&0x0f) * 4
	if ihl < 20 || len(quoted) < ihl+8 {
		return false
	}
	inner := quoted[ihl:]
	if inner[0] != 8 { // ICMP echo request
		return false
	}
	gotID := int(inner[4])<<8 | int(inner[5])
	gotSeq := int(inner[6])<<8 | int(inner[7])
	return echoMatches(mode, gotID, gotSeq, wantID, wantSeq)
}

// dstUnreachName renders an ICMP Destination Unreachable code as the raw cause
// behind the classification, the way the Windows path reports its IP_STATUS name.
func dstUnreachName(code int) string {
	switch code {
	case 0:
		return "NetUnreachable"
	case 1:
		return "HostUnreachable"
	case 2:
		return "ProtocolUnreachable"
	case 3:
		return "PortUnreachable"
	case 4:
		return "FragmentationNeeded"
	case 5:
		return "SourceRouteFailed"
	case 9, 10:
		return "AdminProhibited"
	case 13:
		return "CommunicationAdministrativelyProhibited"
	default:
		return fmt.Sprintf("DestinationUnreachable(code %d)", code)
	}
}
