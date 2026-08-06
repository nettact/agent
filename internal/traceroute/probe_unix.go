//go:build linux || darwin

package traceroute

import (
	"context"
	"math/rand/v2"
	"net"
	"net/netip"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"
)

// Linux and macOS TTL probes. Both modes need to OBSERVE the ICMP Time-Exceeded
// replies intermediate routers send back, and on both OSes only a raw ICMP
// socket (root; CAP_NET_RAW on Linux) is known to deliver those as readable
// packets — Linux's unprivileged ping socket routes its ICMP errors to the
// socket error queue instead, and whether macOS's unprivileged datagram ICMP
// socket delivers them readably is unverified on real hardware, so it is
// deliberately not relied on here. A single raw-socket check therefore gates
// both modes, the same shape as the Windows elevation check gating TCP there.
//
// Sending the probe itself needs no privilege in either mode: the TTL is an
// ordinary IP_TTL socket option.

// detectCapabilities reports whether this process can run traceroute at all,
// which here is exactly "can it open a raw ICMP socket".
func detectCapabilities() capabilities {
	s, err := sysSocket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_ICMP)
	if err != nil {
		return capabilities{}
	}
	_ = unix.Close(s)
	return capabilities{ICMP: true, TCP: true}
}

// icmpProbe sends one ICMP echo toward dest with the given TTL on a raw socket.
// An echo reply from the destination means reached; a Time-Exceeded (or an
// unreachable) quoting our echo is an intermediate responder; nothing
// attributable within the budget is a timeout.
func icmpProbe(ctx context.Context, dest netip.Addr, _ int, ttl int, timeout time.Duration) (probeOutcome, error) {
	if !dest.Is4() {
		return probeOutcome{}, errUnsupported
	}
	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return probeOutcome{}, errUnsupported // raw-socket capability lost since startup
	}
	defer conn.Close()
	p := conn.IPv4PacketConn()
	if p == nil {
		return probeOutcome{}, errUnsupported
	}
	if err := p.SetTTL(ttl); err != nil {
		return probeOutcome{}, err
	}

	if timeout <= 0 {
		timeout = time.Second
	}
	deadline := time.Now().Add(timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return probeOutcome{}, err
	}

	// A raw socket sees every ICMP packet on the host, so id+seq is what keeps
	// concurrent traces from stealing each other's replies.
	id := int(rand.Uint32() & 0xffff)
	seq := int(rand.Uint32() & 0xffff)
	wm := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Body: &icmp.Echo{ID: id, Seq: seq, Data: []byte("nettact-trace")},
	}
	wb, err := wm.Marshal(nil)
	if err != nil {
		return probeOutcome{}, err
	}

	start := time.Now()
	if _, err := conn.WriteTo(wb, &net.IPAddr{IP: dest.AsSlice()}); err != nil {
		return probeOutcome{timeout: true}, nil
	}

	rb := make([]byte, 1500)
	for {
		n, from, rerr := conn.ReadFrom(rb)
		if rerr != nil {
			return probeOutcome{timeout: true}, nil
		}
		rm, perr := icmp.ParseMessage(ipv4.ICMPTypeEchoReply.Protocol(), rb[:n])
		if perr != nil {
			continue
		}
		rtt := float64(time.Since(start).Microseconds()) / 1000.0
		responder := responderFromAddr(from)
		switch body := rm.Body.(type) {
		case *icmp.Echo:
			// Only the destination answers an echo, so this is arrival.
			if rm.Type == ipv4.ICMPTypeEchoReply && body.ID == id && body.Seq == seq {
				return probeOutcome{responder: responder, reached: true, rttMs: rtt}, nil
			}
		case *icmp.TimeExceeded:
			if matchQuotedEcho(body.Data, id, seq) {
				return probeOutcome{responder: responder, rttMs: rtt}, nil
			}
		case *icmp.DstUnreach:
			// A router refusing to forward is still a hop we can name; it is
			// never "reached", which only an echo reply establishes.
			if matchQuotedEcho(body.Data, id, seq) {
				return probeOutcome{responder: responder, rttMs: rtt}, nil
			}
		}
	}
}

// tcpProbe runs one TTL-aware TCP probe. It sets IP_TTL on a non-blocking connect
// socket and, on a raw ICMP socket, watches for a Time-Exceeded whose quoted TCP
// header matches this probe. A completed connect (SYN-ACK) or a refusal (RST)
// means the destination answered; a captured Time-Exceeded is an intermediate
// responder; neither within the budget is a timeout. It never falls back to ICMP.
//
// Both sockets are watched with one poll(2), so there is no goroutine to unblock
// and no close-while-blocked race.
func tcpProbe(ctx context.Context, dest netip.Addr, port, ttl int, timeout time.Duration) (probeOutcome, error) {
	if !dest.Is4() {
		return probeOutcome{}, errUnsupported
	}
	ip4 := dest.As4()

	raw, err := sysSocket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_ICMP)
	if err != nil {
		return probeOutcome{}, errUnsupported // raw-socket capability lost since startup
	}
	defer unix.Close(raw)
	// Bind the raw socket to the local address that reaches dest so it receives the
	// routers' ICMP; INADDR_ANY is the fallback.
	if berr := unix.Bind(raw, &unix.SockaddrInet4{Addr: localIPv4For(dest)}); berr != nil {
		return probeOutcome{}, errUnsupported
	}

	tcp, err := sysSocket(unix.AF_INET, unix.SOCK_STREAM, unix.IPPROTO_TCP)
	if err != nil {
		return probeOutcome{}, err
	}
	defer unix.Close(tcp)
	// Bind to an ephemeral port so the ICMP quotation can be correlated to us.
	if berr := unix.Bind(tcp, &unix.SockaddrInet4{}); berr != nil {
		return probeOutcome{}, berr
	}
	srcPort := 0
	if sa, gerr := unix.Getsockname(tcp); gerr == nil {
		if s4, ok := sa.(*unix.SockaddrInet4); ok {
			srcPort = s4.Port
		}
	}
	if serr := unix.SetsockoptInt(tcp, unix.IPPROTO_IP, unix.IP_TTL, ttl); serr != nil {
		return probeOutcome{}, serr
	}
	if serr := unix.SetNonblock(tcp, true); serr != nil {
		return probeOutcome{}, serr
	}

	start := time.Now()
	rtt := func() float64 { return float64(time.Since(start).Microseconds()) / 1000.0 }

	switch cerr := unix.Connect(tcp, &unix.SockaddrInet4{Addr: ip4, Port: port}); cerr {
	case nil:
		return probeOutcome{responder: dest, reached: true, rttMs: rtt()}, nil
	case unix.EINPROGRESS:
		// Normal: the handshake is in flight, resolved by the poll loop below.
	case unix.ECONNREFUSED:
		return probeOutcome{responder: dest, reached: true, rttMs: rtt()}, nil
	default:
		return probeOutcome{timeout: true}, nil
	}

	if timeout <= 0 {
		timeout = time.Second
	}
	deadline := time.Now().Add(timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}

	fds := []unix.PollFd{
		{Fd: int32(tcp), Events: unix.POLLOUT},
		{Fd: int32(raw), Events: unix.POLLIN},
	}
	buf := make([]byte, 1500)
	for {
		if ctx.Err() != nil {
			return probeOutcome{timeout: true}, nil
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return probeOutcome{timeout: true}, nil
		}
		// Cap each wait so context cancellation is noticed promptly, and never
		// pass 0 — that would turn the loop into a spin for the last sub-
		// millisecond of the budget.
		wait := remaining
		if wait > 100*time.Millisecond {
			wait = 100 * time.Millisecond
		}
		waitMs := int(wait.Milliseconds())
		if waitMs < 1 {
			waitMs = 1
		}
		n, perr := unix.Poll(fds, waitMs)
		if perr == unix.EINTR {
			continue
		}
		if perr != nil {
			return probeOutcome{}, perr
		}
		if n == 0 {
			continue
		}

		// The ICMP side is checked first: when a router answers, that responder is
		// the useful hop even if the connect socket also just reported an error
		// derived from the very same packet.
		if fds[1].Revents&unix.POLLIN != 0 {
			rn, from, rerr := unix.Recvfrom(raw, buf, 0)
			if rerr == nil && rn > 0 && matchICMPQuotation(buf[:rn], ip4, port, srcPort) {
				if s4, ok := from.(*unix.SockaddrInet4); ok {
					return probeOutcome{responder: netip.AddrFrom4(s4.Addr), rttMs: rtt()}, nil
				}
			}
		}
		if fds[0].Revents&(unix.POLLOUT|unix.POLLERR|unix.POLLHUP) != 0 {
			soErr, gerr := unix.GetsockoptInt(tcp, unix.SOL_SOCKET, unix.SO_ERROR)
			if gerr != nil {
				return probeOutcome{timeout: true}, nil
			}
			switch unix.Errno(soErr) {
			case 0:
				return probeOutcome{responder: dest, reached: true, rttMs: rtt()}, nil
			case unix.ECONNREFUSED:
				// RST from the destination: it answered, so it was reached.
				return probeOutcome{responder: dest, reached: true, rttMs: rtt()}, nil
			default:
				// The connect failed off the back of an ICMP error (TTL exceeded,
				// unreachable). Retire the descriptor and give the raw socket the
				// rest of the budget to name the responder.
				//
				// A negative fd is how poll(2) is told to ignore an entry: merely
				// clearing Events would not work, because POLLERR and POLLHUP are
				// reported whether or not they were requested, so this branch would
				// re-fire on every iteration and spin until the deadline.
				fds[0].Fd = -1
			}
		}
	}
}

// responderFromAddr extracts an IPv4 responder address from a raw-socket source.
func responderFromAddr(from net.Addr) netip.Addr {
	ipa, ok := from.(*net.IPAddr)
	if !ok {
		return netip.Addr{}
	}
	a, ok := netip.AddrFromSlice(ipa.IP)
	if !ok {
		return netip.Addr{}
	}
	return a.Unmap()
}
