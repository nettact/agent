//go:build linux || darwin

package traceroute

import (
	"context"
	"errors"
	"math/rand/v2"
	"net"
	"net/netip"
	"sync"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"
)

// Linux and macOS TTL probes. Both modes need to OBSERVE the ICMP Time-Exceeded
// replies intermediate routers send back; sending costs no privilege in either
// mode, since the TTL is an ordinary IP_TTL socket option. What the two OSes
// differ on is which socket can see those replies.
//
// A raw ICMP socket (root; CAP_NET_RAW on Linux) works everywhere and is tried
// first. Failing that, macOS — and only macOS — has a second way in: an
// UNPRIVILEGED datagram ICMP socket, which on Darwin delivers a router's
// Time-Exceeded as an ordinary readable packet. Linux's superficially similar
// ping socket does not: it diverts ICMP errors to the socket error queue, so a
// datagram fallback there would yield a probe that can only ever report
// timeouts — strictly worse than reporting no capability at all. The fallback
// is therefore gated on datagramICMPUsable, a per-OS constant, rather than
// tried opportunistically. See resolveICMPSocket for what was measured.
//
// Whichever socket is chosen, everything downstream is unchanged: the id/seq
// and quotation correlation still has to run (a Darwin datagram socket is NOT
// demuxed to this process's own echoes — it also sees ICMP belonging to other
// processes on the host, so the match is what keeps replies apart), and packets
// read with recvfrom(2) still arrive with their outer IP header on both socket
// kinds, so matchICMPQuotation's offsets hold either way.

// icmpSocketKind is how this process is able to open an ICMP socket, resolved
// once and reused: a privilege level cannot be gained mid-process, and the
// probes re-check on every open anyway (a socket that fails to open is reported
// as errUnsupported, not as a path outcome).
type icmpSocketKind int

const (
	icmpSocketNone icmpSocketKind = iota
	icmpSocketRaw
	icmpSocketDatagram
)

// resolveICMPSocket picks the best ICMP socket this process can open.
//
// The datagram branch is not a degraded mode: measured on macOS 26 as an
// unprivileged user, it delivers intermediate Time-Exceeded messages readably,
// preserves the echo id and sequence into the quotation (Darwin does not
// rewrite them the way Linux's ping socket does, so matchQuotedEcho is
// unaffected), carries the quotation of a TTL-limited TCP SYN so tcpProbe works
// too, and still fails sends with EHOSTUNREACH when the host cannot reach the
// wire, which is what keeps the localUnreachable verdict intact. That is the
// whole contract this file depends on, so both modes are offered on it.
var resolveICMPSocket = sync.OnceValue(func() icmpSocketKind {
	if s, err := sysSocket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_ICMP); err == nil {
		_ = unix.Close(s)
		return icmpSocketRaw
	}
	if datagramICMPUsable {
		if s, err := sysSocket(unix.AF_INET, unix.SOCK_DGRAM, unix.IPPROTO_ICMP); err == nil {
			_ = unix.Close(s)
			return icmpSocketDatagram
		}
	}
	return icmpSocketNone
})

// detectCapabilities reports whether this process can run traceroute at all,
// which here is exactly "can it open an ICMP socket that sees router replies".
// Both modes rise and fall together, the same shape as the Windows elevation
// check gating TCP there.
func detectCapabilities() capabilities {
	if resolveICMPSocket() == icmpSocketNone {
		return capabilities{}
	}
	return capabilities{ICMP: true, TCP: true}
}

// icmpListenNetwork spells the chosen socket kind for x/net/icmp, whose ReadFrom
// normalizes both kinds to the bare ICMP message before it returns.
func icmpListenNetwork(k icmpSocketKind) string {
	if k == icmpSocketDatagram {
		return "udp4"
	}
	return "ip4:icmp"
}

// icmpDestAddr wraps dest in the address type the chosen socket kind accepts:
// a datagram ICMP socket is addressed like UDP (with a meaningless port), a raw
// one by bare IP.
func icmpDestAddr(k icmpSocketKind, dest netip.Addr) net.Addr {
	if k == icmpSocketDatagram {
		return &net.UDPAddr{IP: dest.AsSlice()}
	}
	return &net.IPAddr{IP: dest.AsSlice()}
}

// icmpProbe sends one ICMP echo toward dest with the given TTL. An echo reply
// from the destination means reached; a Time-Exceeded (or an unreachable)
// quoting our echo is an intermediate responder; nothing attributable within
// the budget is a timeout.
func icmpProbe(ctx context.Context, dest netip.Addr, _ int, ttl int, timeout time.Duration) (probeOutcome, error) {
	if !dest.Is4() {
		return probeOutcome{}, errUnsupported
	}
	kind := resolveICMPSocket()
	if kind == icmpSocketNone {
		return probeOutcome{}, errUnsupported
	}
	conn, err := icmp.ListenPacket(icmpListenNetwork(kind), "0.0.0.0")
	if err != nil {
		return probeOutcome{}, errUnsupported // capability lost since startup
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

	// Neither socket kind is demuxed to this probe's own echoes — a raw socket
	// sees every ICMP packet on the host, and a Darwin datagram ICMP socket was
	// measured receiving other processes' replies too — so id+seq is what keeps
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
	if _, err := conn.WriteTo(wb, icmpDestAddr(kind, dest)); err != nil {
		// The kernel refused the packet outright (no route, the egress link down).
		// That is not a silent hop: nothing was sent, so the sweep has nothing left
		// to learn from further TTLs.
		if isLocalSendFailure(err) {
			return probeOutcome{localUnreachable: true}, nil
		}
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
			// never "reached", which only an echo reply establishes. But an
			// unreachable sourced from THIS host is our own kernel reporting that
			// it could not send at all — the packet never reached the wire, the
			// TTL played no part in it, and naming ourselves as the hop would
			// invent a router that does not exist.
			if matchQuotedEcho(body.Data, id, seq) {
				if isLocalAddr(responder) {
					return probeOutcome{localUnreachable: true}, nil
				}
				return probeOutcome{responder: responder, rttMs: rtt}, nil
			}
		}
	}
}

// isLocalSendFailure reports whether a send failed because this host had no way
// to emit the packet, as opposed to any transient socket error. These are the
// errnos the stack returns when routing itself fails, so the probe never made it
// out and no TTL sweep can say anything about the path. EHOSTDOWN is in the list
// for macOS, where a neighbour entry that never resolved commonly surfaces as
// that rather than EHOSTUNREACH.
func isLocalSendFailure(err error) bool {
	return errors.Is(err, unix.ENETUNREACH) ||
		errors.Is(err, unix.EHOSTUNREACH) ||
		errors.Is(err, unix.EHOSTDOWN) ||
		errors.Is(err, unix.ENETDOWN)
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

	kind := resolveICMPSocket()
	if kind == icmpSocketNone {
		return probeOutcome{}, errUnsupported
	}
	sockType := unix.SOCK_RAW
	if kind == icmpSocketDatagram {
		sockType = unix.SOCK_DGRAM
	}
	// This socket only ever RECEIVES; it is the one that can see a router's
	// Time-Exceeded quoting the SYN below. Unlike the x/net/icmp path in
	// icmpProbe, recvfrom(2) hands back the outer IP header on both kinds, so
	// matchICMPQuotation reads the same layout either way.
	raw, err := sysSocket(unix.AF_INET, sockType, unix.IPPROTO_ICMP)
	if err != nil {
		return probeOutcome{}, errUnsupported // capability lost since startup
	}
	defer unix.Close(raw)
	// Bind to the local address that reaches dest so it receives the routers'
	// ICMP; INADDR_ANY is the fallback.
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
	case unix.ENETUNREACH, unix.EHOSTUNREACH, unix.EHOSTDOWN, unix.ENETDOWN:
		// Refused before a SYN could leave — this connect is non-blocking, so an
		// immediate return is the local routing decision and not the path
		// answering. No TTL sweep can learn anything from here.
		return probeOutcome{localUnreachable: true}, nil
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
					responder := netip.AddrFrom4(s4.Addr)
					// Same distinction the ICMP prober makes: an unreachable this
					// host sourced itself is a local send failure, not a hop.
					if isLocalAddr(responder) {
						return probeOutcome{localUnreachable: true}, nil
					}
					return probeOutcome{responder: responder, rttMs: rtt()}, nil
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

// responderFromAddr extracts an IPv4 responder address from a source address as
// x/net/icmp reports it. Both shapes must be handled: a raw ICMP socket yields
// *net.IPAddr, a datagram one *net.UDPAddr (whose port is meaningless here).
// Accepting only the former would not fail loudly — every hop would come back
// with an invalid responder and be normalized into a timeout, so a working
// macOS trace would render as a column of stars.
func responderFromAddr(from net.Addr) netip.Addr {
	var ip net.IP
	switch v := from.(type) {
	case *net.IPAddr:
		ip = v.IP
	case *net.UDPAddr:
		ip = v.IP
	default:
		return netip.Addr{}
	}
	a, ok := netip.AddrFromSlice(ip)
	if !ok {
		return netip.Addr{}
	}
	return a.Unmap()
}
