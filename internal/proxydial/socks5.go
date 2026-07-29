package proxydial

import (
	"context"
	"errors"
	"net"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/proxy"

	"github.com/nettact/agent/internal/netguard"
	pcfg "github.com/nettact/protocol/config"
	"github.com/nettact/protocol/telemetry"
)

// SOCKS5 (RFC 1928) with optional username/password auth (RFC 1929).
//
// x/net/proxy implements the protocol; what this file adds is the two things that
// make a failure diagnosable:
//
//  1. the connection TO the proxy goes through the netguard Guard, so the proxy
//     endpoint is policy-checked and IP-pinned like any other destination the agent
//     dials; and
//  2. the SOCKS5 reply code is translated into a proxy_* reason, so "the proxy
//     refused to reach the target" never surfaces as a target timeout.

// newSOCKS5 builds a SOCKS5 dialer. Nothing is dialed here — proxy.SOCKS5 only
// captures config — so a wrong password surfaces on the first probe as
// ProbeReasonProxyAuth rather than as a build failure with no target attached.
func (m *Manager) newSOCKS5(spec pcfg.ProxySpec) (*Dialer, error) {
	if spec.Host == "" || spec.Port <= 0 {
		return nil, invalidConfig("socks5 proxy needs a host and port")
	}
	addr := net.JoinHostPort(spec.Host, strconv.Itoa(spec.Port))
	var auth *proxy.Auth
	if spec.Username != "" {
		auth = &proxy.Auth{User: spec.Username, Password: spec.Password}
	}
	base := guardDialer{guard: m.guard, timeout: spec.ProxyConnectTimeout()}
	sd, err := proxy.SOCKS5("tcp", addr, auth, base)
	if err != nil {
		return nil, invalidConfig("build socks5 dialer: %v", err)
	}
	ctxDialer, ok := sd.(proxy.ContextDialer)
	if !ok {
		// Without context support a probe's deadline could not cancel a hung
		// handshake. Refuse rather than dial uncancellably.
		return nil, invalidConfig("socks5 dialer does not support contexts")
	}
	return &Dialer{
		Spec: spec,
		dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			// UDP goes through an association, not CONNECT. Handling it here rather than
			// at the call sites keeps the collectors transport-agnostic: they ask for
			// "udp" exactly as they do against the host stack.
			if isUDPNetwork(network) {
				return dialSOCKS5UDPConn(ctx, m.guard, base, addr, spec, address)
			}
			// The handshake budget must cover the SOCKS5 NEGOTIATION, not just the TCP
			// connect. guardDialer's own timeout ends the moment the socket is returned, so
			// a proxy that accepts and then stalls mid-handshake would otherwise run under
			// the probe's full timeout — consuming the whole budget and then being reported
			// as a target that did not answer.
			//
			// x/net/proxy applies ctx.Deadline() to the conn for the exchange and clears it
			// on return (and tears down its own cancellation goroutine), so bounding the
			// whole DialContext call is both sufficient and safe for the returned conn.
			hctx, cancel := handshakeContext(ctx, spec.ProxyConnectTimeout())
			defer cancel()
			conn, derr := ctxDialer.DialContext(hctx, network, address)
			if derr != nil {
				return nil, classifySOCKS5(derr)
			}
			return conn, nil
		},
		// SOCKS5 is the one relay protocol that forwards datagrams (UDP ASSOCIATE,
		// RFC 1928 §7), so it gets a packet conn. Each association is opened on demand
		// and owned by the caller — the STUN probes in particular need one socket that
		// can address several destinations, which is exactly the shape ASSOCIATE gives.
		listenPacket: func() (net.PacketConn, error) {
			// The association setup is bounded by the proxy-handshake budget, separately
			// from the probe's own timeout, for the same reason every other proxy dial is:
			// a proxy that hangs must not consume the whole probe budget and then be
			// reported as a target that did not answer.
			ctx, cancel := context.WithTimeout(context.Background(), spec.ProxyConnectTimeout())
			defer cancel()
			return dialSOCKS5UDP(ctx, base, addr, spec.Username, spec.Password)
		},
	}, nil
}

// guardDialer adapts netguard.Guard to proxy.Dialer/ContextDialer so x/net/proxy
// reaches the proxy endpoint through the agent's target-access policy rather than
// the bare stdlib dialer.
//
// timeout bounds reaching the proxy SEPARATELY from the probe's own budget: a proxy
// that blackholes must not consume the whole probe timeout and then be reported as
// a target that did not answer.
type guardDialer struct {
	guard   *netguard.Guard
	timeout time.Duration
}

// Dial satisfies proxy.Dialer for any caller that ignores the context path.
func (g guardDialer) Dial(network, address string) (net.Conn, error) {
	return g.DialContext(context.Background(), network, address)
}

func (g guardDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if g.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, g.timeout)
		defer cancel()
	}
	conn, err := g.guard.DialContext(ctx, network, address)
	if err != nil {
		// A policy block is the agent refusing to dial; it must stay recognizable as
		// such rather than be tagged as a proxy-reach failure.
		if _, blocked := isBlockedError(err); blocked {
			return nil, err
		}
		// Tag every other failure to REACH the proxy. This is what lets classifySOCKS5
		// tell "could not get to the proxy" from "the proxy answered with a SOCKS reply"
		// without reading OS error text — see errProxyUnreachable.
		return nil, &proxyReachError{err: err}
	}
	return conn, nil
}

// handshakeContext derives the context bounding a proxy handshake — reaching the proxy
// AND completing its protocol negotiation.
//
// The distinction from the probe's own timeout is the point: a proxy that accepts TCP
// and then stalls must fail on the handshake budget, not silently eat the whole probe
// budget and be reported as an unresponsive target. A non-positive timeout means
// "unbounded", leaving the probe context in charge.
func handshakeContext(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if timeout <= 0 {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, timeout)
}

// proxyReachError marks a failure to reach the proxy itself, as opposed to anything
// the proxy said once reached.
//
// It exists because both cases can produce the same text. A closed proxy port yields
// "connection refused" from the OS on Unix, and SOCKS5 reply 0x05 also means
// "connection refused" — but the first is a dead proxy and the second is a live proxy
// reporting a closed TARGET. Distinguishing them by string is therefore both wrong and
// platform-dependent (Windows words the OS error differently), so the distinction is
// made structurally at the one place that knows: the dial to the proxy.
type proxyReachError struct{ err error }

func (e *proxyReachError) Error() string { return e.err.Error() }
func (e *proxyReachError) Unwrap() error { return e.err }

// classifySOCKS5 turns a SOCKS5 dial failure into a *ProxyError carrying the
// reason the operator needs.
//
// The structural checks come FIRST and are what make the result trustworthy; the
// substring matching that follows only ever sees text the proxy itself produced,
// because x/net/proxy does not export a typed reply error and formats the RFC 1928
// reply code into the message. Doing that mapping is still worth it: "the proxy
// rejected your credentials", "the proxy will not relay there" and "the target
// refused the connection" are three different actions, and collapsing them into one
// generic failure would discard the only signal the proxy gave us.
func classifySOCKS5(err error) error {
	// A policy block from the guard is not a proxy fault: it means the agent refused
	// to dial the PROXY. Pass it through untouched so the collector routes it to the
	// monitor-status tracker as a block, exactly as for a direct dial.
	var blocked *netguard.BlockedError
	if errors.As(err, &blocked) {
		return err
	}
	// A failure to REACH the proxy is decided structurally, never by text. This must
	// precede the matching below: a closed proxy port reports "connection refused" on
	// Unix, which is also what SOCKS5 reply 0x05 says about a closed TARGET — so a
	// string match here would report a dead proxy as a dead service, and would do it
	// only on some platforms.
	var unreachable *proxyReachError
	if errors.As(err, &unreachable) {
		return &ProxyError{Reason: telemetry.ProbeReasonProxyConnect, Err: err}
	}
	s := strings.ToLower(err.Error())
	switch {
	case strings.Contains(s, "authentication") || strings.Contains(s, "password"):
		return &ProxyError{Reason: telemetry.ProbeReasonProxyAuth, Err: err}
	// "connection refused" from the SOCKS exchange is reply 0x05: the proxy reached
	// the target and the target refused. That is the one reply genuinely about the
	// target, so it keeps the target's own reason — reporting a closed port as a proxy
	// fault would send the operator to the wrong system.
	case strings.Contains(s, "connection refused"):
		return &ProxyError{Reason: telemetry.ProbeReasonRefused, Err: err, AtTarget: true}
	case strings.Contains(s, "host unreachable"), strings.Contains(s, "network unreachable"),
		strings.Contains(s, "not allowed"), strings.Contains(s, "ttl expired"),
		strings.Contains(s, "general socks server failure"):
		return &ProxyError{Reason: telemetry.ProbeReasonProxyRefused, Err: err}
	case strings.Contains(s, "command not supported"), strings.Contains(s, "address type not supported"):
		return &ProxyError{Reason: telemetry.ProbeReasonProxyConfig, Err: err}
	}
	// Anything else happened while reaching or handshaking with the proxy: the
	// target was never contacted, so it must not be blamed.
	return &ProxyError{Reason: telemetry.ProbeReasonProxyConnect, Err: err}
}
