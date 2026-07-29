package proxydial

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/nettact/agent/internal/netguard"
	pcfg "github.com/nettact/protocol/config"
	"github.com/nettact/protocol/telemetry"
)

// HTTP CONNECT tunnelling, with optional Basic auth.
//
// CONNECT is used for EVERY target, including plain-http ones that an
// absolute-URI GET through the proxy would also satisfy. That is deliberate:
//
//   - one code path means one error-classification path, so an http:// and an
//     https:// monitor through the same proxy report the same reason for the same
//     failure;
//   - the collectors already hold a fully-configured transport (TLS policy,
//     redirect policy, response caps). Handing them a DialContext keeps all of that
//     untouched, whereas Transport.Proxy would reroute request construction and
//     make the absolute-URI form leak the probe's headers to the proxy; and
//   - a TCP monitor needs a raw tunnelled conn anyway, so CONNECT is required
//     regardless.

// newHTTPConnect builds an HTTP CONNECT dialer. As with SOCKS5, nothing is dialed
// at build time.
func (m *Manager) newHTTPConnect(spec pcfg.ProxySpec) (*Dialer, error) {
	if spec.Host == "" || spec.Port <= 0 {
		return nil, invalidConfig("http proxy needs a host and port")
	}
	proxyAddr := net.JoinHostPort(spec.Host, strconv.Itoa(spec.Port))
	var authHeader string
	if spec.Username != "" {
		authHeader = "Basic " + base64.StdEncoding.EncodeToString([]byte(spec.Username+":"+spec.Password))
	}
	base := guardDialer{guard: m.guard, timeout: spec.ProxyConnectTimeout()}
	return &Dialer{
		Spec: spec,
		dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			// CONNECT tunnels a TCP byte stream and nothing else. Without this guard a
			// "udp" dial would still be CONNECTed and hand back a TCP stream aimed at the
			// target's UDP port — a conn that looks usable and carries garbage. The
			// capability matrix already refuses the combination; this fails closed if it
			// ever drifts.
			if isUDPNetwork(network) {
				return nil, fmt.Errorf("%w: http CONNECT cannot carry UDP", ErrProxyKindUnsupported)
			}
			return dialHTTPConnect(ctx, base, proxyAddr, address, authHeader, spec.ProxyConnectTimeout())
		},
	}, nil
}

// dialHTTPConnect opens a tunnel to target through an HTTP proxy.
func dialHTTPConnect(ctx context.Context, base guardDialer, proxyAddr, target, authHeader string,
	handshakeTimeout time.Duration) (net.Conn, error) {
	conn, err := base.DialContext(ctx, "tcp", proxyAddr)
	if err != nil {
		// A policy block means the agent refused to dial the PROXY; pass it through so
		// the collector routes it to the monitor-status tracker as a block.
		var blocked *netguard.BlockedError
		if errors.As(err, &blocked) {
			return nil, err
		}
		return nil, &ProxyError{Reason: telemetry.ProbeReasonProxyConnect, Err: err}
	}

	// The CONNECT exchange itself must honor the probe deadline, so cancellation is
	// wired to the socket rather than left to block on a proxy that accepts and then
	// says nothing. Any early return closes the conn — a leaked half-open tunnel per
	// failed cycle would exhaust the proxy's connection table.
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-done:
		}
	}()
	// The handshake budget must also cover the NEGOTIATION, not just the TCP connect
	// base.DialContext bounded. It is applied as a socket deadline rather than through
	// the cancellation goroutine above on purpose: cancelling a derived context on
	// return would race that goroutine's select, and losing the race would close the
	// tunnel we just established.
	//
	// Cleared on success below, so the returned conn carries no leftover deadline.
	if to := handshakeTimeout; to > 0 {
		_ = conn.SetDeadline(time.Now().Add(to))
	}

	req := "CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n"
	if authHeader != "" {
		req += "Proxy-Authorization: " + authHeader + "\r\n"
	}
	req += "\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		_ = conn.Close()
		return nil, &ProxyError{Reason: telemetry.ProbeReasonProxyConnect, Err: fmt.Errorf("write CONNECT: %w", err)}
	}

	// bufio is required by http.ReadResponse. It must not over-read past the header
	// terminator or the tunnelled bytes would be stranded in a buffer the caller
	// never sees — so the reader is handed to a wrapper that drains it first.
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		_ = conn.Close()
		if ctx.Err() != nil {
			return nil, &ProxyError{Reason: telemetry.ProbeReasonProxyConnect, Err: ctx.Err()}
		}
		return nil, &ProxyError{Reason: telemetry.ProbeReasonProxyConnect, Err: fmt.Errorf("read CONNECT response: %w", err)}
	}
	// The CONNECT response body is never the tunnel; it is an error page at most.
	if resp.Body != nil {
		_ = resp.Body.Close()
	}
	if resp.StatusCode != http.StatusOK {
		_ = conn.Close()
		return nil, &ProxyError{Reason: connectStatusReason(resp.StatusCode),
			Err: fmt.Errorf("proxy CONNECT returned %s", resp.Status)}
	}
	// The tunnel is up: drop the handshake deadline so the caller's own per-probe
	// deadlines are the only ones in force. Leaving it set would abort the tunnelled
	// request the moment the handshake budget elapsed.
	if handshakeTimeout > 0 {
		_ = conn.SetDeadline(time.Time{})
	}
	if n := br.Buffered(); n > 0 {
		return &bufferedConn{Conn: conn, r: br}, nil
	}
	return conn, nil
}

// connectStatusReason maps a CONNECT status onto a proxy_* reason.
//
// The status is the proxy's own verdict on the request, which makes it a far better
// diagnosis than the timeout the probe would otherwise report:
//
//	407 — the proxy wants (different) credentials
//	403/405 — the proxy will not relay to this destination or by this method
//	502/503/504 — the proxy tried and could not reach the target
//
// A 4xx the proxy invented about our request is a config problem on our side; a
// 5xx is the proxy's own upstream failure.
func connectStatusReason(status int) int {
	switch status {
	case http.StatusProxyAuthRequired, http.StatusUnauthorized:
		return telemetry.ProbeReasonProxyAuth
	case http.StatusForbidden, http.StatusMethodNotAllowed:
		return telemetry.ProbeReasonProxyRefused
	case http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return telemetry.ProbeReasonProxyRefused
	}
	if status >= 400 && status < 500 {
		return telemetry.ProbeReasonProxyConfig
	}
	return telemetry.ProbeReasonProxyConnect
}

// bufferedConn hands back bytes the CONNECT response read ahead into the bufio
// buffer before exposing the raw socket.
//
// It is needed because http.ReadResponse reads in chunks: if the proxy sent the
// 200 header and the target's first bytes in one segment, those bytes are already
// in the buffer. Returning the bare conn would silently drop them — which for a
// TLS monitor means a handshake that fails on a truncated ServerHello, with no hint
// that the proxy was involved.
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.r.Read(p) }
