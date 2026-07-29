package proxydial

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nettact/agent/internal/netguard"
	"github.com/nettact/agent/probepolicy"
	pcfg "github.com/nettact/protocol/config"
	"github.com/nettact/protocol/telemetry"
)

// bypassGuard allows every destination, so these tests exercise the proxy
// protocols rather than the target-access policy (which netguard's own tests
// cover).
func bypassGuard() *netguard.Guard { return netguard.New(probepolicy.Policy{}, true) }

func newTestManager() *Manager { return NewManager(bypassGuard()) }

// ---- SOCKS5 test server ----

// socks5Reply is the RFC 1928 reply code the fake server answers CONNECT with.
type socks5Server struct {
	ln net.Listener
	// reply is the CONNECT reply code: 0x00 success, 0x02 not allowed, 0x04 host
	// unreachable, 0x05 connection refused.
	reply byte
	// requireAuth makes the server demand username/password and reject the fixed
	// credentials below if they do not match.
	requireAuth        bool
	wantUser, wantPass string
	// echo is written to the client after a successful CONNECT, so a test can prove
	// the tunnel actually carries bytes.
	echo string
}

func startSOCKS5(t *testing.T, s *socks5Server) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s.ln = ln
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go s.serve(c)
		}
	}()
	return ln.Addr().String()
}

func (s *socks5Server) serve(c net.Conn) {
	defer c.Close()
	br := bufio.NewReader(c)

	// Greeting: VER NMETHODS METHODS...
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(br, hdr); err != nil {
		return
	}
	methods := make([]byte, int(hdr[1]))
	if _, err := io.ReadFull(br, methods); err != nil {
		return
	}
	if s.requireAuth {
		if _, err := c.Write([]byte{0x05, 0x02}); err != nil { // choose user/pass
			return
		}
		// Sub-negotiation: VER ULEN USER PLEN PASS
		ver := make([]byte, 2)
		if _, err := io.ReadFull(br, ver); err != nil {
			return
		}
		user := make([]byte, int(ver[1]))
		if _, err := io.ReadFull(br, user); err != nil {
			return
		}
		plen := make([]byte, 1)
		if _, err := io.ReadFull(br, plen); err != nil {
			return
		}
		pass := make([]byte, int(plen[0]))
		if _, err := io.ReadFull(br, pass); err != nil {
			return
		}
		if string(user) != s.wantUser || string(pass) != s.wantPass {
			_, _ = c.Write([]byte{0x01, 0x01}) // auth failure
			return
		}
		if _, err := c.Write([]byte{0x01, 0x00}); err != nil {
			return
		}
	} else {
		if _, err := c.Write([]byte{0x05, 0x00}); err != nil { // no auth
			return
		}
	}

	// Request: VER CMD RSV ATYP DST.ADDR DST.PORT
	req := make([]byte, 4)
	if _, err := io.ReadFull(br, req); err != nil {
		return
	}
	switch req[3] {
	case 0x01: // IPv4
		if _, err := io.ReadFull(br, make([]byte, 4)); err != nil {
			return
		}
	case 0x03: // domain
		l := make([]byte, 1)
		if _, err := io.ReadFull(br, l); err != nil {
			return
		}
		if _, err := io.ReadFull(br, make([]byte, int(l[0]))); err != nil {
			return
		}
	case 0x04: // IPv6
		if _, err := io.ReadFull(br, make([]byte, 16)); err != nil {
			return
		}
	}
	if _, err := io.ReadFull(br, make([]byte, 2)); err != nil { // port
		return
	}
	// Reply: VER REP RSV ATYP BND.ADDR BND.PORT
	if _, err := c.Write([]byte{0x05, s.reply, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}
	if s.reply == 0x00 && s.echo != "" {
		_, _ = c.Write([]byte(s.echo))
	}
}

func TestSOCKS5DialSucceedsAndCarriesBytes(t *testing.T) {
	addr := startSOCKS5(t, &socks5Server{reply: 0x00, echo: "hello-through-tunnel"})
	host, portStr, _ := net.SplitHostPort(addr)
	port, _ := strconv.Atoi(portStr)

	m := newTestManager()
	spec := pcfg.ProxySpec{ID: "p1", Type: pcfg.ProxyTypeSOCKS5, Host: host, Port: port, ConfigSerial: 1}
	m.Apply([]pcfg.ProxySpec{spec})

	d, err := m.Dialer(context.Background(), "p1")
	if err != nil {
		t.Fatalf("Dialer: %v", err)
	}
	conn, err := d.DialContext(context.Background(), "tcp", "203.0.113.5:443")
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer conn.Close()
	buf := make([]byte, len("hello-through-tunnel"))
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read through tunnel: %v", err)
	}
	if string(buf) != "hello-through-tunnel" {
		t.Fatalf("tunnel payload = %q", buf)
	}
}

// Each SOCKS5 reply code must map to the reason an operator can act on. Collapsing
// them all into one code would throw away the only diagnosis the proxy provided.
func TestSOCKS5ReplyCodeClassification(t *testing.T) {
	cases := []struct {
		name     string
		srv      *socks5Server
		wantCode int
		atTarget bool
	}{
		{
			name:     "auth failure is a proxy fault",
			srv:      &socks5Server{requireAuth: true, wantUser: "right", wantPass: "right"},
			wantCode: telemetry.ProbeReasonProxyAuth,
		},
		{
			name:     "not allowed by ruleset",
			srv:      &socks5Server{reply: 0x02},
			wantCode: telemetry.ProbeReasonProxyRefused,
		},
		{
			name:     "host unreachable via proxy",
			srv:      &socks5Server{reply: 0x04},
			wantCode: telemetry.ProbeReasonProxyRefused,
		},
		{
			// The proxy reached the target and the target said no. This is the one reply
			// that is genuinely a TARGET verdict, so it must not be blamed on the proxy.
			name:     "target refused keeps the target reason",
			srv:      &socks5Server{reply: 0x05},
			wantCode: telemetry.ProbeReasonRefused,
			atTarget: true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			addr := startSOCKS5(t, c.srv)
			host, portStr, _ := net.SplitHostPort(addr)
			port, _ := strconv.Atoi(portStr)
			m := newTestManager()
			spec := pcfg.ProxySpec{
				ID: "p1", Type: pcfg.ProxyTypeSOCKS5, Host: host, Port: port, ConfigSerial: 1,
				Username: "wrong", Password: "wrong",
			}
			m.Apply([]pcfg.ProxySpec{spec})
			d, err := m.Dialer(context.Background(), "p1")
			if err != nil {
				t.Fatalf("Dialer: %v", err)
			}
			_, err = d.DialContext(context.Background(), "tcp", "203.0.113.5:443")
			if err == nil {
				t.Fatal("expected a dial failure")
			}
			reason, atTarget, ok := ProxyReason(err)
			if !ok {
				t.Fatalf("ProxyReason did not recognize %v", err)
			}
			if reason != c.wantCode {
				t.Fatalf("reason = %d, want %d (err: %v)", reason, c.wantCode, err)
			}
			if atTarget != c.atTarget {
				t.Fatalf("atTarget = %v, want %v", atTarget, c.atTarget)
			}
		})
	}
}

// An unreachable proxy must be proxy_connect, never a target timeout — this is the
// core "distinguish proxy failure from target failure" requirement.
func TestSOCKS5UnreachableProxyIsProxyConnect(t *testing.T) {
	// Bind and immediately close, so the port is almost certainly refusing.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	host, portStr, _ := net.SplitHostPort(addr)
	port, _ := strconv.Atoi(portStr)

	m := newTestManager()
	m.Apply([]pcfg.ProxySpec{{ID: "p1", Type: pcfg.ProxyTypeSOCKS5, Host: host, Port: port, ConfigSerial: 1}})
	d, err := m.Dialer(context.Background(), "p1")
	if err != nil {
		t.Fatalf("Dialer: %v", err)
	}
	_, err = d.DialContext(context.Background(), "tcp", "203.0.113.5:443")
	if err == nil {
		t.Fatal("expected a dial failure")
	}
	reason, atTarget, ok := ProxyReason(err)
	if !ok || reason != telemetry.ProbeReasonProxyConnect || atTarget {
		t.Fatalf("reason = %d (atTarget=%v, ok=%v), want ProxyConnect at the proxy — a dead proxy must not look like a dead target",
			reason, atTarget, ok)
	}
}

// The two "connection refused" cases must be told apart STRUCTURALLY, not by text.
//
// A closed proxy port reports ECONNREFUSED from the OS ("connection refused" on Unix,
// different wording on Windows), and SOCKS5 reply 0x05 also means "connection refused"
// — about the TARGET. Classifying by substring therefore reported a dead proxy as a
// dead service, and did so only on some platforms. This asserts both verdicts from one
// test so the distinction cannot regress into a string match again.
func TestSOCKS5RefusedIsAttributedToTheRightHop(t *testing.T) {
	t.Run("dead proxy is the proxy's failure", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		addr := ln.Addr().String()
		_ = ln.Close() // nothing is listening now
		host, portStr, _ := net.SplitHostPort(addr)
		port, _ := strconv.Atoi(portStr)

		m := newTestManager()
		m.Apply([]pcfg.ProxySpec{{ID: "p1", Type: pcfg.ProxyTypeSOCKS5, Host: host, Port: port, ConfigSerial: 1}})
		d, derr := m.Dialer(context.Background(), "p1")
		if derr != nil {
			t.Fatal(derr)
		}
		_, err = d.DialContext(context.Background(), "tcp", "203.0.113.5:443")
		reason, atTarget, ok := ProxyReason(err)
		if !ok || reason != telemetry.ProbeReasonProxyConnect || atTarget {
			t.Fatalf("reason = %d atTarget = %v (ok=%v), want ProxyConnect at the proxy — the target was never reached",
				reason, atTarget, ok)
		}
	})

	t.Run("socks reply 0x05 is the target's failure", func(t *testing.T) {
		// A live proxy answering "connection refused" DID reach the target, so the
		// target's own reason must survive — a closed port has to read as a closed port.
		addr := startSOCKS5(t, &socks5Server{reply: 0x05})
		host, portStr, _ := net.SplitHostPort(addr)
		port, _ := strconv.Atoi(portStr)

		m := newTestManager()
		m.Apply([]pcfg.ProxySpec{{ID: "p1", Type: pcfg.ProxyTypeSOCKS5, Host: host, Port: port, ConfigSerial: 1}})
		d, derr := m.Dialer(context.Background(), "p1")
		if derr != nil {
			t.Fatal(derr)
		}
		_, err := d.DialContext(context.Background(), "tcp", "203.0.113.5:443")
		reason, atTarget, ok := ProxyReason(err)
		if !ok || reason != telemetry.ProbeReasonRefused || !atTarget {
			t.Fatalf("reason = %d atTarget = %v (ok=%v), want Refused at the target", reason, atTarget, ok)
		}
	})
}

// ---- HTTP CONNECT test server ----

type connectServer struct {
	status string // e.g. "200 Connection established"
	// wantAuth, when set, is the exact Proxy-Authorization value required; anything
	// else answers 407.
	wantAuth string
	echo     string
	// earlyPayload writes the echo in the SAME segment as the response header, to
	// prove the buffered-reader handoff does not lose bytes.
	earlyPayload bool
}

func startConnect(t *testing.T, s *connectServer) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				br := bufio.NewReader(c)
				var gotAuth string
				for {
					line, err := br.ReadString('\n')
					if err != nil {
						return
					}
					if strings.HasPrefix(strings.ToLower(line), "proxy-authorization:") {
						gotAuth = strings.TrimSpace(line[len("proxy-authorization:"):])
					}
					if line == "\r\n" || line == "\n" {
						break
					}
				}
				status := s.status
				if s.wantAuth != "" && gotAuth != s.wantAuth {
					status = "407 Proxy Authentication Required"
				}
				resp := "HTTP/1.1 " + status + "\r\n\r\n"
				if s.earlyPayload && strings.HasPrefix(status, "200") {
					// One write: header + first tunnelled bytes in a single segment.
					_, _ = c.Write([]byte(resp + s.echo))
					return
				}
				if _, err := c.Write([]byte(resp)); err != nil {
					return
				}
				if strings.HasPrefix(status, "200") && s.echo != "" {
					_, _ = c.Write([]byte(s.echo))
				}
			}()
		}
	}()
	return ln.Addr().String()
}

func connectManager(t *testing.T, addr, user, pass string) *Dialer {
	t.Helper()
	host, portStr, _ := net.SplitHostPort(addr)
	port, _ := strconv.Atoi(portStr)
	m := newTestManager()
	m.Apply([]pcfg.ProxySpec{{
		ID: "p1", Type: pcfg.ProxyTypeHTTP, Host: host, Port: port, ConfigSerial: 1,
		Username: user, Password: pass,
	}})
	d, err := m.Dialer(context.Background(), "p1")
	if err != nil {
		t.Fatalf("Dialer: %v", err)
	}
	return d
}

func TestHTTPConnectSucceeds(t *testing.T) {
	addr := startConnect(t, &connectServer{status: "200 Connection established", echo: "tunnelled"})
	d := connectManager(t, addr, "", "")
	conn, err := d.DialContext(context.Background(), "tcp", "example.com:443")
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer conn.Close()
	buf := make([]byte, len("tunnelled"))
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read through tunnel: %v", err)
	}
	if string(buf) != "tunnelled" {
		t.Fatalf("payload = %q", buf)
	}
}

// If the proxy sends the 200 header and the target's first bytes in one segment,
// those bytes are already in the bufio buffer. Returning the bare socket would drop
// them — which for a TLS monitor is a handshake failing on a truncated ServerHello,
// with nothing pointing at the proxy.
func TestHTTPConnectDoesNotLoseBytesReadWithTheHeader(t *testing.T) {
	addr := startConnect(t, &connectServer{
		status: "200 Connection established", echo: "early-bytes", earlyPayload: true,
	})
	d := connectManager(t, addr, "", "")
	conn, err := d.DialContext(context.Background(), "tcp", "example.com:443")
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer conn.Close()
	buf := make([]byte, len("early-bytes"))
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read early bytes: %v", err)
	}
	if string(buf) != "early-bytes" {
		t.Fatalf("payload = %q, want the bytes that arrived with the header", buf)
	}
}

func TestHTTPConnectSendsBasicAuth(t *testing.T) {
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("u:p"))
	addr := startConnect(t, &connectServer{status: "200 Connection established", wantAuth: want, echo: "ok"})

	t.Run("correct credentials tunnel", func(t *testing.T) {
		d := connectManager(t, addr, "u", "p")
		conn, err := d.DialContext(context.Background(), "tcp", "example.com:443")
		if err != nil {
			t.Fatalf("DialContext with correct credentials: %v", err)
		}
		_ = conn.Close()
	})
	t.Run("wrong credentials are proxy_auth", func(t *testing.T) {
		d := connectManager(t, addr, "u", "wrong")
		_, err := d.DialContext(context.Background(), "tcp", "example.com:443")
		if err == nil {
			t.Fatal("expected a failure")
		}
		reason, _, ok := ProxyReason(err)
		if !ok || reason != telemetry.ProbeReasonProxyAuth {
			t.Fatalf("reason = %d (ok=%v), want ProxyAuth", reason, ok)
		}
	})
}

func TestHTTPConnectStatusClassification(t *testing.T) {
	cases := []struct {
		status string
		want   int
	}{
		{"407 Proxy Authentication Required", telemetry.ProbeReasonProxyAuth},
		{"401 Unauthorized", telemetry.ProbeReasonProxyAuth},
		{"403 Forbidden", telemetry.ProbeReasonProxyRefused},
		{"405 Method Not Allowed", telemetry.ProbeReasonProxyRefused},
		{"502 Bad Gateway", telemetry.ProbeReasonProxyRefused},
		{"504 Gateway Timeout", telemetry.ProbeReasonProxyRefused},
		// A 4xx the proxy invented about our request is a configuration problem on
		// our side, not an unreachable target.
		{"400 Bad Request", telemetry.ProbeReasonProxyConfig},
		{"500 Internal Server Error", telemetry.ProbeReasonProxyConnect},
	}
	for _, c := range cases {
		t.Run(c.status, func(t *testing.T) {
			addr := startConnect(t, &connectServer{status: c.status})
			d := connectManager(t, addr, "", "")
			_, err := d.DialContext(context.Background(), "tcp", "example.com:443")
			if err == nil {
				t.Fatal("expected a failure")
			}
			reason, atTarget, ok := ProxyReason(err)
			if !ok {
				t.Fatalf("ProxyReason did not recognize %v", err)
			}
			if reason != c.want {
				t.Fatalf("reason = %d, want %d (err: %v)", reason, c.want, err)
			}
			// No CONNECT status ever means "the target itself answered": the tunnel was
			// never established.
			if atTarget {
				t.Fatal("a CONNECT failure must never be attributed to the target")
			}
		})
	}
}

// ---- manager lifecycle ----

// The generation is the mechanism that makes a credential rotation take effect. A
// changed ConfigSerial must produce a NEW dialer, not reuse the one built with the
// old password.
func TestApplyRebuildsOnGenerationChange(t *testing.T) {
	addr := startSOCKS5(t, &socks5Server{reply: 0x00})
	host, portStr, _ := net.SplitHostPort(addr)
	port, _ := strconv.Atoi(portStr)

	m := newTestManager()
	base := pcfg.ProxySpec{ID: "p1", Type: pcfg.ProxyTypeSOCKS5, Host: host, Port: port, ConfigSerial: 1, Password: "old", Username: "u"}
	m.Apply([]pcfg.ProxySpec{base})
	first, err := m.Dialer(context.Background(), "p1")
	if err != nil {
		t.Fatal(err)
	}

	// Same generation re-pushed: the live dialer is kept (rebuilding would drop
	// healthy connections for nothing).
	m.Apply([]pcfg.ProxySpec{base})
	same, err := m.Dialer(context.Background(), "p1")
	if err != nil {
		t.Fatal(err)
	}
	if same != first {
		t.Fatal("re-pushing the same generation rebuilt the dialer")
	}

	// New generation: must be a different dialer carrying the new credential.
	rotated := base
	rotated.ConfigSerial = 2
	rotated.Password = "new"
	m.Apply([]pcfg.ProxySpec{rotated})
	after, err := m.Dialer(context.Background(), "p1")
	if err != nil {
		t.Fatal(err)
	}
	if after == first {
		t.Fatal("a new generation reused the old dialer — a rotated credential would never take effect")
	}
	if after.Spec.Password != "new" {
		t.Fatalf("rebuilt dialer password = %q, want the rotated value", after.Spec.Password)
	}
}

// A rename must NOT rebuild: it changes no dial, and tearing down a live tunnel for
// a cosmetic edit would blank every pinned monitor.
func TestApplyRenameKeepsTheDialer(t *testing.T) {
	addr := startSOCKS5(t, &socks5Server{reply: 0x00})
	host, portStr, _ := net.SplitHostPort(addr)
	port, _ := strconv.Atoi(portStr)

	m := newTestManager()
	base := pcfg.ProxySpec{ID: "p1", Name: "before", Type: pcfg.ProxyTypeSOCKS5, Host: host, Port: port, ConfigSerial: 7}
	m.Apply([]pcfg.ProxySpec{base})
	first, err := m.Dialer(context.Background(), "p1")
	if err != nil {
		t.Fatal(err)
	}
	renamed := base
	renamed.Name = "after"
	m.Apply([]pcfg.ProxySpec{renamed})
	after, err := m.Dialer(context.Background(), "p1")
	if err != nil {
		t.Fatal(err)
	}
	if after != first {
		t.Fatal("a rename rebuilt the dialer")
	}
	if after.Spec.Name != "after" {
		t.Fatalf("display name = %q, want the new one", after.Spec.Name)
	}
}

// A proxy dropped from the push (deleted or disabled server-side) must become an
// unknown pin. The pinned monitors then fail closed instead of dialing directly.
func TestDialerAfterRemovalIsUnknown(t *testing.T) {
	addr := startSOCKS5(t, &socks5Server{reply: 0x00})
	host, portStr, _ := net.SplitHostPort(addr)
	port, _ := strconv.Atoi(portStr)

	m := newTestManager()
	m.Apply([]pcfg.ProxySpec{{ID: "p1", Type: pcfg.ProxyTypeSOCKS5, Host: host, Port: port, ConfigSerial: 1}})
	if _, err := m.Dialer(context.Background(), "p1"); err != nil {
		t.Fatal(err)
	}
	m.Apply(nil)

	_, err := m.Dialer(context.Background(), "p1")
	if !errors.Is(err, ErrUnknownProxy) {
		t.Fatalf("error = %v, want ErrUnknownProxy", err)
	}
	// It must classify as a probe failure, so the collector reports it rather than
	// silently dialing direct.
	reason, _, ok := ProxyReason(err)
	if !ok || reason != telemetry.ProbeReasonProxyConfig {
		t.Fatalf("reason = %d (ok=%v), want ProxyConfig", reason, ok)
	}
}

// An empty pin means "no proxy configured", which is a direct dial by design — not
// an error.
func TestEmptyPinReturnsNoDialer(t *testing.T) {
	m := newTestManager()
	d, err := m.Dialer(context.Background(), "")
	if err != nil || d != nil {
		t.Fatalf("Dialer(\"\") = (%v, %v), want (nil, nil)", d, err)
	}
}

// A broken config must not be retried on every probe cycle: one bad proxy would
// otherwise become a stream of connection attempts. The failure sticks until the
// next generation.
func TestBuildErrorIsStickyUntilNextGeneration(t *testing.T) {
	m := newTestManager()
	bad := pcfg.ProxySpec{ID: "p1", Type: pcfg.ProxyTypeWireGuard, ConfigSerial: 1} // no keys, no endpoint
	m.Apply([]pcfg.ProxySpec{bad})

	first := errOf(t, m, "p1")
	second := errOf(t, m, "p1")
	if first.Error() != second.Error() {
		t.Fatalf("build error was not cached: %v then %v", first, second)
	}
	if !errors.Is(first, ErrProxyInit) {
		t.Fatalf("error = %v, want ErrProxyInit", first)
	}
	// A new generation clears it, so fixing the config takes effect without an agent
	// restart.
	fixed := bad
	fixed.ConfigSerial = 2
	m.Apply([]pcfg.ProxySpec{fixed})
	if _, err := m.Dialer(context.Background(), "p1"); err == nil {
		t.Fatal("expected the still-broken config to fail")
	}
}

func errOf(t *testing.T, m *Manager, id string) error {
	t.Helper()
	_, err := m.Dialer(context.Background(), id)
	if err == nil {
		t.Fatalf("Dialer(%q) unexpectedly succeeded", id)
	}
	return err
}

// A relay transport cannot carry ICMP. DialPing must refuse rather than fall
// through to a host-stack ping, which would silently measure the wrong path.
func TestDialPingRefusedOnRelayTransports(t *testing.T) {
	addr := startSOCKS5(t, &socks5Server{reply: 0x00})
	host, portStr, _ := net.SplitHostPort(addr)
	port, _ := strconv.Atoi(portStr)
	m := newTestManager()
	m.Apply([]pcfg.ProxySpec{{ID: "p1", Type: pcfg.ProxyTypeSOCKS5, Host: host, Port: port, ConfigSerial: 1}})
	d, err := m.Dialer(context.Background(), "p1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.DialPing(context.Background(), "ping4", "1.1.1.1"); !errors.Is(err, ErrProxyKindUnsupported) {
		t.Fatalf("DialPing error = %v, want ErrProxyKindUnsupported", err)
	}
}

func TestResolvesRemotely(t *testing.T) {
	cases := []struct {
		name string
		spec pcfg.ProxySpec
		want bool
	}{
		{"default is local", pcfg.ProxySpec{Type: pcfg.ProxyTypeSOCKS5}, false},
		{"explicit remote", pcfg.ProxySpec{Type: pcfg.ProxyTypeSOCKS5, DNSMode: pcfg.ProxyDNSRemote}, true},
		// A tunnel resolves in-tunnel; there is no proxy side to defer to.
		{"wireguard is never remote", pcfg.ProxySpec{Type: pcfg.ProxyTypeWireGuard, DNSMode: pcfg.ProxyDNSRemote}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := &Dialer{Spec: c.spec}
			if got := d.ResolvesRemotely(); got != c.want {
				t.Fatalf("ResolvesRemotely = %v, want %v", got, c.want)
			}
		})
	}
}

// ProxyReason must not claim ordinary transport errors, or a plain target timeout
// on an unproxied monitor would be relabelled as a proxy fault.
func TestProxyReasonIgnoresNonProxyErrors(t *testing.T) {
	if _, _, ok := ProxyReason(errors.New("i/o timeout")); ok {
		t.Fatal("ProxyReason claimed a plain transport error")
	}
	if _, _, ok := ProxyReason(nil); ok {
		t.Fatal("ProxyReason claimed nil")
	}
}

// A policy block from the guard must pass through unwrapped: it means the agent
// refused to dial the PROXY, which the collector routes to the monitor-status
// tracker as a block rather than reporting as a probe failure.
func TestGuardBlockPassesThroughUnwrapped(t *testing.T) {
	// An allowlist with no allow selectors permits nothing, so dialing the proxy is
	// refused before a single packet leaves.
	policy := probepolicy.Policy{Mode: probepolicy.ModeAllowlist}
	m := NewManager(netguard.New(policy, false))
	m.Apply([]pcfg.ProxySpec{{ID: "p1", Type: pcfg.ProxyTypeSOCKS5, Host: "203.0.113.5", Port: 1080, ConfigSerial: 1}})
	d, derr := m.Dialer(context.Background(), "p1")
	if derr != nil {
		t.Fatalf("Dialer: %v", derr)
	}
	_, err := d.DialContext(context.Background(), "tcp", "198.51.100.7:443")
	var blocked *netguard.BlockedError
	if !errors.As(err, &blocked) {
		t.Fatalf("error = %v (%T), want a *netguard.BlockedError to survive unwrapped", err, err)
	}
	if _, _, ok := ProxyReason(err); ok {
		t.Fatal("a policy block must not be reported as a proxy failure")
	}
}

func TestWireGuardUAPIRendersHexKeysAndRoutes(t *testing.T) {
	priv := base64.StdEncoding.EncodeToString(bytesOf(0x01, 32))
	pub := base64.StdEncoding.EncodeToString(bytesOf(0x02, 32))
	psk := base64.StdEncoding.EncodeToString(bytesOf(0x03, 32))
	spec := pcfg.ProxySpec{
		Type: pcfg.ProxyTypeWireGuard, WGPrivateKey: priv, WGPeerPublicKey: pub, WGPresharedKey: psk,
		WGAllowedIPs: "10.7.0.0/24, 192.168.9.0/24", WGKeepaliveSeconds: 25,
	}
	uapi, err := wireGuardUAPI(spec, "198.51.100.9:51820")
	if err != nil {
		t.Fatal(err)
	}
	// The UAPI speaks hex while the console and the wire carry base64 (what wg(8)
	// prints and users paste), so the conversion is asserted explicitly.
	for _, want := range []string{
		"private_key=" + strings.Repeat("01", 32),
		"public_key=" + strings.Repeat("02", 32),
		"preshared_key=" + strings.Repeat("03", 32),
		"endpoint=198.51.100.9:51820",
		"allowed_ip=10.7.0.0/24",
		"allowed_ip=192.168.9.0/24",
		"persistent_keepalive_interval=25",
	} {
		if !strings.Contains(uapi, want) {
			t.Fatalf("UAPI missing %q:\n%s", want, uapi)
		}
	}
}

func TestWireGuardUAPIRejectsBadInput(t *testing.T) {
	goodKey := base64.StdEncoding.EncodeToString(bytesOf(0x01, 32))
	cases := []struct {
		name string
		spec pcfg.ProxySpec
		want string
	}{
		{"no private key", pcfg.ProxySpec{WGPeerPublicKey: goodKey, WGAllowedIPs: "10.0.0.0/8"}, "wg_private_key"},
		{"short key", pcfg.ProxySpec{
			WGPrivateKey:    base64.StdEncoding.EncodeToString(bytesOf(0x01, 16)),
			WGPeerPublicKey: goodKey, WGAllowedIPs: "10.0.0.0/8",
		}, "32 bytes"},
		{"no allowed ips", pcfg.ProxySpec{WGPrivateKey: goodKey, WGPeerPublicKey: goodKey}, "route nothing"},
		{"bad allowed ip", pcfg.ProxySpec{
			WGPrivateKey: goodKey, WGPeerPublicKey: goodKey, WGAllowedIPs: "10.7.0.1",
		}, "not a CIDR"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := wireGuardUAPI(c.spec, "198.51.100.9:51820")
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("error = %v, want one containing %q", err, c.want)
			}
		})
	}
}

func bytesOf(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

func TestParseAddrAndPrefixLists(t *testing.T) {
	// A tunnel-local address is conventionally written with a prefix length; the
	// address is what netstack needs, so the prefix is dropped.
	addrs, err := parseAddrList("10.7.0.2/32, 10.7.0.3 , ")
	if err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprint(addrs); got != "[10.7.0.2 10.7.0.3]" {
		t.Fatalf("parseAddrList = %s", got)
	}
	// CIDRs are masked so the installed route matches what was stored.
	pfxs, err := parsePrefixList("10.7.0.5/24")
	if err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprint(pfxs); got != "[10.7.0.0/24]" {
		t.Fatalf("parsePrefixList = %s", got)
	}
	if _, err := parseAddrList("not-an-ip"); err == nil {
		t.Fatal("expected an error for a non-address")
	}
	if _, err := parsePrefixList("10.7.0.1"); err == nil {
		t.Fatal("expected an error for a bare address in a CIDR list")
	}
}

// A build failure is cached only when it is DETERMINISTIC. Caching a transient one — the
// peer endpoint briefly unresolvable, the network down at startup — disabled the proxy
// until the server happened to change its generation, long after connectivity returned.
func TestBuildErrorStickinessDependsOnDeterminism(t *testing.T) {
	t.Run("a bad config is cached", func(t *testing.T) {
		m := newTestManager()
		// No keys, no endpoint: unparsable, so no retry can help.
		m.Apply([]pcfg.ProxySpec{{ID: "p1", Type: pcfg.ProxyTypeWireGuard, ConfigSerial: 1}})
		first := errOf(t, m, "p1")
		if !errors.Is(first, ErrProxyInit) {
			t.Fatalf("error = %v, want ErrProxyInit", first)
		}
		m.mu.Lock()
		cached := m.entries["p1"].buildErr != nil
		m.mu.Unlock()
		if !cached {
			t.Fatal("a deterministic config error was not cached, so it retries every probe cycle")
		}
	})

	t.Run("an unresolvable endpoint is retried", func(t *testing.T) {
		m := newTestManager()
		// Valid key material and routes; only the endpoint host fails to resolve. That is
		// a DNS condition that can clear on its own, so it must not disable the proxy
		// until the next config generation.
		key := base64.StdEncoding.EncodeToString(bytesOf(0x01, 32))
		m.Apply([]pcfg.ProxySpec{{
			ID: "p1", Type: pcfg.ProxyTypeWireGuard, ConfigSerial: 1,
			WGPrivateKey: key, WGPeerPublicKey: base64.StdEncoding.EncodeToString(bytesOf(0x02, 32)),
			WGEndpoint:   "peer.invalid.example.test:51820",
			WGAllowedIPs: "10.7.0.0/24", WGLocalAddrs: "10.7.0.2/32",
		}})
		if _, err := m.Dialer(context.Background(), "p1"); err == nil {
			t.Skip("peer.invalid.example.test resolved on this network; the transient case cannot be shown")
		}
		m.mu.Lock()
		cached := m.entries["p1"].buildErr != nil
		m.mu.Unlock()
		if cached {
			t.Fatal("a transient resolution failure was cached, so the proxy stays dead after DNS recovers")
		}
	})
}

// isDeterministicInitError is the predicate the stickiness rests on, asserted directly so
// a misclassification is located precisely.
func TestIsDeterministicInitError(t *testing.T) {
	if !isDeterministicInitError(invalidConfig("bad key")) {
		t.Fatal("an invalid-config error must be deterministic")
	}
	// A policy block cannot clear without a new generation: the policy is immutable for
	// an agent run.
	if !isDeterministicInitError(&netguard.BlockedError{Target: "1.2.3.4"}) {
		t.Fatal("a policy block must be deterministic")
	}
	if isDeterministicInitError(errors.New("dial udp: i/o timeout")) {
		t.Fatal("a plain network error must be retryable")
	}
	if isDeterministicInitError(context.Canceled) {
		t.Fatal("a cancelled setup must be retryable")
	}
}
