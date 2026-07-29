package proxydial

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nettact/agent/internal/netguard"
	"github.com/nettact/agent/probepolicy"
	pcfg "github.com/nettact/protocol/config"
	"github.com/nettact/protocol/telemetry"
)

// Regressions for SOCKS5 UDP: proxy-side DNS, and reply headers that name the origin
// by domain.

// The domain form of the request header is what makes proxy-side DNS work for datagram
// probes. Resolving locally instead defeats the split-horizon setup the mode exists
// for: a name that only resolves on the proxy's network would fail before a packet was
// sent.
func TestSOCKS5UDPRemoteDNSSendsDomainHeader(t *testing.T) {
	srv := &recordingUDPRelay{}
	proxyAddr := srv.start(t)
	host, portStr, _ := net.SplitHostPort(proxyAddr)
	port, _ := strconv.Atoi(portStr)

	m := newTestManager()
	m.Apply([]pcfg.ProxySpec{{
		ID: "p1", Type: pcfg.ProxyTypeSOCKS5, Host: host, Port: port,
		DNSMode: pcfg.ProxyDNSRemote, ConfigSerial: 1,
	}})
	d, err := m.Dialer(context.Background(), "p1")
	if err != nil {
		t.Fatal(err)
	}

	// A name that resolves nowhere locally: under the old unconditional local vetting
	// this failed before any datagram was sent.
	conn, err := d.DialContext(context.Background(), "udp", "resolver.internal.invalid:53")
	if err != nil {
		t.Fatalf("remote-DNS udp dial: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write([]byte("query")); err != nil {
		t.Fatalf("write: %v", err)
	}

	got := srv.waitForDatagram(t)
	if got.atyp != socks5ATYPDomain {
		t.Fatalf("request ATYP = 0x%02x, want DOMAIN(0x03) so the proxy resolves the name", got.atyp)
	}
	if got.host != "resolver.internal.invalid" || got.port != 53 {
		t.Fatalf("request named %q:%d, want the hostname passed through", got.host, got.port)
	}
	if string(got.payload) != "query" {
		t.Fatalf("payload = %q", got.payload)
	}
}

// A literal destination still travels as a literal even in remote mode: there is
// nothing for the proxy to resolve, and the address form is the more compatible one.
func TestSOCKS5UDPRemoteDNSKeepsLiteralsAsAddresses(t *testing.T) {
	srv := &recordingUDPRelay{}
	proxyAddr := srv.start(t)
	host, portStr, _ := net.SplitHostPort(proxyAddr)
	port, _ := strconv.Atoi(portStr)

	m := newTestManager()
	m.Apply([]pcfg.ProxySpec{{
		ID: "p1", Type: pcfg.ProxyTypeSOCKS5, Host: host, Port: port,
		DNSMode: pcfg.ProxyDNSRemote, ConfigSerial: 1,
	}})
	d, _ := m.Dialer(context.Background(), "p1")
	conn, err := d.DialContext(context.Background(), "udp", "198.51.100.7:53")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write([]byte("q")); err != nil {
		t.Fatal(err)
	}
	got := srv.waitForDatagram(t)
	if got.atyp != socks5ATYPv4 || got.host != "198.51.100.7" {
		t.Fatalf("request ATYP=0x%02x host=%q, want the IPv4 form", got.atyp, got.host)
	}
}

// Local mode must still vet: a name resolving to a denied address must not reach the
// proxy at all.
func TestSOCKS5UDPLocalDNSStillVets(t *testing.T) {
	srv := &recordingUDPRelay{}
	proxyAddr := srv.start(t)
	host, portStr, _ := net.SplitHostPort(proxyAddr)
	port, _ := strconv.Atoi(portStr)

	// Deny the loopback literal that "localhost" resolves to. The NAME is fine; only an
	// ADDRESS check catches it — which is precisely what remote mode gives up.
	denied := netip.MustParseAddr("127.0.0.1")
	policy := probepolicy.Policy{
		Mode: probepolicy.ModeDenylist,
		Deny: []probepolicy.Selector{{Kind: probepolicy.KindIP, Addr: denied}},
	}
	m := NewManager(netguard.New(policy, false))
	m.Apply([]pcfg.ProxySpec{{
		ID: "p1", Type: pcfg.ProxyTypeSOCKS5, Host: host, Port: port,
		DNSMode: pcfg.ProxyDNSLocal, ConfigSerial: 1,
	}})
	d, err := m.Dialer(context.Background(), "p1")
	if err != nil {
		t.Fatal(err)
	}
	_, err = d.DialContext(context.Background(), "udp", "localhost:53")
	var blocked *netguard.BlockedError
	if !errors.As(err, &blocked) {
		t.Fatalf("error = %v, want a policy block on the resolved address", err)
	}
}

// A reply whose origin is named by DOMAIN has a header up to 262 bytes. Sizing the read
// buffer for a 16-byte address truncated such a datagram, so a near-capacity DNS answer
// failed to parse and surfaced as a timeout.
func TestSOCKS5UDPReadsDomainOriginReplies(t *testing.T) {
	// The payload must NEARLY FILL the caller's buffer for the header allowance to
	// matter: truncation happens only when header+payload exceeds len(p)+allowance. With
	// the old 22-byte (IPv6-sized) allowance an 89-byte domain header overflowed by 57
	// bytes and silently cut the answer short.
	const readBuf = 1500
	const payloadLen = readBuf - 10
	longHost := strings.Repeat("a", 60) + ".resolver.example.test" // 82 bytes → 89-byte header
	srv := &recordingUDPRelay{
		replyFromDomain: longHost,
		replyPayload:    bytes.Repeat([]byte("D"), payloadLen),
	}
	proxyAddr := srv.start(t)
	host, portStr, _ := net.SplitHostPort(proxyAddr)
	port, _ := strconv.Atoi(portStr)

	m := newTestManager()
	m.Apply([]pcfg.ProxySpec{{ID: "p1", Type: pcfg.ProxyTypeSOCKS5, Host: host, Port: port, ConfigSerial: 1}})
	d, _ := m.Dialer(context.Background(), "p1")
	pc, err := d.ListenPacket()
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	_ = pc.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := pc.WriteTo([]byte("q"), &net.UDPAddr{IP: net.IPv4(198, 51, 100, 7), Port: 53}); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, readBuf)
	n, from, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom with a domain-named origin: %v", err)
	}
	if n != payloadLen {
		t.Fatalf("read %d bytes, want the full %d-byte payload — an undersized header allowance truncated it",
			n, payloadLen)
	}
	// A domain origin carries no numeric address, so only the port is reported rather
	// than guessed by a second, unvetted lookup.
	fromUDP, ok := from.(*net.UDPAddr)
	if !ok || fromUDP.Port != 53 {
		t.Fatalf("origin = %v, want the port with no invented address", from)
	}
}

// The header builder must reject a host too long to length-prefix, rather than emit a
// truncated header the proxy would misparse.
func TestSOCKS5UDPHeaderRejectsOverlongHost(t *testing.T) {
	_, err := socks5UDPHeader(socks5UDPDest{host: strings.Repeat("x", 256), port: 53})
	if err == nil || !strings.Contains(err.Error(), "255") {
		t.Fatalf("error = %v, want the 255-byte domain limit", err)
	}
	// The header round-trips for a legal host.
	hdr, err := socks5UDPHeader(socks5UDPDest{host: "a.example", port: 53})
	if err != nil {
		t.Fatal(err)
	}
	payload, from, perr := parseSOCKS5UDPDatagram(append(hdr, 'z'))
	if perr != nil {
		t.Fatal(perr)
	}
	if string(payload) != "z" || from.Port != 53 {
		t.Fatalf("round-trip gave payload=%q port=%d", payload, from.Port)
	}
}

// ---- a relay that records requests and can answer with a domain-named origin ----

type recordedDatagram struct {
	atyp    byte
	host    string
	port    int
	payload []byte
}

type recordingUDPRelay struct {
	// replyFromDomain, when set, names the reply origin by domain (ATYP=3).
	replyFromDomain string
	// replyPayload is echoed back after a request arrives.
	replyPayload []byte

	got chan recordedDatagram
}

func (r *recordingUDPRelay) start(t *testing.T) string {
	t.Helper()
	r.got = make(chan recordedDatagram, 4)
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
			go r.serve(t, c)
		}
	}()
	return ln.Addr().String()
}

func (r *recordingUDPRelay) serve(t *testing.T, control net.Conn) {
	defer control.Close()
	if !socks5ServerHandshake(control) {
		return
	}
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return
	}
	defer pc.Close()
	bound := pc.LocalAddr().(*net.UDPAddr)
	ip := bound.IP.To4()
	reply := []byte{0x05, 0x00, 0x00, 0x01, ip[0], ip[1], ip[2], ip[3], 0, 0}
	binary.BigEndian.PutUint16(reply[8:], uint16(bound.Port))
	if _, err := control.Write(reply); err != nil {
		return
	}

	go func() {
		buf := make([]byte, 64<<10)
		for {
			n, client, err := pc.ReadFromUDP(buf)
			if err != nil {
				return
			}
			rec, ok := parseRecordedRequest(buf[:n])
			if !ok {
				continue
			}
			select {
			case r.got <- rec:
			default:
			}
			if r.replyPayload == nil {
				continue
			}
			hdr := r.buildReplyHeader()
			_, _ = pc.WriteToUDP(append(hdr, r.replyPayload...), client)
		}
	}()
	// Hold the association open until the control connection closes.
	_, _ = control.Read(make([]byte, 1))
}

func (r *recordingUDPRelay) buildReplyHeader() []byte {
	if r.replyFromDomain != "" {
		h := []byte{0x00, 0x00, 0x00, socks5ATYPDomain, byte(len(r.replyFromDomain))}
		h = append(h, r.replyFromDomain...)
		return append(h, 0x00, 0x35)
	}
	return []byte{0x00, 0x00, 0x00, socks5ATYPv4, 198, 51, 100, 7, 0x00, 0x35}
}

func (r *recordingUDPRelay) waitForDatagram(t *testing.T) recordedDatagram {
	t.Helper()
	select {
	case rec := <-r.got:
		return rec
	case <-time.After(3 * time.Second):
		t.Fatal("the relay received no datagram")
		return recordedDatagram{}
	}
}

// parseRecordedRequest reads a SOCKS5 UDP request header, keeping the raw ATYP and the
// destination as written — the point is to observe the form the client chose.
func parseRecordedRequest(b []byte) (recordedDatagram, bool) {
	if len(b) < 4 || b[2] != 0x00 {
		return recordedDatagram{}, false
	}
	rec := recordedDatagram{atyp: b[3]}
	rest := b[4:]
	switch b[3] {
	case socks5ATYPv4:
		if len(rest) < 6 {
			return recordedDatagram{}, false
		}
		rec.host = net.IP(rest[:4]).String()
		rest = rest[4:]
	case socks5ATYPv6:
		if len(rest) < 18 {
			return recordedDatagram{}, false
		}
		rec.host = net.IP(rest[:16]).String()
		rest = rest[16:]
	case socks5ATYPDomain:
		if len(rest) < 1 || len(rest) < int(rest[0])+3 {
			return recordedDatagram{}, false
		}
		l := int(rest[0])
		rec.host = string(rest[1 : 1+l])
		rest = rest[1+l:]
	default:
		return recordedDatagram{}, false
	}
	rec.port = int(binary.BigEndian.Uint16(rest[:2]))
	rec.payload = append([]byte(nil), rest[2:]...)
	return rec, true
}

// socks5ServerHandshake performs the no-auth greeting and reads the UDP ASSOCIATE
// request, reporting whether it got that far.
func socks5ServerHandshake(c net.Conn) bool {
	hdr := make([]byte, 2)
	if _, err := readFull(c, hdr); err != nil {
		return false
	}
	if _, err := readFull(c, make([]byte, int(hdr[1]))); err != nil {
		return false
	}
	if _, err := c.Write([]byte{0x05, 0x00}); err != nil {
		return false
	}
	req := make([]byte, 4)
	if _, err := readFull(c, req); err != nil {
		return false
	}
	// DST.ADDR/DST.PORT: the client sends the IPv4 wildcard.
	if _, err := readFull(c, make([]byte, 6)); err != nil {
		return false
	}
	return req[1] == 0x03
}

func readFull(c net.Conn, p []byte) (int, error) {
	got := 0
	for got < len(p) {
		n, err := c.Read(p[got:])
		got += n
		if err != nil {
			return got, err
		}
	}
	return got, nil
}

// Adding UDP support must not have opened ICMP: SOCKS5 has no command for relaying an
// echo, so ping stays tunnel-only.
func TestSOCKS5StillRefusesICMP(t *testing.T) {
	srv := &recordingUDPRelay{}
	addr := srv.start(t)
	host, portStr, _ := net.SplitHostPort(addr)
	port, _ := strconv.Atoi(portStr)
	m := newTestManager()
	m.Apply([]pcfg.ProxySpec{{ID: "p1", Type: pcfg.ProxyTypeSOCKS5, Host: host, Port: port, ConfigSerial: 1}})
	d, err := m.Dialer(context.Background(), "p1")
	if err != nil {
		t.Fatal(err)
	}
	_, perr := d.DialPing(context.Background(), "ping4", "1.1.1.1")
	if !errors.Is(perr, ErrProxyKindUnsupported) {
		t.Fatalf("DialPing error = %v, want ErrProxyKindUnsupported", perr)
	}
	// And it must classify as a probe failure so the collector reports it rather than
	// falling back to the host stack.
	reason, _, ok := ProxyReason(perr)
	if !ok || reason != telemetry.ProbeReasonProxyConfig {
		t.Fatalf("reason = %d (ok=%v), want ProxyConfig", reason, ok)
	}
}

// The handshake budget must bound the NEGOTIATION, not just the TCP connect.
//
// A proxy that accepts the connection and then says nothing used to run under the
// probe's full timeout: connect_timeout_ms only covered the dial, so a stalled proxy
// consumed the whole probe budget and was then reported as an unresponsive target.
func TestProxyHandshakeTimeoutBoundsNegotiation(t *testing.T) {
	// A listener that accepts and never speaks.
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
			// Hold it open, silent, until the test ends.
			t.Cleanup(func() { _ = c.Close() })
		}
	}()
	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)

	for _, ty := range []string{pcfg.ProxyTypeSOCKS5, pcfg.ProxyTypeHTTP} {
		t.Run(ty, func(t *testing.T) {
			m := newTestManager()
			m.Apply([]pcfg.ProxySpec{{
				ID: "p1", Type: ty, Host: host, Port: port, ConfigSerial: 1,
				ConnectTimeoutMs: 150,
			}})
			d, derr := m.Dialer(context.Background(), "p1")
			if derr != nil {
				t.Fatal(derr)
			}
			// A probe budget far larger than the handshake budget: the handshake one must
			// be what fires.
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			start := time.Now()
			_, err := d.DialContext(ctx, "tcp", "203.0.113.5:443")
			elapsed := time.Since(start)
			if err == nil {
				t.Fatal("expected the stalled handshake to fail")
			}
			if elapsed > 3*time.Second {
				t.Fatalf("handshake took %v — the 150ms connect_timeout_ms did not bound the negotiation", elapsed)
			}
			reason, atTarget, ok := ProxyReason(err)
			if !ok || reason != telemetry.ProbeReasonProxyConnect || atTarget {
				t.Fatalf("reason = %d atTarget = %v (ok=%v), want ProxyConnect at the proxy", reason, atTarget, ok)
			}
		})
	}
}
