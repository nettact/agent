package proxydial

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	pcfg "github.com/nettact/protocol/config"
	"github.com/nettact/protocol/telemetry"
)

// A real UDP ASSOCIATE relay. It performs the RFC 1928 handshake on the TCP control
// connection, opens a UDP socket, and forwards datagrams both ways with the SOCKS5
// UDP header applied/stripped — so the tests exercise the actual wire format rather
// than a stub that happens to agree with our encoder.
type udpRelay struct {
	// associateReply overrides the ASSOCIATE reply code (0x00 = success). 0x07
	// (command not supported) is what a server without UDP ASSOCIATE answers.
	associateReply byte
	// wildcardBND answers the ASSOCIATE with 0.0.0.0 as BND.ADDR, which several real
	// servers do and which the client must interpret as "the proxy's own host".
	wildcardBND bool
	// requireAuth demands the fixed credentials below.
	requireAuth        bool
	wantUser, wantPass string
	// fragment sets FRAG != 0 on relayed replies, which the client must drop rather
	// than hand upward as a whole message.
	fragment bool
	// replyFromDomain names the origin by hostname (ATYP=3) instead of by IP.
	replyFromDomain string
}

// startUDPRelay returns the proxy's TCP address.
func startUDPRelay(t *testing.T, r *udpRelay) string {
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
			go r.serve(t, c)
		}
	}()
	return ln.Addr().String()
}

func (r *udpRelay) serve(t *testing.T, control net.Conn) {
	defer control.Close()
	br := bufio.NewReader(control)

	// Greeting.
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(br, hdr); err != nil {
		return
	}
	if _, err := io.ReadFull(br, make([]byte, int(hdr[1]))); err != nil {
		return
	}
	if r.requireAuth {
		if _, err := control.Write([]byte{0x05, 0x02}); err != nil {
			return
		}
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
		if string(user) != r.wantUser || string(pass) != r.wantPass {
			_, _ = control.Write([]byte{0x01, 0x01})
			return
		}
		if _, err := control.Write([]byte{0x01, 0x00}); err != nil {
			return
		}
	} else if _, err := control.Write([]byte{0x05, 0x00}); err != nil {
		return
	}

	// Request: expect UDP ASSOCIATE (0x03).
	req := make([]byte, 4)
	if _, err := io.ReadFull(br, req); err != nil {
		return
	}
	if err := skipSOCKS5Addr(br, req[3]); err != nil {
		return
	}
	if r.associateReply != 0x00 {
		_, _ = control.Write([]byte{0x05, r.associateReply, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	if req[1] != 0x03 {
		_, _ = control.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // command not supported
		return
	}

	// Open the relay socket and announce it.
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return
	}
	defer pc.Close()
	bound := pc.LocalAddr().(*net.UDPAddr)
	ip := bound.IP.To4()
	if r.wildcardBND {
		ip = net.IPv4zero.To4()
	}
	reply := []byte{0x05, 0x00, 0x00, 0x01, ip[0], ip[1], ip[2], ip[3], 0, 0}
	binary.BigEndian.PutUint16(reply[8:], uint16(bound.Port))
	if _, err := control.Write(reply); err != nil {
		return
	}

	// Forward datagrams until the control connection closes.
	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(io.Discard, br)
		close(done)
		_ = pc.Close()
	}()
	go r.relayLoop(pc)
	<-done
}

// relayLoop forwards each client datagram to its stated destination and returns the
// answer wrapped in a SOCKS5 UDP reply header.
func (r *udpRelay) relayLoop(pc *net.UDPConn) {
	buf := make([]byte, 64<<10)
	for {
		n, client, err := pc.ReadFromUDP(buf)
		if err != nil {
			return
		}
		payload, dst, perr := parseSOCKS5UDPDatagram(buf[:n])
		if perr != nil {
			continue
		}
		// Actually send it onward, so the test proves end-to-end delivery.
		out, err := net.DialUDP("udp", nil, dst)
		if err != nil {
			continue
		}
		_ = out.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err := out.Write(payload); err != nil {
			_ = out.Close()
			continue
		}
		resp := make([]byte, 64<<10)
		rn, err := out.Read(resp)
		_ = out.Close()
		if err != nil {
			continue
		}
		hdr := r.replyHeader(dst)
		_, _ = pc.WriteToUDP(append(hdr, resp[:rn]...), client)
	}
}

// replyHeader builds the SOCKS5 UDP reply header naming the origin.
func (r *udpRelay) replyHeader(from *net.UDPAddr) []byte {
	frag := byte(0x00)
	if r.fragment {
		frag = 0x01
	}
	if r.replyFromDomain != "" {
		h := []byte{0x00, 0x00, frag, socks5ATYPDomain, byte(len(r.replyFromDomain))}
		h = append(h, r.replyFromDomain...)
		var port [2]byte
		binary.BigEndian.PutUint16(port[:], uint16(from.Port))
		return append(h, port[:]...)
	}
	ip := from.IP.To4()
	h := []byte{0x00, 0x00, frag, socks5ATYPv4, ip[0], ip[1], ip[2], ip[3], 0, 0}
	binary.BigEndian.PutUint16(h[8:], uint16(from.Port))
	return h
}

func skipSOCKS5Addr(r io.Reader, atyp byte) error {
	switch atyp {
	case socks5ATYPv4:
		_, err := io.ReadFull(r, make([]byte, 4+2))
		return err
	case socks5ATYPv6:
		_, err := io.ReadFull(r, make([]byte, 16+2))
		return err
	case socks5ATYPDomain:
		var l [1]byte
		if _, err := io.ReadFull(r, l[:]); err != nil {
			return err
		}
		_, err := io.ReadFull(r, make([]byte, int(l[0])+2))
		return err
	}
	return errors.New("bad atyp")
}

// startEchoUDP runs a UDP echo server, standing in for a resolver or STUN server.
func startEchoUDP(t *testing.T) *net.UDPAddr {
	t.Helper()
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		buf := make([]byte, 4096)
		for {
			n, from, err := pc.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_, _ = pc.WriteToUDP(append([]byte("echo:"), buf[:n]...), from)
		}
	}()
	return pc.LocalAddr().(*net.UDPAddr)
}

func socks5UDPManager(t *testing.T, proxyAddr, user, pass string) *Dialer {
	t.Helper()
	host, portStr, _ := net.SplitHostPort(proxyAddr)
	port, _ := strconv.Atoi(portStr)
	m := newTestManager()
	m.Apply([]pcfg.ProxySpec{{
		ID: "p1", Type: pcfg.ProxyTypeSOCKS5, Host: host, Port: port, ConfigSerial: 1,
		Username: user, Password: pass,
	}})
	d, err := m.Dialer(context.Background(), "p1")
	if err != nil {
		t.Fatalf("Dialer: %v", err)
	}
	return d
}

// The end-to-end proof that UDP ASSOCIATE works: a datagram written through the
// association reaches a real UDP server and its answer comes back.
func TestSOCKS5UDPAssociateRoundTrip(t *testing.T) {
	echo := startEchoUDP(t)
	proxyAddr := startUDPRelay(t, &udpRelay{})
	d := socks5UDPManager(t, proxyAddr, "", "")

	pc, err := d.ListenPacket()
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	defer pc.Close()
	_ = pc.SetDeadline(time.Now().Add(5 * time.Second))

	if _, err := pc.WriteTo([]byte("ping"), echo); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	buf := make([]byte, 512)
	n, from, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	if got := string(buf[:n]); got != "echo:ping" {
		t.Fatalf("payload = %q, want the echo of what was sent", got)
	}
	// The reported source must be the ORIGIN, not the relay: the STUN filtering test
	// compares the source against the destination it wrote to, and reporting the relay
	// would make every such comparison wrong.
	fromUDP, ok := from.(*net.UDPAddr)
	if !ok {
		t.Fatalf("ReadFrom returned %T, want *net.UDPAddr", from)
	}
	if fromUDP.Port != echo.Port {
		t.Fatalf("source port = %d, want the origin's %d (not the relay's)", fromUDP.Port, echo.Port)
	}
}

// One association must address SEVERAL destinations from one local port — that is the
// property RFC 5780 mapping/filtering discovery depends on.
func TestSOCKS5UDPOneAssociationManyPeers(t *testing.T) {
	a := startEchoUDP(t)
	b := startEchoUDP(t)
	proxyAddr := startUDPRelay(t, &udpRelay{})
	d := socks5UDPManager(t, proxyAddr, "", "")

	pc, err := d.ListenPacket()
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	_ = pc.SetDeadline(time.Now().Add(5 * time.Second))

	seen := map[int]bool{}
	for _, dst := range []*net.UDPAddr{a, b} {
		if _, err := pc.WriteTo([]byte("x"), dst); err != nil {
			t.Fatalf("WriteTo %v: %v", dst, err)
		}
	}
	buf := make([]byte, 512)
	for range 2 {
		_, from, err := pc.ReadFrom(buf)
		if err != nil {
			t.Fatalf("ReadFrom: %v", err)
		}
		seen[from.(*net.UDPAddr).Port] = true
	}
	if !seen[a.Port] || !seen[b.Port] {
		t.Fatalf("replies seen from %v, want both %d and %d", seen, a.Port, b.Port)
	}
}

// dial(ctx, "udp", …) must work too, since the DNS collector uses a connected conn.
func TestSOCKS5UDPConnectedConn(t *testing.T) {
	echo := startEchoUDP(t)
	proxyAddr := startUDPRelay(t, &udpRelay{})
	d := socks5UDPManager(t, proxyAddr, "", "")

	conn, err := d.DialContext(context.Background(), "udp", echo.String())
	if err != nil {
		t.Fatalf("DialContext udp: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte("q")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if got := string(buf[:n]); got != "echo:q" {
		t.Fatalf("payload = %q", got)
	}
}

// A server that answers "command not supported" is the common real case (ssh -D has
// no UDP ASSOCIATE). It must be a CONFIG diagnosis, not a generic outage, so the
// operator is told the proxy cannot do this rather than hunting a network problem.
func TestSOCKS5UDPUnsupportedByServerIsProxyConfig(t *testing.T) {
	proxyAddr := startUDPRelay(t, &udpRelay{associateReply: 0x07})
	d := socks5UDPManager(t, proxyAddr, "", "")

	_, err := d.ListenPacket()
	if err == nil {
		t.Fatal("expected the association to be refused")
	}
	reason, atTarget, ok := ProxyReason(err)
	if !ok || reason != telemetry.ProbeReasonProxyConfig {
		t.Fatalf("reason = %d (ok=%v), want ProxyConfig — a server without UDP ASSOCIATE is a config mismatch", reason, ok)
	}
	if atTarget {
		t.Fatal("a refused association must never be attributed to the target")
	}
}

func TestSOCKS5UDPAssociateReplyClassification(t *testing.T) {
	cases := []struct {
		name  string
		reply byte
		want  int
	}{
		{"not allowed by ruleset", 0x02, telemetry.ProbeReasonProxyRefused},
		{"network unreachable", 0x03, telemetry.ProbeReasonProxyRefused},
		{"host unreachable", 0x04, telemetry.ProbeReasonProxyRefused},
		{"general failure", 0x01, telemetry.ProbeReasonProxyRefused},
		{"command not supported", 0x07, telemetry.ProbeReasonProxyConfig},
		{"address type not supported", 0x08, telemetry.ProbeReasonProxyConfig},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			proxyAddr := startUDPRelay(t, &udpRelay{associateReply: c.reply})
			d := socks5UDPManager(t, proxyAddr, "", "")
			_, err := d.ListenPacket()
			if err == nil {
				t.Fatal("expected a refusal")
			}
			reason, _, ok := ProxyReason(err)
			if !ok || reason != c.want {
				t.Fatalf("reason = %d (ok=%v), want %d", reason, ok, c.want)
			}
		})
	}
}

// A wildcard BND.ADDR means "the host you are already talking to". Dialing 0.0.0.0
// literally would send datagrams nowhere, so it must be substituted.
func TestSOCKS5UDPWildcardBindAddressUsesProxyHost(t *testing.T) {
	echo := startEchoUDP(t)
	proxyAddr := startUDPRelay(t, &udpRelay{wildcardBND: true})
	d := socks5UDPManager(t, proxyAddr, "", "")

	pc, err := d.ListenPacket()
	if err != nil {
		t.Fatalf("ListenPacket with a wildcard BND.ADDR: %v", err)
	}
	defer pc.Close()
	_ = pc.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := pc.WriteTo([]byte("ping"), echo); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 512)
	if _, _, err := pc.ReadFrom(buf); err != nil {
		t.Fatalf("no reply through a wildcard-announced relay: %v", err)
	}
}

func TestSOCKS5UDPAuth(t *testing.T) {
	echo := startEchoUDP(t)
	proxyAddr := startUDPRelay(t, &udpRelay{requireAuth: true, wantUser: "u", wantPass: "p"})

	t.Run("correct credentials associate", func(t *testing.T) {
		d := socks5UDPManager(t, proxyAddr, "u", "p")
		pc, err := d.ListenPacket()
		if err != nil {
			t.Fatalf("ListenPacket: %v", err)
		}
		defer pc.Close()
		_ = pc.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := pc.WriteTo([]byte("ping"), echo); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 512)
		if _, _, err := pc.ReadFrom(buf); err != nil {
			t.Fatalf("no reply: %v", err)
		}
	})
	t.Run("wrong credentials are proxy_auth", func(t *testing.T) {
		d := socks5UDPManager(t, proxyAddr, "u", "wrong")
		_, err := d.ListenPacket()
		if err == nil {
			t.Fatal("expected an auth failure")
		}
		reason, _, ok := ProxyReason(err)
		if !ok || reason != telemetry.ProbeReasonProxyAuth {
			t.Fatalf("reason = %d (ok=%v), want ProxyAuth", reason, ok)
		}
	})
	t.Run("missing credentials are proxy_auth", func(t *testing.T) {
		// The proxy demands credentials we were not given. That is an auth problem to
		// fix in the config, not a connectivity one.
		d := socks5UDPManager(t, proxyAddr, "", "")
		_, err := d.ListenPacket()
		if err == nil {
			t.Fatal("expected an auth failure")
		}
		reason, _, ok := ProxyReason(err)
		if !ok || reason != telemetry.ProbeReasonProxyAuth {
			t.Fatalf("reason = %d (ok=%v), want ProxyAuth", reason, ok)
		}
	})
}

// A fragmented datagram must be DROPPED, not handed up as a whole message: passing a
// fragment to a DNS or STUN parser reads as a corrupt answer instead of a lost packet.
func TestSOCKS5UDPDropsFragments(t *testing.T) {
	echo := startEchoUDP(t)
	proxyAddr := startUDPRelay(t, &udpRelay{fragment: true})
	d := socks5UDPManager(t, proxyAddr, "", "")

	pc, err := d.ListenPacket()
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	// A short deadline: the expected outcome is a timeout, because every reply is
	// dropped as a fragment.
	_ = pc.SetDeadline(time.Now().Add(600 * time.Millisecond))
	if _, err := pc.WriteTo([]byte("ping"), echo); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 512)
	if _, _, err := pc.ReadFrom(buf); err == nil {
		t.Fatal("a fragmented datagram was accepted; it must be dropped")
	}
}

// The datagram encoder/decoder is asserted directly too, so a wire-format regression
// is located precisely rather than showing up as "the relay test hangs".
func TestSOCKS5UDPDatagramCodec(t *testing.T) {
	dst := &net.UDPAddr{IP: net.IPv4(198, 51, 100, 7), Port: 53}
	dstD, err := destFromUDPAddr(dst)
	if err != nil {
		t.Fatal(err)
	}
	hdr, err := socks5UDPHeader(dstD)
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{0x00, 0x00, 0x00, socks5ATYPv4, 198, 51, 100, 7, 0x00, 0x35}
	if !bytes.Equal(hdr, want) {
		t.Fatalf("header = % x, want % x", hdr, want)
	}

	payload, from, err := parseSOCKS5UDPDatagram(append(hdr, []byte("body")...))
	if err != nil {
		t.Fatal(err)
	}
	if string(payload) != "body" {
		t.Fatalf("payload = %q", payload)
	}
	if from.Port != 53 || !from.IP.Equal(dst.IP) {
		t.Fatalf("origin = %v, want %v", from, dst)
	}

	t.Run("ipv6 destination", func(t *testing.T) {
		v6 := &net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 3478}
		v6D, err := destFromUDPAddr(v6)
		if err != nil {
			t.Fatal(err)
		}
		h, err := socks5UDPHeader(v6D)
		if err != nil {
			t.Fatal(err)
		}
		if h[3] != socks5ATYPv6 {
			t.Fatalf("atyp = 0x%02x, want IPv6", h[3])
		}
		_, got, err := parseSOCKS5UDPDatagram(append(h, 'x'))
		if err != nil {
			t.Fatal(err)
		}
		if !got.IP.Equal(v6.IP) || got.Port != 3478 {
			t.Fatalf("origin = %v, want %v", got, v6)
		}
	})

	t.Run("rejects truncated and fragmented input", func(t *testing.T) {
		for _, bad := range [][]byte{
			{},
			{0x00, 0x00, 0x00},
			{0x00, 0x00, 0x01, socks5ATYPv4, 1, 2, 3, 4, 0, 53}, // FRAG != 0
			{0x00, 0x00, 0x00, socks5ATYPv4, 1, 2},              // truncated address
			{0x00, 0x00, 0x00, 0x09, 1, 2, 3, 4, 0, 53},         // unknown ATYP
		} {
			if _, _, err := parseSOCKS5UDPDatagram(bad); err == nil {
				t.Fatalf("accepted malformed datagram % x", bad)
			}
		}
	})

	t.Run("a domain origin reports only the port", func(t *testing.T) {
		// Resolving the name here would be a second, unvetted lookup, so the address is
		// left unset rather than guessed.
		h := []byte{0x00, 0x00, 0x00, socks5ATYPDomain, 3, 'a', '.', 'b', 0x00, 0x35}
		_, from, err := parseSOCKS5UDPDatagram(append(h, 'z'))
		if err != nil {
			t.Fatal(err)
		}
		if from.IP != nil {
			t.Fatalf("IP = %v, want nil for a domain-named origin", from.IP)
		}
		if from.Port != 53 {
			t.Fatalf("port = %d, want 53", from.Port)
		}
	})
}

// Closing the control connection ends the association, so an in-flight read must not
// block forever on a relay that is no longer forwarding.
func TestSOCKS5UDPControlCloseEndsAssociation(t *testing.T) {
	proxyAddr := startUDPRelay(t, &udpRelay{})
	d := socks5UDPManager(t, proxyAddr, "", "")
	pc, err := d.ListenPacket()
	if err != nil {
		t.Fatal(err)
	}
	// Closing our side must release both sockets and make further use fail rather
	// than hang.
	if err := pc.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	_ = pc.SetDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 16)
	if _, _, err := pc.ReadFrom(buf); err == nil {
		t.Fatal("ReadFrom succeeded after Close")
	}
	// Close is idempotent: the manager may close a dialer that a caller already closed.
	if err := pc.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		t.Fatalf("second Close: %v", err)
	}
}

// HTTP has only CONNECT, so it must refuse a packet conn rather than silently opening
// one on the host stack and measuring the wrong path.
func TestHTTPProxyRefusesPacketConn(t *testing.T) {
	addr := startConnect(t, &connectServer{status: "200 Connection established"})
	d := connectManager(t, addr, "", "")
	if _, err := d.ListenPacket(); !errors.Is(err, ErrProxyKindUnsupported) {
		t.Fatalf("ListenPacket error = %v, want ErrProxyKindUnsupported", err)
	}
	if _, err := d.DialContext(context.Background(), "udp", "198.51.100.7:53"); err == nil {
		t.Fatal("an HTTP proxy accepted a udp dial")
	}
}
