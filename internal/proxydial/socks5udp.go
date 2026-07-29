package proxydial

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/nettact/agent/internal/netguard"
	pcfg "github.com/nettact/protocol/config"
	"github.com/nettact/protocol/telemetry"
)

// isBlockedError reports whether err is a target-access policy block from the guard.
// Such an error must travel to the collector UNWRAPPED: it means the agent refused to
// dial, which the collector routes to the monitor-status tracker rather than reporting
// as a probe failure.
func isBlockedError(err error) (*netguard.BlockedError, bool) {
	var be *netguard.BlockedError
	if errors.As(err, &be) {
		return be, true
	}
	return nil, false
}

// SOCKS5 UDP ASSOCIATE (RFC 1928 §4, §6, §7).
//
// golang.org/x/net/proxy implements CONNECT only, so the UDP path is written here.
// It is worth the code: SOCKS5 is the one relay protocol that forwards datagrams, so
// it is what makes plain-UDP DNS and STUN over udp/dtls work through a proxy at all.
// (HTTP has only CONNECT, and neither relay has any notion of forwarding ICMP.)
//
// # Shape of an association
//
//  1. Open a TCP control connection to the proxy and authenticate as usual.
//  2. Send UDP ASSOCIATE. DST.ADDR/DST.PORT is the address the CLIENT will send
//     from; we send the wildcard, which RFC 1928 §4 explicitly allows for a client
//     that does not yet know it.
//  3. The reply's BND.ADDR/BND.PORT is the relay endpoint to send datagrams to.
//  4. Each datagram carries a SOCKS5 UDP request header naming its final
//     destination, so ONE association can talk to many peers — which is exactly what
//     STUN's mapping/filtering tests need.
//  5. The association lives as long as the TCP control connection. Closing that
//     tears the relay down, so the control connection is held open and its EOF is
//     treated as the association ending.
//
// # Deliberate limits
//
//   - FRAG is always 0 on send, and a datagram arriving with FRAG != 0 is dropped.
//     Reassembly is optional in RFC 1928 and essentially no server implements it;
//     silently accepting a fragment would surface as a corrupt DNS/STUN response
//     rather than as a lost packet.
//   - A wildcard BND.ADDR in the reply means "the same host you are already talking
//     to" — several servers answer 0.0.0.0 — so it is replaced by the proxy's own
//     address rather than dialed as-is (which would send datagrams nowhere).

// socks5UDPHeaderMax bounds the per-datagram header: RSV(2) + FRAG(1) + ATYP(1) +
// address + PORT(2), where the largest address form is a domain name — one length byte
// plus up to 255 bytes.
//
// Sizing this for a 16-byte IPv6 address instead was a bug worth naming: a relay that
// reports the origin as a hostname (ATYP=DOMAIN, which RFC 1928 permits) would overrun
// the read buffer, so a near-capacity DNS answer came back truncated, failed to parse,
// and surfaced as a timeout with nothing pointing at the cause.
const socks5UDPHeaderMax = 2 + 1 + 1 + 1 + 255 + 2

// maxSOCKS5DomainLen is RFC 1928's domain-name limit: DST.ADDR is length-prefixed by a
// single byte.
const maxSOCKS5DomainLen = 255

// SOCKS5 address types (RFC 1928 §5).
const (
	socks5ATYPv4     = 0x01
	socks5ATYPDomain = 0x03
	socks5ATYPv6     = 0x04
)

// socks5UDPConn is a net.PacketConn whose datagrams are relayed by a SOCKS5 proxy.
//
// It is a PacketConn (not a connected conn) on purpose: the STUN behaviour probes
// must send to several destinations from one association, and callers already speak
// WriteTo/ReadFrom against the host stack.
type socks5UDPConn struct {
	// relay is the local UDP socket that talks to the proxy's relay endpoint.
	relay net.Conn
	// control is the TCP connection that owns the association. It carries no data;
	// keeping it open is what keeps the relay alive.
	control net.Conn

	closeOnce sync.Once
}

// dialSOCKS5UDP establishes a UDP association with the proxy and returns a
// PacketConn that relays through it.
//
// ctx bounds only the association setup. The returned conn outlives it — the
// association must survive for as long as the caller keeps probing — so the caller
// governs per-cycle timing with the conn's own deadlines.
// It returns the concrete type: the connected-conn wrapper needs writeToDest, which is
// not part of net.PacketConn. Callers wanting the interface (ListenPacket) get it by
// assignment.
func dialSOCKS5UDP(ctx context.Context, base guardDialer, proxyAddr, username, password string) (*socks5UDPConn, error) {
	control, err := base.DialContext(ctx, "tcp", proxyAddr)
	if err != nil {
		// A guard policy block means the agent refused to dial the PROXY; it must reach
		// the collector unwrapped so it is routed as a block, not a probe failure.
		if _, blocked := isBlockedError(err); blocked {
			return nil, err
		}
		return nil, &ProxyError{Reason: telemetry.ProbeReasonProxyConnect, Err: err}
	}
	ok := false
	defer func() {
		if !ok {
			_ = control.Close()
		}
	}()

	// The handshake is bounded by the guard dialer's own connect timeout via the
	// deadline set here; the association itself has no deadline (the caller sets one
	// per probe cycle on the returned conn).
	if err := control.SetDeadline(time.Now().Add(base.timeout)); err != nil {
		return nil, &ProxyError{Reason: telemetry.ProbeReasonProxyConnect, Err: err}
	}
	if err := socks5Greet(control, username, password); err != nil {
		return nil, err
	}
	relayAddr, err := socks5Associate(control, proxyAddr)
	if err != nil {
		return nil, err
	}
	// Clear the handshake deadline: from here the caller owns the timing.
	if err := control.SetDeadline(time.Time{}); err != nil {
		return nil, &ProxyError{Reason: telemetry.ProbeReasonProxyConnect, Err: err}
	}

	// The relay endpoint is a concrete address the proxy told us to use. It goes
	// through the guard like any other destination the agent sends to.
	relay, err := base.DialContext(ctx, "udp", relayAddr)
	if err != nil {
		if _, blocked := isBlockedError(err); blocked {
			return nil, err
		}
		return nil, &ProxyError{Reason: telemetry.ProbeReasonProxyConnect, Err: err}
	}

	c := &socks5UDPConn{relay: relay, control: control}
	// The association dies with the control connection, so a server-side teardown
	// must close the relay socket too — otherwise reads would block forever on a
	// relay that is no longer forwarding.
	go func() {
		_, _ = io.Copy(io.Discard, control)
		_ = c.Close()
	}()
	ok = true
	return c, nil
}

// socks5Greet performs the method negotiation and, when credentials are supplied,
// the RFC 1929 username/password sub-negotiation.
func socks5Greet(rw net.Conn, username, password string) error {
	methods := []byte{0x00} // no auth
	if username != "" {
		methods = []byte{0x02, 0x00} // prefer user/pass, accept no-auth
	}
	req := append([]byte{0x05, byte(len(methods))}, methods...)
	if _, err := rw.Write(req); err != nil {
		return &ProxyError{Reason: telemetry.ProbeReasonProxyConnect, Err: fmt.Errorf("socks5 greeting: %w", err)}
	}
	var resp [2]byte
	if _, err := io.ReadFull(rw, resp[:]); err != nil {
		return &ProxyError{Reason: telemetry.ProbeReasonProxyConnect, Err: fmt.Errorf("socks5 greeting reply: %w", err)}
	}
	if resp[0] != 0x05 {
		return &ProxyError{Reason: telemetry.ProbeReasonProxyConnect,
			Err: fmt.Errorf("socks5 version %d not supported by proxy", resp[0])}
	}
	switch resp[1] {
	case 0x00:
		return nil
	case 0x02:
		if username == "" {
			// The proxy demands credentials we were not given. That is an auth failure,
			// not a connectivity one — the operator must add them.
			return &ProxyError{Reason: telemetry.ProbeReasonProxyAuth,
				Err: errors.New("socks5 proxy requires username/password authentication")}
		}
		return socks5UserPassAuth(rw, username, password)
	case 0xFF:
		return &ProxyError{Reason: telemetry.ProbeReasonProxyAuth,
			Err: errors.New("socks5 proxy rejected all offered authentication methods")}
	default:
		return &ProxyError{Reason: telemetry.ProbeReasonProxyAuth,
			Err: fmt.Errorf("socks5 proxy selected unsupported auth method 0x%02x", resp[1])}
	}
}

// socks5UserPassAuth runs the RFC 1929 sub-negotiation.
func socks5UserPassAuth(rw net.Conn, username, password string) error {
	if len(username) > 255 || len(password) > 255 {
		return &ProxyError{Reason: telemetry.ProbeReasonProxyConfig,
			Err: errors.New("socks5 username/password must each be at most 255 bytes")}
	}
	buf := make([]byte, 0, 3+len(username)+len(password))
	buf = append(buf, 0x01, byte(len(username)))
	buf = append(buf, username...)
	buf = append(buf, byte(len(password)))
	buf = append(buf, password...)
	if _, err := rw.Write(buf); err != nil {
		return &ProxyError{Reason: telemetry.ProbeReasonProxyAuth, Err: fmt.Errorf("socks5 auth: %w", err)}
	}
	var resp [2]byte
	if _, err := io.ReadFull(rw, resp[:]); err != nil {
		return &ProxyError{Reason: telemetry.ProbeReasonProxyAuth, Err: fmt.Errorf("socks5 auth reply: %w", err)}
	}
	if resp[1] != 0x00 {
		return &ProxyError{Reason: telemetry.ProbeReasonProxyAuth,
			Err: errors.New("socks5 proxy rejected the supplied credentials")}
	}
	return nil
}

// socks5Associate sends UDP ASSOCIATE and returns the relay endpoint to send
// datagrams to.
func socks5Associate(rw net.Conn, proxyAddr string) (string, error) {
	// DST.ADDR/DST.PORT is where the client will send FROM. RFC 1928 §4 allows the
	// wildcard when the client does not know it yet — which is our case, since the
	// local UDP socket is not bound until the relay endpoint is known.
	req := []byte{0x05, 0x03, 0x00, socks5ATYPv4, 0, 0, 0, 0, 0, 0}
	if _, err := rw.Write(req); err != nil {
		return "", &ProxyError{Reason: telemetry.ProbeReasonProxyConnect, Err: fmt.Errorf("socks5 udp associate: %w", err)}
	}
	var head [4]byte
	if _, err := io.ReadFull(rw, head[:]); err != nil {
		return "", &ProxyError{Reason: telemetry.ProbeReasonProxyConnect, Err: fmt.Errorf("socks5 udp associate reply: %w", err)}
	}
	if head[0] != 0x05 {
		return "", &ProxyError{Reason: telemetry.ProbeReasonProxyConnect,
			Err: fmt.Errorf("socks5 version %d not supported by proxy", head[0])}
	}
	if head[1] != 0x00 {
		return "", &ProxyError{Reason: socks5ReplyReason(head[1]),
			Err: fmt.Errorf("socks5 udp associate refused: %s", socks5ReplyText(head[1]))}
	}
	host, port, err := readSOCKS5Addr(rw, head[3])
	if err != nil {
		return "", &ProxyError{Reason: telemetry.ProbeReasonProxyConnect, Err: err}
	}
	// A wildcard BND.ADDR means "the host you are already talking to". Several
	// servers answer 0.0.0.0; dialing that literally would send datagrams nowhere.
	if isWildcardHost(host) {
		proxyHost, _, splitErr := net.SplitHostPort(proxyAddr)
		if splitErr != nil {
			return "", &ProxyError{Reason: telemetry.ProbeReasonProxyConfig,
				Err: fmt.Errorf("socks5 relay address is wildcard and proxy address %q is unparsable", proxyAddr)}
		}
		host = proxyHost
	}
	return net.JoinHostPort(host, strconv.Itoa(int(port))), nil
}

// readSOCKS5Addr reads an ATYP-tagged address+port from a reply.
func readSOCKS5Addr(r io.Reader, atyp byte) (string, uint16, error) {
	var raw []byte
	switch atyp {
	case socks5ATYPv4:
		raw = make([]byte, 4)
	case socks5ATYPv6:
		raw = make([]byte, 16)
	case socks5ATYPDomain:
		var l [1]byte
		if _, err := io.ReadFull(r, l[:]); err != nil {
			return "", 0, fmt.Errorf("socks5 address length: %w", err)
		}
		raw = make([]byte, int(l[0]))
	default:
		return "", 0, fmt.Errorf("socks5 unknown address type 0x%02x", atyp)
	}
	if _, err := io.ReadFull(r, raw); err != nil {
		return "", 0, fmt.Errorf("socks5 address: %w", err)
	}
	var portRaw [2]byte
	if _, err := io.ReadFull(r, portRaw[:]); err != nil {
		return "", 0, fmt.Errorf("socks5 port: %w", err)
	}
	port := binary.BigEndian.Uint16(portRaw[:])
	if atyp == socks5ATYPDomain {
		return string(raw), port, nil
	}
	addr, ok := netip.AddrFromSlice(raw)
	if !ok {
		return "", 0, errors.New("socks5 returned an unusable address")
	}
	return addr.Unmap().String(), port, nil
}

// isWildcardHost reports whether an address means "unspecified".
func isWildcardHost(host string) bool {
	a, err := netip.ParseAddr(host)
	return err == nil && a.IsUnspecified()
}

// socks5ReplyText renders an RFC 1928 §6 reply code.
func socks5ReplyText(code byte) string {
	switch code {
	case 0x01:
		return "general SOCKS server failure"
	case 0x02:
		return "connection not allowed by ruleset"
	case 0x03:
		return "network unreachable"
	case 0x04:
		return "host unreachable"
	case 0x05:
		return "connection refused"
	case 0x06:
		return "TTL expired"
	case 0x07:
		return "command not supported (the proxy has no UDP ASSOCIATE)"
	case 0x08:
		return "address type not supported"
	}
	return fmt.Sprintf("reply code 0x%02x", code)
}

// socks5ReplyReason maps an RFC 1928 §6 reply code to a probe reason.
//
// This is the typed counterpart of classifySOCKS5's string matching: the UDP path
// parses the protocol itself, so it reads the code directly instead of the error text
// x/net/proxy formats.
func socks5ReplyReason(code byte) int {
	switch code {
	case 0x05:
		// The relay reached the target and the target refused. A real target verdict.
		return telemetry.ProbeReasonRefused
	case 0x02, 0x03, 0x04, 0x06, 0x01:
		return telemetry.ProbeReasonProxyRefused
	case 0x07, 0x08:
		// The proxy cannot do what we asked — most often a server without UDP
		// ASSOCIATE. That is a configuration mismatch, not an outage.
		return telemetry.ProbeReasonProxyConfig
	}
	return telemetry.ProbeReasonProxyConnect
}

// isUDPNetwork reports whether a dial network names UDP.
func isUDPNetwork(network string) bool {
	switch network {
	case "udp", "udp4", "udp6":
		return true
	}
	return false
}

// dialSOCKS5UDPConn opens an association and returns a CONNECTED net.Conn to one
// destination, so a caller that would have done net.Dial("udp", …) against the host
// stack needs no changes.
//
// WHERE the destination is resolved follows the proxy's DNS mode, matching the TCP and
// CONNECT paths:
//
//   - local (default): resolved and policy-vetted here, and the approved LITERAL goes
//     into every datagram header. That keeps the guard's resolve-once/pin-the-address
//     contract intact — a proxy must not become a hole in netguard.
//   - remote: the hostname is carried in the header's domain form (ATYP=0x03) for the
//     proxy to resolve. Vetting it locally instead would break the split-horizon setup
//     the mode exists for: a name resolvable only on the proxy's network would fail
//     before a packet was sent. monitoreval gates this mode on the name being
//     policy-authorized, which is the check that replaces the address check here.
//
// Note the endpoint in question is the DIALED one — for a DNS probe the resolver
// server, never the queried name (the probe does not dial what it looks up).
func dialSOCKS5UDPConn(ctx context.Context, guard *netguard.Guard, base guardDialer,
	proxyAddr string, spec pcfg.ProxySpec, address string) (net.Conn, error) {
	var dst socks5UDPDest
	if spec.DNSModeOrDefault() == pcfg.ProxyDNSRemote {
		host, portStr, err := net.SplitHostPort(address)
		if err != nil {
			return nil, &ProxyError{Reason: telemetry.ProbeReasonProxyConfig, Err: err}
		}
		port, err := strconv.Atoi(portStr)
		if err != nil || port < 1 || port > 65535 {
			return nil, &ProxyError{Reason: telemetry.ProbeReasonProxyConfig,
				Err: fmt.Errorf("socks5 udp destination port %q is not in 1-65535", portStr)}
		}
		// A literal still travels as a literal: there is nothing for the proxy to
		// resolve, and the address form is the more compatible one.
		if a, perr := netip.ParseAddr(host); perr == nil {
			dst = socks5UDPDest{ip: a.Unmap(), port: port}
		} else {
			dst = socks5UDPDest{host: host, port: port}
		}
	} else {
		vetted, err := guard.VetUDPAddr(ctx, address)
		if err != nil {
			if _, blocked := isBlockedError(err); blocked {
				return nil, err
			}
			return nil, &ProxyError{Reason: telemetry.ProbeReasonProxyDNS, Err: err}
		}
		d, derr := destFromUDPAddr(vetted)
		if derr != nil {
			return nil, &ProxyError{Reason: telemetry.ProbeReasonProxyConfig, Err: derr}
		}
		dst = d
	}
	pc, err := dialSOCKS5UDP(ctx, base, proxyAddr, spec.Username, spec.Password)
	if err != nil {
		return nil, err
	}
	return &socks5UDPSession{conn: pc, remote: dst}, nil
}

// socks5UDPSession adapts a relayed association to connected-conn semantics.
//
// Reads deliberately do NOT filter by source address. The relay reports the origin,
// and a STUN filtering test exists precisely to see whether a reply arrives from a
// DIFFERENT address than the one written to — dropping those would turn the test's
// positive result into a silent timeout.
type socks5UDPSession struct {
	// conn is the concrete association rather than the net.PacketConn interface,
	// because a hostname destination has to reach writeToDest — WriteTo can only take
	// a net.Addr.
	conn   *socks5UDPConn
	remote socks5UDPDest
}

func (s *socks5UDPSession) Read(p []byte) (int, error) {
	n, _, err := s.conn.ReadFrom(p)
	return n, err
}

func (s *socks5UDPSession) Write(p []byte) (int, error) {
	return s.conn.writeToDest(p, s.remote)
}

func (s *socks5UDPSession) Close() error                       { return s.conn.Close() }
func (s *socks5UDPSession) LocalAddr() net.Addr                { return s.conn.LocalAddr() }
func (s *socks5UDPSession) RemoteAddr() net.Addr               { return s.remote.netAddr() }
func (s *socks5UDPSession) SetDeadline(t time.Time) error      { return s.conn.SetDeadline(t) }
func (s *socks5UDPSession) SetReadDeadline(t time.Time) error  { return s.conn.SetReadDeadline(t) }
func (s *socks5UDPSession) SetWriteDeadline(t time.Time) error { return s.conn.SetWriteDeadline(t) }

// ---- net.PacketConn ----

// WriteTo prefixes the datagram with a SOCKS5 UDP request header naming addr, so one
// association can address many peers.
func (c *socks5UDPConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	udpAddr, err := toUDPAddr(addr)
	if err != nil {
		return 0, err
	}
	dst, err := destFromUDPAddr(udpAddr)
	if err != nil {
		return 0, err
	}
	return c.writeToDest(p, dst)
}

// writeToDest is the shared send path. It exists separately from WriteTo because a
// hostname destination (proxy-side DNS) has no *net.UDPAddr form to route through.
func (c *socks5UDPConn) writeToDest(p []byte, dst socks5UDPDest) (int, error) {
	hdr, err := socks5UDPHeader(dst)
	if err != nil {
		return 0, err
	}
	buf := make([]byte, 0, len(hdr)+len(p))
	buf = append(buf, hdr...)
	buf = append(buf, p...)
	n, err := c.relay.Write(buf)
	if err != nil {
		return 0, err
	}
	// Report the caller's payload length, not the wire length: a caller comparing n
	// against len(p) must not see a short write because of our header.
	if n < len(hdr) {
		return 0, io.ErrShortWrite
	}
	written := n - len(hdr)
	if written > len(p) {
		written = len(p)
	}
	return written, nil
}

// ReadFrom strips the SOCKS5 UDP reply header and reports the ORIGINATING peer, not
// the relay — callers such as the STUN filtering test compare the source address
// against the destination they sent to, and reporting the relay would make every
// comparison wrong.
func (c *socks5UDPConn) ReadFrom(p []byte) (int, net.Addr, error) {
	buf := make([]byte, len(p)+socks5UDPHeaderMax)
	for {
		n, err := c.relay.Read(buf)
		if err != nil {
			return 0, nil, err
		}
		payload, from, perr := parseSOCKS5UDPDatagram(buf[:n])
		if perr != nil {
			// A malformed or fragmented datagram is dropped rather than surfaced: handing
			// a partial DNS/STUN message upward would read as a corrupt answer instead of
			// a lost packet. The caller's read deadline still bounds the wait.
			continue
		}
		copied := copy(p, payload)
		return copied, from, nil
	}
}

// parseSOCKS5UDPDatagram splits a relayed datagram into its payload and origin.
func parseSOCKS5UDPDatagram(b []byte) ([]byte, *net.UDPAddr, error) {
	if len(b) < 4 {
		return nil, nil, errors.New("socks5 udp datagram too short")
	}
	if b[2] != 0x00 {
		// FRAG != 0. Reassembly is optional in RFC 1928 and effectively unimplemented;
		// accepting a fragment as a whole message would corrupt the response.
		return nil, nil, errors.New("socks5 udp fragmentation is not supported")
	}
	rest := b[4:]
	var ipLen int
	switch b[3] {
	case socks5ATYPv4:
		ipLen = 4
	case socks5ATYPv6:
		ipLen = 16
	case socks5ATYPDomain:
		if len(rest) < 1 {
			return nil, nil, errors.New("socks5 udp datagram truncated")
		}
		ipLen = int(rest[0])
		rest = rest[1:]
	default:
		return nil, nil, fmt.Errorf("socks5 udp unknown address type 0x%02x", b[3])
	}
	if len(rest) < ipLen+2 {
		return nil, nil, errors.New("socks5 udp datagram truncated")
	}
	addrRaw := rest[:ipLen]
	port := binary.BigEndian.Uint16(rest[ipLen : ipLen+2])
	payload := rest[ipLen+2:]

	from := &net.UDPAddr{Port: int(port)}
	if b[3] == socks5ATYPDomain {
		// A relay that names the origin by hostname gives us nothing to compare
		// numerically. Resolving it here would be a second, unvetted lookup, so the
		// address is left unset and only the port is reported.
		from.IP = nil
	} else {
		a, ok := netip.AddrFromSlice(addrRaw)
		if !ok {
			return nil, nil, errors.New("socks5 udp datagram has an unusable source address")
		}
		from.IP = a.Unmap().AsSlice()
	}
	return payload, from, nil
}

// socks5UDPDest is one datagram destination. Exactly one of ip/host is set: a vetted
// literal under local DNS mode, or a hostname the PROXY resolves under remote mode.
//
// Carrying the hostname matters: RFC 1928 §7 lets a UDP request header name its
// destination by domain (ATYP=0x03), which is what makes proxy-side DNS work for
// datagram probes. Resolving it locally instead would defeat the split-horizon setup
// the mode exists for — a name that only resolves on the proxy's network would fail
// before a single packet was sent.
type socks5UDPDest struct {
	ip   netip.Addr
	host string
	port int
}

func destFromUDPAddr(addr *net.UDPAddr) (socks5UDPDest, error) {
	a, ok := netip.AddrFromSlice(addr.IP)
	if !ok {
		return socks5UDPDest{}, fmt.Errorf("socks5 udp destination %v is not an IP address", addr.IP)
	}
	return socks5UDPDest{ip: a.Unmap(), port: addr.Port}, nil
}

// netAddr renders the destination as a net.Addr for RemoteAddr reporting. A hostname
// destination has no *net.UDPAddr form, so it is reported as an opaque address rather
// than resolved just to satisfy the accessor.
func (d socks5UDPDest) netAddr() net.Addr {
	if d.host != "" {
		return hostPortAddr(net.JoinHostPort(d.host, strconv.Itoa(d.port)))
	}
	return net.UDPAddrFromAddrPort(netip.AddrPortFrom(d.ip, uint16(d.port)))
}

// hostPortAddr is a net.Addr for an unresolved host:port.
type hostPortAddr string

func (hostPortAddr) Network() string  { return "udp" }
func (a hostPortAddr) String() string { return string(a) }

// socks5UDPHeader builds the per-datagram request header for a destination.
func socks5UDPHeader(d socks5UDPDest) ([]byte, error) {
	hdr := []byte{0x00, 0x00, 0x00} // RSV RSV FRAG(0)
	switch {
	case d.host != "":
		if len(d.host) > maxSOCKS5DomainLen {
			return nil, fmt.Errorf("socks5 udp destination host is longer than %d bytes", maxSOCKS5DomainLen)
		}
		hdr = append(hdr, socks5ATYPDomain, byte(len(d.host)))
		hdr = append(hdr, d.host...)
	case d.ip.Is4():
		hdr = append(hdr, socks5ATYPv4)
		v4 := d.ip.As4()
		hdr = append(hdr, v4[:]...)
	case d.ip.IsValid():
		hdr = append(hdr, socks5ATYPv6)
		v16 := d.ip.As16()
		hdr = append(hdr, v16[:]...)
	default:
		return nil, errors.New("socks5 udp destination is neither an address nor a host")
	}
	var port [2]byte
	binary.BigEndian.PutUint16(port[:], uint16(d.port))
	return append(hdr, port[:]...), nil
}

// toUDPAddr narrows a net.Addr to a *net.UDPAddr.
func toUDPAddr(addr net.Addr) (*net.UDPAddr, error) {
	switch a := addr.(type) {
	case *net.UDPAddr:
		return a, nil
	default:
		u, err := net.ResolveUDPAddr("udp", addr.String())
		if err != nil {
			return nil, fmt.Errorf("socks5 udp destination %v: %w", addr, err)
		}
		return u, nil
	}
}

func (c *socks5UDPConn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		// Closing the control connection is what releases the association server-side;
		// closing the relay socket is what unblocks any in-flight read.
		err = c.relay.Close()
		if cerr := c.control.Close(); err == nil {
			err = cerr
		}
	})
	return err
}

// LocalAddr reports the local UDP socket. Note this is the address facing the PROXY,
// not a reflexive address of the agent.
func (c *socks5UDPConn) LocalAddr() net.Addr { return c.relay.LocalAddr() }

func (c *socks5UDPConn) SetDeadline(t time.Time) error      { return c.relay.SetDeadline(t) }
func (c *socks5UDPConn) SetReadDeadline(t time.Time) error  { return c.relay.SetReadDeadline(t) }
func (c *socks5UDPConn) SetWriteDeadline(t time.Time) error { return c.relay.SetWriteDeadline(t) }
