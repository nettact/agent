package collector

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nettact/agent/internal/netguard"
	"github.com/nettact/agent/internal/proxydial"
	"github.com/nettact/agent/probepolicy"
	pcfg "github.com/nettact/protocol/config"
	"github.com/nettact/protocol/telemetry"
)

// Regressions for the egress-policy guarantees the proxy paths make.
//
// The theme: a proxy must not become a hole in netguard. Handing a HOSTNAME to a proxy
// moves resolution to the far side, where the agent can no longer see the address the
// connection reaches — so under the default local-DNS mode every proxied dial has to
// resolve and vet locally and pass the approved literal on. These tests assert on what
// the proxy actually received on the wire, not on internal call shapes.

// recordingSOCKS5 accepts the SOCKS5 handshake, records the destination the client
// asked for, and refuses. Recording the real request is the point: it is the only way
// to prove whether a hostname or a vetted literal was handed over.
type recordingSOCKS5 struct {
	mu   sync.Mutex
	dsts []string
}

func (s *recordingSOCKS5) start(t *testing.T) string {
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
			go s.serve(c)
		}
	}()
	return ln.Addr().String()
}

func (s *recordingSOCKS5) serve(c net.Conn) {
	defer c.Close()
	br := bufio.NewReader(c)
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(br, hdr); err != nil {
		return
	}
	if _, err := io.ReadFull(br, make([]byte, int(hdr[1]))); err != nil {
		return
	}
	if _, err := c.Write([]byte{0x05, 0x00}); err != nil { // no auth
		return
	}
	req := make([]byte, 4)
	if _, err := io.ReadFull(br, req); err != nil {
		return
	}
	var dst string
	switch req[3] {
	case 0x01:
		raw := make([]byte, 4)
		if _, err := io.ReadFull(br, raw); err != nil {
			return
		}
		dst = net.IP(raw).String()
	case 0x03:
		l := make([]byte, 1)
		if _, err := io.ReadFull(br, l); err != nil {
			return
		}
		name := make([]byte, int(l[0]))
		if _, err := io.ReadFull(br, name); err != nil {
			return
		}
		dst = string(name)
	case 0x04:
		raw := make([]byte, 16)
		if _, err := io.ReadFull(br, raw); err != nil {
			return
		}
		dst = net.IP(raw).String()
	}
	if _, err := io.ReadFull(br, make([]byte, 2)); err != nil {
		return
	}
	s.mu.Lock()
	s.dsts = append(s.dsts, dst)
	s.mu.Unlock()
	// Refuse: the test only cares what was requested.
	_, _ = c.Write([]byte{0x05, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
}

func (s *recordingSOCKS5) seen() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.dsts...)
}

// socks5DialerVia builds a real SOCKS5 Dialer pointed at addr. newSOCKS5 does not dial
// at construction time, so this never touches the network until a probe does.
func socks5DialerVia(t *testing.T, guard *netguard.Guard, addr string, dnsMode string) *proxydial.Dialer {
	t.Helper()
	host, portStr, _ := net.SplitHostPort(addr)
	port, _ := strconv.Atoi(portStr)
	mgr := proxydial.NewManager(guard)
	mgr.Apply([]pcfg.ProxySpec{{
		ID: "p", Type: pcfg.ProxyTypeSOCKS5, Host: host, Port: port,
		DNSMode: dnsMode, ConfigSerial: 1,
	}})
	d, err := mgr.Dialer(context.Background(), "p")
	if err != nil {
		t.Fatalf("Dialer: %v", err)
	}
	return d
}

// denyAddrPolicy denies one literal address while allowing everything else, so a
// hostname resolving to it is caught only by an ADDRESS check — never by a name check.
// That is exactly what a proxy handed a hostname would miss.
func denyAddrPolicy(t *testing.T, addr string) probepolicy.Policy {
	t.Helper()
	a, err := netip.ParseAddr(addr)
	if err != nil {
		t.Fatal(err)
	}
	return probepolicy.Policy{
		Mode: probepolicy.ModeDenylist,
		Deny: []probepolicy.Selector{{Kind: probepolicy.KindIP, Addr: a}},
	}
}

// In local DNS mode the proxy must receive the vetted LITERAL, never the hostname.
// Otherwise the proxy resolves it and no ip:/cidr:/scope: rule can ever apply.
func TestProxyDialFuncHandsProxyAVettedLiteral(t *testing.T) {
	srv := &recordingSOCKS5{}
	addr := srv.start(t)
	guard := netguard.New(probepolicy.Policy{}, true)
	d := socks5DialerVia(t, guard, addr, pcfg.ProxyDNSLocal)

	// "localhost" resolves to a loopback literal; bypass allows it, so the request
	// reaches the proxy and what it recorded is the assertion.
	_, _ = proxyDialFunc(guard, d)(context.Background(), "tcp", "localhost:443")

	got := srv.seen()
	if len(got) == 0 {
		t.Fatal("the proxy received no CONNECT request")
	}
	if _, err := netip.ParseAddr(got[0]); err != nil {
		t.Fatalf("the proxy was asked for %q — a hostname, so IT would resolve it and the agent's address policy could never apply", got[0])
	}
}

// The vetting must actually block: a hostname resolving to a denied address must not
// reach the proxy at all.
func TestProxyDialFuncBlocksHostnameResolvingToDeniedAddress(t *testing.T) {
	srv := &recordingSOCKS5{}
	addr := srv.start(t)
	// The proxy endpoint itself is 127.0.0.1, so it cannot be the denied address here.
	// Deny a public literal and resolve a name to it via a stub-free route: use the
	// literal directly for the deny case, and assert the hostname case separately with
	// loopback denied but the proxy reached over an already-open connection is not
	// possible — so this case denies the resolved loopback and accepts that the proxy
	// dial is blocked too. What matters is that NOTHING reached the proxy.
	guard := netguard.New(denyAddrPolicy(t, "127.0.0.1"), false)
	d := socks5DialerVia(t, guard, addr, pcfg.ProxyDNSLocal)

	_, err := proxyDialFunc(guard, d)(context.Background(), "tcp", "localhost:443")
	var blocked *netguard.BlockedError
	if !errors.As(err, &blocked) {
		t.Fatalf("error = %v, want a policy block on the resolved address", err)
	}
	if got := srv.seen(); len(got) != 0 {
		t.Fatalf("the proxy was asked for %v despite the resolved address being denied", got)
	}
}

// A literal destination is checked too, not just hostnames.
func TestProxyDialFuncBlocksDeniedLiteral(t *testing.T) {
	srv := &recordingSOCKS5{}
	addr := srv.start(t)
	guard := netguard.New(denyAddrPolicy(t, "203.0.113.5"), false)
	d := socks5DialerVia(t, guard, addr, pcfg.ProxyDNSLocal)

	_, err := proxyDialFunc(guard, d)(context.Background(), "tcp", "203.0.113.5:443")
	var blocked *netguard.BlockedError
	if !errors.As(err, &blocked) {
		t.Fatalf("error = %v, want a policy block", err)
	}
	if got := srv.seen(); len(got) != 0 {
		t.Fatalf("a denied literal was handed to the proxy: %v", got)
	}
}

// Remote DNS is the deliberate opt-out: the hostname goes through verbatim, because
// resolving it locally is exactly what that mode exists to avoid.
func TestProxyDialFuncPassesHostnameInRemoteDNSMode(t *testing.T) {
	srv := &recordingSOCKS5{}
	addr := srv.start(t)
	guard := netguard.New(probepolicy.Policy{}, true)
	d := socks5DialerVia(t, guard, addr, pcfg.ProxyDNSRemote)

	_, _ = proxyDialFunc(guard, d)(context.Background(), "tcp", "split.example.test:443")

	got := srv.seen()
	if len(got) != 1 || got[0] != "split.example.test" {
		t.Fatalf("the proxy was asked for %v, want the hostname passed through for proxy-side resolution", got)
	}
}

// An unproxied target keeps using the guard's own dial.
func TestProxyDialFuncNilProxyUsesGuard(t *testing.T) {
	guard := netguard.New(denyAddrPolicy(t, "203.0.113.5"), false)
	_, err := proxyDialFunc(guard, nil)(context.Background(), "tcp", "203.0.113.5:443")
	var blocked *netguard.BlockedError
	if !errors.As(err, &blocked) {
		t.Fatalf("error = %v, want the guard's policy block", err)
	}
}

// End-to-end through the HTTP collector: the CONNECT request the proxy receives must
// name a literal, proving the collector uses the vetting dial rather than the raw one.
func TestHTTPProxiedRequestVetsHostLocally(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()
	_, portStr, _ := net.SplitHostPort(target.Listener.Addr().String())

	srv := &recordingSOCKS5{}
	proxyAddr := srv.start(t)
	phost, pportStr, _ := net.SplitHostPort(proxyAddr)
	pport, _ := strconv.Atoi(pportStr)

	mgr := proxydial.NewManager(testGuard())
	mgr.Apply([]pcfg.ProxySpec{{
		ID: "prx", Type: pcfg.ProxyTypeSOCKS5, Host: phost, Port: pport, ConfigSerial: 1,
	}})
	c := NewHTTPCollector(testGuard(), mgr, true)
	// A hostname URL: under local DNS the agent must resolve it and ask for the IP.
	c.SetTargets([]pcfg.ProbeTarget{{
		MonitorID: "m1", Kind: "http", Target: "http://localhost:" + portStr, ProxyID: "prx", ConfigSerial: 1,
	}})
	if _, err := c.Collect(context.Background()); err != nil {
		t.Fatal(err)
	}

	got := srv.seen()
	if len(got) == 0 {
		t.Fatal("the proxy received no request")
	}
	if _, err := netip.ParseAddr(got[0]); err != nil {
		t.Fatalf("the proxy was asked for %q — it would resolve that itself, so the agent's address policy could not apply", got[0])
	}
}

// A DNS monitor pinned to a proxy but using the SYSTEM resolver must NOT run: there is
// no address for a proxy to relay to, so the query would leave the host directly and
// the monitor would report success while the pinned egress was down.
func TestDNSProxiedWithoutResolverFailsClosed(t *testing.T) {
	mgr := proxydial.NewManager(testGuard())
	mgr.Apply([]pcfg.ProxySpec{{
		ID: "prx", Type: pcfg.ProxyTypeSOCKS5, Host: "127.0.0.1", Port: 1, ConfigSerial: 1,
	}})
	c := NewDNSCollector(testGuard(), mgr)
	c.SetTargets([]pcfg.ProbeTarget{{
		MonitorID: "m1", Kind: "dns", Target: "example.test", ProxyID: "prx", ConfigSerial: 1,
	}})

	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ok := metricByKind(res, telemetry.DNSOK)
	if ok == nil || ok.Value != 0 {
		t.Fatalf("dns ok = %+v, want a 0 sample rather than a host-resolved success", ok)
	}
	ec := metricByKind(res, telemetry.DNSErrorClass)
	if ec == nil || int(ec.Value) != telemetry.ProbeReasonProxyConfig {
		t.Fatalf("error class = %+v, want ProxyConfig(%d)", ec, telemetry.ProbeReasonProxyConfig)
	}
	// No resolve-latency sample: nothing was measured.
	if metricByKind(res, telemetry.DNSResolve) != nil {
		t.Fatal("an un-attempted DNS query emitted a resolve latency sample")
	}
}

// Under proxy-side DNS a redirect hop is only ever gated by the NAME check, so that
// check must require authorization rather than merely "not denied" — otherwise an
// authorized endpoint could bounce the probe to any host the policy never mentions.
func TestClassifyRedirectRequiresNameAuthorizationUnderRemoteDNS(t *testing.T) {
	// An allowlist authorizing exactly one host. Everything else is unlisted:
	// NameAuthorized=false, but NOT Denied.
	policy := probepolicy.Policy{
		Mode:  probepolicy.ModeAllowlist,
		Allow: []probepolicy.Selector{{Kind: probepolicy.KindHost, Host: "allowed.example.test"}},
	}
	c := NewHTTPCollector(netguard.New(policy, false), nil, true)
	// Only Spec is read by classifyRedirect, so a bare Dialer carries enough.
	remote := &proxydial.Dialer{Spec: pcfg.ProxySpec{
		ID: "p", Type: pcfg.ProxyTypeSOCKS5, DNSMode: pcfg.ProxyDNSRemote,
	}}
	local := &proxydial.Dialer{Spec: pcfg.ProxySpec{
		ID: "p", Type: pcfg.ProxyTypeSOCKS5, DNSMode: pcfg.ProxyDNSLocal,
	}}

	req := func(host string) *http.Request {
		r, err := http.NewRequest(http.MethodGet, "https://"+host+"/", nil)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}

	t.Run("remote dns refuses an unlisted redirect host", func(t *testing.T) {
		err := c.classifyRedirect(req("elsewhere.example.test"), remote)
		var blocked *netguard.BlockedError
		if !errors.As(err, &blocked) {
			t.Fatalf("error = %v, want a block: the proxy would resolve this name, so no address check can run", err)
		}
	})
	t.Run("remote dns allows an authorized redirect host", func(t *testing.T) {
		if err := c.classifyRedirect(req("allowed.example.test"), remote); err != nil {
			t.Fatalf("an authorized host was refused: %v", err)
		}
	})
	t.Run("local dns leaves the address check to dial time", func(t *testing.T) {
		// In local mode proxyDialFunc vets the resolved address, so the name check stays
		// a cheap pre-filter and must not reject a merely-unlisted name here.
		if err := c.classifyRedirect(req("elsewhere.example.test"), local); err != nil {
			t.Fatalf("local mode rejected at redirect time: %v", err)
		}
	})
	t.Run("unproxied is unaffected", func(t *testing.T) {
		if err := c.classifyRedirect(req("elsewhere.example.test"), nil); err != nil {
			t.Fatalf("an unproxied redirect was rejected: %v", err)
		}
	})
}

// A WireGuard proxy's in-tunnel address belongs to no OS interface, so without it the
// open-NAT comparison misses and a NAT-free tunnelled path reads as full-cone.
func TestClassifyRecognizesTunnelLocalAddress(t *testing.T) {
	tunnelAddr := netip.MustParseAddr("10.7.0.2")
	reflexive := "10.7.0.2:51820"

	if classify(reflexive, natEndpointIndependent, natEndpointIndependent, nil) == natTypeOpen {
		t.Skip("10.7.0.2 is a host address on this machine, so the negative case cannot be shown")
	}
	got := classify(reflexive, natEndpointIndependent, natEndpointIndependent, []netip.Addr{tunnelAddr})
	if got != natTypeOpen {
		t.Fatalf("classify = %d, want natTypeOpen(%d): the reflexive address IS the tunnel address, so there is no NAT",
			got, natTypeOpen)
	}
}

func TestTunnelLocalAddrs(t *testing.T) {
	got := tunnelLocalAddrs(&proxydial.Dialer{Spec: pcfg.ProxySpec{
		Type: pcfg.ProxyTypeWireGuard, WGLocalAddrs: "10.7.0.2/32, 10.7.0.3 , ",
	}})
	if len(got) != 2 || got[0].String() != "10.7.0.2" || got[1].String() != "10.7.0.3" {
		t.Fatalf("tunnelLocalAddrs = %v, want both addresses with prefixes stripped", got)
	}
	// A relay's reflexive address is the RELAY's mapping, never one of ours, so a relay
	// contributes nothing even if the field happens to be populated.
	if got := tunnelLocalAddrs(&proxydial.Dialer{Spec: pcfg.ProxySpec{
		Type: pcfg.ProxyTypeSOCKS5, WGLocalAddrs: "10.7.0.2",
	}}); got != nil {
		t.Fatalf("a socks5 proxy contributed tunnel-local addresses: %v", got)
	}
	if got := tunnelLocalAddrs(nil); got != nil {
		t.Fatalf("nil proxy contributed %v", got)
	}
}

// A proxied DoH monitor must vet its resolver endpoint locally too. This was the one
// DNS path still handing a hostname to the proxy after the others were fixed, so the
// concrete address never passed Guard.CheckAddr.
func TestDoHProxiedRequestVetsResolverLocally(t *testing.T) {
	srv := &recordingSOCKS5{}
	proxyAddr := srv.start(t)
	phost, pportStr, _ := net.SplitHostPort(proxyAddr)
	pport, _ := strconv.Atoi(pportStr)

	mgr := proxydial.NewManager(testGuard())
	mgr.Apply([]pcfg.ProxySpec{{
		ID: "prx", Type: pcfg.ProxyTypeSOCKS5, Host: phost, Port: pport, ConfigSerial: 1,
	}})
	c := NewDNSCollector(testGuard(), mgr)
	// A hostname DoH endpoint: under local DNS the agent must resolve it and ask the
	// proxy for the literal.
	c.SetTargets([]pcfg.ProbeTarget{{
		MonitorID: "m1", Kind: "dns", Target: "example.test", ProxyID: "prx", ConfigSerial: 1,
		Params: pcfg.ProbeParams{ResolverProtocol: "doh", ResolverServer: "https://localhost/dns-query"},
	}})
	if _, err := c.Collect(context.Background()); err != nil {
		t.Fatal(err)
	}

	got := srv.seen()
	if len(got) == 0 {
		t.Fatal("the proxy received no DoH connection attempt")
	}
	if _, err := netip.ParseAddr(got[0]); err != nil {
		t.Fatalf("the proxy was asked for %q — it would resolve that itself, so the agent's address policy could not apply", got[0])
	}
}

// Rotating a proxy must not leave the previous generation's DoH transport cached: those
// transports hold authenticated tunnels, so accumulating them leaks connections and file
// descriptors for as long as the agent runs.
func TestDoHClientsEvictSupersededGenerations(t *testing.T) {
	c := NewDNSCollector(testGuard(), proxydial.NewManager(testGuard()))
	gen := func(serial int) *proxydial.Dialer {
		return &proxydial.Dialer{Spec: pcfg.ProxySpec{ID: "prx", ConfigSerial: serial}}
	}
	first := c.dohClientFor(gen(1))
	again := c.dohClientFor(gen(1))
	if first != again {
		t.Fatal("the same generation built two DoH clients")
	}
	rotated := c.dohClientFor(gen(2))
	if rotated == first {
		t.Fatal("a new generation reused the old DoH client, so a rotated credential would not take effect")
	}
	c.mu.Lock()
	n := len(c.dohClients)
	c.mu.Unlock()
	if n != 1 {
		t.Fatalf("cached DoH clients = %d, want only the current generation", n)
	}
	// An unrelated proxy is untouched by the eviction.
	other := c.dohClientFor(&proxydial.Dialer{Spec: pcfg.ProxySpec{ID: "other", ConfigSerial: 1}})
	c.mu.Lock()
	n = len(c.dohClients)
	c.mu.Unlock()
	if n != 2 || other == rotated {
		t.Fatalf("cached clients = %d after adding a second proxy, want 2 distinct", n)
	}
}

// Same contract for the HTTP collector's client cache: it is keyed by generation, so the
// superseded entries have to go rather than sit on pooled connections to the old egress.
func TestHTTPClientsEvictSupersededGenerations(t *testing.T) {
	c := NewHTTPCollector(testGuard(), proxydial.NewManager(testGuard()), true)
	gen := func(serial int) *proxydial.Dialer {
		return &proxydial.Dialer{Spec: pcfg.ProxySpec{ID: "prx", ConfigSerial: serial}}
	}
	// Two live entries for one generation: the key also carries the TLS/redirect policy.
	c.clientFor(false, 0, gen(1))
	c.clientFor(true, 0, gen(1))
	c.mu.Lock()
	n := len(c.clients)
	c.mu.Unlock()
	if n != 2 {
		t.Fatalf("clients = %d, want one per TLS/redirect policy", n)
	}

	c.clientFor(false, 0, gen(2))
	c.mu.Lock()
	defer c.mu.Unlock()
	for k := range c.clients {
		if strings.HasSuffix(k, "prx@1") {
			t.Fatalf("a superseded generation survived in the cache: %q", k)
		}
	}
	if len(c.clients) != 1 {
		t.Fatalf("clients = %d after rotation, want only the current generation", len(c.clients))
	}
}

// filteringBehavior deliberately uses a FRESH socket, but it must still be a PROXIED
// one. Opening it on the host stack leaked direct STUN traffic despite the pin and
// combined the host's filtering result with the proxy egress's mapping result, giving a
// NATType that described no single path.
//
// Asserted structurally, because the observable end-to-end (which egress a STUN reply
// came back on) needs a cooperating multi-address STUN server. filteringBehavior takes
// the proxy explicitly and derives its round tripper the same way probeNAT does, so a
// regression would have to delete the parameter — which this pins.
func TestNATFilteringUsesTheProxiedRoundTripper(t *testing.T) {
	// A proxy that cannot carry datagrams: ListenPacket fails, so a PROXIED filtering
	// socket cannot be created and the result must be natUnknown. A host-stack socket
	// would succeed and return a real verdict — which is exactly the bug.
	httpProxy := &proxydial.Dialer{Spec: pcfg.ProxySpec{ID: "p", Type: pcfg.ProxyTypeHTTP}}
	got, err := filteringBehavior(context.Background(), testGuard(), httpProxy, "127.0.0.1:3478", 50*time.Millisecond)
	if err != nil {
		t.Fatalf("filteringBehavior: %v", err)
	}
	if got != natUnknown {
		t.Fatalf("filtering = %d, want natUnknown(%d): a proxy that cannot carry UDP must not fall back to the host stack",
			got, natUnknown)
	}
}
