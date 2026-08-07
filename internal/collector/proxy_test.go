package collector

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/nettact/agent/internal/netguard"
	"github.com/nettact/agent/internal/proxydial"
	"github.com/nettact/agent/probepolicy"
	pcfg "github.com/nettact/protocol/config"
	"github.com/nettact/protocol/telemetry"
)

func testGuard() *netguard.Guard { return netguard.New(probepolicy.Policy{}, true) }

// startCONNECTProxy runs a real HTTP CONNECT proxy: it accepts CONNECT, dials the
// requested target, answers 200, then splices the two connections. A real relay
// (rather than a stub) is what lets these tests assert that a proxied probe reaches
// the target and produces the same metrics a direct one would.
func startCONNECTProxy(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			client, err := ln.Accept()
			if err != nil {
				return
			}
			go serveCONNECT(client)
		}
	}()
	return ln.Addr().String()
}

func serveCONNECT(client net.Conn) {
	br := bufio.NewReader(client)
	req, err := http.ReadRequest(br)
	if err != nil || req.Method != http.MethodConnect {
		_ = client.Close()
		return
	}
	upstream, err := net.Dial("tcp", req.Host)
	if err != nil {
		_, _ = client.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		_ = client.Close()
		return
	}
	if _, err := client.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n")); err != nil {
		_ = client.Close()
		_ = upstream.Close()
		return
	}
	var wg sync.WaitGroup
	wg.Add(2)
	// Bytes the CONNECT parse buffered must be forwarded first, or the target would
	// see a truncated first request.
	go func() { defer wg.Done(); _, _ = io.Copy(upstream, br) }()
	go func() { defer wg.Done(); _, _ = io.Copy(client, upstream) }()
	wg.Wait()
	_ = client.Close()
	_ = upstream.Close()
}

// A monitor pinned to a proxy that is not in the pushed config must report
// ProxyConfig and NOT be dialed directly. This is the fail-closed contract: a
// direct fallback would probe from the real egress IP the operator routed away
// from, and report "up" for a path that was never tested.
func TestHTTPProxyMissingReportsProxyConfigWithoutDialing(t *testing.T) {
	// A live server the probe would reach IF it wrongly fell back to a direct dial.
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	mgr := proxydial.NewManager(testGuard())
	c := NewHTTPCollector(testGuard(), mgr, true, nil)
	c.SetTargets([]pcfg.ProbeTarget{{
		MonitorID: "m1", Kind: "http", Target: srv.URL, ProxyID: "prx_absent", ConfigSerial: 1,
	}})

	res := collectSettled(t, context.Background(), c)
	if hits != 0 {
		t.Fatalf("the probe reached the target %d time(s) — a missing proxy must never fall back to a direct dial", hits)
	}
	ok := metricByKind(res, telemetry.HTTPOK)
	if ok == nil || ok.Value != 0 {
		t.Fatalf("http ok metric = %+v, want a 0 sample", ok)
	}
	ec := metricByKind(res, telemetry.HTTPErrorClass)
	if ec == nil || int(ec.Value) != telemetry.ProbeReasonProxyConfig {
		t.Fatalf("error class = %+v, want ProxyConfig(%d)", ec, telemetry.ProbeReasonProxyConfig)
	}
	// No latency or status sample: nothing was measured, and a zero-latency sample
	// would be indistinguishable from a fast success in the history.
	if metricByKind(res, telemetry.HTTPLat) != nil || metricByKind(res, telemetry.HTTPStatus) != nil {
		t.Fatal("an un-attempted probe emitted latency/status samples")
	}
}

// A pinned proxy that is present but unreachable must report ProxyConnect — the
// distinction from a target timeout is the entire point of the 8x family.
func TestHTTPUnreachableProxyIsProxyConnectNotTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// A port that is bound and released, so connecting is refused rather than hanging.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	deadAddr := ln.Addr().String()
	_ = ln.Close()
	host, portStr, _ := net.SplitHostPort(deadAddr)
	port, _ := strconv.Atoi(portStr)

	mgr := proxydial.NewManager(testGuard())
	mgr.Apply([]pcfg.ProxySpec{{
		ID: "prx", Type: pcfg.ProxyTypeSOCKS5, Host: host, Port: port, ConfigSerial: 1,
	}})
	c := NewHTTPCollector(testGuard(), mgr, true, nil)
	c.SetTargets([]pcfg.ProbeTarget{{
		MonitorID: "m1", Kind: "http", Target: srv.URL, ProxyID: "prx", ConfigSerial: 1,
	}})

	res := collectSettled(t, context.Background(), c)
	ec := metricByKind(res, telemetry.HTTPErrorClass)
	if ec == nil {
		t.Fatal("no error class emitted")
	}
	if int(ec.Value) != telemetry.ProbeReasonProxyConnect {
		t.Fatalf("error class = %d, want ProxyConnect(%d) — a dead proxy must not be reported as an unreachable site",
			int(ec.Value), telemetry.ProbeReasonProxyConnect)
	}
	// The event must name the egress path, so the operator does not start by
	// investigating a healthy service.
	if len(res.Events) != 1 {
		t.Fatalf("events = %+v, want one", res.Events)
	}
	if want := "egress proxy"; !strings.Contains(res.Events[0].Message, want) {
		t.Fatalf("event message = %q, want it to mention %q", res.Events[0].Message, want)
	}
}

// A proxied HTTP probe that SUCCEEDS must look exactly like a direct one: the same
// metrics, and the request must actually arrive at the target through the tunnel.
func TestHTTPThroughProxySucceeds(t *testing.T) {
	var got *http.Request
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Clone(r.Context())
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("body-marker"))
	}))
	defer srv.Close()

	proxyAddr := startCONNECTProxy(t)
	host, portStr, _ := net.SplitHostPort(proxyAddr)
	port, _ := strconv.Atoi(portStr)

	mgr := proxydial.NewManager(testGuard())
	mgr.Apply([]pcfg.ProxySpec{{
		ID: "prx", Type: pcfg.ProxyTypeHTTP, Host: host, Port: port, ConfigSerial: 1,
	}})
	c := NewHTTPCollector(testGuard(), mgr, true, nil)
	c.SetTargets([]pcfg.ProbeTarget{{
		MonitorID: "m1", Kind: "http", Target: srv.URL, ProxyID: "prx", ConfigSerial: 1,
		Params: pcfg.ProbeParams{Keyword: "body-marker"},
	}})

	res := collectSettled(t, context.Background(), c)
	if got == nil {
		t.Fatal("the request never reached the target through the proxy")
	}
	// Origin-form request URI: going through DialContext (not Transport.Proxy) is
	// what keeps the probe's request identical to a direct one.
	if got.URL.IsAbs() {
		t.Fatalf("request URI was absolute (%s) — the proxy must be transparent to the request", got.URL)
	}
	ok := metricByKind(res, telemetry.HTTPOK)
	if ok == nil || ok.Value != 1 {
		t.Fatalf("http ok = %+v, want 1 through the proxy", ok)
	}
	ec := metricByKind(res, telemetry.HTTPErrorClass)
	if ec == nil || int(ec.Value) != telemetry.ProbeReasonNone {
		t.Fatalf("error class = %+v, want None", ec)
	}
	if metricByKind(res, telemetry.HTTPLat) == nil {
		t.Fatal("a successful proxied probe emitted no latency sample")
	}
}

// The client cache must be keyed on the proxy GENERATION, or a rotated credential
// would keep being served over the connection pool built with the old one.
func TestHTTPClientCacheIsKeyedByProxyGeneration(t *testing.T) {
	c := NewHTTPCollector(testGuard(), proxydial.NewManager(testGuard()), true, nil)
	d1 := &proxydial.Dialer{Spec: pcfg.ProxySpec{ID: "prx", ConfigSerial: 1}}
	d2 := &proxydial.Dialer{Spec: pcfg.ProxySpec{ID: "prx", ConfigSerial: 2}}

	direct := c.clientFor(false, 0, nil)
	first := c.clientFor(false, 0, d1)
	again := c.clientFor(false, 0, d1)
	rotated := c.clientFor(false, 0, d2)

	if direct == first {
		t.Fatal("the direct client was reused for a proxied target")
	}
	if first != again {
		t.Fatal("the same proxy generation built two clients")
	}
	if first == rotated {
		t.Fatal("a new proxy generation reused the old client — a rotated credential would never take effect")
	}
}

// A proxied TCP probe must not emit a dns_ms segment under proxy-side DNS: the
// agent did not resolve, so that segment does not exist. Reporting it as zero would
// be indistinguishable from an instant resolution.
func TestTCPRemoteDNSEmitsNoDNSSegment(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer target.Close()
	u, _ := url.Parse(target.URL)
	port, _ := strconv.Atoi(u.Port())

	proxyAddr := startCONNECTProxy(t)
	phost, pportStr, _ := net.SplitHostPort(proxyAddr)
	pport, _ := strconv.Atoi(pportStr)

	mgr := proxydial.NewManager(testGuard())
	mgr.Apply([]pcfg.ProxySpec{{
		ID: "prx", Type: pcfg.ProxyTypeHTTP, Host: phost, Port: pport,
		DNSMode: pcfg.ProxyDNSRemote, ConfigSerial: 1,
	}})
	c := NewTCPCollector(testGuard(), mgr, nil)
	// A hostname target, so a local-DNS run WOULD have produced a dns_ms sample.
	c.SetTargets([]pcfg.ProbeTarget{{
		MonitorID: "m1", Kind: "tcp", Target: "localhost", ProxyID: "prx", ConfigSerial: 1,
		Params: pcfg.ProbeParams{Port: port},
	}})

	res := collectSettled(t, context.Background(), c)
	if metricByKind(res, telemetry.TCPDNSms) != nil {
		t.Fatal("proxy-side DNS emitted a dns_ms segment the agent never measured")
	}
	ok := metricByKind(res, telemetry.TCPOK)
	if ok == nil || ok.Value != 1 {
		t.Fatalf("tcp ok = %+v, want a successful connect through the proxy", ok)
	}
	if metricByKind(res, telemetry.TCPConnectMs) == nil {
		t.Fatal("a successful proxied connect emitted no connect_ms")
	}
}

func TestTCPProxyMissingReportsProxyConfig(t *testing.T) {
	c := NewTCPCollector(testGuard(), proxydial.NewManager(testGuard()), nil)
	c.SetTargets([]pcfg.ProbeTarget{{
		MonitorID: "m1", Kind: "tcp", Target: "203.0.113.5", ProxyID: "prx_absent", ConfigSerial: 1,
		Params: pcfg.ProbeParams{Port: 443},
	}})
	res := collectSettled(t, context.Background(), c)
	ec := metricByKind(res, telemetry.TCPErrorClass)
	if ec == nil || int(ec.Value) != telemetry.ProbeReasonProxyConfig {
		t.Fatalf("error class = %+v, want ProxyConfig(%d)", ec, telemetry.ProbeReasonProxyConfig)
	}
	if metricByKind(res, telemetry.TCPConnectMs) != nil {
		t.Fatal("an un-attempted connect emitted a connect_ms sample")
	}
}

// classifyProxyAwareError is the single decision point for "whose failure was
// this". Getting it wrong in either direction misdirects an operator.
func TestClassifyProxyAwareError(t *testing.T) {
	plain := &net.OpError{Op: "dial", Err: errTimeoutStub{}}

	t.Run("unproxied errors keep their own classification", func(t *testing.T) {
		reason, atTarget := classifyProxyAwareError(plain, false)
		if !atTarget {
			t.Fatal("an unproxied failure was attributed away from the target")
		}
		if reason == telemetry.ProbeReasonProxyConnect {
			t.Fatal("an unproxied failure was classified as a proxy fault")
		}
	})
	t.Run("proxy errors win over the generic classifier", func(t *testing.T) {
		perr := &proxydial.ProxyError{Reason: telemetry.ProbeReasonProxyAuth}
		reason, atTarget := classifyProxyAwareError(perr, true)
		if reason != telemetry.ProbeReasonProxyAuth || atTarget {
			t.Fatalf("reason = %d atTarget = %v, want ProxyAuth at the proxy", reason, atTarget)
		}
	})
	t.Run("a proxy-reported target verdict stays with the target", func(t *testing.T) {
		perr := &proxydial.ProxyError{Reason: telemetry.ProbeReasonRefused, AtTarget: true}
		reason, atTarget := classifyProxyAwareError(perr, true)
		if reason != telemetry.ProbeReasonRefused || !atTarget {
			t.Fatalf("reason = %d atTarget = %v, want Refused at the target — a closed port is a real target verdict",
				reason, atTarget)
		}
	})
	t.Run("a non-proxy error on a proxied probe still blames the target", func(t *testing.T) {
		// It came from the tunnelled connection itself (a TLS failure, a read timeout),
		// so the target is the right attribution.
		_, atTarget := classifyProxyAwareError(plain, true)
		if !atTarget {
			t.Fatal("a tunnelled connection error was attributed to the proxy")
		}
	})
}

// errTimeoutStub is a timeout-shaped error for the classifier.
type errTimeoutStub struct{}

func (errTimeoutStub) Error() string { return "i/o timeout" }
func (errTimeoutStub) Timeout() bool { return true }
