package collector

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/nettact/agent/internal/netguard"
	"github.com/nettact/agent/probepolicy"
	pcfg "github.com/nettact/protocol/config"
	"github.com/nettact/protocol/telemetry"
)

// httpCollect runs one HTTP probe cycle for a single target.
func httpCollect(t *testing.T, target pcfg.ProbeTarget) Result {
	t.Helper()
	c := NewHTTPCollector(netguard.New(probepolicy.Policy{}, true), nil, true, nil)
	c.SetTargets([]pcfg.ProbeTarget{target})
	return collectSettled(t, context.Background(), c)
}

func httpRunTarget(c *HTTPCollector, target pcfg.ProbeTarget) Result {
	res, _ := c.runTarget(context.Background(), scheduledProbe{Target: target, NextDue: time.Now().Add(time.Minute)})
	return res
}

func metricValue(t *testing.T, res Result, kind telemetry.MetricKind) float64 {
	t.Helper()
	m := metricByKind(res, kind)
	if m == nil {
		t.Fatalf("missing %s metric in %+v", kind, res.Metrics)
	}
	return m.Value
}

func TestHTTPTimingIncludesRequiredBodyWork(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		time.Sleep(80 * time.Millisecond)
		_, _ = io.WriteString(w, "ready")
	}))
	defer srv.Close()

	res := httpCollect(t, pcfg.ProbeTarget{MonitorID: "timed-body", Kind: "http", Target: srv.URL,
		Params: pcfg.ProbeParams{Keyword: "ready", TimeoutMs: 2000}})
	total := metricValue(t, res, telemetry.HTTPTotalMs)
	ttfb := metricValue(t, res, telemetry.HTTPTTFBMs)
	if total < 60 {
		t.Fatalf("total_ms = %.3f, want delayed keyword body included", total)
	}
	if total-ttfb < 50 {
		t.Fatalf("total_ms - ttfb_ms = %.3f, want body delay excluded from TTFB", total-ttfb)
	}
	if legacy := metricValue(t, res, telemetry.HTTPLat); legacy >= total-40 {
		t.Fatalf("legacy latency_ms = %.3f, total_ms = %.3f; legacy header timing changed", legacy, total)
	}
}

func TestHTTPTTFBUsesFinalRedirectResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/start" {
			http.Redirect(w, r, "/final", http.StatusFound)
			return
		}
		time.Sleep(70 * time.Millisecond)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	res := httpCollect(t, pcfg.ProbeTarget{MonitorID: "redirect-ttfb", Kind: "http", Target: srv.URL + "/start",
		Params: pcfg.ProbeParams{TimeoutMs: 2000}})
	if got := metricValue(t, res, telemetry.HTTPTTFBMs); got < 50 {
		t.Fatalf("ttfb_ms = %.3f, want final redirect response delay", got)
	}
	if got := metricValue(t, res, telemetry.HTTPConnectionReused); got != 1 {
		t.Fatalf("connection_reused = %.0f, want final redirect hop's reused connection", got)
	}
}

func TestHTTPTimingOmitsPhasesOnConnectionReuse(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	_, port, err := net.SplitHostPort(u.Host)
	if err != nil {
		t.Fatal(err)
	}
	u.Host = net.JoinHostPort("localhost", port)
	target := pcfg.ProbeTarget{MonitorID: "reuse", Kind: "http", Target: u.String(),
		Params: pcfg.ProbeParams{Method: http.MethodHead, IgnoreTLS: true, TimeoutMs: 2000}}
	c := NewHTTPCollector(netguard.New(probepolicy.Policy{}, true), nil, true, nil)

	first := httpRunTarget(c, target)
	if got := metricValue(t, first, telemetry.HTTPConnectionReused); got != 0 {
		t.Fatalf("first connection_reused = %.0f, want new connection", got)
	}
	for _, kind := range []telemetry.MetricKind{telemetry.HTTPDNSMs, telemetry.HTTPConnectMs, telemetry.HTTPTLSMs} {
		if metricByKind(first, kind) == nil {
			t.Fatalf("first request missing %s", kind)
		}
	}

	second := httpRunTarget(c, target)
	if got := metricValue(t, second, telemetry.HTTPConnectionReused); got != 1 {
		t.Fatalf("second connection_reused = %.0f, want pooled connection", got)
	}
	for _, kind := range []telemetry.MetricKind{telemetry.HTTPDNSMs, telemetry.HTTPConnectMs, telemetry.HTTPTLSMs} {
		if got := metricByKind(second, kind); got != nil {
			t.Fatalf("reused request unexpectedly emitted %s: %+v", kind, got)
		}
	}
}

func TestHTTPTransportFailureOmitsTimingMetrics(t *testing.T) {
	dead := httptest.NewServer(http.NotFoundHandler())
	deadURL := dead.URL
	dead.Close()
	res := httpCollect(t, pcfg.ProbeTarget{MonitorID: "timing-failure", Kind: "http", Target: deadURL,
		Params: pcfg.ProbeParams{TimeoutMs: 2000}})
	for _, kind := range []telemetry.MetricKind{
		telemetry.HTTPTotalMs, telemetry.HTTPTTFBMs, telemetry.HTTPDNSMs,
		telemetry.HTTPConnectMs, telemetry.HTTPTLSMs, telemetry.HTTPConnectionReused,
	} {
		if got := metricByKind(res, kind); got != nil {
			t.Fatalf("transport failure unexpectedly emitted %s: %+v", kind, got)
		}
	}
}

func TestHTTPTimingIgnoresLateBindingLoserDial(t *testing.T) {
	firstArrived := make(chan struct{})
	secondArrived := make(chan struct{})
	releaseFirst := make(chan struct{})
	releaseSecond := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/first":
			close(firstArrived)
			<-releaseFirst
		case "/second":
			close(secondArrived)
			<-releaseSecond
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	secondDialStarted := make(chan struct{})
	releaseSecondDial := make(chan struct{})
	secondDialDone := make(chan struct{})
	var dialMu sync.Mutex
	dialCount := 0
	dialer := &net.Dialer{}
	tr := &http.Transport{Proxy: nil, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		dialMu.Lock()
		dialCount++
		n := dialCount
		dialMu.Unlock()
		if n == 2 {
			close(secondDialStarted)
			<-releaseSecondDial
		}
		conn, err := dialer.DialContext(ctx, network, address)
		if err != nil {
			return nil, err
		}
		timed := &httpTimingConn{Conn: conn, connectMs: float64(n * 100), haveConnect: true}
		if n == 2 {
			close(secondDialDone)
		}
		return timed, nil
	}}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr}

	firstDone := make(chan error, 1)
	go func() {
		resp, err := client.Get(srv.URL + "/first")
		if err == nil {
			err = resp.Body.Close()
		}
		firstDone <- err
	}()
	waitHTTPTestSignal(t, firstArrived, "first request to arrive")

	timing := &httpTimingTrace{}
	req, err := http.NewRequest(http.MethodGet, srv.URL+"/second", nil)
	if err != nil {
		t.Fatal(err)
	}
	req = timing.traceRequest(req)
	timing.started = time.Now()
	secondResponse := make(chan struct {
		resp *http.Response
		err  error
	}, 1)
	go func() {
		resp, requestErr := client.Do(req)
		secondResponse <- struct {
			resp *http.Response
			err  error
		}{resp: resp, err: requestErr}
	}()
	waitHTTPTestSignal(t, secondDialStarted, "second dial to start")

	// Returning the first connection to the pool late-binds the waiting second
	// request to it even though its own dial is already running.
	close(releaseFirst)
	waitHTTPTestSignal(t, secondArrived, "second request to use the returned connection")

	// Complete the now-unused candidate before the second response. A dial-time
	// recorder would contaminate the second request here; connection-bound timing
	// remains uncommitted because GotConn selected the reused first connection.
	close(releaseSecondDial)
	waitHTTPTestSignal(t, secondDialDone, "late-binding loser dial to finish")
	close(releaseSecond)
	got := <-secondResponse
	if got.err != nil {
		t.Fatalf("second request: %v", got.err)
	}
	_ = got.resp.Body.Close()
	if err := <-firstDone; err != nil {
		t.Fatalf("first request: %v", err)
	}
	snapshot := timing.finish()
	if !snapshot.haveReuse || !snapshot.reused {
		t.Fatalf("second request reuse = have %t value %t, want reused connection", snapshot.haveReuse, snapshot.reused)
	}
	if snapshot.haveConn {
		t.Fatalf("late-bound request recorded unused dial connect_ms = %.3f", snapshot.connMs)
	}
}

func TestHTTPTTFBOmittedAfterInformationalResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Link", "</style.css>; rel=preload")
		w.WriteHeader(http.StatusEarlyHints)
		w.(http.Flusher).Flush()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	res := httpCollect(t, pcfg.ProbeTarget{MonitorID: "early-hints", Kind: "http", Target: srv.URL})
	if metricByKind(res, telemetry.HTTPTotalMs) == nil {
		t.Fatal("completed request missing total_ms")
	}
	if got := metricByKind(res, telemetry.HTTPTTFBMs); got != nil {
		t.Fatalf("TTFB from 103 was reported as final response timing: %+v", got)
	}
}

func waitHTTPTestSignal(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(3 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
	}
}

func TestHTTPErrorClassDetail(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/down" {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	t.Run("success has no detail", func(t *testing.T) {
		res := httpCollect(t, pcfg.ProbeTarget{MonitorID: "h1", Kind: "http", Target: srv.URL + "/ok"})
		ec := metricByKind(res, telemetry.HTTPErrorClass)
		if ec == nil || ec.Value != float64(telemetry.ProbeReasonNone) {
			t.Fatalf("success error_class = %+v, want None", ec)
		}
		if _, has := ec.Labels[telemetry.ProbeReasonDetailLabel]; has {
			t.Fatalf("success error_class must not carry a detail label: %+v", ec.Labels)
		}
	})

	t.Run("unaccepted status", func(t *testing.T) {
		res := httpCollect(t, pcfg.ProbeTarget{MonitorID: "h2", Kind: "http", Target: srv.URL + "/down"})
		ec := metricByKind(res, telemetry.HTTPErrorClass)
		if ec == nil || ec.Value != float64(telemetry.ProbeReasonHTTPStatus) {
			t.Fatalf("error_class = %+v, want HTTPStatus", ec)
		}
		if got := ec.Labels[telemetry.ProbeReasonDetailLabel]; got != "HTTP 503" {
			t.Fatalf("detail = %q, want \"HTTP 503\"", got)
		}
		// probe.http.ok / probe.http.status semantics are unchanged by the reason.
		if okm := metricByKind(res, telemetry.HTTPOK); okm == nil || okm.Value != 0 {
			t.Fatalf("http.ok = %+v, want 0", okm)
		}
		if sm := metricByKind(res, telemetry.HTTPStatus); sm == nil || sm.Value != 503 {
			t.Fatalf("http.status = %+v, want 503", sm)
		}
	})

	t.Run("keyword missing", func(t *testing.T) {
		res := httpCollect(t, pcfg.ProbeTarget{MonitorID: "h3", Kind: "http", Target: srv.URL + "/ok",
			Params: pcfg.ProbeParams{Keyword: "welcome"}})
		ec := metricByKind(res, telemetry.HTTPErrorClass)
		if ec == nil || ec.Value != float64(telemetry.ProbeReasonHTTPKeyword) {
			t.Fatalf("error_class = %+v, want HTTPKeyword", ec)
		}
		if got := ec.Labels[telemetry.ProbeReasonDetailLabel]; got != `keyword "welcome" not found` {
			t.Fatalf("detail = %q", got)
		}
	})

	// A body cut short mid-transfer is a transport fault, not bad content: the
	// keyword may well have been in the part that never arrived, so blaming the
	// content would send the operator hunting for a page change that never
	// happened.
	t.Run("keyword miss on a truncated body blames the transport", func(t *testing.T) {
		cut := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			conn, buf, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Errorf("hijack: %v", err)
				return
			}
			defer conn.Close()
			// Promise 4096 bytes, deliver a few, then hang up.
			buf.WriteString("HTTP/1.1 200 OK\r\nContent-Length: 4096\r\n\r\npartial")
			buf.Flush()
		}))
		defer cut.Close()

		res := httpCollect(t, pcfg.ProbeTarget{MonitorID: "h5", Kind: "http", Target: cut.URL,
			Params: pcfg.ProbeParams{Keyword: "welcome", TimeoutMs: 3000}})
		ec := metricByKind(res, telemetry.HTTPErrorClass)
		if ec == nil {
			t.Fatal("missing error_class metric")
		}
		if ec.Value == float64(telemetry.ProbeReasonHTTPKeyword) {
			t.Fatalf("a truncated body was blamed on content (HTTPKeyword); want a transport class")
		}
		if ec.Value != float64(telemetry.ProbeReasonOther) && ec.Value != float64(telemetry.ProbeReasonReset) {
			t.Fatalf("error_class = %v, want Other or Reset", ec.Value)
		}
		if ec.Labels[telemetry.ProbeReasonDetailLabel] == "" {
			t.Fatalf("truncated body missing detail label: %+v", ec.Labels)
		}
		if okm := metricByKind(res, telemetry.HTTPOK); okm == nil || okm.Value != 0 {
			t.Fatalf("http.ok = %+v, want 0", okm)
		}
		for _, kind := range []telemetry.MetricKind{
			telemetry.HTTPTotalMs, telemetry.HTTPTTFBMs, telemetry.HTTPDNSMs,
			telemetry.HTTPConnectMs, telemetry.HTTPTLSMs, telemetry.HTTPConnectionReused,
		} {
			if got := metricByKind(res, kind); got != nil {
				t.Fatalf("truncated body unexpectedly emitted %s: %+v", kind, got)
			}
		}
	})

	// The mirror case: once the keyword has been seen, a body that stops early
	// does not retract it — "contains" is already proven, so the probe passes.
	t.Run("keyword found before truncation still passes", func(t *testing.T) {
		cut := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			conn, buf, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Errorf("hijack: %v", err)
				return
			}
			defer conn.Close()
			buf.WriteString("HTTP/1.1 200 OK\r\nContent-Length: 4096\r\n\r\nwelcome home")
			buf.Flush()
		}))
		defer cut.Close()

		res := httpCollect(t, pcfg.ProbeTarget{MonitorID: "h6", Kind: "http", Target: cut.URL,
			Params: pcfg.ProbeParams{Keyword: "welcome", TimeoutMs: 3000}})
		ec := metricByKind(res, telemetry.HTTPErrorClass)
		if ec == nil || ec.Value != float64(telemetry.ProbeReasonNone) {
			t.Fatalf("error_class = %+v, want None", ec)
		}
		if okm := metricByKind(res, telemetry.HTTPOK); okm == nil || okm.Value != 1 {
			t.Fatalf("http.ok = %+v, want 1", okm)
		}
		for _, kind := range []telemetry.MetricKind{telemetry.HTTPTotalMs, telemetry.HTTPTTFBMs} {
			if got := metricByKind(res, kind); got == nil {
				t.Fatalf("completed keyword verdict missing %s", kind)
			}
		}
	})

	t.Run("transport failure carries the dial error", func(t *testing.T) {
		dead := httptest.NewServer(http.NotFoundHandler())
		deadURL := dead.URL
		dead.Close() // the port is now closed: the connect is actively refused
		res := httpCollect(t, pcfg.ProbeTarget{MonitorID: "h4", Kind: "http", Target: deadURL,
			Params: pcfg.ProbeParams{TimeoutMs: 3000}})
		ec := metricByKind(res, telemetry.HTTPErrorClass)
		if ec == nil || ec.Value != float64(telemetry.ProbeReasonRefused) {
			t.Fatalf("error_class = %+v, want Refused", ec)
		}
		if ec.Labels[telemetry.ProbeReasonDetailLabel] == "" {
			t.Fatalf("transport failure missing detail label: %+v", ec.Labels)
		}
		// The request never completed: no status sample exists to carry a value.
		if sm := metricByKind(res, telemetry.HTTPStatus); sm != nil {
			t.Fatalf("unexpected http.status on transport failure: %+v", sm)
		}
	})
}
