package collector

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"sync"
	"testing"
	"time"

	pcfg "github.com/nettact/protocol/config"
	"github.com/nettact/protocol/telemetry"
)

func runHTTPFanoutCycle(c *HTTPCollector, target pcfg.ProbeTarget) Result {
	return c.runFanout(context.Background(), target, time.Now().UTC(), httpTimeout(target.Params), func() {})
}

func TestHTTPFanoutUsesStableDistinctSourcePorts(t *testing.T) {
	var mu sync.Mutex
	var cycles [][]int
	current := []int{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, rawPort, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			t.Errorf("split remote address: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		port, _ := strconv.Atoi(rawPort)
		mu.Lock()
		current = append(current, port)
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	c := NewHTTPCollector(testGuard(), nil, true, nil)
	target := pcfg.ProbeTarget{MonitorID: "http_fanout", ConfigSerial: 7, Kind: "http", Target: srv.URL,
		Params: pcfg.ProbeParams{Method: http.MethodGet, FlowFanout: 4, MaxRedirects: -1, TimeoutMs: 3000}}
	for cycle := 0; cycle < 2; cycle++ {
		res := runHTTPFanoutCycle(c, target)
		if ok := metricByKind(res, telemetry.HTTPOK); ok == nil || ok.Value != 1 {
			t.Fatalf("cycle %d http.ok = %+v, want 1", cycle+1, ok)
		}
		ff := metricByKind(res, telemetry.HTTPFlowFanout)
		if ff == nil || ff.Value != 1 || ff.Labels[telemetry.FlowFanoutFlowsLabel] != "4" || ff.Labels[telemetry.FlowFanoutOKLabel] != "4" {
			t.Fatalf("cycle %d flow fan-out = %+v, want four clean branches", cycle+1, ff)
		}
		for _, kind := range []telemetry.MetricKind{telemetry.HTTPTotalMs, telemetry.HTTPTTFBMs, telemetry.HTTPConnectMs} {
			if metricByKind(res, kind) == nil {
				t.Fatalf("cycle %d missing fan-out %s", cycle+1, kind)
			}
		}
		if reused := metricByKind(res, telemetry.HTTPConnectionReused); reused == nil || reused.Value != 0 {
			t.Fatalf("cycle %d connection_reused = %+v, want 0 with keep-alives disabled", cycle+1, reused)
		}
		mu.Lock()
		got := append([]int(nil), current...)
		current = nil
		mu.Unlock()
		sort.Ints(got)
		if len(got) != 4 {
			t.Fatalf("cycle %d source ports = %v, want four requests", cycle+1, got)
		}
		for i := 1; i < len(got); i++ {
			if got[i] == got[i-1] {
				t.Fatalf("cycle %d reused a connection/source port: %v", cycle+1, got)
			}
		}
		cycles = append(cycles, got)
	}
	for i := range cycles[0] {
		if cycles[0][i] != cycles[1][i] {
			t.Fatalf("source-port set changed across cycles: %v vs %v", cycles[0], cycles[1])
		}
	}
}

func TestHTTPFanoutClassifiesStableFailingBranch(t *testing.T) {
	badSourcePort := 0
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, rawPort, _ := net.SplitHostPort(r.RemoteAddr)
		port, _ := strconv.Atoi(rawPort)
		mu.Lock()
		if badSourcePort == 0 {
			badSourcePort = port
		}
		bad := port == badSourcePort
		mu.Unlock()
		if bad {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := NewHTTPCollector(testGuard(), nil, true, nil)
	target := pcfg.ProbeTarget{MonitorID: "http_bad_branch", ConfigSerial: 2, Kind: "http", Target: srv.URL,
		Params: pcfg.ProbeParams{Method: http.MethodHead, FlowFanout: 4, MaxRedirects: -1, TimeoutMs: 3000}}
	first := runHTTPFanoutCycle(c, target)
	if ff := metricByKind(first, telemetry.HTTPFlowFanout); ff == nil || ff.Value != 1 || ff.Labels[telemetry.FlowFanoutBadNewLabel] != "1" {
		t.Fatalf("first cycle fan-out = %+v, want one new bad branch", ff)
	}
	second := runHTTPFanoutCycle(c, target)
	ff := metricByKind(second, telemetry.HTTPFlowFanout)
	if ff == nil || ff.Value != 2 || ff.Labels[telemetry.FlowFanoutBadStableLabel] != "1" || ff.Labels[telemetry.FlowFanoutOKLabel] != "3" {
		t.Fatalf("second cycle fan-out = %+v, want stable 1 bad / 3 clean", ff)
	}
	if ok := metricByKind(second, telemetry.HTTPOK); ok == nil || ok.Value != 0 {
		t.Fatalf("aggregate http.ok = %+v, want 0 when one branch failed", ok)
	}
	if status := metricByKind(second, telemetry.HTTPStatus); status == nil || status.Value != http.StatusServiceUnavailable {
		t.Fatalf("representative status = %+v, want failing branch 503", status)
	}
	if ec := metricByKind(second, telemetry.HTTPErrorClass); ec == nil || ec.Value != float64(telemetry.ProbeReasonHTTPStatus) {
		t.Fatalf("error class = %+v, want HTTP status failure", ec)
	}
}

func TestHTTPFanoutTruncatedKeywordBodiesOmitTiming(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		conn, buf, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Errorf("hijack: %v", err)
			return
		}
		defer conn.Close()
		_, _ = buf.WriteString("HTTP/1.1 200 OK\r\nContent-Length: 4096\r\n\r\npartial")
		_ = buf.Flush()
	}))
	defer srv.Close()

	c := NewHTTPCollector(testGuard(), nil, true, nil)
	target := pcfg.ProbeTarget{MonitorID: "http_truncated_fanout", ConfigSerial: 3, Kind: "http", Target: srv.URL,
		Params: pcfg.ProbeParams{Keyword: "welcome", FlowFanout: 4, MaxRedirects: -1, TimeoutMs: 3000}}
	res := runHTTPFanoutCycle(c, target)

	if ok := metricByKind(res, telemetry.HTTPOK); ok == nil || ok.Value != 0 {
		t.Fatalf("http.ok = %+v, want 0", ok)
	}
	if ec := metricByKind(res, telemetry.HTTPErrorClass); ec == nil || ec.Value == float64(telemetry.ProbeReasonHTTPKeyword) {
		t.Fatalf("error class = %+v, want a transport failure", ec)
	}
	for _, kind := range []telemetry.MetricKind{
		telemetry.HTTPTotalMs, telemetry.HTTPTTFBMs, telemetry.HTTPDNSMs,
		telemetry.HTTPConnectMs, telemetry.HTTPTLSMs, telemetry.HTTPConnectionReused,
	} {
		if got := metricByKind(res, kind); got != nil {
			t.Fatalf("truncated fan-out unexpectedly emitted %s: %+v", kind, got)
		}
	}
}
