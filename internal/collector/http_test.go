package collector

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

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
