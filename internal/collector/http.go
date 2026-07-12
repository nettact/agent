package collector

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/nettact/protocol/capability"
	pcfg "github.com/nettact/protocol/config"
	"github.com/nettact/protocol/telemetry"
)

// defaultMaxResponseBytes bounds how much body is read for keyword matching when
// a target does not set max_response_bytes. Defaults to 1 KiB.
const defaultMaxResponseBytes = 1024

// errTooManyRedirects marks a redirect chain that exceeded the configured limit
// as a failure (returned from CheckRedirect so Client.Do surfaces an error).
var errTooManyRedirects = errors.New("too many redirects")

// HTTPCollector performs HTTP/HTTPS availability checks against a
// server-configured URL set (architecture §4 service layer). Each URL carries
// its own per-target params (timeout, interval, method, status acceptance,
// keyword match, headers/body, redirect + TLS policy) and is probed on its own
// schedule via schedState.
type HTTPCollector struct {
	sched *schedState

	// clients caches an *http.Client per (ignoreTLS, maxRedirects) policy so we do
	// not build a new TLS transport on every probe. Access is guarded by mu.
	mu      sync.Mutex
	clients map[string]*http.Client
}

func NewHTTPCollector() *HTTPCollector {
	return &HTTPCollector{
		sched:   newSchedState(30 * time.Second),
		clients: map[string]*http.Client{},
	}
}

func (c *HTTPCollector) SetTargets(targets []pcfg.ProbeTarget) {
	var urls []pcfg.ProbeTarget
	for _, t := range targets {
		if t.Kind == "http" && t.Target != "" {
			urls = append(urls, t)
		}
	}
	c.sched.set(urls)
}

func (c *HTTPCollector) Name() string { return "http" }

func (c *HTTPCollector) Capabilities() []capability.Capability {
	return []capability.Capability{capability.ProbeHTTP}
}

func (c *HTTPCollector) Tier() Tier { return TierRegular }

// clientFor returns a cached client honoring the target's TLS-verification and
// redirect policy. maxRedirects: 0 = library default (follow up to 10), <0 =
// never follow (report the first response), >0 = follow up to that many.
func (c *HTTPCollector) clientFor(ignoreTLS bool, maxRedirects int) *http.Client {
	key := fmt.Sprintf("%t|%d", ignoreTLS, maxRedirects)
	c.mu.Lock()
	defer c.mu.Unlock()
	if cl, ok := c.clients[key]; ok {
		return cl
	}
	// Clone the default transport so proxy support (ProxyFromEnvironment) and the
	// stdlib dial/timeout defaults are preserved; only override TLS verification.
	// No client-level Timeout: each request is bounded by its own per-target
	// context timeout, so a configured TimeoutMs above the default is honored.
	tr := http.DefaultTransport.(*http.Transport).Clone()
	if ignoreTLS {
		if tr.TLSClientConfig == nil {
			tr.TLSClientConfig = &tls.Config{}
		}
		tr.TLSClientConfig.InsecureSkipVerify = true
	}
	cl := &http.Client{Transport: tr}
	switch {
	case maxRedirects < 0:
		cl.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	case maxRedirects > 0:
		// via holds the requests already made; on the Nth redirect len(via)==N.
		// Allow up to maxRedirects hops. Exceeding the limit is a real error (not
		// ErrUseLastResponse) so Client.Do fails and the probe is marked down,
		// rather than silently reporting the intermediate 3xx as success.
		cl.CheckRedirect = func(_ *http.Request, via []*http.Request) error {
			if len(via) > maxRedirects {
				return errTooManyRedirects
			}
			return nil
		}
	}
	c.clients[key] = cl
	return cl
}

func (c *HTTPCollector) Collect(ctx context.Context) (Result, error) {
	targets := c.sched.due(time.Now())
	if len(targets) == 0 {
		return Result{}, nil
	}

	now := time.Now().UTC()
	var res Result
	for _, t := range targets {
		timeout := time.Duration(t.Params.TimeoutMs) * time.Millisecond
		if timeout <= 0 {
			timeout = 10 * time.Second
		}
		method := t.Params.Method
		if method == "" {
			method = http.MethodGet
		}

		var bodyReader io.Reader
		if t.Params.Body != "" && method != http.MethodGet && method != http.MethodHead {
			bodyReader = strings.NewReader(t.Params.Body)
		}

		cctx, cancel := context.WithTimeout(ctx, timeout)
		req, err := http.NewRequestWithContext(cctx, method, t.Target, bodyReader)
		if err != nil {
			cancel()
			continue
		}
		for k, v := range t.Params.Headers {
			// Go's transport reads the Host header from req.Host, not req.Header, so a
			// custom Host (virtual-host probing) must be set there or it is ignored.
			if strings.EqualFold(k, "Host") {
				req.Host = v
				continue
			}
			req.Header.Set(k, v)
		}

		client := c.clientFor(t.Params.IgnoreTLS, t.Params.MaxRedirects)
		t0 := time.Now()
		resp, err := client.Do(req)
		lat := float64(time.Since(t0).Microseconds()) / 1000.0
		if err != nil {
			cancel()
			res.Metrics = append(res.Metrics, telemetry.Metric{
				TS: now, Kind: telemetry.HTTPOK, Target: t.Target, Layer: telemetry.LayerService, Value: 0, Unit: telemetry.UnitBool,
				MonitorID: t.MonitorID,
			})
			res.Events = append(res.Events, telemetry.Event{
				ID: newID(), TS: now, Type: telemetry.EventProbeFailed, Layer: telemetry.LayerService,
				Severity: telemetry.SeverityWarn, Message: "HTTP request failed: " + t.Target,
			})
			continue
		}
		status := resp.StatusCode

		// Read the body only when a keyword match is configured, bounded so a large
		// response can't blow up agent memory. Otherwise drain a little and close.
		bodyMatch := true
		if t.Params.Keyword != "" {
			limit := t.Params.MaxResponseBytes
			if limit <= 0 {
				limit = defaultMaxResponseBytes
			}
			buf, _ := io.ReadAll(io.LimitReader(resp.Body, int64(limit)))
			found := strings.Contains(string(buf), t.Params.Keyword)
			bodyMatch = found != t.Params.KeywordInvert // invert flips the required condition
		}
		resp.Body.Close()
		cancel()

		statusOK := statusAccepted(status, t.Params.AcceptedStatuses, t.Params.ExpectedStatus)
		ok := 0.0
		if statusOK && bodyMatch {
			ok = 1.0
		}
		res.Metrics = append(res.Metrics,
			telemetry.Metric{TS: now, Kind: telemetry.HTTPStatus, Target: t.Target, Layer: telemetry.LayerService, Value: float64(status), Unit: telemetry.UnitCode, MonitorID: t.MonitorID},
			telemetry.Metric{TS: now, Kind: telemetry.HTTPLat, Target: t.Target, Layer: telemetry.LayerService, Value: lat, Unit: telemetry.UnitMs, MonitorID: t.MonitorID},
			telemetry.Metric{TS: now, Kind: telemetry.HTTPOK, Target: t.Target, Layer: telemetry.LayerService, Value: ok, Unit: telemetry.UnitBool, MonitorID: t.MonitorID},
		)
	}
	return res, nil
}

// statusAccepted decides whether an HTTP status counts as up. Precedence:
//  1. accepted (CSV of codes/ranges, e.g. "200-299,301") when non-empty;
//  2. expected (legacy single exact code) when > 0;
//  3. default: any 2xx or 3xx.
func statusAccepted(status int, accepted string, expected int) bool {
	if accepted != "" {
		for _, part := range strings.Split(accepted, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			lo, hi, ok := strings.Cut(part, "-")
			if !ok {
				hi = lo
			}
			a, err1 := strconv.Atoi(strings.TrimSpace(lo))
			b, err2 := strconv.Atoi(strings.TrimSpace(hi))
			if err1 != nil || err2 != nil {
				continue
			}
			if status >= a && status <= b {
				return true
			}
		}
		return false
	}
	if expected > 0 {
		return status == expected
	}
	return status >= 200 && status < 400
}
