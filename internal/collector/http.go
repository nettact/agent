package collector

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/nettact/agent/internal/netguard"
	pcfg "github.com/nettact/protocol/config"
	"github.com/nettact/protocol/permission"
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
	guard *netguard.Guard

	// allowExtended is whether probe.http.extended is effective, so a defensive
	// re-check at request-build time never sends a non-basic request the monitor
	// evaluator would have blocked.
	allowExtended bool

	// clients caches an *http.Client per (ignoreTLS, maxRedirects) policy so we do
	// not build a new TLS transport on every probe. Access is guarded by mu.
	mu      sync.Mutex
	clients map[string]*http.Client
}

func NewHTTPCollector(guard *netguard.Guard, allowExtended bool) *HTTPCollector {
	return &HTTPCollector{
		sched:         newSchedState(pcfg.DefaultHTTPInterval),
		guard:         guard,
		allowExtended: allowExtended,
		clients:       map[string]*http.Client{},
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
	// Build a fresh transport with the environment proxy DISABLED and every dial
	// routed through the guard, so a cloned default transport can never dial an
	// allowed proxy that relays to a denied destination. The guard pins the vetted
	// IP; SNI/verification stay against the original host (ServerName defaults to
	// the request URL host). No client-level Timeout: each request is bounded by
	// its own per-target context timeout.
	tr := &http.Transport{
		Proxy:                 nil,
		DialContext:           c.guard.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
	}
	if ignoreTLS {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // opt-in via ignore_tls
	}
	cl := &http.Client{Transport: tr}
	// CheckRedirect classifies every redirect hop's host through the guard (a
	// denied hop is refused even though the dial would already block it) and keeps
	// the max-redirects accounting. maxRedirects 0 means "library default": Go's
	// stdlib caps an unconfigured chain at 10, so we reproduce that cap here (a
	// custom CheckRedirect otherwise disables the stdlib default and would follow
	// indefinitely until the context expires).
	base := func(_ *http.Request, via []*http.Request) error {
		limit := maxRedirects
		if limit == 0 {
			limit = 10
		}
		if len(via) > limit {
			return errTooManyRedirects
		}
		return nil
	}
	switch {
	case maxRedirects < 0:
		cl.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	default:
		cl.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			if err := c.classifyRedirect(req); err != nil {
				return err
			}
			return base(req, via)
		}
	}
	c.clients[key] = cl
	return cl
}

// classifyRedirect refuses a redirect whose host the policy denies, before the
// transport dials it. Deny is conclusive; a resolvable-but-authorized host is
// vetted at dial time by the guard.
func (c *HTTPCollector) classifyRedirect(req *http.Request) error {
	host := req.URL.Hostname()
	if host == "" {
		return nil
	}
	if a, err := netip.ParseAddr(host); err == nil {
		if dec := c.guard.CheckAddr(a.Unmap()); !dec.Allowed {
			return &netguard.BlockedError{Target: host, Matched: dec.Matched}
		}
		return nil
	}
	if hd := c.guard.CheckHost(host); hd.Denied {
		return &netguard.BlockedError{Target: host, Matched: hd.Matched}
	}
	return nil
}

func (c *HTTPCollector) Collect(ctx context.Context) (Result, error) {
	targets := c.sched.due(time.Now())
	if len(targets) == 0 {
		return Result{}, nil
	}

	now := time.Now().UTC()
	var res Result
	for _, t := range targets {
		// A pass aborted by run cancellation (agent shutdown) must not fabricate
		// request failures — they would replay from the WAL as a false service
		// outage on the next start.
		if ctx.Err() != nil {
			break
		}
		// Defensive re-check: a non-basic HTTP request requires probe.http.extended.
		// The monitor evaluator already excludes such targets when the permission is
		// absent, so this only fires on a policy/eval drift — skip silently, never a
		// metric.
		if !c.allowExtended && httpParamsNeedExtended(t.Params) {
			continue
		}
		timeout := time.Duration(t.Params.TimeoutMs) * time.Millisecond
		if timeout <= 0 {
			timeout = pcfg.DefaultHTTPTimeout
		}
		method := t.Params.Method
		if method == "" {
			method = http.MethodGet
		}

		var bodyReader io.Reader
		if t.Params.Body != "" {
			// Any request body requires probe.http.extended, so reaching here means it
			// is authorized (the defensive check above skips otherwise). Send it as
			// configured for every method, including GET/HEAD, rather than silently
			// dropping it.
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
			// A policy block (denied target, denied redirect hop, or a hostname that
			// resolved to a denied address) is NOT a probe failure: emit no metric or
			// event, and route the block to the monitor-status tracker.
			var be *netguard.BlockedError
			if errors.As(err, &be) {
				res.Blocked = append(res.Blocked, blockedFromErr(t, be))
				continue
			}
			if ctx.Err() != nil {
				break // the request was aborted by the cancelled run, not the service
			}
			res.Metrics = append(res.Metrics, telemetry.Metric{
				TS: now, Kind: telemetry.HTTPOK, Target: t.Target, Layer: telemetry.LayerService, Value: 0, Unit: telemetry.UnitBool,
				MonitorID: t.MonitorID, ConfigSerial: t.ConfigSerial,
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
			telemetry.Metric{TS: now, Kind: telemetry.HTTPStatus, Target: t.Target, Layer: telemetry.LayerService, Value: float64(status), Unit: telemetry.UnitCode, MonitorID: t.MonitorID, ConfigSerial: t.ConfigSerial},
			telemetry.Metric{TS: now, Kind: telemetry.HTTPLat, Target: t.Target, Layer: telemetry.LayerService, Value: lat, Unit: telemetry.UnitMs, MonitorID: t.MonitorID, ConfigSerial: t.ConfigSerial},
			telemetry.Metric{TS: now, Kind: telemetry.HTTPOK, Target: t.Target, Layer: telemetry.LayerService, Value: ok, Unit: telemetry.UnitBool, MonitorID: t.MonitorID, ConfigSerial: t.ConfigSerial},
		)
	}
	return res, nil
}

// httpParamsNeedExtended mirrors permission.RequiredForTarget's HTTP rule: a
// non-GET/HEAD method, a body, or any non-allowlisted header requires
// probe.http.extended.
func httpParamsNeedExtended(p pcfg.ProbeParams) bool {
	switch strings.ToUpper(strings.TrimSpace(p.Method)) {
	case "", "GET", "HEAD":
	default:
		return true
	}
	if p.Body != "" {
		return true
	}
	for name := range p.Headers {
		if !permission.BasicHTTPHeaderAllowed(name) {
			return true
		}
	}
	return false
}

// blockedFromErr builds a BlockedProbe from a policy block, choosing a reason
// that distinguishes a resolved/redirect block from a literal-IP block. It carries
// the originating target's MonitorID and ConfigSerial so the block is attributable
// to the exact generation that produced it.
func blockedFromErr(t pcfg.ProbeTarget, be *netguard.BlockedError) BlockedProbe {
	reason := "literal_denied"
	if be.FromResolve {
		reason = "resolved_denied"
	}
	return BlockedProbe{MonitorID: t.MonitorID, ConfigSerial: t.ConfigSerial, Matched: be.Matched, Reason: reason}
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

// SetMinInterval applies the local per-target probe-interval floor (stability limit).
func (c *HTTPCollector) SetMinInterval(d time.Duration) { c.sched.SetMinInterval(d) }
