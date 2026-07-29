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
	"github.com/nettact/agent/internal/proxydial"
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
	sched   *schedState
	guard   *netguard.Guard
	proxies *proxydial.Manager

	// allowExtended is whether probe.http.extended is effective, so a defensive
	// re-check at request-build time never sends a non-basic request the monitor
	// evaluator would have blocked.
	allowExtended bool

	// clients caches an *http.Client per (ignoreTLS, maxRedirects, proxy generation)
	// policy so we do not build a new TLS transport on every probe. The proxy id AND
	// its config_serial are part of the key: a re-keyed or re-credentialed proxy must
	// get a fresh transport, or its pooled connections would keep serving probes over
	// the egress path the operator just replaced.
	mu      sync.Mutex
	clients map[string]*http.Client
}

func NewHTTPCollector(guard *netguard.Guard, proxies *proxydial.Manager, allowExtended bool) *HTTPCollector {
	return &HTTPCollector{
		sched:         newSchedState(pcfg.DefaultHTTPInterval),
		guard:         guard,
		proxies:       proxies,
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
// redirect policy, dialing through proxy when the target is pinned to one.
// maxRedirects: 0 = library default (follow up to 10), <0 = never follow (report
// the first response), >0 = follow up to that many.
func (c *HTTPCollector) clientFor(ignoreTLS bool, maxRedirects int, proxy *proxydial.Dialer) *http.Client {
	// The proxy's generation is part of the key, not just its id: a rotated
	// credential or re-keyed tunnel produces a new generation, and reusing the cached
	// client would keep its pooled connections — and therefore the OLD egress path —
	// alive after the operator replaced it.
	proxyKey := "direct"
	if proxy != nil {
		proxyKey = proxy.Spec.ID + "@" + strconv.Itoa(proxy.Spec.ConfigSerial)
	}
	key := fmt.Sprintf("%t|%d|%s", ignoreTLS, maxRedirects, proxyKey)
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
	//
	// A pinned target swaps DialContext for the proxy's tunnelled dial — and still
	// never sets Transport.Proxy. Going through DialContext keeps TLS verification,
	// SNI, redirect classification and the response caps exactly as configured, and
	// keeps the request in origin-form so the probe's headers are never handed to the
	// proxy the way an absolute-URI request would.
	//
	// proxyDialFunc (not proxy.DialContext directly) is what keeps the guard's
	// address check alive through the proxy: in the default local-DNS mode it resolves
	// and vets the host here and hands the proxy the approved literal. Handing over a
	// hostname would move resolution to the far side, where no ip:/cidr:/scope: rule
	// could be applied. Redirects use this same dial, so each hop is vetted too.
	//
	// TLS is unaffected by dialing a literal: Transport takes ServerName from the
	// request URL, not from the dial address.
	dial := proxyDialFunc(c.guard, proxy)
	tr := &http.Transport{
		Proxy:                 nil,
		DialContext:           dial,
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
			if err := c.classifyRedirect(req, proxy); err != nil {
				return err
			}
			return base(req, via)
		}
	}
	// Evict the superseded generations of this proxy and close their idle connections.
	// The cache key includes the generation so a rotated credential gets a fresh
	// transport — but without this the old transport stayed in the map holding pooled
	// connections to the replaced egress until they idled out.
	if proxy != nil {
		c.evictProxyClientsLocked(proxy.Spec.ID, proxy.Spec.ConfigSerial, key)
	}
	c.clients[key] = cl
	return cl
}

// evictProxyClientsLocked drops cached clients belonging to older generations of a
// proxy, closing their idle connections. Caller holds mu.
//
// Keys are "<ignoreTLS>|<maxRedirects>|<proxyID>@<serial>", so one proxy legitimately
// has several live entries (one per TLS/redirect policy). Only entries whose serial
// differs from the current one are stale.
func (c *HTTPCollector) evictProxyClientsLocked(proxyID string, serial int, keep string) {
	liveSerial := strconv.Itoa(serial)
	for k, cl := range c.clients {
		if k == keep {
			continue
		}
		// The proxy part is the key's last "|"-separated field.
		tail := k
		if i := strings.LastIndex(k, "|"); i >= 0 {
			tail = k[i+1:]
		}
		id, entrySerial, ok := strings.Cut(tail, "@")
		if !ok || id != proxyID || entrySerial == liveSerial {
			continue
		}
		if tr, ok := cl.Transport.(*http.Transport); ok {
			tr.CloseIdleConnections()
		}
		delete(c.clients, k)
	}
}

// classifyRedirect refuses a redirect whose host the policy denies, before the
// transport dials it. Deny is conclusive; a resolvable-but-authorized host is
// vetted at dial time by the guard.
func (c *HTTPCollector) classifyRedirect(req *http.Request, proxy *proxydial.Dialer) error {
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
	hd := c.guard.CheckHost(host)
	if hd.Denied {
		return &netguard.BlockedError{Target: host, Matched: hd.Matched}
	}
	// Under proxy-side DNS the name is resolved on the far side, so the address check
	// at dial time can never run — the pre-resolution NAME check is the only gate
	// there is, and it has to be conclusive rather than merely "not denied".
	//
	// monitoreval applies exactly this rule to the target's own hostname, but a
	// redirect destination is discovered at runtime and never passed through it. Without
	// this an authorized endpoint could bounce the probe to any host the policy simply
	// never mentions. Every other mode is covered at dial time by proxyDialFunc /
	// guard.DialContext vetting the resolved address.
	if proxy != nil && proxy.ResolvesRemotely() && !hd.NameAuthorized {
		return &netguard.BlockedError{Target: host, FromResolve: true}
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
		// Resolve the pinned egress proxy. A pin that cannot be honored is a probe
		// FAILURE reported as such — never a direct dial, which would send the request
		// from the real egress IP the operator routed away from and make an "up" verdict
		// meaningless.
		proxy, perr := resolveProxy(ctx, c.proxies, t)
		if perr != nil {
			res.Metrics = append(res.Metrics, proxyFailureMetrics(now, t, telemetry.HTTPOK, telemetry.HTTPErrorClass, nil, perr)...)
			res.Events = append(res.Events, proxyFailureEvent(now, t, "HTTP request not attempted"))
			continue
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

		client := c.clientFor(t.Params.IgnoreTLS, t.Params.MaxRedirects, proxy)
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
			// Classify the transport failure (DNS/refused/timeout/unreachable/TLS) so a
			// fired alert records WHY, not just "unavailable", with the raw transport
			// error as the detail behind the code. No status/latency metric — the
			// request never completed.
			//
			// For a proxied target the classification also decides WHOSE failure it was:
			// a proxy that is down or rejecting must not be reported as an unreachable
			// site, or the alert sends someone to investigate a healthy service.
			reason, atTarget := classifyProxyAwareError(err, proxy != nil)
			msg := "HTTP request failed: " + t.Target
			if !atTarget {
				msg = "HTTP request failed at the egress proxy: " + t.Target
			}
			res.Metrics = append(res.Metrics, telemetry.Metric{
				TS: now, Kind: telemetry.HTTPOK, Target: t.Target, Layer: telemetry.LayerService, Value: 0, Unit: telemetry.UnitBool,
				MonitorID: t.MonitorID, ConfigSerial: t.ConfigSerial,
			}, telemetry.Metric{
				TS: now, Kind: telemetry.HTTPErrorClass, Target: t.Target, Layer: telemetry.LayerService,
				Value: float64(reason), Unit: telemetry.UnitCode,
				Labels:    withDetail(nil, errText(err)),
				MonitorID: t.MonitorID, ConfigSerial: t.ConfigSerial,
			})
			res.Events = append(res.Events, telemetry.Event{
				ID: newID(), TS: now, Type: telemetry.EventProbeFailed, Layer: telemetry.LayerService,
				Severity: telemetry.SeverityWarn, Message: msg,
			})
			continue
		}
		status := resp.StatusCode

		// Read the body only when a keyword match is configured, bounded so a large
		// response can't blow up agent memory. Otherwise drain a little and close.
		bodyMatch := true
		// bodyErr is kept so a body cut short by a reset/truncation is not mistaken
		// for a content mismatch: reading only part of the body proves nothing about
		// what the rest contained. Hitting the LimitReader cap is not an error
		// (ReadAll swallows the EOF), so a legitimately large body stays unaffected.
		var bodyErr error
		if t.Params.Keyword != "" {
			limit := t.Params.MaxResponseBytes
			if limit <= 0 {
				limit = defaultMaxResponseBytes
			}
			var buf []byte
			buf, bodyErr = io.ReadAll(io.LimitReader(resp.Body, int64(limit)))
			found := strings.Contains(string(buf), t.Params.Keyword)
			bodyMatch = found != t.Params.KeywordInvert // invert flips the required condition
		}
		resp.Body.Close()
		cancel()

		statusOK := statusAccepted(status, t.Params.AcceptedStatuses)
		ok := 0.0
		if statusOK && bodyMatch {
			ok = 1.0
		}
		// The headers arrived, so a failure here is normally an acceptance failure:
		// the rejected status or keyword IS the reason, carried as its own refined
		// code (a status rejection outranks a keyword miss — the body of an
		// unaccepted response proves nothing) with the concrete rejection as the
		// detail. The exception is a keyword miss on a body that failed to read
		// through: that is a transport fault, not bad content, so it classifies by
		// the read error. None only when the probe fully passed.
		errClass := telemetry.ProbeReasonNone
		detail := ""
		switch {
		case !statusOK:
			errClass = telemetry.ProbeReasonHTTPStatus
			detail = "HTTP " + strconv.Itoa(status)
		case !bodyMatch && bodyErr != nil:
			errClass = classifyNetError(bodyErr)
			detail = errText(bodyErr)
		case !bodyMatch:
			// State the configured check that failed: without invert the keyword was
			// required and missing; with invert it was forbidden and present.
			errClass = telemetry.ProbeReasonHTTPKeyword
			if t.Params.KeywordInvert {
				detail = "keyword " + strconv.Quote(t.Params.Keyword) + " unexpectedly present"
			} else {
				detail = "keyword " + strconv.Quote(t.Params.Keyword) + " not found"
			}
		}
		ec := telemetry.Metric{TS: now, Kind: telemetry.HTTPErrorClass, Target: t.Target, Layer: telemetry.LayerService, Value: float64(errClass), Unit: telemetry.UnitCode, MonitorID: t.MonitorID, ConfigSerial: t.ConfigSerial}
		if errClass != telemetry.ProbeReasonNone {
			ec.Labels = withDetail(nil, detail)
		}
		res.Metrics = append(res.Metrics,
			telemetry.Metric{TS: now, Kind: telemetry.HTTPStatus, Target: t.Target, Layer: telemetry.LayerService, Value: float64(status), Unit: telemetry.UnitCode, MonitorID: t.MonitorID, ConfigSerial: t.ConfigSerial},
			telemetry.Metric{TS: now, Kind: telemetry.HTTPLat, Target: t.Target, Layer: telemetry.LayerService, Value: lat, Unit: telemetry.UnitMs, MonitorID: t.MonitorID, ConfigSerial: t.ConfigSerial},
			telemetry.Metric{TS: now, Kind: telemetry.HTTPOK, Target: t.Target, Layer: telemetry.LayerService, Value: ok, Unit: telemetry.UnitBool, MonitorID: t.MonitorID, ConfigSerial: t.ConfigSerial},
			ec,
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

// statusAccepted decides whether an HTTP status counts as up: the accepted CSV
// of codes/ranges (e.g. "200-299,301") when non-empty, else any 2xx or 3xx.
func statusAccepted(status int, accepted string) bool {
	if accepted == "" {
		return status >= 200 && status < 400
	}
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

// SetMinInterval applies the local per-target probe-interval floor (stability limit).
func (c *HTTPCollector) SetMinInterval(d time.Duration) { c.sched.SetMinInterval(d) }
