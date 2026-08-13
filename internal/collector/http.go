package collector

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/netip"
	"net/textproto"
	"net/url"
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

// httpTimingTrace is scoped to one logical Client.Do call (including redirects).
// The cached Transport is shared by concurrent targets, so measurement state must
// travel in the request context rather than live on the client or transport.
type httpTimingTrace struct {
	mu sync.Mutex

	started time.Time

	firstByte     time.Time
	haveFirstByte bool
	gotConn       bool
	reused        bool

	dnsMs     float64
	connectMs float64
	tlsMs     float64
	haveDNS   bool
	haveConn  bool
	haveTLS   bool
}

type httpTimingSnapshot struct {
	totalMs float64
	ttfbMs  float64
	dnsMs   float64
	connMs  float64
	tlsMs   float64

	haveTTFB  bool
	haveDNS   bool
	haveConn  bool
	haveTLS   bool
	haveReuse bool
	reused    bool
}

// httpTimingConn carries the phase work that produced one candidate connection.
// A Transport can start this dial and then late-bind the request to a different
// idle connection. Keeping the candidate data on the connection means GotConn,
// which names the connection actually selected, is the only place that commits
// it to the request's timing totals.
type httpTimingConn struct {
	net.Conn
	dnsMs       float64
	connectMs   float64
	haveDNS     bool
	haveConnect bool

	ioMu      sync.Mutex
	ioStarted time.Time
	ioDone    time.Time
}

// Read and Write bracket all I/O below the Transport. Before GotConn, HTTPS
// uses that connection only for its TLS handshake; request bytes are written
// afterwards. The interval therefore measures the successful TLS handshake on
// the selected candidate without relying on trace callbacks that carry no
// connection identity and can belong to a late-binding loser.
func (c *httpTimingConn) Read(p []byte) (int, error) {
	c.noteIOStart()
	n, err := c.Conn.Read(p)
	c.noteIODone()
	return n, err
}

func (c *httpTimingConn) Write(p []byte) (int, error) {
	c.noteIOStart()
	n, err := c.Conn.Write(p)
	c.noteIODone()
	return n, err
}

func (c *httpTimingConn) noteIOStart() {
	c.ioMu.Lock()
	if c.ioStarted.IsZero() {
		c.ioStarted = time.Now()
	}
	c.ioMu.Unlock()
}

func (c *httpTimingConn) noteIODone() {
	c.ioMu.Lock()
	c.ioDone = time.Now()
	c.ioMu.Unlock()
}

func (c *httpTimingConn) tlsMs() (float64, bool) {
	c.ioMu.Lock()
	defer c.ioMu.Unlock()
	if c.ioStarted.IsZero() || c.ioDone.Before(c.ioStarted) {
		return 0, false
	}
	return durationMs(c.ioDone.Sub(c.ioStarted)), true
}

func selectedHTTPConnTiming(conn net.Conn) (*httpTimingConn, bool) {
	tlsUsed := false
	if tlsConn, ok := conn.(*tls.Conn); ok {
		conn = tlsConn.NetConn()
		tlsUsed = true
	}
	timed, _ := conn.(*httpTimingConn)
	return timed, tlsUsed
}

func (t *httpTimingTrace) traceRequest(req *http.Request) *http.Request {
	trace := &httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) {
			t.mu.Lock()
			defer t.mu.Unlock()
			// Redirect round trips are sequential. Overwriting here deliberately
			// leaves the connection used by the final response.
			t.gotConn = true
			t.reused = info.Reused
			if info.Reused {
				return
			}
			connTiming, tlsUsed := selectedHTTPConnTiming(info.Conn)
			if connTiming == nil {
				return
			}
			if connTiming.haveDNS {
				t.dnsMs += connTiming.dnsMs
				t.haveDNS = true
			}
			if connTiming.haveConnect {
				t.connectMs += connTiming.connectMs
				t.haveConn = true
			}
			if tlsMs, ok := connTiming.tlsMs(); tlsUsed && ok {
				t.tlsMs += tlsMs
				t.haveTLS = true
			}
		},
		GotFirstResponseByte: func() {
			t.mu.Lock()
			// The last callback belongs to the final redirect hop.
			t.firstByte = time.Now()
			t.haveFirstByte = true
			t.mu.Unlock()
		},
		Got1xxResponse: func(_ int, _ textproto.MIMEHeader) error {
			t.mu.Lock()
			// net/http calls GotFirstResponseByte only once per round trip. If an
			// informational response arrived first, there is no trace hook for the
			// final response's first byte, so omit TTFB for this hop. A later
			// redirect hop gets its own GotFirstResponseByte and restores it.
			t.haveFirstByte = false
			t.mu.Unlock()
			return nil
		},
	}
	return req.WithContext(httptrace.WithClientTrace(req.Context(), trace))
}

func (t *httpTimingTrace) finish() httpTimingSnapshot {
	t.mu.Lock()
	defer t.mu.Unlock()
	s := httpTimingSnapshot{
		totalMs: durationMs(time.Since(t.started)),
		dnsMs:   t.dnsMs, connMs: t.connectMs, tlsMs: t.tlsMs,
		haveDNS: t.haveDNS, haveConn: t.haveConn, haveTLS: t.haveTLS,
		haveReuse: t.gotConn, reused: t.reused,
	}
	if t.haveFirstByte {
		s.ttfbMs = durationMs(t.firstByte.Sub(t.started))
		s.haveTTFB = true
	}
	return s
}

func durationMs(d time.Duration) float64 {
	return float64(d.Microseconds()) / 1000.0
}

// httpDialFunc preserves proxyDialFunc's fail-closed resolve/vet/pin behavior,
// while splitting the phases whose duration can be attributed to the target.
// The whole successful DialVettedAddrs call is connect time: failed addresses
// tried before the winning address still delayed obtaining that new connection.
func httpDialFunc(guard *netguard.Guard, proxy *proxydial.Dialer) proxydial.DialFunc {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}

		if a, parseErr := netip.ParseAddr(host); parseErr == nil {
			if proxy != nil {
				dec := guard.CheckAddr(a.Unmap())
				if !dec.Allowed {
					return nil, &netguard.BlockedError{Target: host, Matched: dec.Matched}
				}
				conn, dialErr := proxy.DialContext(ctx, network, address)
				if dialErr != nil {
					return nil, dialErr
				}
				return &httpTimingConn{Conn: conn}, nil
			}
			started := time.Now()
			conn, dialErr := guard.DialContext(ctx, network, address)
			if dialErr != nil {
				return nil, dialErr
			}
			return &httpTimingConn{Conn: conn, connectMs: msSince(started), haveConnect: true}, nil
		}

		if proxy != nil && proxy.ResolvesRemotely() {
			conn, dialErr := proxy.DialContext(ctx, network, address)
			if dialErr != nil {
				return nil, dialErr
			}
			return &httpTimingConn{Conn: conn}, nil
		}
		hd := guard.CheckHost(host)
		if hd.Denied {
			return nil, &netguard.BlockedError{Target: host, Matched: hd.Matched}
		}
		resolveStarted := time.Now()
		vetted, resolveErr := guard.ResolveVetted(ctx, host, hd.NameAuthorized)
		if resolveErr != nil {
			return nil, resolveErr
		}
		dnsMs := msSince(resolveStarted)

		if proxy != nil {
			var lastErr error
			for _, a := range vetted {
				conn, dialErr := proxy.DialContext(ctx, network, net.JoinHostPort(a.String(), port))
				if dialErr == nil {
					return &httpTimingConn{Conn: conn, dnsMs: dnsMs, haveDNS: true}, nil
				}
				lastErr = dialErr
			}
			if lastErr == nil {
				lastErr = &netguard.BlockedError{Target: host, FromResolve: true}
			}
			return nil, lastErr
		}

		connectStarted := time.Now()
		conn, dialErr := guard.DialVettedAddrs(ctx, network, vetted, port, host)
		if dialErr != nil {
			return nil, dialErr
		}
		return &httpTimingConn{Conn: conn, dnsMs: dnsMs, connectMs: msSince(connectStarted),
			haveDNS: true, haveConnect: true}, nil
	}
}

// HTTPCollector performs HTTP/HTTPS availability checks against a
// server-configured URL set (architecture §4 service layer). Each URL carries
// its own per-target params (timeout, interval, method, status acceptance,
// keyword match, headers/body, redirect + TLS policy) and is probed on its own
// schedule and its own goroutine via probeRunner.
type HTTPCollector struct {
	guard   *netguard.Guard
	proxies *proxydial.Manager
	*probeRunner

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

	flowHistory *flowHistory
}

func NewHTTPCollector(guard *netguard.Guard, proxies *proxydial.Manager, allowExtended bool, gate *ProbeGate) *HTTPCollector {
	return &HTTPCollector{
		probeRunner:   newProbeRunner(pcfg.DefaultHTTPInterval, gate),
		guard:         guard,
		proxies:       proxies,
		allowExtended: allowExtended,
		clients:       map[string]*http.Client{},
		flowHistory:   newFlowHistory(),
	}
}

func (c *HTTPCollector) SetTargets(targets []pcfg.ProbeTarget) {
	var urls []pcfg.ProbeTarget
	for _, t := range targets {
		if t.Kind == "http" && t.Target != "" {
			urls = append(urls, t)
		}
	}
	c.setTargets(urls)
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
	dial := httpDialFunc(c.guard, proxy)
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

// Collect hands back the requests that finished since the last pass and starts
// the targets that have come due — see probeRunner for why they no longer run
// inline.
func (c *HTTPCollector) Collect(ctx context.Context) (Result, error) {
	return c.collect(ctx, c.runTarget), nil
}

// httpTimeout is the per-request budget: the configured TimeoutMs, else the
// default. It is what pcfg.CycleDeadline derives for an http target.
func httpTimeout(p pcfg.ProbeParams) time.Duration {
	if p.TimeoutMs > 0 {
		return time.Duration(p.TimeoutMs) * time.Millisecond
	}
	return pcfg.DefaultHTTPTimeout
}

// runTarget probes one URL on its own goroutine, under a slot from the
// machine-wide budget.
func (c *HTTPCollector) runTarget(ctx context.Context, sp scheduledProbe) (Result, func(*Result)) {
	t := sp.Target
	// Defensive re-check: a non-basic HTTP request requires probe.http.extended.
	// The monitor evaluator already excludes such targets when the permission is
	// absent, so this only fires on a policy/eval drift — skip silently, never a
	// metric. Checked before the budget so a target that will not be probed
	// cannot consume a slot or count as overload.
	if !c.allowExtended && httpParamsNeedExtended(t.Params) {
		return Result{}, nil
	}
	timeout := httpTimeout(t.Params)
	if c.gate.Acquire(ctx, gateWaitDeadline(sp.NextDue, timeout)) != AdmittedOK {
		// Cancelled (shutdown or a superseded generation) or shut out by the
		// budget. Nothing was requested, so nothing is reported: a fabricated
		// failure would replay from the WAL as a false service outage.
		return Result{}, nil
	}
	gateHeld := true
	defer func() {
		if gateHeld {
			c.gate.Release()
		}
	}()
	// A run aborted by cancellation (agent shutdown) must not fabricate request
	// failures — they would replay from the WAL as a false service outage on the
	// next start.
	if ctx.Err() != nil {
		return Result{}, nil
	}
	// Stamped where the measurement happens: after the wait for a slot, not when
	// the pass that scheduled it began.
	now := time.Now().UTC()
	var res Result
	{
		// Resolve the pinned egress proxy. A pin that cannot be honored is a probe
		// FAILURE reported as such — never a direct dial, which would send the request
		// from the real egress IP the operator routed away from and make an "up" verdict
		// meaningless.
		proxy, perr := resolveProxy(ctx, c.proxies, t)
		if perr != nil {
			res.Metrics = append(res.Metrics, proxyFailureMetrics(now, t, telemetry.HTTPOK, telemetry.HTTPErrorClass, nil, perr)...)
			res.Events = append(res.Events, proxyFailureEvent(now, t, "HTTP request not attempted"))
			return res, nil
		}
		method := t.Params.Method
		if method == "" {
			method = http.MethodGet
		}
		if t.Params.FlowFanout >= 2 && proxy == nil && (method == http.MethodGet || method == http.MethodHead) {
			return c.runFanout(ctx, t, now, timeout, func() {
				c.gate.Release()
				gateHeld = false
			}), nil
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
			return Result{}, nil
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
		timing := &httpTimingTrace{}
		req = timing.traceRequest(req)
		t0 := time.Now()
		timing.started = t0
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
				return res, nil
			}
			if ctx.Err() != nil {
				return Result{}, nil // the request was aborted by the cancelled run, not the service
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
			return res, nil
		}
		status := resp.StatusCode

		// Read the body only when a keyword match is configured, bounded so a large
		// response can't blow up agent memory. Otherwise drain a little and close.
		bodyMatch := true
		bodyVerdictComplete := true
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
			// Seeing the keyword settles both positive and inverted checks even if
			// the connection fails later. Without a match, an incomplete body cannot
			// prove either absence or success of the inverted check.
			bodyVerdictComplete = bodyErr == nil || found
		}
		statusOK := statusAccepted(status, t.Params.AcceptedStatuses)
		timingSnapshot := timing.finish()
		resp.Body.Close()
		cancel()

		ok := 0.0
		if statusOK && bodyVerdictComplete && bodyMatch {
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
		case !bodyVerdictComplete:
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
		// A body read failure can happen after valid response headers arrived. When
		// it prevents the configured keyword check from reaching a verdict, the
		// round is still a transport failure and must not publish partial timings.
		timingEligible := !statusOK || bodyVerdictComplete
		if timingEligible {
			res.Metrics = append(res.Metrics, httpTimingMetrics(now, t, timingSnapshot)...)
		}
	}
	return res, nil
}

func httpTimingMetrics(now time.Time, t pcfg.ProbeTarget, timing httpTimingSnapshot) []telemetry.Metric {
	mk := func(kind telemetry.MetricKind, value float64, unit string) telemetry.Metric {
		return telemetry.Metric{TS: now, Kind: kind, Target: t.Target, Layer: telemetry.LayerService,
			Value: value, Unit: unit, MonitorID: t.MonitorID, ConfigSerial: t.ConfigSerial}
	}
	metrics := []telemetry.Metric{mk(telemetry.HTTPTotalMs, timing.totalMs, telemetry.UnitMs)}
	if timing.haveTTFB {
		metrics = append(metrics, mk(telemetry.HTTPTTFBMs, timing.ttfbMs, telemetry.UnitMs))
	}
	if timing.haveDNS {
		metrics = append(metrics, mk(telemetry.HTTPDNSMs, timing.dnsMs, telemetry.UnitMs))
	}
	if timing.haveConn {
		metrics = append(metrics, mk(telemetry.HTTPConnectMs, timing.connMs, telemetry.UnitMs))
	}
	if timing.haveTLS {
		metrics = append(metrics, mk(telemetry.HTTPTLSMs, timing.tlsMs, telemetry.UnitMs))
	}
	if timing.haveReuse {
		reused := 0.0
		if timing.reused {
			reused = 1
		}
		metrics = append(metrics, mk(telemetry.HTTPConnectionReused, reused, telemetry.UnitBool))
	}
	return metrics
}

type httpFanoutBranch struct {
	attempted bool
	bad       bool
	status    int
	latencyMs float64
	timing    httpTimingSnapshot
	timingOK  bool
	reason    int
	detail    string
	blocked   *netguard.BlockedError
}

// runFanout executes a complete HTTP check on each deterministic source port.
// Redirects are intentionally not followed: every branch must describe the same
// original destination and five-tuple, while a redirect is a different target.
func (c *HTTPCollector) runFanout(ctx context.Context, t pcfg.ProbeTarget, now time.Time, timeout time.Duration, releaseOuter func()) Result {
	u, err := url.Parse(t.Target)
	if err != nil || u.Hostname() == "" {
		return Result{}
	}
	host := u.Hostname()
	port := 80
	if u.Scheme == "https" {
		port = 443
	}
	if u.Port() != "" {
		port, err = strconv.Atoi(u.Port())
		if err != nil {
			return Result{}
		}
	}

	cycleCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	dst := host
	var dnsMs float64
	haveDNS := false
	if a, parseErr := netip.ParseAddr(host); parseErr == nil {
		dst = a.Unmap().String()
		if dec := c.guard.CheckAddr(a.Unmap()); !dec.Allowed {
			return Result{Blocked: []BlockedProbe{{MonitorID: t.MonitorID, ConfigSerial: t.ConfigSerial, Matched: dec.Matched, Reason: "literal_denied"}}}
		}
	} else {
		hd := c.guard.CheckHost(host)
		if hd.Denied {
			return Result{Blocked: []BlockedProbe{{MonitorID: t.MonitorID, ConfigSerial: t.ConfigSerial, Matched: hd.Matched, Reason: "resolved_denied"}}}
		}
		resolveStarted := time.Now()
		vetted, resolveErr := c.guard.ResolveVetted(cycleCtx, host, hd.NameAuthorized)
		if resolveErr != nil {
			var be *netguard.BlockedError
			if errors.As(resolveErr, &be) {
				return Result{Blocked: []BlockedProbe{blockedFromErr(t, be)}}
			}
			if ctx.Err() != nil {
				return Result{}
			}
			reason := classifyNetError(resolveErr)
			if reason == telemetry.ProbeReasonOther {
				reason = telemetry.ProbeReasonDNS
			}
			// Resolution failed before any branch had a destination or source port,
			// so this is an HTTP availability failure but not a fan-out sample. Code 4
			// is reserved for a cycle that entered the branch phase yet produced fewer
			// than two attempted branches (for example, local binds all failed).
			return httpFanoutFailureResult(now, t, reason, errText(resolveErr), "HTTP DNS resolution failed: "+t.Target)
		}
		dnsMs = msSince(resolveStarted)
		haveDNS = true
		dst = vetted[0].String()
	}

	// The target-level admission slot protected resolution. Branches account for
	// themselves, so release it before starting N concurrent socket operations.
	releaseOuter()
	n := t.Params.FlowFanout
	ports := flowPorts(dst, port, t.MonitorID, t.ConfigSerial, n)
	out := make([]httpFanoutBranch, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		if cycleCtx.Err() != nil {
			break
		}
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			fctx, fcancel := context.WithTimeout(cycleCtx, timeout)
			defer fcancel()
			dl, _ := fctx.Deadline()
			if c.gate.Acquire(fctx, dl) != AdmittedOK {
				return
			}
			defer c.gate.Release()
			out[i] = c.httpFanoutRequest(fctx, t, dst, host, port, ports[i])
		}(i)
	}
	wg.Wait()
	if ctx.Err() != nil {
		return Result{}
	}
	for i := range out {
		if out[i].blocked != nil {
			return Result{Blocked: []BlockedProbe{blockedFromErr(t, out[i].blocked)}}
		}
	}

	attempted := make([]bool, n)
	bad := make([]bool, n)
	firstBad := -1
	firstResponseStatus := 0
	responseCount := 0
	latencySum := 0.0
	var timingSum httpTimingSnapshot
	ttfbCount := 0
	connectCount := 0
	tlsCount := 0
	for i, branch := range out {
		attempted[i] = branch.attempted
		bad[i] = branch.bad
		if !branch.attempted {
			continue
		}
		if branch.bad && firstBad < 0 {
			firstBad = i
		}
		if branch.status > 0 {
			if firstResponseStatus == 0 {
				firstResponseStatus = branch.status
			}
			responseCount++
			latencySum += branch.latencyMs
			if branch.timingOK {
				timingSum.totalMs += branch.timing.totalMs
				timingSum.ttfbMs += branch.timing.ttfbMs
				timingSum.connMs += branch.timing.connMs
				timingSum.tlsMs += branch.timing.tlsMs
				timingSum.haveTTFB = timingSum.haveTTFB || branch.timing.haveTTFB
				timingSum.haveConn = timingSum.haveConn || branch.timing.haveConn
				timingSum.haveTLS = timingSum.haveTLS || branch.timing.haveTLS
				if branch.timing.haveTTFB {
					ttfbCount++
				}
				if branch.timing.haveConn {
					connectCount++
				}
				if branch.timing.haveTLS {
					tlsCount++
				}
			}
		}
	}
	code, flows, badStable, badNew, okCount := c.flowHistory.outcome(t.MonitorID, t.ConfigSerial, attempted, bad)
	labels := map[string]string{
		telemetry.FlowFanoutFlowsLabel:     strconv.Itoa(flows),
		telemetry.FlowFanoutBadStableLabel: strconv.Itoa(badStable),
		telemetry.FlowFanoutBadNewLabel:    strconv.Itoa(badNew),
		telemetry.FlowFanoutOKLabel:        strconv.Itoa(okCount),
	}
	ff := telemetry.Metric{TS: now, Kind: telemetry.HTTPFlowFanout, Target: t.Target, Layer: telemetry.LayerService,
		Value: float64(code), Unit: telemetry.UnitCode, Labels: labels, MonitorID: t.MonitorID, ConfigSerial: t.ConfigSerial}
	if flows == 0 {
		return Result{Metrics: []telemetry.Metric{ff}}
	}

	ok := firstBad < 0
	okValue := 0.0
	reason := telemetry.ProbeReasonNone
	detail := ""
	if ok {
		okValue = 1
	} else {
		reason = out[firstBad].reason
		detail = out[firstBad].detail
	}
	representativeStatus := firstResponseStatus
	if firstBad >= 0 && out[firstBad].status > 0 {
		representativeStatus = out[firstBad].status
	}
	ec := telemetry.Metric{TS: now, Kind: telemetry.HTTPErrorClass, Target: t.Target, Layer: telemetry.LayerService,
		Value: float64(reason), Unit: telemetry.UnitCode, MonitorID: t.MonitorID, ConfigSerial: t.ConfigSerial}
	if reason != telemetry.ProbeReasonNone {
		ec.Labels = withDetail(nil, detail)
	}
	res := Result{Metrics: []telemetry.Metric{
		{TS: now, Kind: telemetry.HTTPOK, Target: t.Target, Layer: telemetry.LayerService, Value: okValue, Unit: telemetry.UnitBool, MonitorID: t.MonitorID, ConfigSerial: t.ConfigSerial},
		ec,
		ff,
	}}
	if representativeStatus > 0 {
		timingCount := 0
		for _, branch := range out {
			if branch.status > 0 && branch.timingOK {
				timingCount++
			}
		}
		if timingCount > 0 {
			timingSum.totalMs /= float64(timingCount)
			// Fan-out deliberately disables keep-alives and closes every request, so
			// connection reuse is an aggregate invariant rather than a branch value.
			timingSum.haveReuse = true
			timingSum.reused = false
		}
		if ttfbCount > 0 {
			timingSum.ttfbMs /= float64(ttfbCount)
		}
		if connectCount > 0 {
			timingSum.connMs /= float64(connectCount)
		}
		if tlsCount > 0 {
			timingSum.tlsMs /= float64(tlsCount)
		}
		if haveDNS && timingCount > 0 {
			timingSum.dnsMs = dnsMs
			timingSum.haveDNS = true
			// Fan-out resolves once before its concurrent branch requests. Account
			// that shared prerequisite in each branch-shaped end-to-end duration.
			timingSum.totalMs += dnsMs
			if timingSum.haveTTFB {
				timingSum.ttfbMs += dnsMs
			}
		}
		res.Metrics = append(res.Metrics,
			telemetry.Metric{TS: now, Kind: telemetry.HTTPStatus, Target: t.Target, Layer: telemetry.LayerService, Value: float64(representativeStatus), Unit: telemetry.UnitCode, MonitorID: t.MonitorID, ConfigSerial: t.ConfigSerial},
			telemetry.Metric{TS: now, Kind: telemetry.HTTPLat, Target: t.Target, Layer: telemetry.LayerService, Value: latencySum / float64(responseCount), Unit: telemetry.UnitMs, MonitorID: t.MonitorID, ConfigSerial: t.ConfigSerial},
		)
		if timingCount > 0 {
			res.Metrics = append(res.Metrics, httpTimingMetrics(now, t, timingSum)...)
		}
	}
	if !ok {
		res.Events = append(res.Events, telemetry.Event{ID: newID(), TS: now, Type: telemetry.EventProbeFailed,
			Layer: telemetry.LayerService, Severity: telemetry.SeverityWarn, Message: "HTTP fan-out request failed: " + t.Target})
	}
	return res
}

func (c *HTTPCollector) httpFanoutRequest(ctx context.Context, t pcfg.ProbeTarget, dst, host string, port, sourcePort int) httpFanoutBranch {
	tr := &http.Transport{
		Proxy:               nil,
		DisableKeepAlives:   true,
		ForceAttemptHTTP2:   false,
		TLSHandshakeTimeout: 10 * time.Second,
		DialContext: func(dialCtx context.Context, network, _ string) (net.Conn, error) {
			started := time.Now()
			conn, dialErr := c.guard.DialSourcePort(dialCtx, network, net.JoinHostPort(dst, strconv.Itoa(port)), sourcePort, host)
			if dialErr != nil {
				return nil, dialErr
			}
			return &httpTimingConn{Conn: conn, connectMs: msSince(started), haveConnect: true}, nil
		},
	}
	if t.Params.IgnoreTLS {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // explicit monitor setting
	}
	client := &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer tr.CloseIdleConnections()
	method := t.Params.Method
	if method == "" {
		method = http.MethodGet
	}
	var body io.Reader
	if t.Params.Body != "" {
		body = strings.NewReader(t.Params.Body)
	}
	req, err := http.NewRequestWithContext(ctx, method, t.Target, body)
	if err != nil {
		return httpFanoutBranch{}
	}
	req.Close = true
	for k, v := range t.Params.Headers {
		if strings.EqualFold(k, "Host") {
			req.Host = v
		} else {
			req.Header.Set(k, v)
		}
	}
	timing := &httpTimingTrace{}
	req = timing.traceRequest(req)
	t0 := time.Now()
	timing.started = t0
	resp, err := client.Do(req)
	latency := msSince(t0)
	if err != nil {
		var be *netguard.BlockedError
		if errors.As(err, &be) {
			return httpFanoutBranch{blocked: be}
		}
		if isAddrInUse(err) {
			return httpFanoutBranch{}
		}
		return httpFanoutBranch{attempted: true, bad: true, reason: classifyNetError(err), detail: errText(err)}
	}
	bodyMatch := true
	bodyVerdictComplete := true
	var bodyErr error
	if t.Params.Keyword != "" {
		limit := t.Params.MaxResponseBytes
		if limit <= 0 {
			limit = defaultMaxResponseBytes
		}
		buf, readErr := io.ReadAll(io.LimitReader(resp.Body, int64(limit)))
		bodyErr = readErr
		found := strings.Contains(string(buf), t.Params.Keyword)
		bodyMatch = found != t.Params.KeywordInvert
		bodyVerdictComplete = bodyErr == nil || found
	}
	statusOK := statusAccepted(resp.StatusCode, t.Params.AcceptedStatuses)
	timingSnapshot := timing.finish()
	_ = resp.Body.Close()
	b := httpFanoutBranch{attempted: true, status: resp.StatusCode, latencyMs: latency}
	switch {
	case !statusOK:
		b.bad, b.reason, b.detail = true, telemetry.ProbeReasonHTTPStatus, "HTTP "+strconv.Itoa(resp.StatusCode)
	case !bodyVerdictComplete:
		b.bad, b.reason, b.detail = true, classifyNetError(bodyErr), errText(bodyErr)
	case !bodyMatch:
		b.bad, b.reason = true, telemetry.ProbeReasonHTTPKeyword
		if t.Params.KeywordInvert {
			b.detail = "keyword " + strconv.Quote(t.Params.Keyword) + " unexpectedly present"
		} else {
			b.detail = "keyword " + strconv.Quote(t.Params.Keyword) + " not found"
		}
	}
	b.timing = timingSnapshot
	// A status rejection is already a complete acceptance verdict, even if its
	// body later truncated. Otherwise a body read error that leaves the keyword
	// unresolved makes this branch ineligible for timing aggregation.
	b.timingOK = !statusOK || bodyVerdictComplete
	return b
}

func httpFanoutFailureResult(now time.Time, t pcfg.ProbeTarget, reason int, detail, message string) Result {
	return Result{
		Metrics: []telemetry.Metric{
			{TS: now, Kind: telemetry.HTTPOK, Target: t.Target, Layer: telemetry.LayerService, Value: 0, Unit: telemetry.UnitBool, MonitorID: t.MonitorID, ConfigSerial: t.ConfigSerial},
			{TS: now, Kind: telemetry.HTTPErrorClass, Target: t.Target, Layer: telemetry.LayerService, Value: float64(reason), Unit: telemetry.UnitCode, Labels: withDetail(nil, detail), MonitorID: t.MonitorID, ConfigSerial: t.ConfigSerial},
		},
		Events: []telemetry.Event{{ID: newID(), TS: now, Type: telemetry.EventProbeFailed, Layer: telemetry.LayerService, Severity: telemetry.SeverityWarn, Message: message}},
	}
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
