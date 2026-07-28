package traceroute

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/nettact/agent/internal/netguard"
	pcfg "github.com/nettact/protocol/config"
	"github.com/nettact/protocol/permission"
	"github.com/nettact/protocol/telemetry"
)

// Local clamp ceilings (spec §DIAG-001 §17): the server also bounds these, but
// the Agent re-clamps every request as a defense against a malformed push.
const (
	maxHopsCeiling  = 64
	maxAttempts     = 5
	maxTotalTimeout = 120 * time.Second

	defaultMaxHops      = 30
	defaultAttempts     = 3
	defaultTotalTimeout = 90 * time.Second

	// Per-attempt probe budget bounds, derived from the total timeout and hop
	// count and then clamped into this window so one slow hop cannot starve the
	// rest and a tiny budget still sends a real probe.
	minPerAttempt = 500 * time.Millisecond
	maxPerAttempt = 3 * time.Second

	// Reverse-DNS budget (spec): per-lookup and total ceilings with bounded
	// concurrency. A lookup failure leaves the hostname empty and never changes
	// the path status.
	revDNSPerLookup   = 200 * time.Millisecond
	revDNSTotalBudget = 1 * time.Second
	revDNSConcurrency = 4

	// DefaultConcurrency is the per-Agent limit on simultaneously executing
	// traces (distinct report ids). Different keys run concurrently up to this;
	// the value is a construction default New falls back to.
	DefaultConcurrency = 4
)

// Stable terminal reason codes (TraceResult.Reason).
const (
	reasonInvalidMode        = "invalid_mode"
	reasonInvalidPort        = "invalid_port"
	reasonInvalidDestination = "invalid_destination"
	reasonPolicyDenied       = "policy_denied"
	reasonDNSError           = "dns_error"
	reasonNoIPv4             = "no_ipv4_address"
	reasonPermissionDenied   = "permission_denied"
	reasonUnsupportedPlat    = "unsupported_platform"
	reasonRawSocketUnavail   = "raw_socket_unavailable"
	reasonProbeFailed        = "probe_failed"
	reasonDeadlineExceeded   = "deadline_exceeded"
	reasonCanceled           = "canceled"
)

// errUnsupported is the sentinel a non-implementing platform probe returns; the
// engine maps it to an unsupported terminal status.
var errUnsupported = errors.New("traceroute: mode not supported on this platform")

// Engine executes incident traceroutes under a per-Agent concurrency limit. It
// is constructed once per agent runtime and shared across reconnects; in-flight
// traces are canceled with their session via the context passed to Run.
type Engine struct {
	guard     *netguard.Guard
	effective permission.Set
	granted   permission.Set
	supported permission.Set

	sem  chan struct{} // per-Agent concurrency limiter
	caps capabilities
}

// New builds an Engine. concurrency <= 0 selects DefaultConcurrency. The
// permission views are the agent's immutable process-wide sets; supported must
// already reflect this build+runtime's real ICMP/TCP capability (see Supported).
func New(guard *netguard.Guard, effective, granted, supported permission.Set, concurrency int) *Engine {
	if concurrency <= 0 {
		concurrency = DefaultConcurrency
	}
	return &Engine{
		guard:     guard,
		effective: effective,
		granted:   granted,
		supported: supported,
		sem:       make(chan struct{}, concurrency),
		caps:      detectCapabilities(),
	}
}

// Supported reports whether this build+runtime can execute ICMP / TCP
// traceroute, so the runtime can gate the dedicated diagnostic permissions in
// its supported view (effective stays supported∩granted).
func Supported() (icmp bool, tcp bool) {
	c := detectCapabilities()
	return c.ICMP, c.TCP
}

// Run executes one trace and returns its terminal result. ctx is the session
// context: cancellation (reconnect/shutdown) aborts the trace with a canceled
// status. The request budget — anchored at receivedAt, the caller's arrival
// instant, so worker scheduling delay is not handed back as extra window — and
// the clamped total timeout bound the run; the destination is resolved once
// through the guard and the actual destination IP is reported.
func (e *Engine) Run(ctx context.Context, req pcfg.TraceRequest, receivedAt time.Time) telemetry.TraceResult {
	res := telemetry.TraceResult{ReportID: req.ReportID, Mode: req.Mode}

	// Validate + clamp locally. Invalid mode/port/destination send no probes.
	mode := req.Mode
	if mode != pcfg.TraceModeICMP && mode != pcfg.TraceModeTCP {
		return terminal(res, telemetry.TraceStatusFailed, reasonInvalidMode)
	}
	if req.DestinationHost == "" {
		return terminal(res, telemetry.TraceStatusFailed, reasonInvalidDestination)
	}
	port := req.TCPPort
	if mode == pcfg.TraceModeTCP && (port <= 0 || port > 65535) {
		return terminal(res, telemetry.TraceStatusFailed, reasonInvalidPort)
	}
	maxHops := clampInt(req.MaxHops, defaultMaxHops, 1, maxHopsCeiling)
	attempts := clampInt(req.AttemptsPerHop, defaultAttempts, 1, maxAttempts)
	totalTimeout := clampTotalTimeout(req.TotalTimeoutMs)

	// Permission/capability gate. effective already = granted∩supported, and
	// supported reflects the real platform/runtime capability, so a missing
	// effective permission is either a policy denial or a capability gap.
	permID := permission.DiagnosticTracerouteICMP
	if mode == pcfg.TraceModeTCP {
		permID = permission.DiagnosticTracerouteTCP
	}
	if !e.effective.Has(permID) {
		return terminal(res, telemetry.TraceStatusUnsupported, e.capabilityReason(permID, mode))
	}

	// The request budget is the only validity window. It arrives as a duration and
	// is anchored to this agent's own clock — never to a server timestamp, so clock
	// skew between server and agent cannot shrink the window. Spent, do not start.
	deadline, ok := pcfg.BudgetWindow(req.BudgetMs, receivedAt, time.Now())
	if !ok {
		return terminal(res, telemetry.TraceStatusTimedOut, reasonDeadlineExceeded)
	}
	if ctx.Err() != nil {
		return terminal(res, telemetry.TraceStatusCanceled, reasonCanceled)
	}

	// Resolve the destination exactly once through the guard; report the actual IP.
	dest, reason := e.resolveDestination(ctx, req.DestinationHost)
	if reason != "" {
		return terminal(res, telemetry.TraceStatusFailed, reason)
	}
	res.DestinationIP = dest.String()
	res.StartedAt = time.Now().UTC()

	// Acquire a per-Agent slot; distinct reports run concurrently up to the limit.
	// A waiter that loses its whole budget/deadline before a slot frees returns a
	// clean terminal state rather than blocking forever.
	if st, rsn, ok := e.acquire(ctx, deadline); !ok {
		res.CompletedAt = time.Now().UTC()
		return terminal(res, st, rsn)
	}
	defer func() { <-e.sem }()

	// Run window = earliest of the request's budget deadline and now+totalTimeout.
	runDeadline := time.Now().Add(totalTimeout)
	if deadline.Before(runDeadline) {
		runDeadline = deadline
	}
	runCtx, cancel := context.WithDeadline(ctx, runDeadline)
	defer cancel()

	probe := e.proberFor(mode)
	perAttempt := perAttemptBudget(totalTimeout, maxHops)

	out := e.walk(ctx, runCtx, probe, dest, port, maxHops, attempts, perAttempt, runDeadline)
	res.Hops = out.hops
	res.Reached = out.reached
	res.ReachedTTL = out.reachedTTL

	if req.ResolveHopHostnames {
		resolveHopHostnames(ctx, res.Hops)
	}

	res.Status, res.Reason = out.status, out.reason
	res.CompletedAt = time.Now().UTC()
	return res
}

// walkResult is the outcome of the hop loop before status finalization.
type walkResult struct {
	hops       []telemetry.TraceHop
	reached    bool
	reachedTTL int
	status     string
	reason     string
}

// walk sends the TTL sweep and classifies the terminal status. It continues past
// non-responding (`*`) hops; only a destination response stops the sweep. Session
// cancellation ends it as canceled; running out of the deadline/budget ends it as
// timed_out with the partial hops captured so far; a hard probe error ends it as
// failed; completing the sweep with usable-but-no-reach hops is partial.
func (e *Engine) walk(sessionCtx, runCtx context.Context, probe prober, dest netip.Addr, port, maxHops, attempts int, perAttempt time.Duration, runDeadline time.Time) walkResult {
	var out walkResult
	var hardErr error
	canceled := false
	budgetExpired := false

sweep:
	for ttl := 1; ttl <= maxHops; ttl++ {
		hop := telemetry.TraceHop{TTL: ttl}
		for a := 0; a < attempts; a++ {
			if sessionCtx.Err() != nil {
				canceled = true
				break sweep
			}
			remaining := time.Until(runDeadline)
			if remaining <= 0 {
				budgetExpired = true
				break sweep
			}
			to := perAttempt
			if remaining < to {
				to = remaining
			}
			outcome, err := probe(runCtx, dest, port, ttl, to)
			if err != nil {
				hardErr = err
				break sweep
			}
			att := telemetry.TraceAttempt{}
			if outcome.timeout || !outcome.responder.IsValid() {
				att.Timeout = true
			} else {
				att.ResponderAddr = outcome.responder.String()
				att.RTTMs = outcome.rttMs
			}
			hop.Attempts = append(hop.Attempts, att)
			if outcome.reached {
				out.reached = true
				out.reachedTTL = ttl
			}
		}
		out.hops = append(out.hops, hop)
		if out.reached {
			break sweep
		}
	}

	switch {
	case out.reached:
		out.status = telemetry.TraceStatusSucceeded
	case hardErr != nil:
		if errors.Is(hardErr, errUnsupported) {
			out.status, out.reason = telemetry.TraceStatusUnsupported, reasonUnsupportedPlat
		} else {
			out.status, out.reason = telemetry.TraceStatusFailed, reasonProbeFailed
		}
	case canceled:
		out.status, out.reason = telemetry.TraceStatusCanceled, reasonCanceled
	case budgetExpired || !time.Now().Before(runDeadline):
		out.status, out.reason = telemetry.TraceStatusTimedOut, reasonDeadlineExceeded
	default:
		out.status = telemetry.TraceStatusPartial
	}
	return out
}

// acquire waits for a per-Agent concurrency slot, honoring session cancellation
// and the request's budget deadline. It returns ok=false with the terminal
// status/reason to use when the slot never frees in time.
func (e *Engine) acquire(ctx context.Context, deadline time.Time) (status, reason string, ok bool) {
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	select {
	case e.sem <- struct{}{}:
		return "", "", true
	case <-ctx.Done():
		return telemetry.TraceStatusCanceled, reasonCanceled, false
	case <-timer.C:
		return telemetry.TraceStatusTimedOut, reasonDeadlineExceeded, false
	}
}

// capabilityReason explains a missing effective permission: a policy denial
// (granted excludes it) vs a capability gap (granted but the platform/runtime
// cannot execute the mode — raw-socket for TCP, platform for ICMP).
func (e *Engine) capabilityReason(id permission.ID, mode string) string {
	if !e.granted.Has(id) {
		return reasonPermissionDenied
	}
	if mode == pcfg.TraceModeTCP {
		return reasonRawSocketUnavail
	}
	return reasonUnsupportedPlat
}

// proberFor returns the platform probe for a mode. The mode was already gated by
// the effective permission (which reflects real capability), so on a supporting
// platform this never returns an unsupported stub.
func (e *Engine) proberFor(mode string) prober {
	if mode == pcfg.TraceModeTCP {
		return tcpProbe
	}
	return icmpProbe
}

// resolveDestination resolves host once through the guard and returns the single
// IPv4 destination to trace toward, or a stable reason on denial/failure. IPv4 is
// required because the platform TTL paths are IPv4-only.
func (e *Engine) resolveDestination(ctx context.Context, host string) (netip.Addr, string) {
	if a, err := netip.ParseAddr(host); err == nil {
		a = a.Unmap()
		if dec := e.guard.CheckAddr(a); !dec.Allowed {
			return netip.Addr{}, reasonPolicyDenied
		}
		if !a.Is4() {
			return netip.Addr{}, reasonNoIPv4
		}
		return a, ""
	}
	hd := e.guard.CheckHost(host)
	if hd.Denied {
		return netip.Addr{}, reasonPolicyDenied
	}
	vetted, err := e.guard.ResolveVetted(ctx, host, hd.NameAuthorized)
	if err != nil {
		var be *netguard.BlockedError
		if errors.As(err, &be) {
			return netip.Addr{}, reasonPolicyDenied
		}
		return netip.Addr{}, reasonDNSError
	}
	for _, a := range vetted {
		if a.Is4() {
			return a, ""
		}
	}
	return netip.Addr{}, reasonNoIPv4
}

// resolveHopHostnames fills in reverse-DNS hostnames for the distinct responder
// addresses, bounded by a per-lookup timeout, a total budget, and limited
// concurrency. A failed or slow lookup leaves the hostname empty and never
// changes any attempt's address or the path status.
func resolveHopHostnames(ctx context.Context, hops []telemetry.TraceHop) {
	// Collect the distinct responder addresses.
	unique := map[string]struct{}{}
	for _, h := range hops {
		for _, a := range h.Attempts {
			if a.ResponderAddr != "" {
				unique[a.ResponderAddr] = struct{}{}
			}
		}
	}
	if len(unique) == 0 {
		return
	}
	addrs := make([]string, 0, len(unique))
	for a := range unique {
		addrs = append(addrs, a)
	}
	sort.Strings(addrs)

	budgetCtx, cancel := context.WithTimeout(ctx, revDNSTotalBudget)
	defer cancel()

	var mu sync.Mutex
	names := make(map[string]string, len(addrs))
	sem := make(chan struct{}, revDNSConcurrency)
	var wg sync.WaitGroup
	for _, addr := range addrs {
		if budgetCtx.Err() != nil {
			break
		}
		wg.Add(1)
		go func(addr string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			if budgetCtx.Err() != nil {
				return
			}
			lookupCtx, lcancel := context.WithTimeout(budgetCtx, revDNSPerLookup)
			defer lcancel()
			hostnames, err := net.DefaultResolver.LookupAddr(lookupCtx, addr)
			if err != nil || len(hostnames) == 0 {
				return
			}
			mu.Lock()
			names[addr] = hostnames[0]
			mu.Unlock()
		}(addr)
	}
	wg.Wait()

	if len(names) == 0 {
		return
	}
	for hi := range hops {
		for ai := range hops[hi].Attempts {
			if n, ok := names[hops[hi].Attempts[ai].ResponderAddr]; ok {
				hops[hi].Attempts[ai].Hostname = n
			}
		}
	}
}

// terminal stamps a terminal status/reason and the completion time onto res.
func terminal(res telemetry.TraceResult, status, reason string) telemetry.TraceResult {
	res.Status = status
	res.Reason = reason
	if res.CompletedAt.IsZero() {
		res.CompletedAt = time.Now().UTC()
	}
	return res
}

// clampInt applies a default for a non-positive value and bounds it to [min,max].
func clampInt(v, def, min, max int) int {
	if v <= 0 {
		v = def
	}
	if v < min {
		v = min
	}
	if v > max {
		v = max
	}
	return v
}

// clampTotalTimeout applies the default/ceiling to the request total timeout.
func clampTotalTimeout(ms int) time.Duration {
	if ms <= 0 {
		return defaultTotalTimeout
	}
	d := time.Duration(ms) * time.Millisecond
	if d > maxTotalTimeout {
		return maxTotalTimeout
	}
	return d
}

// perAttemptBudget derives the per-probe timeout from the total budget and hop
// count, clamped into [minPerAttempt, maxPerAttempt].
func perAttemptBudget(total time.Duration, maxHops int) time.Duration {
	if maxHops <= 0 {
		maxHops = defaultMaxHops
	}
	per := total / time.Duration(maxHops)
	if per < minPerAttempt {
		per = minPerAttempt
	}
	if per > maxPerAttempt {
		per = maxPerAttempt
	}
	return per
}
