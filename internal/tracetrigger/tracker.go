// Package tracetrigger decides, locally, when this agent should traceroute a
// target it has just found unreachable — and runs it.
//
// # Why the agent decides
//
// Traceroute used to be a server-issued command: the fault engine confirmed a
// fault, the server queued a report and pushed it down the WebSocket, the agent
// executed and answered on the same socket. That works for every fault except
// the ones worth diagnosing. A network fault is, overwhelmingly, also the reason
// the agent cannot reach its server — so the command never arrives, and if it
// did the answer would not get back. The diagnostic was reliably absent exactly
// when it mattered and reliably present when it did not.
//
// Moving the decision here inverts that. The agent is already running the probes
// that fail; it counts its own consecutive failures, derives the plan from the
// target it was pushed, and traces while the fault is still happening. The
// result goes into the outbox with everything else, so it survives the outage
// and is delivered when the link comes back. The server keeps the policy (see
// config.DiagPolicy) and keeps the interpretation — which incident this report
// is evidence for — but no longer holds the trigger.
//
// # What counts as a failure
//
// Only hard availability failures: total ICMP loss, a TCP connect that did not
// connect, an HTTP/DNS/NAT probe that reported not-ok. Quality degradation never
// triggers a trace — a target answering slowly is a target answering, and a
// traceroute would spend the machine's probe budget measuring a path that works.
// The threshold matches the server's own availability confirmation count, so a
// trace fires as the fault becomes real rather than before it (noise) or well
// after (evidence collected past the interesting moment).
//
// # Why not monitoreval.Tracker
//
// That tracker answers "may this monitor run at all" from permissions, proxy
// availability and target policy — a question about configuration, decided when
// configuration changes. This one answers "has this target been failing", a
// question about measurements, decided on every round. Folding the second into
// the first would put a per-round counter inside a component whose whole state is
// supposed to change only on a push.
package tracetrigger

import (
	"context"
	"log"
	"math"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/nettact/agent/internal/traceroute"
	pcfg "github.com/nettact/protocol/config"
	"github.com/nettact/protocol/permission"
	"github.com/nettact/protocol/telemetry"
)

// Policy is the resolved path-diagnostic policy: config.DiagPolicy with every
// unset field filled from the defaults below. Resolving once, here, is what
// keeps "0 means default" from having to be re-decided at each use.
type Policy struct {
	Enabled             bool
	ConsecutiveFailures int
	Cooldown            time.Duration
	MaxHops             int
	Attempts            int
	PerHopTimeoutMs     int
	BudgetMs            int
}

// Policy defaults. ConsecutiveFailures mirrors the server's balanced
// availability profile (3 failing rounds confirm), so an agent left entirely
// unconfigured traces at the same moment the server would have called the fault.
// The cooldown is deliberately much longer than a probe interval: a target that
// stays down produces a failing round every few seconds, and the path to it does
// not change that often — re-tracing it would burn the machine's probe budget
// re-answering a question nobody asked twice.
const (
	defaultConsecutiveFailures = 3
	defaultCooldown            = 15 * time.Minute
	defaultMaxHops             = 30
	defaultAttempts            = 3
	defaultBudgetMs            = 300_000
)

// ResolvePolicy fills a pushed policy's unset fields with the defaults. A nil
// block means the server said nothing, which enables the feature on defaults —
// the diagnostic is zero-config by design, and a server that has not been
// upgraded to state a policy should not silently disable it.
func ResolvePolicy(p *pcfg.DiagPolicy) Policy {
	out := Policy{
		Enabled:             true,
		ConsecutiveFailures: defaultConsecutiveFailures,
		Cooldown:            defaultCooldown,
		MaxHops:             defaultMaxHops,
		Attempts:            defaultAttempts,
		BudgetMs:            defaultBudgetMs,
	}
	if p == nil {
		return out
	}
	out.Enabled = p.Enabled
	if p.ConsecutiveFailures > 0 {
		out.ConsecutiveFailures = p.ConsecutiveFailures
	}
	if p.CooldownSeconds > 0 {
		out.Cooldown = time.Duration(p.CooldownSeconds) * time.Second
	}
	if p.MaxHops > 0 {
		out.MaxHops = p.MaxHops
	}
	if p.Attempts > 0 {
		out.Attempts = p.Attempts
	}
	if p.PerHopTimeoutMs > 0 {
		out.PerHopTimeoutMs = p.PerHopTimeoutMs
	}
	if p.BudgetMs > 0 {
		out.BudgetMs = p.BudgetMs
	}
	return out
}

// Runner executes one trace. Satisfied by (*traceroute.Engine).Run; injected so
// the trigger's decision logic is testable without raw sockets.
type Runner func(ctx context.Context, req traceroute.Request, decidedAt time.Time) telemetry.TraceResult

// Sink receives every finished report, terminal-at-planning ones included. In
// the agent it appends to this server's slice of the outbox.
type Sink func(res telemetry.TraceResult)

// ProxyLookup returns the egress specs currently pushed to this server, so a
// pinned target's fault can be diagnosed on the leg that actually carried it.
// Satisfied by (*proxydial.Manager).Specs.
type ProxyLookup func() map[string]pcfg.ProxySpec

// streak is one monitor's consecutive-failure state.
//
// firstFailedAt and lastRoundAt are MEASUREMENT timestamps — when the rounds
// were taken, not when this tracker got to look at them. See observeRound for
// why the two clocks are kept apart.
//
// firedAt is not here on purpose: the cooldown is keyed by the planned trace's
// cohort (destination, mode, port, path — see plan.cohortKey), not by monitor.
// Two monitors on one host share a path, and tracing it twice because two
// monitors noticed the same outage answers the same question twice.
type streak struct {
	fails         int
	firstFailedAt time.Time
	lastRoundAt   time.Time
	configSerial  int
	// fired marks that this streak already produced a trace. The trigger is an
	// EDGE: a target that stays down keeps failing rounds forever, and firing per
	// round would traceroute a dead host until it came back.
	fired bool
}

// Tracker counts each target's consecutive hard availability failures and fires
// one traceroute when a target crosses the policy threshold.
//
// It is per server, like everything else in a server's pipeline: the targets are
// that server's, the permissions gating the trace are that server's, and the
// resulting report belongs in that server's outbox slice. Two servers watching
// the same host each trace it, which is correct — each is entitled to its own
// evidence, and neither can be told about the other's grant.
type Tracker struct {
	runner    Runner
	sink      Sink
	proxies   ProxyLookup
	effective permission.Set
	granted   permission.Set
	supported permission.Set
	name      string // server name, for log lines

	mu       sync.Mutex
	policy   Policy
	targets  map[string]pcfg.ProbeTarget // monitor id → the pushed target
	streaks  map[string]*streak          // monitor id → its failure state
	cooldown map[string]time.Time        // plan cohort key → when a trace last finished
	inflight map[string]struct{}         // plan cohort key → a trace is running now

	ctx  context.Context
	wg   sync.WaitGroup
	stop bool
}

// New builds a tracker. proxies may be nil (no egress support), in which case a
// pinned target's fault plans as an unnameable proxy path rather than as a
// direct trace — the same fail-closed rule the engine applies to the pin itself.
func New(name string, effective, granted, supported permission.Set, proxies ProxyLookup, runner Runner, sink Sink) *Tracker {
	return &Tracker{
		runner:    runner,
		sink:      sink,
		proxies:   proxies,
		effective: effective,
		granted:   granted,
		supported: supported,
		name:      name,
		policy:    ResolvePolicy(nil),
		targets:   map[string]pcfg.ProbeTarget{},
		streaks:   map[string]*streak{},
		cooldown:  map[string]time.Time{},
		inflight:  map[string]struct{}{},
	}
}

// Start arms the trigger with the runtime context. Until it is called the
// tracker still counts rounds but launches nothing — construction happens before
// there is a context to cancel against, and a trace started outside the runtime's
// lifetime would append to an outbox that is about to close.
func (t *Tracker) Start(ctx context.Context) {
	t.mu.Lock()
	t.ctx = ctx
	t.mu.Unlock()
}

// Wait joins the in-flight traces. The agent runtime calls it in the same phase
// as the schedulers' Wait, and for the same reason: these goroutines append to
// the outbox, which must not close underneath them.
func (t *Tracker) Wait() {
	t.mu.Lock()
	t.stop = true
	t.mu.Unlock()
	t.wg.Wait()
}

// SetTargets installs the pushed generation. It satisfies conn.Configurable, so
// the tracker is handed the same runnable target set the collectors get —
// anything blocked by permission or target policy never produces rounds here
// either.
//
// A target whose material generation changed has its streak dropped: the
// counters were accumulated against a different endpoint, and carrying them over
// would let an edit inherit the old address's failures.
func (t *Tracker) SetTargets(targets []pcfg.ProbeTarget) {
	t.mu.Lock()
	defer t.mu.Unlock()
	next := make(map[string]pcfg.ProbeTarget, len(targets))
	for _, tg := range targets {
		if tg.MonitorID == "" {
			continue
		}
		next[tg.MonitorID] = tg
	}
	t.targets = next
	for id, st := range t.streaks {
		tg, ok := next[id]
		if !ok || tg.ConfigSerial != st.configSerial {
			delete(t.streaks, id)
		}
	}
}

// ApplyDiagPolicy installs the pushed path-diagnostic policy. Satisfied through
// conn.DiagApplier; applying the same policy twice is harmless.
//
// A policy that disables the diagnostic ZEROES every streak rather than freezing
// it. While the feature is off, Observe returns before any streak is touched —
// the world simply stops being observed — so counters kept across the gap would
// resume as if the unobserved rounds had agreed with them. Two failures, a
// disable, a healthy round nobody recorded, a re-enable inside the staleness
// window and one more failure would otherwise reach a threshold of three that no
// three consecutive OBSERVED rounds ever supported; symmetrically, a preserved
// fired bit would suppress the first trace of a genuinely fresh outage. A
// disabled interval has no failure count to carry, so it carries none.
//
// The cooldowns deliberately survive: they bound what this machine spends on
// tracing a path, which an operator toggling a policy has not undone.
func (t *Tracker) ApplyDiagPolicy(p *pcfg.DiagPolicy) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.policy = ResolvePolicy(p)
	if !t.policy.Enabled {
		t.streaks = map[string]*streak{}
	}
}

// Observe folds one collector round's metrics into the per-target streaks and
// fires a trace for any target that just crossed the threshold.
//
// It runs on the collector's own goroutine (the pipeline sink), so it does no
// I/O: deriving the plan is pure, and the trace itself goes to a goroutine of
// its own bounded by the machine's traceroute limiter.
func (t *Tracker) Observe(ms []telemetry.Metric) {
	if len(ms) == 0 {
		return
	}
	now := time.Now()
	for _, r := range t.buildRounds(ms) {
		t.observeRound(r, now)
	}
}

// observeRound advances one monitor's streak and returns having fired at most
// one trace.
//
// Two clocks meet here and they are not interchangeable. Everything about the
// STREAK — whether two rounds are adjacent, when it began, whether the round
// that confirmed it still describes the present — reads the rounds' own
// measurement timestamps, because a batch of results can reach this sink long
// after it was taken (a suspended machine, a stalled scheduler, a pipeline
// backed up behind a slow sink) and judging every one of them against a single
// drain-time clock would call rounds minutes apart adjacent and rounds seconds
// apart stale. Everything about SPENDING — the per-cohort in-flight slot, the
// cooldown, the report's own start/finish times — reads now, because those bound
// what this machine is about to do, which happens at the wall clock whatever the
// samples say about when they were measured.
func (t *Tracker) observeRound(r round, now time.Time) {
	t.mu.Lock()
	pol := t.policy
	tg, known := t.targets[r.monitorID]
	if !pol.Enabled || !known {
		t.mu.Unlock()
		return
	}
	st := t.streaks[r.monitorID]
	if st == nil {
		st = &streak{configSerial: tg.ConfigSerial}
		t.streaks[r.monitorID] = st
	}
	// A streak is N CONSECUTIVE rounds, and consecutive has to mean something in
	// wall-clock terms: an agent suspended for six hours resumes with its last
	// round still in memory, and treating that round and the next one as adjacent
	// asserts a continuity nobody observed. The tolerance is the target's own
	// staleness window, which is derived from its own interval — probe intervals
	// span three orders of magnitude, so no flat number works for all of them.
	// The distance is measured between the two rounds' own timestamps and taken as
	// a magnitude: a round that arrives out of order is no more adjacent to its
	// predecessor than a late one is.
	if st.fails > 0 && !st.lastRoundAt.IsZero() {
		if absDuration(r.ts.Sub(st.lastRoundAt)) > staleAfter(tg) {
			*st = streak{configSerial: tg.ConfigSerial}
		}
	}
	st.lastRoundAt = r.ts

	if !r.failed {
		// Recovery wipes the streak, so the next outage starts counting from one
		// and the next trace is a fresh finding rather than a continuation.
		st.fails, st.fired = 0, false
		st.firstFailedAt = time.Time{}
		t.mu.Unlock()
		return
	}

	st.fails++
	if st.fails == 1 {
		st.firstFailedAt = r.ts
	}
	if st.fired || st.fails < pol.ConsecutiveFailures {
		t.mu.Unlock()
		return
	}
	// The confirming round must still describe the present. A backlog drained after
	// a suspend can cross the threshold here long after the path came back, and
	// tracing then measures a working path and files it as evidence for a fault
	// that is over. The streak is deliberately NOT burned: the rest of the backlog
	// still counts, so an outage that really is ongoing fires as soon as one of its
	// rounds is current enough to speak for the present.
	if now.Sub(r.ts) > staleAfter(tg) {
		t.mu.Unlock()
		return
	}
	st.fired = true
	streakLen, firstFailedAt := st.fails, st.firstFailedAt

	p, ok := derivePlan(t.evidenceFor(tg, r), t.effective, t.granted, t.supported)
	if !ok {
		t.mu.Unlock()
		return
	}

	// Path-level dedupe and cooldown. Both are keyed by the plan's cohort — the
	// probe, destination and path — rather than by the monitor, because what is
	// being spared is the path: three monitors on one host going down together
	// describe one outage, and three traces of one path are three copies of one
	// answer. A different mode, port or egress leg is a different question and
	// gets its own slot (see plan.cohortKey).
	cohort := p.cohortKey()
	if _, running := t.inflight[cohort]; running {
		t.mu.Unlock()
		return
	}
	if last, seen := t.cooldown[cohort]; seen && now.Sub(last) < pol.Cooldown {
		t.mu.Unlock()
		return
	}
	reportID := "trace_" + uuid.NewString()

	if p.terminal != "" {
		// Nothing will be probed, so nothing needs a slot or a cooldown: emit the
		// finding and let the next fault re-derive it (the plan is deterministic, so
		// re-deriving costs nothing and stays correct if permissions change).
		t.mu.Unlock()
		t.sink(p.terminalResult(reportID, pol, streakLen, firstFailedAt, now.UTC()))
		return
	}
	if t.stop || t.ctx == nil {
		t.mu.Unlock()
		return
	}
	t.inflight[cohort] = struct{}{}
	ctx := t.ctx
	t.mu.Unlock()

	req := p.request(reportID, pol, streakLen, firstFailedAt)
	log.Printf("[%s] traceroute %s %s after %d consecutive failures (%s)",
		t.name, p.mode, p.destHost, streakLen, p.subjectKind)
	t.wg.Add(1)
	go func() {
		defer t.wg.Done()
		res := t.runner(ctx, req, now)
		t.mu.Lock()
		delete(t.inflight, cohort)
		t.cooldown[cohort] = time.Now()
		t.mu.Unlock()
		t.sink(res)
	}()
}

// evidenceFor assembles the failing round's facts for plan derivation, pairing
// the round's own reported endpoints with the pushed target's egress pin.
func (t *Tracker) evidenceFor(tg pcfg.ProbeTarget, r round) evidence {
	evd := evidence{
		probeKind:        tg.Kind,
		targetAddr:       tg.Target,
		targetPort:       tg.Params.Port,
		reasonCode:       r.reasonCode,
		resolverAddr:     r.resolverAddr,
		resolverProtocol: r.resolverProtocol,
		stunAddr:         r.stunAddr,
		stunTransport:    r.stunTransport,
	}
	if tg.ProxyID == "" {
		return evd
	}
	evd.proxyID = tg.ProxyID
	if t.proxies == nil {
		return evd // pin with no resolvable spec: planProxy reports it unnameable
	}
	spec, ok := t.proxies()[tg.ProxyID]
	if !ok {
		return evd
	}
	evd.proxyType = spec.Type
	evd.proxyConfigSerial = spec.ConfigSerial
	evd.proxyAddr = proxyAddr(spec)
	return evd
}

// proxyAddr is the endpoint a proxy spec names: the relay's listener for
// socks5/http, the peer endpoint for wireguard.
func proxyAddr(spec pcfg.ProxySpec) string {
	if spec.Type == pcfg.ProxyTypeWireGuard {
		return spec.WGEndpoint
	}
	if spec.Host == "" {
		return ""
	}
	return net.JoinHostPort(spec.Host, strconv.Itoa(spec.Port))
}

// staleAfter is how far apart two of a target's rounds may be and still count as
// consecutive. It reuses the same formula the server uses to call a sample too
// old to describe the present: if the gap exceeds it, the earlier round would
// already have been called stale, so treating the two as adjacent members of one
// streak asserts a continuity nobody observed.
func staleAfter(tg pcfg.ProbeTarget) time.Duration {
	return pcfg.StaleAfter(
		pcfg.EffectiveInterval(tg.Kind, tg.Params),
		pcfg.CycleDeadline(tg.Kind, tg.Params),
		0,
	)
}

// absDuration is |d|, so a comparison against a window is about distance rather
// than direction.
func absDuration(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}

// round is one probe cycle's availability verdict for one monitor, plus the
// endpoint facts plan derivation needs.
//
// ts is when the cycle was MEASURED, taken from the metrics themselves. It is
// what every streak decision reads, because the moment this tracker gets to look
// at a round says nothing about when the round happened — see observeRound.
type round struct {
	monitorID string
	ts        time.Time
	failed    bool

	reasonCode       int
	resolverAddr     string
	resolverProtocol string
	stunAddr         string
	stunTransport    string
}

// buildRounds groups a collector result's metrics into per-(monitor, timestamp)
// rounds and classifies each one, keeping only those that reached a hard
// availability verdict.
//
// It deliberately mirrors the server's own round building rather than inventing
// a second notion of "a round": both read the kind's primary success metric,
// pair it with the error_class sample from the SAME cycle, and refuse a verdict
// where the primary metric is missing or non-finite. The one place they differ
// is the failure bar — see classify.
func (t *Tracker) buildRounds(ms []telemetry.Metric) []round {
	type key struct {
		monitorID string
		ts        int64
	}
	type acc struct {
		hasPrimary bool
		value      float64
		sent       int
		hasSent    bool
		round
	}
	t.mu.Lock()
	targets := t.targets
	t.mu.Unlock()

	accs := map[key]*acc{}
	order := make([]key, 0, len(ms))
	for i := range ms {
		m := &ms[i]
		if m.MonitorID == "" {
			continue // system/host series carry no availability verdict
		}
		tg, ok := targets[m.MonitorID]
		if !ok || !TraceEligibleKind(tg.Kind) {
			continue
		}
		// The sample must belong to the generation currently installed. A v1
		// collector result can still be queued when SetTargets installs v2, and the
		// monitor id alone cannot tell them apart: counting it would let the OLD
		// endpoint's failure advance the new one's streak and traceroute the address
		// the edit just moved away from. Series identity includes the serial
		// everywhere else in this system — the server rejects a mismatched sample
		// outright — so the trigger reads it the same way.
		if m.ConfigSerial != tg.ConfigSerial {
			continue
		}
		primary := successMetricKind(tg.Kind)
		if primary == "" {
			continue
		}
		kind := string(m.Kind)
		reason, hasReason := reasonMetricKind(tg.Kind)
		isPrimary := kind == primary
		isReason := hasReason && kind == reason
		isSent := tg.Kind == "icmp" && kind == string(telemetry.ICMPSent)
		if !isPrimary && !isReason && !isSent {
			continue
		}
		k := key{monitorID: m.MonitorID, ts: m.TS.Unix()}
		a := accs[k]
		if a == nil {
			a = &acc{}
			a.monitorID = m.MonitorID
			a.ts = m.TS
			accs[k] = a
			order = append(order, k)
		}
		switch {
		case isSent:
			a.sent, a.hasSent = int(m.Value), true
		case isPrimary:
			a.hasPrimary, a.value = true, m.Value
			a.stunAddr = m.Labels[telemetry.NATServerLabel]
			a.stunTransport = m.Labels[telemetry.NATTransportLabel]
		case isReason:
			a.reasonCode = int(m.Value)
			a.resolverAddr = m.Labels[telemetry.DNSResolverLabel]
			a.resolverProtocol = m.Labels[telemetry.DNSResolverProtocolLabel]
		}
	}

	out := make([]round, 0, len(order))
	for _, k := range order {
		a := accs[k]
		if !a.hasPrimary {
			continue
		}
		tg := targets[a.monitorID]
		// An ICMP cycle the probe budget truncated reports either 0% or 100% over
		// the echoes it managed — figures indistinguishable from a healthy or a dead
		// target on exactly the metric this reads. It is not a verdict, so it neither
		// starts nor breaks a streak.
		if tg.Kind == "icmp" && !icmpRoundComplete(a.hasSent, a.sent, pcfg.PingCount(tg.Params)) {
			continue
		}
		cls, ok := classify(tg.Kind, a.value)
		if !ok {
			continue
		}
		r := a.round
		r.failed = cls
		out = append(out, r)
	}
	return out
}

// successMetricKind maps a probe kind to the metric whose value decides whether
// a round succeeded, matching the server's definition of "up" exactly. ICMP has
// no boolean: a cycle's health is its loss percentage. Everything else emits an
// explicit probe.<kind>.ok, whose semantics (expected status codes, body
// keyword, TLS) the probe already decided from the target's configuration.
func successMetricKind(probeKind string) string {
	switch probeKind {
	case "icmp":
		return string(telemetry.ICMPLoss)
	case "tcp":
		return string(telemetry.TCPOK)
	case "http":
		return string(telemetry.HTTPOK)
	case "dns":
		return string(telemetry.DNSOK)
	case "nat":
		return string(telemetry.NATOK)
	}
	return ""
}

// reasonMetricKind maps a probe kind to the metric carrying its failure-reason
// code, or ("", false) for a kind with no reason concept (nat).
func reasonMetricKind(probeKind string) (string, bool) {
	switch probeKind {
	case "icmp":
		return string(telemetry.ICMPErrorClass), true
	case "dns":
		return string(telemetry.DNSErrorClass), true
	case "http":
		return string(telemetry.HTTPErrorClass), true
	case "tcp":
		return string(telemetry.TCPErrorClass), true
	}
	return "", false
}

// classify decides whether a round is a HARD availability failure. ok=false
// means the value is not a verdict at all.
//
// The ICMP bar is total loss, deliberately, and deliberately NOT the server's
// tunable icmp_loss_pct. That setting is a statement about when a user wants to
// be TOLD about loss; this is a decision about when to spend the machine's probe
// budget on a path diagnostic. A target at 40% loss is still answering, and a
// traceroute of a path that works is the noise this trigger exists to avoid. The
// server remains free to call that target faulty — the two thresholds answer
// different questions and are allowed to disagree.
func classify(probeKind string, value float64) (failed bool, ok bool) {
	if math.IsNaN(value) || math.IsInf(value, 0) {
		return false, false
	}
	if probeKind == "icmp" {
		return value >= 100, true
	}
	return value < 0.5, true
}

// icmpRoundComplete reports whether an ICMP cycle sent everything it was
// configured to send, so its loss ratio may be trusted with a verdict.
//
// A missing count fails CLOSED (no verdict): every collector in this build emits
// probe.icmp.sent, so its absence is a producer regression, and waving it
// through would silently restore the truncated-round behaviour the count exists
// to catch. A missing CONFIGURED count fails open, because that is this agent's
// own bookkeeping being unreadable and the comparison is then inapplicable
// rather than failed.
func icmpRoundComplete(hasSent bool, sent, want int) bool {
	if want <= 0 {
		return true
	}
	if !hasSent {
		return false
	}
	return sent >= want
}
