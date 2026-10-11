package collector

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/nettact/agent/internal/netguard"
	"github.com/nettact/agent/internal/traceroute"
	"github.com/nettact/agent/internal/tracetrigger"
	pcfg "github.com/nettact/protocol/config"
	"github.com/nettact/protocol/permission"
	"github.com/nettact/protocol/telemetry"
)

// Route-monitor metric kinds. They are defined here rather than beside the
// other probe kinds in protocol/telemetry because nothing but this collector
// emits them and nothing in the shared types needs to name them; the strings
// follow the same probe.<kind>.<measure> shape, so a receiver treats them like
// any other probe series.
//
// The sweep itself travels as a TraceResult; these three are the summary a
// time-series chart can draw without reading hop tables.
const (
	// TraceReached: 1 when the destination itself answered, else 0.
	TraceReached telemetry.MetricKind = "probe.trace.reached"
	// TraceHopCount: the TTL the destination answered at, or — not reached —
	// the highest TTL anything answered at (0 when nothing did).
	TraceHopCount telemetry.MetricKind = "probe.trace.hop_count"
	// TraceDestRTT: mean RTT of the destination's own replies at the reached
	// TTL. Emitted only when reached; an unreached sweep has no destination RTT,
	// and a zero would read as an impossibly fast one.
	TraceDestRTT telemetry.MetricKind = "probe.trace.dest_rtt_ms"
)

// traceBusyRetry is how soon a route monitor whose sweep found the machine's
// trace budget busy is tried again. Short next to the interval (a default
// monitor runs every ten minutes, so losing a whole one to a busy budget would
// halve its sampling during exactly the incidents that occupy the budget), long
// next to a sweep's typical length, so a backlog of monitors due together —
// every one of them, on the first tick after the agent starts — drains in a few
// rounds rather than retrying on every one-second tick.
const traceBusyRetry = time.Minute

// traceRunFunc runs one scheduled sweep. Satisfied by (*traceroute.Engine).TryRun;
// injected so tests can drive the collector without a raw socket.
type traceRunFunc func(ctx context.Context, req traceroute.Request, decidedAt time.Time) (telemetry.TraceResult, bool)

// TraceCollector runs periodic route monitors (probe kind "trace"): one bounded
// traceroute per target per interval, reported as a TraceResult stamped with the
// monitor id and generation, plus three summary metrics.
//
// It drives the same traceroute engine incident diagnosis uses, so a route
// sample and a diagnosis sweep of one destination are the same measurement made
// for different reasons — same TTL walk, same per-attempt budgeting, same
// destination resolution through the target-access guard, same reverse-DNS
// bounds. What differs is admission. A diagnosis waits for a slot in the
// machine-wide trace budget; a route sample takes one only if it is free right
// now and inside the share diagnosis cannot be crowded out of (see
// traceroute.Limiter), and otherwise retries shortly. A route sample can always
// be taken again; evidence about an outage cannot.
//
// It does not draw on the probe budget (ProbeGate) as well. That budget paces
// the short probes, and a sweep may legitimately hold its slot for minutes;
// holding one of those for that long would starve the ping cycles to protect a
// resource the trace limiter already bounds on its own.
//
// It is built in the lite (router) build too, unlike incident scenes. The
// engine already ships there for diagnosis, so it adds no code; the router is
// usually the device that owns the WAN uplink, which makes it the best vantage
// point a route history can have; and the outbox cost that keeps scenes off
// lite does not apply the same way — a sweep is one record per monitor per
// interval, the interval is floored at five minutes whatever the push says, and
// the permission is off by default, so a router spends nothing on it unless
// someone deliberately asked for route monitoring there.
//
// Scheduling is the shared probeRunner/schedState machinery, so a generation
// edit cancels the old sweep and a new generation runs on the next tick. The
// runner is a named field rather than embedded so the collector does not
// advertise a probe budget it never draws from.
type TraceCollector struct {
	runner *probeRunner
	run    traceRunFunc
}

// NewTraceCollector builds the route-monitor collector for one server.
//
// granted and supported are that server's views. Authority for a scheduled
// sweep is permission.ProbeTraceroute, not the diagnostic pair the engine
// adjudicates, so the engine this collector drives is handed a translated view
// (scheduledTraceViews) instead of the server's own; lim is the machine-wide
// trace budget — pass the same one every engine of every server shares.
func NewTraceCollector(guard *netguard.Guard, granted, supported permission.Set, lim *traceroute.Limiter) *TraceCollector {
	eff, gr, sup := scheduledTraceViews(granted, supported)
	// No egress resolver: a route monitor never runs over a proxy (monitoreval
	// refuses a pinned one), and the engine fails closed on any egress request
	// without one.
	e := traceroute.New(guard, eff, gr, sup, lim, nil)
	return newTraceCollector(e.TryRun)
}

func newTraceCollector(run traceRunFunc) *TraceCollector {
	c := &TraceCollector{runner: newProbeRunner(pcfg.DefaultTraceInterval, nil), run: run}
	c.SetMinInterval(0)
	return c
}

// scheduledTraceViews translates a server's views into the ones the traceroute
// engine adjudicates a scheduled sweep under.
//
// The engine knows one authority per mode — diagnostic.traceroute.icmp/tcp —
// and that is right for a diagnosis. A route monitor is authorized by a
// different grant (probe.traceroute: a standing sweep every interval, not an
// occasional one when something already failed), so holding the diagnostic pair
// must not be enough to run one, and holding probe.traceroute must not need it.
// Mapping the one grant onto both modes, and keeping the server's per-mode
// capability as it is, reuses every refusal the engine already makes: a TCP
// monitor on a machine that cannot observe TCP-traceroute replies comes back
// unsupported with the engine's own reason, rather than quietly running as ICMP
// — a different measurement that would be filed as the same route history.
//
// Why not teach the engine a third permission: the engine is shared with
// diagnosis, whose adjudication is subtle (the egress grant-only rule), and the
// translation keeps that code path byte-for-byte what it was.
func scheduledTraceViews(granted, supported permission.Set) (effective, gr, sup permission.Set) {
	modes := []permission.ID{permission.DiagnosticTracerouteICMP, permission.DiagnosticTracerouteTCP}
	gr, sup = permission.Set{}, permission.Set{}
	for _, id := range modes {
		if granted.Has(permission.ProbeTraceroute) {
			gr.Add(id)
		}
		if supported.Has(id) {
			sup.Add(id)
		}
	}
	return permission.EffectiveFrom(gr, sup), gr, sup
}

func (c *TraceCollector) Name() string { return "trace" }

func (c *TraceCollector) Tier() Tier { return TierRegular }

// SetTargets keeps the route monitors. A pinned (ProxyID) target is dropped as
// defense in depth — monitoreval already reports it un-runnable, and a sweep
// over the host stack would measure a path the monitor was not configured for.
func (c *TraceCollector) SetTargets(targets []pcfg.ProbeTarget) {
	var tr []pcfg.ProbeTarget
	for _, t := range targets {
		if t.Kind == "trace" && t.Target != "" && t.ProxyID == "" {
			tr = append(tr, t)
		}
	}
	c.runner.setTargets(tr)
}

// SetMinInterval applies the agent-local probe-interval floor, itself floored at
// config.MinTraceInterval. The server validates the same minimum, but the agent
// enforces it regardless of what it is pushed: a sweep is up to MaxHops x
// AttemptsPerHop probes, and a malformed or older push must not turn a route
// monitor into a packet generator.
func (c *TraceCollector) SetMinInterval(d time.Duration) {
	if d < pcfg.MinTraceInterval {
		d = pcfg.MinTraceInterval
	}
	c.runner.SetMinInterval(d)
}

// WaitIdle blocks until every in-flight sweep has returned (see probeRunner).
func (c *TraceCollector) WaitIdle() { c.runner.WaitIdle() }

// Collect hands back the sweeps finished since the last pass and starts the
// targets that have come due.
func (c *TraceCollector) Collect(ctx context.Context) (Result, error) {
	return c.runner.collect(ctx, c.runTarget), nil
}

// runTarget runs one target's sweep on its own goroutine.
func (c *TraceCollector) runTarget(ctx context.Context, sp scheduledProbe) (Result, func(*Result)) {
	t := sp.Target
	if ctx.Err() != nil {
		return Result{}, nil
	}
	tr, ok := c.run(ctx, traceRequest(t, "trace_"+uuid.NewString()), time.Now())
	if !ok {
		// The budget was busy. Nothing was probed, so nothing is reported, and the
		// target is retried soon rather than a whole interval later. finish then
		// records the run as not having reported, so a first sweep stays a first.
		c.runner.sched.retryAt(sp, time.Now().Add(traceBusyRetry))
		return Result{}, nil
	}
	if ctx.Err() != nil || tr.Status == telemetry.TraceStatusCanceled {
		// Shutdown or a superseded generation: a half-walked path is not a sample.
		return Result{}, nil
	}
	if tr.Reason == traceroute.ReasonPolicyDenied {
		// The target-access guard refused the destination (typically a hostname
		// that resolved into a denied range). Every other collector surfaces that
		// as a monitor block, not as a probe outcome, and so does this one: an
		// empty route sample would read as "the path is unknown", when the truth
		// is "this agent may not look".
		return Result{Blocked: []BlockedProbe{{
			MonitorID: t.MonitorID, ConfigSerial: t.ConfigSerial, Reason: "resolved_denied",
		}}}, nil
	}
	tr.MonitorID = t.MonitorID
	tr.ConfigSerial = t.ConfigSerial
	return Result{TraceResults: []telemetry.TraceResult{tr}, Metrics: traceMetrics(t, tr)}, nil
}

// traceRequest maps a route monitor's params onto an engine request, filling the
// protocol defaults (config/schedule.go) for every field left at zero.
//
// An unrecognised TraceMode is passed through rather than defaulted: the engine
// refuses it as invalid_mode, which is the honest report for a push this agent
// does not understand — running it as ICMP would file a different measurement
// under the monitor's history.
func traceRequest(t pcfg.ProbeTarget, reportID string) traceroute.Request {
	p := t.Params
	mode := p.TraceMode
	if mode == "" {
		mode = pcfg.TraceModeICMP
	}
	port := 0
	if mode == pcfg.TraceModeTCP {
		port = p.Port
		if port <= 0 {
			port = pcfg.DefaultTraceTCPPort
		}
	}
	maxHops := p.MaxHops
	if maxHops <= 0 {
		maxHops = pcfg.DefaultTraceMaxHops
	}
	attempts := p.AttemptsPerHop
	if attempts <= 0 {
		attempts = pcfg.DefaultTraceAttemptsPerHop
	}
	// Keyed exactly as a diagnosis of the same destination would be, so the two
	// kinds of report about one destination agree on what it is called.
	destKey, destHost := tracetrigger.CanonicalDest(t.Target)
	return traceroute.Request{
		ReportID: reportID,
		Mode:     mode,
		DestKey:  destKey,
		DestHost: destHost,
		Port:     port,

		SubjectKind:   telemetry.TraceSubjectTarget,
		TriggerReason: telemetry.TraceTriggerScheduled,

		MaxHops:             maxHops,
		AttemptsPerHop:      attempts,
		TotalTimeoutMs:      int(pcfg.CycleDeadline("trace", p) / time.Millisecond),
		PerHopTimeoutMs:     p.TimeoutMs,
		ResolveHopHostnames: true,
	}
}

// traceMeasured reports whether a finished sweep says something about the path,
// and so deserves summary metrics. A completed, partial or timed-out walk does;
// so do the refusals that ARE the path's answer — no route from this host, a
// name that does not resolve, a destination with no IPv4 address. A capability
// gap, an invalid push or an engine fault measured nothing: the TraceResult
// still carries the reason, but a reached=0 sample would chart as an outage.
func traceMeasured(tr telemetry.TraceResult) bool {
	switch tr.Status {
	case telemetry.TraceStatusSucceeded, telemetry.TraceStatusPartial, telemetry.TraceStatusTimedOut:
		return true
	case telemetry.TraceStatusFailed:
		switch tr.Reason {
		case traceroute.ReasonLocalNoRoute, traceroute.ReasonDNSError, traceroute.ReasonNoIPv4:
			return true
		}
	}
	return false
}

// traceMetrics summarizes one sweep as probe.trace.* samples, stamped with the
// monitor id and generation like every other probe series.
func traceMetrics(t pcfg.ProbeTarget, tr telemetry.TraceResult) []telemetry.Metric {
	if !traceMeasured(tr) {
		return nil
	}
	ts := tr.StartedAt
	if ts.IsZero() {
		ts = tr.CompletedAt
	}
	if ts.IsZero() {
		ts = time.Now().UTC()
	}
	mk := func(kind telemetry.MetricKind, v float64, unit string) telemetry.Metric {
		return telemetry.Metric{TS: ts, Kind: kind, Target: t.Target, Layer: telemetry.LayerInternet,
			Value: v, Unit: unit, MonitorID: t.MonitorID, ConfigSerial: t.ConfigSerial}
	}
	reached := 0.0
	if tr.Reached {
		reached = 1
	}
	out := []telemetry.Metric{
		mk(TraceReached, reached, telemetry.UnitBool),
		mk(TraceHopCount, float64(traceHopCount(tr)), telemetry.UnitCount),
	}
	if rtt, ok := traceDestRTT(tr); ok {
		out = append(out, mk(TraceDestRTT, rtt, telemetry.UnitMs))
	}
	return out
}

// traceHopCount is the reached TTL, or the highest TTL with any responder.
func traceHopCount(tr telemetry.TraceResult) int {
	if tr.Reached && tr.ReachedTTL > 0 {
		return tr.ReachedTTL
	}
	last := 0
	for _, h := range tr.Hops {
		for _, a := range h.Attempts {
			if !a.Timeout && a.ResponderAddr != "" && h.TTL > last {
				last = h.TTL
			}
		}
	}
	return last
}

// traceDestRTT is the mean RTT of the destination's replies at the reached TTL.
// Replies from another responder at that TTL (a load-balanced last hop answering
// one attempt) are not the destination's and are left out.
func traceDestRTT(tr telemetry.TraceResult) (float64, bool) {
	if !tr.Reached {
		return 0, false
	}
	var sum float64
	n := 0
	for _, h := range tr.Hops {
		if h.TTL != tr.ReachedTTL {
			continue
		}
		for _, a := range h.Attempts {
			if a.Timeout || a.ResponderAddr == "" {
				continue
			}
			if tr.DestinationIP != "" && a.ResponderAddr != tr.DestinationIP {
				continue
			}
			sum += a.RTTMs
			n++
		}
	}
	if n == 0 {
		return 0, false
	}
	return sum / float64(n), true
}
