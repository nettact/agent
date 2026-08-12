package collector

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"hash/fnv"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/nettact/agent/internal/netguard"
	"github.com/nettact/agent/internal/proxydial"
	pcfg "github.com/nettact/protocol/config"
	"github.com/nettact/protocol/telemetry"
)

// TCPCollector performs a TCP connect (optionally followed by a TLS handshake)
// against a server-configured host:port set (a TCP port monitor).
// Each target carries its own per-protocol params (port, tls, timeout, interval)
// and is probed on its own schedule and its own goroutine via probeRunner.
type TCPCollector struct {
	guard   *netguard.Guard
	proxies *proxydial.Manager
	*probeRunner
	// flowPrev keeps each monitor's previous fan-out cycle's per-flow failure
	// flags, keyed by monitorID, so a deterministic bad subset (bad_stable) is
	// distinguishable from a flapping one (bad_new) across consecutive cycles —
	// the reproducibility that pinned source ports exist to create. The config
	// serial the history was measured under travels with it: a material config
	// edit re-derives the flow ports (the serial is in the seed), so the new set
	// starts a fresh history rather than being compared against a different port
	// set. Cycles run on separate goroutines, hence the mutex.
	flowPrev   map[string]flowPrevState
	flowPrevMu sync.Mutex
}

// flowPrevState is one monitor's previous fan-out cycle: the per-flow failure
// flags in flow-plan order, and the config serial that cycle ran under.
type flowPrevState struct {
	serial int
	bad    []bool
}

// NewTCPCollector builds the collector. gate is the machine-wide probe budget —
// pass the same one to every collector of every server; nil means unlimited.
func NewTCPCollector(guard *netguard.Guard, proxies *proxydial.Manager, gate *ProbeGate) *TCPCollector {
	return &TCPCollector{
		guard: guard, proxies: proxies,
		flowPrev: map[string]flowPrevState{},
		probeRunner: newProbeRunner(pcfg.DefaultTCPInterval, gate),
	}
}

func (c *TCPCollector) SetTargets(targets []pcfg.ProbeTarget) {
	var tcp []pcfg.ProbeTarget
	for _, t := range targets {
		if t.Kind == "tcp" && t.Target != "" && t.Params.Port > 0 {
			tcp = append(tcp, t)
		}
	}
	c.setTargets(tcp)
}

func (c *TCPCollector) Name() string { return "tcp" }

func (c *TCPCollector) Tier() Tier { return TierRegular }

// Collect hands back the probes that finished since the last pass and starts the
// targets that have come due — see probeRunner for why they no longer run inline.
func (c *TCPCollector) Collect(ctx context.Context) (Result, error) {
	return c.collect(ctx, c.runTarget), nil
}

// runTarget probes one target on its own goroutine, under a slot from the
// machine-wide budget (acquired inside probe — the fan-out path hands it back
// before its concurrent flow dials).
func (c *TCPCollector) runTarget(ctx context.Context, sp scheduledProbe) (Result, func(*Result)) {
	t := sp.Target
	// A pass aborted by run cancellation (agent shutdown) must not fabricate
	// connect failures — they would replay from the WAL as a false service
	// outage on the next start (probe drops its own aborted result too).
	if ctx.Err() != nil {
		return Result{}, nil
	}
	var res Result
	c.probe(ctx, time.Now().UTC(), t, gateWaitDeadline(sp.NextDue, tcpTimeout(t.Params)), &res)
	return res, nil
}

// tcpTimeout is the per-probe budget: the configured TimeoutMs, else the default.
// It bounds the whole probe (resolve + connect + TLS), which is what
// pcfg.CycleDeadline derives for a tcp target.
func tcpTimeout(p pcfg.ProbeParams) time.Duration {
	if p.TimeoutMs > 0 {
		return time.Duration(p.TimeoutMs) * time.Millisecond
	}
	return pcfg.DefaultTCPTimeout
}

// flowPorts derives a fan-out cycle's source ports: base..base+n-1 where base is
// deterministic in the target, so the same flow set repeats every cycle. That
// stability is what makes a bad subset reproducible — ECMP/LAG hashing keys on
// the full five-tuple, so the same source port hits the same member every time,
// and a bad member shows up as the same flows failing cycle after cycle. The
// config serial is in the seed, so a material config edit (even one that leaves
// the target and port untouched) starts a fresh, unrelated port set.
func flowPorts(targetIP string, port int, monitorID string, configSerial, n int) []int {
	h := fnv.New32a()
	h.Write([]byte(fmt.Sprintf("%s:%d:%s:%d", targetIP, port, monitorID, configSerial)))
	base := 10000 + int(h.Sum32()%22000)
	out := make([]int, n)
	for i := range out {
		out[i] = base + i
	}
	return out
}

// classifyFlowFanout classifies one fan-out cycle's per-flow outcomes into the
// probe.tcp.flow_fanout code. Codes:
//
//	4 = insufficient — fewer than two flows ran (could not bind enough source
//	    ports, or the cycle's budget cut it short)
//	3 = all flows failed — target unreachable, not merely degraded
//	2 = member-level — a deterministic bad subset (bad_stable>0) while some flows
//	    stay clean: the ECMP/LAG member fault the fan-out exists to find
//	1 = uniform — no deterministic bad subset (all clean, or failures flapping
//	    across flows)
//
// bad_stable / bad_new come from the one-cycle history flowOutcome keeps; this
// function only folds the counts.
func classifyFlowFanout(flows, badStable, badNew int) int {
	switch {
	case flows < 2:
		return 4
	case badStable == flows && badNew == 0:
		return 3
	case badStable > 0 && badStable+badNew < flows:
		return 2
	default:
		return 1
	}
}

// flowOutcome folds one cycle's per-flow outcomes into the flow_fanout facts and
// advances the monitor's history. attempted[i] reports that flow i actually bound
// a source port and dialed; bad[i] that the dial failed. It returns the
// classification code plus the label counts (flows / bad_stable / bad_new / ok)
// per the contract in protocol/telemetry. A flow that did not run this cycle
// carries no verdict, so it is absent from every count; the ok count therefore
// also rises when a flow was clean this cycle and was not measured (or was clean)
// last cycle.
func (c *TCPCollector) flowOutcome(monitorID string, configSerial int, attempted, bad []bool) (code, flows, badStable, badNew, okCount int) {
	c.flowPrevMu.Lock()
	defer c.flowPrevMu.Unlock()
	prev, have := c.flowPrev[monitorID]
	if !have || prev.serial != configSerial {
		prev = flowPrevState{}
	}
	next := make([]bool, len(attempted))
	for i := range attempted {
		if !attempted[i] {
			continue
		}
		flows++
		prevBad := i < len(prev.bad) && prev.bad[i]
		next[i] = bad[i]
		switch {
		case bad[i] && prevBad:
			badStable++
		case bad[i]:
			badNew++
		case !prevBad:
			okCount++
		}
	}
	c.flowPrev[monitorID] = flowPrevState{serial: configSerial, bad: next}
	return classifyFlowFanout(flows, badStable, badNew), flows, badStable, badNew, okCount
}

// probe runs one TCP cycle: it times DNS resolution, the pure TCP connect, and
// (when enabled) the TLS handshake as separate segments so a slow-DNS vs
// slow-connect vs slow-TLS problem is separable, and classifies the failure. Each
// segment's latency is emitted only when THAT segment succeeded — a failure is
// never recorded as a zero-latency sample; probe.tcp.error_class carries the
// reason and probe.tcp.ok the overall outcome (both every cycle).
func (c *TCPCollector) probe(ctx context.Context, now time.Time, t pcfg.ProbeTarget, gateDeadline time.Time, res *Result) {
	timeout := tcpTimeout(t.Params)
	// The cycle's slot is acquired HERE — inside probe — so the fan-out path can
	// hand it back before its concurrent flow dials (each of which acquires its
	// own slot). Acquired in runTarget, the slot would be held for the whole
	// probe and the flows would re-acquire under it: N+1 slots for N dials, which
	// self-starves completely at a budget of 1.
	if gate := c.gate; gate.Acquire(ctx, gateDeadline) != AdmittedOK {
		// Cancelled (shutdown or a superseded generation) or shut out by the
		// budget. Either way nothing was measured, and a fabricated connect
		// failure would replay from the WAL as a false service outage.
		return
	}
	gateHeld := true
	defer func() {
		if gateHeld {
			c.gate.Release()
		}
	}()
	port := strconv.Itoa(t.Params.Port)
	labels := map[string]string{"port": port}
	mk := func(kind telemetry.MetricKind, v float64, unit string) telemetry.Metric {
		return telemetry.Metric{TS: now, Kind: kind, Target: t.Target, Layer: telemetry.LayerService,
			Value: v, Unit: unit, Labels: labels, MonitorID: t.MonitorID, ConfigSerial: t.ConfigSerial}
	}

	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Resolve the pinned egress proxy first: a pin that cannot be honored means the
	// probe is not attempted at all (fail-closed — never a direct connect, which
	// would measure a path the operator did not configure).
	proxy, prerr := resolveProxy(ctx, c.proxies, t)
	if prerr != nil {
		res.Metrics = append(res.Metrics, proxyFailureMetrics(now, t, telemetry.TCPOK, telemetry.TCPErrorClass, labels, prerr)...)
		res.Events = append(res.Events, proxyFailureEvent(now, t, "TCP connect not attempted"))
		return
	}
	// Proxy-side DNS means the agent does not resolve at all, so there is no
	// resolution segment to time: dns_ms is ABSENT rather than zero, matching this
	// package's rule that a segment which did not happen is never reported as a
	// zero-latency sample.
	remoteDNS := proxy != nil && proxy.ResolvesRemotely()

	// Phase 1 — resolution. A literal-IP target has no DNS segment (dns_ms is
	// absent, not zero). A hostname is policy-checked before any query, then the
	// vetted resolution is timed and the vetted literal IPs are dialed directly —
	// the raw name never reaches the stdlib dialer (DNS-rebinding defense). With a
	// proxy in local DNS mode the same vetting happens and the approved literal is
	// what the proxy is asked to connect to, so the defense survives the proxy.
	literal := false
	var vetted []netip.Addr
	var dnsMs float64
	haveDNS := false
	if _, perr := netip.ParseAddr(t.Target); perr == nil {
		literal = true
	} else if remoteDNS {
		// The name is handed to the proxy verbatim. monitoreval already refused this
		// combination unless the policy authorizes the name, so no check is repeated.
	} else {
		hd := c.guard.CheckHost(t.Target)
		if hd.Denied {
			res.Blocked = append(res.Blocked, BlockedProbe{MonitorID: t.MonitorID, ConfigSerial: t.ConfigSerial, Matched: hd.Matched, Reason: "resolved_denied"})
			return
		}
		r0 := time.Now()
		v, err := c.guard.ResolveVetted(cctx, t.Target, hd.NameAuthorized)
		if err != nil {
			var be *netguard.BlockedError
			if errors.As(err, &be) {
				res.Blocked = append(res.Blocked, blockedFromErr(t, be))
				return
			}
			if ctx.Err() != nil {
				return // resolution aborted by the cancelled run, not a DNS fault
			}
			// Plain resolution failure: down, classified as finely as the resolver
			// error allows — the failing phase IS resolution, so an error the
			// classifier cannot place still lands in the DNS family. No dns_ms (the
			// resolution did not produce a valid latency).
			reason := classifyNetError(err)
			if reason == telemetry.ProbeReasonOther {
				reason = telemetry.ProbeReasonDNS
			}
			ec := mk(telemetry.TCPErrorClass, float64(reason), telemetry.UnitCode)
			ec.Labels = withDetail(labels, errText(err))
			res.Metrics = append(res.Metrics, mk(telemetry.TCPOK, 0, telemetry.UnitBool), ec)
			res.Events = append(res.Events, telemetry.Event{
				ID: newID(), TS: now, Type: telemetry.EventProbeFailed, Layer: telemetry.LayerService,
				Severity: telemetry.SeverityWarn, Message: "TCP DNS resolution failed: " + t.Target,
			})
			return
		}
		dnsMs = msSince(r0)
		haveDNS = true
		vetted = v
	}

	// Phase 2 — pure TCP connect. Timed alone, so connect_ms excludes DNS and TLS.
	// A literal-IP target dials directly (full CheckAddr); a resolved hostname dials
	// its vetted addresses in order via DialVettedAddrs — preserving BOTH the
	// per-address fallback and the hostname-authorization semantics that the guard's
	// own DialContext applies (pinning one IP through DialContext would rerun the
	// full allowlist and drop the fallback).
	//
	// A PROXIED connect goes through the proxy's tunnelled dial instead. It is handed
	// the vetted literal under local DNS mode (so the address the policy approved is
	// the address the proxy reaches) or the hostname under remote mode. The guard's
	// per-address fallback does not apply here: the proxy owns the connection attempt,
	// so only the first vetted address is offered.
	//
	// A source-port FAN-OUT (ProbeParams.FlowFanout >= 2, direct dial only) replaces
	// the single connect with FlowFanout connects from deterministic pinned source
	// ports against ONE vetted literal destination. Aggregate semantics: probe.tcp.ok
	// is 1 only when every flow succeeded; connect_ms is the mean over successful
	// flows (emitted when at least one succeeded); error_class carries the first
	// failing flow's reason; TLS still runs on flow 0 only. The per-flow outcomes
	// feed probe.tcp.flow_fanout below.
	fanout := t.Params.FlowFanout
	fanoutOn := fanout >= 2 && proxy == nil // a proxied local endpoint belongs to the tunnel and cannot be pinned

	addr := net.JoinHostPort(t.Target, port)
	var (
		conn          net.Conn
		connectOK     bool
		connectMs     float64
		haveConnectMs bool
		errClass      = telemetry.ProbeReasonNone
		detail        string
		atTarget      = true // a direct dial is always about the target
		fanoutCode    int
		fanoutLabels  map[string]string
		// noMeasurement marks a fan-out cycle in which no flow actually reached
		// the target (every source-port bind failed locally, or the cycle budget
		// expired first). Such a cycle emits no availability verdict at all.
		noMeasurement bool
	)
	if fanoutOn {
		// Hand the cycle's slot back to the budget: the concurrent flow dials
		// below each acquire their own, so the cycle must not hold N+1 slots for
		// N dials (see the gateHeld note at the acquisition above).
		c.gate.Release()
		gateHeld = false
		// The destination every flow dials: the vetted literal. A literal target is
		// already one; a hostname pins the fan-out to its first vetted address. The
		// per-address fallback has no place here — a stable five-tuple is the whole
		// point (ECMP/LAG hashing), so every flow must hit the same destination.
		dst := t.Target
		if !literal {
			dst = vetted[0].String()
		}
		ports := flowPorts(dst, t.Params.Port, t.MonitorID, t.ConfigSerial, fanout)
		var (
			firstBad     = telemetry.ProbeReasonNone
			firstBadIdx  = -1
			firstDetail  string
			attempted    = make([]bool, fanout)
			bad          = make([]bool, fanout)
			successFlows int
			msSum        float64
		)
		// The flows dial CONCURRENTLY, not sequentially: a silently-dropped SYN on
		// one bad ECMP member (a full per-flow timeout) must not consume the shared
		// cycle deadline and starve every later flow — if the bad member happened to
		// be flow 0, sequential dials would collapse the fan-out to one sample per
		// cycle and the deterministic bad subset would never be observed. Each flow
		// is independently bounded by the single-dial timeout, so the whole fan-out
		// completes within roughly one tcpTimeout (the cycle deadline) no matter how
		// many members are silently dropping SYNs.
		{
			var (
				blockedOnce sync.Once
				blockedErr  *netguard.BlockedError
				wg          sync.WaitGroup
			)
			// out[i] is written by exactly one goroutine (its own index), so no lock
			// guards it. The TLS candidate conn is selected AFTER Wait from the
			// lowest-index successful flow, so it is deterministic across cycles —
			// whichever goroutine happened to finish first must not decide which path
			// a TLS handshake rides (each pinned source port can traverse a different
			// ECMP member).
			out := make([]struct {
				attempted bool
				bad       bool
				ok        bool
				ms        float64
				reason    int
				detail    string
				conn      net.Conn
			}, fanout)
			for i := 0; i < fanout; i++ {
				// A flow that could not start before the cycle's deadline is not
				// evidence: it is excluded rather than counted bad, so budget
				// exhaustion can never fabricate a deterministic bad subset. A flow
				// that STARTED and ran out of its own budget is a failure, exactly as
				// a single dial that times out is.
				if cctx.Err() != nil {
					break
				}
				wg.Add(1)
				go func(i int) {
					defer wg.Done()
					fctx, fcancel := context.WithTimeout(cctx, tcpTimeout(t.Params))
					defer fcancel()
					// Each flow dial is accounted against the machine-wide probe
					// budget like every other socket operation: without this a
					// fan-out would burst fanout × targets concurrent dials past
					// max_probe_concurrency. A flow the budget refuses is skipped
					// (no measurement), exactly as a truncated ICMP cycle is.
					dl, _ := fctx.Deadline()
					if gate := c.gate; gate.Acquire(fctx, dl) != AdmittedOK {
						return
					}
					defer c.gate.Release()
					c0 := time.Now()
					fconn, ferr := c.guard.DialSourcePort(fctx, "tcp", net.JoinHostPort(dst, port), ports[i], t.Target)
					ms := msSince(c0)
					if ferr != nil {
						var be *netguard.BlockedError
						if errors.As(ferr, &be) {
							blockedOnce.Do(func() { blockedErr = be })
							return
						}
						if isAddrInUse(ferr) {
							// The local source port is taken: this flow never happened,
							// so it is neither a flow nor a verdict about the target —
							// it is simply skipped. If every flow lands here, the cycle
							// reports no measurement at all rather than an outage (see
							// noMeasurement).
							return
						}
						out[i].attempted = true
						out[i].bad = true
						out[i].reason = classifyNetError(ferr)
						out[i].detail = errText(ferr)
						return
					}
					out[i].attempted = true
					out[i].ok = true
					out[i].ms = ms
					out[i].conn = fconn
				}(i)
			}
			wg.Wait()
			if blockedErr != nil {
				res.Blocked = append(res.Blocked, blockedFromErr(t, blockedErr))
				return
			}
			// Deterministic TLS candidate: the LOWEST-index successful flow's
			// connection. connectOK requires every attempted flow to succeed, so a
			// non-nil conn is guaranteed whenever connectOK is true — and flow 0
			// failing to bind locally while the rest succeed can never leave conn nil
			// (which would make the later tls.Client(nil, …) panic, and the runner
			// does not recover panics).
			for i := range out {
				if out[i].conn == nil {
					continue
				}
				if conn == nil {
					conn = out[i].conn
				} else {
					_ = out[i].conn.Close()
				}
			}
			for i, o := range out {
				if o.attempted {
					attempted[i] = true
				}
				if o.bad {
					bad[i] = true
					if firstBadIdx < 0 {
						firstBad, firstBadIdx, firstDetail = o.reason, i, o.detail
					}
				}
				if o.ok {
					successFlows++
					msSum += o.ms
				}
			}
		}
		flows := 0
		for _, a := range attempted {
			if a {
				flows++
			}
		}
		// If nothing was actually attempted — every derived source port was locally
		// in use, or the cycle deadline expired before any flow started — no
		// connection ever reached the target, so the condition is LOCAL, not a
		// verdict about the service. The cycle reports no availability sample at
		// all (see the emission below) rather than fabricating an outage from a
		// bind error.
		noMeasurement = flows == 0
		connectOK = flows > 0 && successFlows == flows
		if successFlows > 0 {
			connectMs = msSum / float64(successFlows)
			haveConnectMs = true
		}
		switch {
		case firstBadIdx >= 0:
			errClass, detail = firstBad, firstDetail
		}
		code, flowsN, badStable, badNew, okN := c.flowOutcome(t.MonitorID, t.ConfigSerial, attempted, bad)
		fanoutCode = code
		fanoutLabels = make(map[string]string, len(labels)+4)
		for k, v := range labels {
			fanoutLabels[k] = v
		}
		fanoutLabels[telemetry.FlowFanoutFlowsLabel] = strconv.Itoa(flowsN)
		fanoutLabels[telemetry.FlowFanoutBadStableLabel] = strconv.Itoa(badStable)
		fanoutLabels[telemetry.FlowFanoutBadNewLabel] = strconv.Itoa(badNew)
		fanoutLabels[telemetry.FlowFanoutOKLabel] = strconv.Itoa(okN)
	} else {
		var dialErr error
		c0 := time.Now()
		switch {
		case proxy != nil:
			conn, dialErr = proxy.DialContext(cctx, "tcp", proxyTargetAddress(proxy, t.Target, port, vetted))
		case literal:
			conn, dialErr = c.guard.DialContext(cctx, "tcp", addr)
		default:
			conn, dialErr = c.guard.DialVettedAddrs(cctx, "tcp", vetted, port, t.Target)
		}
		connectMs = msSince(c0)
		connectOK = dialErr == nil
		haveConnectMs = connectOK

		// A literal-IP connect can still hit a policy block (surfaced by the guard).
		var be *netguard.BlockedError
		if errors.As(dialErr, &be) {
			res.Blocked = append(res.Blocked, blockedFromErr(t, be))
			return
		}
		// A proxied target configured for a fan-out cannot pin its local endpoint: it
		// runs single-flow and reports the unsupported code 0 with nothing bound.
		if fanout >= 2 {
			fanoutCode = 0
			fanoutLabels = make(map[string]string, len(labels)+4)
			for k, v := range labels {
				fanoutLabels[k] = v
			}
			fanoutLabels[telemetry.FlowFanoutFlowsLabel] = "0"
			fanoutLabels[telemetry.FlowFanoutBadStableLabel] = "0"
			fanoutLabels[telemetry.FlowFanoutBadNewLabel] = "0"
			fanoutLabels[telemetry.FlowFanoutOKLabel] = "0"
		}
		if !connectOK {
			// The failing dial is classified proxy-aware: a dead or rejecting proxy
			// must not be reported as a closed service — that is the distinction the
			// whole proxy_* family exists to preserve.
			errClass, atTarget = classifyProxyAwareError(dialErr, proxy != nil)
			detail = errText(dialErr)
		}
	}

	// Phase 3 — optional TLS handshake over the live connection, timed alone.
	var tlsMs float64
	haveTLS := false
	var tlsErr error
	if connectOK && t.Params.TLS {
		tconn := tls.Client(conn, &tls.Config{
			ServerName:         t.Target,
			InsecureSkipVerify: t.Params.IgnoreTLS,
		})
		h0 := time.Now()
		tlsErr = tconn.HandshakeContext(cctx)
		tlsMs = msSince(h0)
		conn = tconn
		haveTLS = tlsErr == nil
	}
	if conn != nil {
		_ = conn.Close()
	}

	overallOK := connectOK && tlsErr == nil
	if !overallOK && ctx.Err() != nil {
		return // connect/handshake aborted by the cancelled run, not the service
	}
	// A TLS failure overrides the connect-phase classification (it can only happen
	// when the connect succeeded): the failing phase IS the handshake, so an error
	// the classifier cannot refine still lands in the TLS family (expired/untrusted/
	// hostname otherwise).
	if connectOK && tlsErr != nil {
		errClass = telemetry.ProbeReasonTLS
		if code, tlsShaped := classifyTLSError(tlsErr); tlsShaped {
			errClass = code
		}
		detail = errText(tlsErr)
	}

	ok := 0.0
	if overallOK {
		ok = 1.0
	}
	// The raw cause rides only on the error_class sample, on its own copied label
	// map — mk aliases one shared map across the cycle's metrics.
	ec := mk(telemetry.TCPErrorClass, float64(errClass), telemetry.UnitCode)
	if errClass != telemetry.ProbeReasonNone {
		ec.Labels = withDetail(labels, detail)
	}
	if !noMeasurement {
		// A no-measurement cycle (every fan-out flow failed to bind a local source
		// port) carries no ok/error verdict at all: emitting ok=0 here would feed a
		// purely local resource conflict into service availability as a false
		// outage. The round simply carries no availability sample, which the
		// detector reads as "no verdict", not "down".
		res.Metrics = append(res.Metrics,
			mk(telemetry.TCPOK, ok, telemetry.UnitBool),
			ec,
		)
	}
	if haveDNS {
		res.Metrics = append(res.Metrics, mk(telemetry.TCPDNSms, dnsMs, telemetry.UnitMs))
	}
	if haveConnectMs {
		res.Metrics = append(res.Metrics, mk(telemetry.TCPConnectMs, connectMs, telemetry.UnitMs))
	}
	if haveTLS {
		res.Metrics = append(res.Metrics, mk(telemetry.TCPTLSms, tlsMs, telemetry.UnitMs))
	}
	// The fan-out classification rides on every cycle where it applies (code 0 for a
	// proxied target), on its own label map carrying the shared port plus the counts.
	if fanout >= 2 {
		ff := mk(telemetry.TCPFlowFanout, float64(fanoutCode), telemetry.UnitCode)
		ff.Labels = fanoutLabels
		res.Metrics = append(res.Metrics, ff)
	}
	if !overallOK && !noMeasurement {
		msg := "TCP connect failed: " + addr
		if !atTarget {
			// Naming the egress path in the message matters: the operator reading this
			// event must not start by checking a service that was never reached.
			msg = "TCP connect failed at the egress proxy: " + addr
		}
		res.Events = append(res.Events, telemetry.Event{
			ID: newID(), TS: now, Type: telemetry.EventProbeFailed, Layer: telemetry.LayerService,
			Severity: telemetry.SeverityWarn, Message: msg,
		})
	}
}
