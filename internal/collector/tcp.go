package collector

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/netip"
	"strconv"
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
}

// NewTCPCollector builds the collector. gate is the machine-wide probe budget —
// pass the same one to every collector of every server; nil means unlimited.
func NewTCPCollector(guard *netguard.Guard, proxies *proxydial.Manager, gate *ProbeGate) *TCPCollector {
	return &TCPCollector{
		guard: guard, proxies: proxies,
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
// machine-wide budget.
func (c *TCPCollector) runTarget(ctx context.Context, sp scheduledProbe) (Result, func(*Result)) {
	t := sp.Target
	timeout := tcpTimeout(t.Params)
	if gate := c.gate; gate.Acquire(ctx, gateWaitDeadline(sp.NextDue, timeout)) != AdmittedOK {
		// Cancelled (shutdown or a superseded generation) or shut out by the
		// budget. Either way nothing was measured, and a fabricated connect
		// failure would replay from the WAL as a false service outage.
		return Result{}, nil
	}
	defer c.gate.Release()
	// A pass aborted by run cancellation (agent shutdown) must not fabricate
	// connect failures — they would replay from the WAL as a false service
	// outage on the next start (probe drops its own aborted result too).
	if ctx.Err() != nil {
		return Result{}, nil
	}
	// Stamped where the measurement happens: after the wait for a slot, not when
	// the pass that scheduled it began.
	var res Result
	c.probe(ctx, time.Now().UTC(), t, &res)
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

// probe runs one TCP cycle: it times DNS resolution, the pure TCP connect, and
// (when enabled) the TLS handshake as separate segments so a slow-DNS vs
// slow-connect vs slow-TLS problem is separable, and classifies the failure. Each
// segment's latency is emitted only when THAT segment succeeded — a failure is
// never recorded as a zero-latency sample; probe.tcp.error_class carries the
// reason and probe.tcp.ok the overall outcome (both every cycle).
func (c *TCPCollector) probe(ctx context.Context, now time.Time, t pcfg.ProbeTarget, res *Result) {
	timeout := tcpTimeout(t.Params)
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
	addr := net.JoinHostPort(t.Target, port)
	c0 := time.Now()
	var conn net.Conn
	var dialErr error
	switch {
	case proxy != nil:
		conn, dialErr = proxy.DialContext(cctx, "tcp", proxyTargetAddress(proxy, t.Target, port, vetted))
	case literal:
		conn, dialErr = c.guard.DialContext(cctx, "tcp", addr)
	default:
		conn, dialErr = c.guard.DialVettedAddrs(cctx, "tcp", vetted, port, t.Target)
	}
	connectMs := msSince(c0)
	connectOK := dialErr == nil

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

	// A literal-IP connect can still hit a policy block (surfaced by the guard).
	var be *netguard.BlockedError
	if errors.As(dialErr, &be) {
		res.Blocked = append(res.Blocked, blockedFromErr(t, be))
		return
	}

	overallOK := connectOK && tlsErr == nil
	if !overallOK && ctx.Err() != nil {
		return // connect/handshake aborted by the cancelled run, not the service
	}
	errClass := telemetry.ProbeReasonNone
	detail := ""
	// atTarget records whether the failure is the target's. For a proxied probe a
	// dead or rejecting proxy must not be reported as a closed service — that is the
	// distinction the whole proxy_* family exists to preserve.
	atTarget := true
	switch {
	case !connectOK:
		errClass, atTarget = classifyProxyAwareError(dialErr, proxy != nil)
		detail = errText(dialErr)
	case tlsErr != nil:
		// The failing phase IS the handshake, so a TLS error the classifier cannot
		// refine still lands in the TLS family (expired/untrusted/hostname otherwise).
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
	res.Metrics = append(res.Metrics,
		mk(telemetry.TCPOK, ok, telemetry.UnitBool),
		ec,
	)
	if haveDNS {
		res.Metrics = append(res.Metrics, mk(telemetry.TCPDNSms, dnsMs, telemetry.UnitMs))
	}
	if connectOK {
		res.Metrics = append(res.Metrics, mk(telemetry.TCPConnectMs, connectMs, telemetry.UnitMs))
	}
	if haveTLS {
		res.Metrics = append(res.Metrics, mk(telemetry.TCPTLSms, tlsMs, telemetry.UnitMs))
	}
	if !overallOK {
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
