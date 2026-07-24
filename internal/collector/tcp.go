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
	pcfg "github.com/nettact/protocol/config"
	"github.com/nettact/protocol/telemetry"
)

// TCPCollector performs a TCP connect (optionally followed by a TLS handshake)
// against a server-configured host:port set (a TCP port monitor).
// Each target carries its own per-protocol params (port, tls, timeout, interval)
// and is probed on its own schedule via schedState.
type TCPCollector struct {
	sched *schedState
	guard *netguard.Guard
}

func NewTCPCollector(guard *netguard.Guard) *TCPCollector {
	return &TCPCollector{sched: newSchedState(pcfg.DefaultTCPInterval), guard: guard}
}

func (c *TCPCollector) SetTargets(targets []pcfg.ProbeTarget) {
	var tcp []pcfg.ProbeTarget
	for _, t := range targets {
		if t.Kind == "tcp" && t.Target != "" && t.Params.Port > 0 {
			tcp = append(tcp, t)
		}
	}
	c.sched.set(tcp)
}

func (c *TCPCollector) Name() string { return "tcp" }

func (c *TCPCollector) Tier() Tier { return TierRegular }

func (c *TCPCollector) Collect(ctx context.Context) (Result, error) {
	targets := c.sched.due(time.Now())
	if len(targets) == 0 {
		return Result{}, nil
	}

	now := time.Now().UTC()
	var res Result
	for _, t := range targets {
		// A pass aborted by run cancellation (agent shutdown) must not fabricate
		// connect failures — they would replay from the WAL as a false service
		// outage on the next start (probe drops its own aborted result too).
		if ctx.Err() != nil {
			break
		}
		c.probe(ctx, now, t, &res)
	}
	return res, nil
}

// probe runs one TCP cycle: it times DNS resolution, the pure TCP connect, and
// (when enabled) the TLS handshake as separate segments so a slow-DNS vs
// slow-connect vs slow-TLS problem is separable, and classifies the failure. Each
// segment's latency is emitted only when THAT segment succeeded — a failure is
// never recorded as a zero-latency sample; probe.tcp.error_class carries the
// reason and probe.tcp.ok the overall outcome (both every cycle).
func (c *TCPCollector) probe(ctx context.Context, now time.Time, t pcfg.ProbeTarget, res *Result) {
	timeout := time.Duration(t.Params.TimeoutMs) * time.Millisecond
	if timeout <= 0 {
		timeout = pcfg.DefaultTCPTimeout
	}
	port := strconv.Itoa(t.Params.Port)
	labels := map[string]string{"port": port}
	mk := func(kind telemetry.MetricKind, v float64, unit string) telemetry.Metric {
		return telemetry.Metric{TS: now, Kind: kind, Target: t.Target, Layer: telemetry.LayerService,
			Value: v, Unit: unit, Labels: labels, MonitorID: t.MonitorID, ConfigSerial: t.ConfigSerial}
	}

	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Phase 1 — resolution. A literal-IP target has no DNS segment (dns_ms is
	// absent, not zero). A hostname is policy-checked before any query, then the
	// vetted resolution is timed and the vetted literal IPs are dialed directly —
	// the raw name never reaches the stdlib dialer (DNS-rebinding defense).
	literal := false
	var vetted []netip.Addr
	nameAuthorized := false
	var dnsMs float64
	haveDNS := false
	if _, perr := netip.ParseAddr(t.Target); perr == nil {
		literal = true
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
			// Plain resolution failure: down, classified as DNS. No dns_ms (the
			// resolution did not produce a valid latency).
			res.Metrics = append(res.Metrics, mk(telemetry.TCPOK, 0, telemetry.UnitBool),
				mk(telemetry.TCPErrorClass, telemetry.TCPErrDNS, telemetry.UnitCode))
			res.Events = append(res.Events, telemetry.Event{
				ID: newID(), TS: now, Type: telemetry.EventProbeFailed, Layer: telemetry.LayerService,
				Severity: telemetry.SeverityWarn, Message: "TCP DNS resolution failed: " + t.Target,
			})
			return
		}
		dnsMs = msSince(r0)
		haveDNS = true
		vetted = v
		nameAuthorized = hd.NameAuthorized
	}

	// Phase 2 — pure TCP connect. Timed alone, so connect_ms excludes DNS and TLS.
	// A literal-IP target dials directly (full CheckAddr); a resolved hostname dials
	// its vetted addresses in order via DialVettedAddrs — preserving BOTH the
	// per-address fallback and the hostname-authorization semantics that the guard's
	// own DialContext applies (pinning one IP through DialContext would rerun the
	// full allowlist and drop the fallback).
	addr := net.JoinHostPort(t.Target, port)
	c0 := time.Now()
	var conn net.Conn
	var dialErr error
	if literal {
		conn, dialErr = c.guard.DialContext(cctx, "tcp", addr)
	} else {
		conn, dialErr = c.guard.DialVettedAddrs(cctx, "tcp", vetted, port, nameAuthorized)
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
	errClass := telemetry.TCPErrNone
	switch {
	case !connectOK:
		errClass = classifyConnectError(dialErr)
	case tlsErr != nil:
		errClass = telemetry.TCPErrTLS
	}

	ok := 0.0
	if overallOK {
		ok = 1.0
	}
	res.Metrics = append(res.Metrics,
		mk(telemetry.TCPOK, ok, telemetry.UnitBool),
		mk(telemetry.TCPErrorClass, float64(errClass), telemetry.UnitCode),
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
		res.Events = append(res.Events, telemetry.Event{
			ID: newID(), TS: now, Type: telemetry.EventProbeFailed, Layer: telemetry.LayerService,
			Severity: telemetry.SeverityWarn, Message: "TCP connect failed: " + addr,
		})
	}
}

// SetMinInterval applies the local per-target probe-interval floor (stability limit).
func (c *TCPCollector) SetMinInterval(d time.Duration) { c.sched.SetMinInterval(d) }
