package collector

import (
	"context"
	"errors"
	"net/netip"
	"time"

	"github.com/nettact/agent/internal/netguard"
	"github.com/nettact/agent/internal/platform"
	"github.com/nettact/agent/internal/proxydial"
	pcfg "github.com/nettact/protocol/config"
	"github.com/nettact/protocol/telemetry"
)

// PublicPingCollector pings a set of public targets pushed down from the server
// as DesiredState (architecture §4 internet layer). Each target carries its own
// per-protocol params (timeout, packet size, retries, interval) and is probed on
// its own schedule via the shared probeRunner — the agent drives Collect on a
// fine tick, and each due target's cycle runs on its own goroutine because a
// spread cycle occupies most of its check interval (see probeRunner, pingLoop).
type PublicPingCollector struct {
	p       platform.Platform
	guard   *netguard.Guard
	proxies *proxydial.Manager
	*probeRunner
}

// NewPublicPingCollector builds the collector. gate is the machine-wide probe
// budget — pass the same one to every collector of every server; nil means
// unlimited.
func NewPublicPingCollector(p platform.Platform, guard *netguard.Guard, proxies *proxydial.Manager, gate *ProbeGate) *PublicPingCollector {
	// 10s fallback matches the old base-tier cadence, so targets that don't set
	// interval_seconds keep probing at the previous rate rather than every tick.
	return &PublicPingCollector{
		p: p, guard: guard, proxies: proxies,
		probeRunner: newProbeRunner(pcfg.DefaultICMPInterval, gate),
	}
}

// SetTargets replaces the ICMP target list from a DesiredState update.
func (c *PublicPingCollector) SetTargets(targets []pcfg.ProbeTarget) {
	var icmp []pcfg.ProbeTarget
	for _, t := range targets {
		if t.Kind == "icmp" && t.Target != "" {
			icmp = append(icmp, t)
		}
	}
	c.setTargets(icmp)
}

func (c *PublicPingCollector) Name() string { return "public_ping" }

func (c *PublicPingCollector) Tier() Tier { return TierBase }

// Collect hands back the cycles that finished since the last pass and starts the
// targets that have come due. A target's samples therefore surface on a later
// tick than the Collect that started it — see probeRunner for why the cycles no
// longer run inline.
func (c *PublicPingCollector) Collect(ctx context.Context) (Result, error) {
	return c.collect(ctx, c.runTarget), nil
}

// runTarget resolves, vets and probes one target, returning everything that one
// cycle produced. It runs on its own goroutine, so it touches nothing shared
// beyond the platform HAL, the guard and the proxy manager (all safe for
// concurrent use) — the Result travels back through the runner's buffer.
func (c *PublicPingCollector) runTarget(ctx context.Context, sp scheduledProbe) (Result, func(*Result)) {
	t := sp.Target
	// A cycle aborted by run cancellation (agent shutdown) must not fabricate
	// loss: under a cancelled context resolution and every remaining echo fail
	// instantly, which the emitted sample cannot distinguish from a real
	// outage — it would sit in the WAL and raise a false alert on the next
	// start. Drop the whole cycle instead.
	if ctx.Err() != nil {
		return Result{}, nil
	}
	var res Result
	labels := map[string]string{"ip": t.Target}
	// Resolve the pinned egress proxy. ICMP only traverses a WireGuard tunnel — the
	// capability matrix refuses both relay protocols, neither of which has any
	// command for forwarding an ICMP echo (SOCKS5 relays UDP, but not ICMP). So a
	// pin that cannot be honored means the cycle is not run: reporting 100% loss
	// measured on the HOST's stack would be an answer about the wrong path.
	proxy, prerr := resolveProxy(ctx, c.proxies, t)
	if prerr != nil {
		reason, _, _ := proxydial.ProxyReason(prerr)
		appendICMPMetrics(&res, cycleNow().UTC(), t.MonitorID, t.ConfigSerial, t.Target, telemetry.LayerInternet, labels,
			pingCycleResult{Loss: 100, Sent: pcfg.PingCount(t.Params), Reason: reason, Detail: errText(prerr)})
		return res, nil
	}
	// Vet the destination before dialing: a literal IP is checked directly; a
	// hostname is resolved once through the guard and the vetted IP is pinned to
	// the ping. A policy block is a target-policy block, not a loss sample.
	pingTarget, blocked, resolveErr := c.vet(ctx, t)
	if blocked != nil {
		blocked.MonitorID = t.MonitorID
		blocked.ConfigSerial = t.ConfigSerial
		res.Blocked = append(res.Blocked, *blocked)
		return res, nil
	}
	if resolveErr != nil {
		// Resolution failed AFTER policy vetting. Record a probe failure (100%
		// loss) rather than handing the raw name to the platform pinger, which
		// would re-resolve it through the system resolver OUTSIDE the guard — a
		// DNS-rebinding / policy-bypass hole (e.g. a dual-stack name whose AAAA
		// fails but A resolves to a denied address).
		if ctx.Err() != nil {
			return Result{}, nil // resolution failed because the run was cancelled, not the network
		}
		// The failing phase IS resolution, so an error the classifier cannot place
		// still lands in the DNS family rather than a meaningless "other".
		reason := classifyNetError(resolveErr)
		if reason == telemetry.ProbeReasonOther {
			reason = telemetry.ProbeReasonDNS
		}
		appendICMPMetrics(&res, cycleNow().UTC(), t.MonitorID, t.ConfigSerial, t.Target, telemetry.LayerInternet, labels,
			pingCycleResult{Loss: 100, Sent: pcfg.PingCount(t.Params), Reason: reason, Detail: errText(resolveErr)})
		return res, nil
	}
	// A tunnelled target builds its own echoes on the tunnel's ICMP socket; the
	// platform pinger sends from the HOST stack and could not reach a tunnel-only
	// destination at all.
	var r pingCycleResult
	if proxy != nil {
		r = tunnelPingCycle(ctx, proxy, pingTarget, t.Params, pacingDeadline(sp), c.gate)
	} else {
		r = pingCycle(ctx, c.p, pingTarget, t.Params, pacingDeadline(sp), c.gate)
	}
	if ctx.Err() != nil {
		return Result{}, nil // cycle aborted mid-flight: unsent echoes are not lost echoes
	}
	if r.Sent == 0 {
		// The concurrency budget admitted no echo inside this cycle's own timing
		// budget. There is nothing measured to report, and 100% loss over zero
		// packets would be the agent's own busyness dressed up as an outage. The
		// gap speaks for itself: the server's staleness window catches it, and
		// the heartbeat's overload event says why.
		return Result{}, nil
	}
	// Stamped at completion, not at the start of the pass: a spread cycle spans
	// most of its interval, and the sample summarizes the window that just ended.
	appendICMPMetrics(&res, cycleNow().UTC(), t.MonitorID, t.ConfigSerial, t.Target, telemetry.LayerInternet, labels, r)
	return res, nil
}

// vet resolves and policy-checks an ICMP target, returning the literal IP to
// ping. A policy block is returned as a BlockedProbe (MonitorID filled by the
// caller). A plain resolution failure returns the resolver's error so the caller
// records a classified loss sample WITHOUT pinging the raw name (which the
// platform pinger would re-resolve outside the guard).
func (c *PublicPingCollector) vet(ctx context.Context, t pcfg.ProbeTarget) (pingTarget string, blocked *BlockedProbe, resolveErr error) {
	if a, err := netip.ParseAddr(t.Target); err == nil {
		if dec := c.guard.CheckAddr(a.Unmap()); !dec.Allowed {
			return "", &BlockedProbe{Matched: dec.Matched, Reason: "literal_denied"}, nil
		}
		return t.Target, nil, nil
	}
	hd := c.guard.CheckHost(t.Target)
	if hd.Denied {
		return "", &BlockedProbe{Matched: hd.Matched, Reason: "resolved_denied"}, nil
	}
	vetted, err := c.guard.ResolveVetted(ctx, t.Target, hd.NameAuthorized)
	if err != nil {
		var be *netguard.BlockedError
		if errors.As(err, &be) {
			return "", &BlockedProbe{Matched: be.Matched, Reason: "resolved_denied"}, nil
		}
		// A plain resolution failure is a probe failure, not a block — but the raw
		// name must NEVER reach the pinger (it would re-resolve outside the guard).
		return "", nil, err
	}
	return pickPingAddr(vetted).String(), nil, nil
}

// pickPingAddr chooses a vetted address the ICMP path can actually use. The
// platform ICMP implementations currently support IPv4 only, so a dual-stack
// name must ping a vetted IPv4 address rather than whichever the resolver
// happened to return first — otherwise a permitted IPv4 result is ignored and an
// IPv6-first order fabricates a 100% loss (false outage). Falls back to the first
// vetted address when no IPv4 candidate survived the policy.
func pickPingAddr(vetted []netip.Addr) netip.Addr {
	for _, a := range vetted {
		if a.Unmap().Is4() {
			return a.Unmap()
		}
	}
	return vetted[0].Unmap()
}

// pingCycle runs one ICMP probe cycle against target on the host's stack, paced
// to land its last echo before nextDue. The cycle contract — packet count,
// spread pacing, fail-fast on loss, per-echo timeout, global deadline, the
// machine-wide concurrency budget, and the rule that a lost echo contributes to
// loss and never to the latency distribution — lives in pingLoop, which the
// in-tunnel path shares.
func pingCycle(ctx context.Context, p platform.Platform, target string, params pcfg.ProbeParams, nextDue time.Time, gate *ProbeGate) pingCycleResult {
	return pingLoop(ctx, params, nextDue, gate, func(ectx context.Context, seq int, timeout time.Duration) (time.Duration, int, string, bool) {
		// A size-sweeping cycle derives the echo's payload from its sequence
		// number (round-robin across the swept sizes); otherwise the fixed
		// PacketSize. pingLoop tallies per-size facts by the same mapping.
		pr, err := p.Ping(ectx, target, platform.PingOptions{Timeout: timeout, PayloadSize: sweepSize(params, seq)})
		if err != nil {
			// The pinger could not run this echo at all. It still counts as lost,
			// but with no class of its own: inventing one would put words in the
			// platform's mouth.
			return 0, telemetry.ProbeReasonNone, "", false
		}
		if pr.Received {
			return pr.RTT, telemetry.ProbeReasonNone, "", true
		}
		return 0, pr.Reason, pr.Detail, false
	})
}
