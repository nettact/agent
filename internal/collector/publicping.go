package collector

import (
	"context"
	"errors"
	"net/netip"
	"time"

	"github.com/nettact/agent/internal/netguard"
	"github.com/nettact/agent/internal/platform"
	pcfg "github.com/nettact/protocol/config"
	"github.com/nettact/protocol/telemetry"
)

// PublicPingCollector pings a set of public targets pushed down from the server
// as DesiredState (architecture §4 internet layer). Each target carries its own
// per-protocol params (timeout, packet size, retries, interval) and is probed on
// its own schedule via schedState — the agent drives Collect on a fine tick.
type PublicPingCollector struct {
	p     platform.Platform
	guard *netguard.Guard
	sched *schedState
}

func NewPublicPingCollector(p platform.Platform, guard *netguard.Guard) *PublicPingCollector {
	// 10s fallback matches the old base-tier cadence, so targets that don't set
	// interval_seconds keep probing at the previous rate rather than every tick.
	return &PublicPingCollector{p: p, guard: guard, sched: newSchedState(10 * time.Second)}
}

// SetTargets replaces the ICMP target list from a DesiredState update.
func (c *PublicPingCollector) SetTargets(targets []pcfg.ProbeTarget) {
	var icmp []pcfg.ProbeTarget
	for _, t := range targets {
		if t.Kind == "icmp" && t.Target != "" {
			icmp = append(icmp, t)
		}
	}
	c.sched.set(icmp)
}

func (c *PublicPingCollector) Name() string { return "public_ping" }

func (c *PublicPingCollector) Tier() Tier { return TierBase }

func (c *PublicPingCollector) Collect(ctx context.Context) (Result, error) {
	targets := c.sched.due(time.Now())
	if len(targets) == 0 {
		return Result{}, nil
	}

	now := time.Now().UTC()
	var res Result
	for _, t := range targets {
		// Vet the destination before dialing: a literal IP is checked directly; a
		// hostname is resolved once through the guard and the vetted IP is pinned to
		// the ping. A policy block is a target-policy block, not a loss sample.
		pingTarget, blocked, unresolved := c.vet(ctx, t)
		if blocked != nil {
			blocked.MonitorID = t.MonitorID
			res.Blocked = append(res.Blocked, *blocked)
			continue
		}
		labels := map[string]string{"ip": t.Target}
		if unresolved {
			// Resolution failed AFTER policy vetting. Record a probe failure (100%
			// loss) rather than handing the raw name to the platform pinger, which
			// would re-resolve it through the system resolver OUTSIDE the guard — a
			// DNS-rebinding / policy-bypass hole (e.g. a dual-stack name whose AAAA
			// fails but A resolves to a denied address).
			res.Metrics = append(res.Metrics,
				telemetry.Metric{TS: now, Kind: telemetry.ICMPLoss, Target: t.Target, Layer: telemetry.LayerInternet,
					Value: 100, Unit: telemetry.UnitPct, Labels: labels, MonitorID: t.MonitorID})
			continue
		}
		loss, avgMs, received := pingCycle(ctx, c.p, pingTarget, t.Params)
		res.Metrics = append(res.Metrics,
			telemetry.Metric{TS: now, Kind: telemetry.ICMPLoss, Target: t.Target, Layer: telemetry.LayerInternet,
				Value: loss, Unit: telemetry.UnitPct, Labels: labels, MonitorID: t.MonitorID})
		if received > 0 {
			res.Metrics = append(res.Metrics,
				telemetry.Metric{TS: now, Kind: telemetry.ICMPRTTms, Target: t.Target, Layer: telemetry.LayerInternet,
					Value: avgMs, Unit: telemetry.UnitMs, Labels: labels, MonitorID: t.MonitorID})
		}
	}
	return res, nil
}

// vet resolves and policy-checks an ICMP target, returning the literal IP to
// ping. A policy block is returned as a BlockedProbe (MonitorID filled by the
// caller). A plain resolution failure returns unresolved=true so the caller
// records a loss sample WITHOUT pinging the raw name (which the platform pinger
// would re-resolve outside the guard).
func (c *PublicPingCollector) vet(ctx context.Context, t pcfg.ProbeTarget) (pingTarget string, blocked *BlockedProbe, unresolved bool) {
	if a, err := netip.ParseAddr(t.Target); err == nil {
		if dec := c.guard.CheckAddr(a.Unmap()); !dec.Allowed {
			return "", &BlockedProbe{Matched: dec.Matched, Reason: "literal_denied"}, false
		}
		return t.Target, nil, false
	}
	hd := c.guard.CheckHost(t.Target)
	if hd.Denied {
		return "", &BlockedProbe{Matched: hd.Matched, Reason: "resolved_denied"}, false
	}
	vetted, err := c.guard.ResolveVetted(ctx, t.Target, hd.NameAuthorized)
	if err != nil {
		var be *netguard.BlockedError
		if errors.As(err, &be) {
			return "", &BlockedProbe{Matched: be.Matched, Reason: "resolved_denied"}, false
		}
		// A plain resolution failure is a probe failure, not a block — but the raw
		// name must NEVER reach the pinger (it would re-resolve outside the guard).
		return "", nil, true
	}
	return pickPingAddr(vetted).String(), nil, false
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

// pingCycle runs one ICMP probe cycle for target per its ProbeParams and returns
// the loss percentage, the average RTT (ms) over received echoes, and the number
// received. Shared by the public-ping and gateway collectors so both honor the
// same per-target packet count, payload size, per-echo timeout and global
// deadline semantics.
func pingCycle(ctx context.Context, p platform.Platform, target string, params pcfg.ProbeParams) (loss, avgMs float64, received int) {
	// PacketCount supersedes the legacy Retries+1 count when set; both fall back
	// to a single echo.
	count := params.PacketCount
	if count < 1 {
		count = params.Retries + 1
	}
	if count < 1 {
		count = 1
	}
	timeout := time.Duration(params.TimeoutMs) * time.Millisecond
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	// GlobalTimeoutMs bounds the whole cycle across all echoes, regardless of how
	// many packets are configured. We enforce it with a wall-clock deadline and by
	// capping each ping's own timeout to the time remaining — context cancellation
	// alone can't interrupt a synchronous platform ping (e.g. Windows IcmpSendEcho
	// honors only PingOptions.Timeout).
	pctx := ctx
	var cancel context.CancelFunc
	var deadline time.Time
	if params.GlobalTimeoutMs > 0 {
		d := time.Duration(params.GlobalTimeoutMs) * time.Millisecond
		deadline = time.Now().Add(d)
		pctx, cancel = context.WithTimeout(ctx, d)
	}

	var rttSum time.Duration
	for i := 0; i < count; i++ {
		if pctx.Err() != nil {
			break
		}
		callTimeout := timeout
		if !deadline.IsZero() {
			remaining := time.Until(deadline)
			if remaining <= 0 {
				break
			}
			if remaining < callTimeout {
				callTimeout = remaining
			}
		}
		opts := platform.PingOptions{Timeout: callTimeout, PayloadSize: params.PacketSize}
		pr, err := p.Ping(pctx, target, opts)
		if err != nil {
			continue
		}
		if pr.Received {
			received++
			rttSum += pr.RTT
		}
	}
	if cancel != nil {
		cancel()
	}

	loss = float64(count-received) / float64(count) * 100.0
	if received > 0 {
		avgMs = float64(rttSum.Microseconds()) / float64(received) / 1000.0
	}
	return loss, avgMs, received
}

// SetMinInterval applies the local per-target probe-interval floor (stability limit).
func (c *PublicPingCollector) SetMinInterval(d time.Duration) { c.sched.SetMinInterval(d) }
