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
	return &PublicPingCollector{p: p, guard: guard, sched: newSchedState(pcfg.DefaultICMPInterval)}
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
		// A pass aborted by run cancellation (agent shutdown) must not fabricate
		// loss: under a cancelled context resolution and every remaining echo fail
		// instantly, which the emitted sample cannot distinguish from a real
		// outage — it would sit in the WAL and raise a false alert on the next
		// start. Keep what was measured before the cancel; drop the rest.
		if ctx.Err() != nil {
			break
		}
		// Vet the destination before dialing: a literal IP is checked directly; a
		// hostname is resolved once through the guard and the vetted IP is pinned to
		// the ping. A policy block is a target-policy block, not a loss sample.
		pingTarget, blocked, unresolved := c.vet(ctx, t)
		if blocked != nil {
			blocked.MonitorID = t.MonitorID
			blocked.ConfigSerial = t.ConfigSerial
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
			if ctx.Err() != nil {
				break // resolution failed because the run was cancelled, not the network
			}
			appendICMPMetrics(&res, now, t.MonitorID, t.ConfigSerial, t.Target, telemetry.LayerInternet, labels, pingCycleResult{Loss: 100})
			continue
		}
		r := pingCycle(ctx, c.p, pingTarget, t.Params)
		if ctx.Err() != nil {
			break // cycle aborted mid-flight: unsent echoes are not lost echoes
		}
		appendICMPMetrics(&res, now, t.MonitorID, t.ConfigSerial, t.Target, telemetry.LayerInternet, labels, r)
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

// pingSpacing is the fixed delay between echoes in a multi-packet cycle, so a
// single cycle samples jitter over a short window (~1s for the default 5 packets)
// rather than back-to-back. Sourced from the shared schedule helpers (not
// configurable in v1) so the collector and the server's cycle-deadline math agree.
const pingSpacing = pcfg.PingSpacing

// pingCycle runs one ICMP probe cycle for target per its ProbeParams and returns
// the loss percentage and the RTT distribution (avg/min/max/jitter) over the
// received echoes. Shared by the public-ping and gateway collectors so both honor
// the same per-target packet count, spacing, payload size, per-echo timeout and
// global deadline semantics. Lost echoes contribute to loss only — never a
// zero-latency sample — so the distribution is computed over received echoes.
//
// The packet count, per-echo timeout, and inter-echo spacing come from the shared
// protocol/config schedule helpers, so a probe's real cycle timing can never
// drift from the whole-cycle deadline the server derives (pcfg.CycleDeadline).
func pingCycle(ctx context.Context, p platform.Platform, target string, params pcfg.ProbeParams) pingCycleResult {
	// PacketCount takes precedence; failing that, the legacy Retries knob (count =
	// retries+1) when a user set it; otherwise a short burst so jitter/min/max are
	// meaningful by default.
	count := pcfg.PingCount(params)
	// Default per-echo timeout is 1s: generous for real ICMP RTTs (<1s worldwide)
	// yet keeps a fully-lost default cycle (5×1s + 4×200ms ≈ 5.8s) under the 10s
	// interval so one dead target does not starve the self-loop.
	timeout := pcfg.PingEchoTimeout(params)
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

	rtts := make([]time.Duration, 0, count)
	for i := 0; i < count; i++ {
		if pctx.Err() != nil {
			break
		}
		if i > 0 && !sleepCtx(pctx, pingSpacing) {
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
			rtts = append(rtts, pr.RTT)
		}
	}
	if cancel != nil {
		cancel()
	}

	received := len(rtts)
	r := pingCycleResult{
		Loss:     float64(count-received) / float64(count) * 100.0,
		Sent:     count,
		Received: received,
	}
	r.AvgMs, r.MinMs, r.MaxMs, r.JitterMs, r.HaveJitter = pingStats(rtts)
	return r
}

// SetMinInterval applies the local per-target probe-interval floor (stability limit).
func (c *PublicPingCollector) SetMinInterval(d time.Duration) { c.sched.SetMinInterval(d) }
