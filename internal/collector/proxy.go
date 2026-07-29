package collector

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"time"

	"github.com/nettact/agent/internal/netguard"
	"github.com/nettact/agent/internal/proxydial"
	pcfg "github.com/nettact/protocol/config"
	"github.com/nettact/protocol/telemetry"
)

// Shared egress-proxy plumbing for the collectors.
//
// Three things live here because all of them must behave identically across
// icmp/dns/http/tcp/nat, and a per-collector copy would drift:
//
//  1. resolving a target's pin to a live dialer, failing CLOSED;
//  2. emitting the "never attempted" metric pair when the pin cannot be honored; and
//  3. deciding whether a failed dial gets a proxy_* reason or the target's own.

// resolveProxy returns the dialer for a target's pin, or nil for an unpinned
// target (a direct dial is what was configured).
//
// A pin that cannot be honored returns an error and NO dialer. Callers must then
// report a failed probe — never retry directly. Falling back would (a) send the
// probe from the real egress IP the operator deliberately routed away from, and
// (b) make a green check assert "reachable from somewhere" rather than "reachable
// through the configured path", which is not what the monitor was created to say.
func resolveProxy(ctx context.Context, mgr *proxydial.Manager, t pcfg.ProbeTarget) (*proxydial.Dialer, error) {
	if t.ProxyID == "" {
		return nil, nil
	}
	if mgr == nil {
		// No proxy support in this build/wiring. Still fails closed rather than
		// silently downgrading a pinned monitor to a direct one.
		return nil, proxydial.ErrUnknownProxy
	}
	return mgr.Dialer(ctx, t.ProxyID)
}

// proxyFailureMetrics builds the metric pair for a probe that was NEVER ATTEMPTED
// because its proxy pin could not be honored: ok=0 plus the error class carrying
// the proxy reason and the raw cause as the detail label.
//
// No latency sample is emitted — nothing was measured. That matches the existing
// contract everywhere else in this package: a failure is never recorded as a
// zero-latency success-shaped sample, because charts and availability math cannot
// tell those apart afterwards.
//
// labels may be nil; when set it is COPIED before the detail is added, since
// callers share one label map across a cycle's metrics.
func proxyFailureMetrics(now time.Time, t pcfg.ProbeTarget, okKind, errKind telemetry.MetricKind,
	labels map[string]string, err error) []telemetry.Metric {
	reason, _, ok := proxydial.ProxyReason(err)
	if !ok {
		reason = telemetry.ProbeReasonProxyConfig
	}
	mk := func(kind telemetry.MetricKind, v float64, unit string) telemetry.Metric {
		return telemetry.Metric{
			TS: now, Kind: kind, Target: t.Target, Layer: telemetry.LayerService,
			Value: v, Unit: unit, Labels: labels,
			MonitorID: t.MonitorID, ConfigSerial: t.ConfigSerial,
		}
	}
	ec := mk(errKind, float64(reason), telemetry.UnitCode)
	ec.Labels = withDetail(labels, errText(err))
	return []telemetry.Metric{mk(okKind, 0, telemetry.UnitBool), ec}
}

// proxyFailureEvent records the un-attempted probe as an event, with a message that
// names the egress path rather than the target — the operator must not go looking at
// a service that was never contacted.
func proxyFailureEvent(now time.Time, t pcfg.ProbeTarget, what string) telemetry.Event {
	return telemetry.Event{
		ID: newID(), TS: now, Type: telemetry.EventProbeFailed, Layer: telemetry.LayerService,
		Severity: telemetry.SeverityWarn,
		Message:  what + " — egress proxy unavailable: " + t.Target,
	}
}

// classifyProxyAwareError classifies a dial/request failure for a possibly-proxied
// probe. It returns the reason plus whether the failure belongs to the TARGET.
//
// The split is the whole point of the feature. On an unproxied probe the caller's
// own classifyNetError is authoritative. On a proxied one, most failures happened on
// the egress path and must NOT be attributed to the target — with the deliberate
// exception of the cases the proxy explicitly reports as a target verdict (a SOCKS5
// "connection refused" reply, a RST delivered through a tunnel), which keep the
// target's own reason so a genuinely closed port still reads as a closed port.
func classifyProxyAwareError(err error, proxied bool) (reason int, atTarget bool) {
	if r, at, ok := proxydial.ProxyReason(err); ok {
		return r, at
	}
	if !proxied {
		return classifyNetError(err), true
	}
	// A proxied probe whose error is not a recognized proxy failure: it came from the
	// tunnelled connection itself (a TLS failure, a read timeout on a response), so
	// the target IS the right attribution.
	return classifyNetError(err), true
}

// proxyTargetAddress renders the "host:port" a proxied dial should ask for.
//
// Under DNS mode local the agent resolves and policy-vets the name itself and hands
// the proxy the approved LITERAL address — that is what preserves the guard's
// resolve-once/pin-the-address contract (the DNS-rebinding defense) through a proxy
// that would otherwise resolve independently. Under remote mode the hostname is
// passed through for the proxy to resolve, which monitoreval only permits when the
// name is policy-authorized.
//
// vetted may be empty for a literal-IP target, in which case host is already the
// literal.
func proxyTargetAddress(d *proxydial.Dialer, host, port string, vetted []netip.Addr) string {
	if d != nil && !d.ResolvesRemotely() && len(vetted) > 0 {
		return net.JoinHostPort(vetted[0].String(), port)
	}
	return net.JoinHostPort(host, port)
}

// proxyDialFunc returns the dial function a probe should use for its egress: the
// guard's own dial when unproxied, or a proxied dial that keeps the guard's
// guarantees.
//
// The wrapper exists because handing a HOSTNAME to a proxy silently moves resolution
// to the far side, where the agent cannot see the address the connection actually
// reaches. Under DNS mode local — the default — that would defeat the whole point of
// netguard: an ip:/cidr:/scope: deny would never be applied, and the resolve-once,
// pin-the-address rebinding defense would be gone. So local mode resolves and vets
// here, exactly as guard.DialContext does, and hands the proxy the approved LITERAL
// address. The proxy never learns the hostname, which also means it cannot substitute
// a different address for it.
//
// Remote mode is the deliberate opt-out: the name goes to the proxy verbatim, and
// monitoreval only allows that combination when the policy authorizes the name.
func proxyDialFunc(guard *netguard.Guard, proxy *proxydial.Dialer) proxydial.DialFunc {
	if proxy == nil {
		return guard.DialContext
	}
	if proxy.ResolvesRemotely() {
		return proxy.DialContext
	}
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		// A literal address gets the full check, then goes straight through.
		if _, perr := netip.ParseAddr(host); perr == nil {
			dec, cerr := guard.CheckAddrString(host)
			if cerr != nil {
				return nil, cerr
			}
			if !dec.Allowed {
				return nil, &netguard.BlockedError{Target: host, Matched: dec.Matched}
			}
			return proxy.DialContext(ctx, network, address)
		}
		// A hostname is refused before any query when the policy is conclusive, then
		// resolved once and vetted — the same order guard.DialContext uses.
		hd := guard.CheckHost(host)
		if hd.Denied {
			return nil, &netguard.BlockedError{Target: host, Matched: hd.Matched}
		}
		vetted, rerr := guard.ResolveVetted(ctx, host, hd.NameAuthorized)
		if rerr != nil {
			return nil, rerr
		}
		// Try the vetted addresses in order, preserving the per-address fallback a
		// direct dial would get for a multi-homed name.
		var lastErr error
		for _, a := range vetted {
			conn, derr := proxy.DialContext(ctx, network, net.JoinHostPort(a.String(), port))
			if derr == nil {
				return conn, nil
			}
			lastErr = derr
		}
		if lastErr == nil {
			lastErr = &netguard.BlockedError{Target: host, FromResolve: true}
		}
		return nil, lastErr
	}
}

// isPolicyBlock reports whether err is a target-access policy block, which is NOT a
// probe failure: it is routed to the monitor-status tracker instead, exactly as for
// an unproxied dial.
func isPolicyBlock(err error) (*netguard.BlockedError, bool) {
	var be *netguard.BlockedError
	if errors.As(err, &be) {
		return be, true
	}
	return nil, false
}
