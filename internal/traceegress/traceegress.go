// Package traceegress bridges the traceroute engine to the proxy manager.
//
// It exists so neither side has to know the other: traceroute declares the
// resolver shape it needs, proxydial owns the live tunnels, and this package is
// the only place that speaks both. That keeps the engine testable without a
// tunnel and the manager free of diagnostic concerns.
//
// It is also where the DIAG-004 fail-closed contract is enforced: a pinned
// {proxy id, config generation} either resolves to the exact tunnel the
// diagnosed fault was observed on, or the trace refuses. Never a newer
// generation, never the host stack — a trace over either would describe a path
// the fault never took, which is the misreading this whole feature exists to
// prevent.
package traceegress

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/nettact/agent/internal/proxydial"
	"github.com/nettact/agent/internal/traceroute"
	pcfg "github.com/nettact/protocol/config"
)

// Resolver returns the engine's egress resolver over a proxy manager.
func Resolver(proxies *proxydial.Manager) traceroute.EgressResolver {
	return func(ctx context.Context, proxyID string, serial int) (traceroute.EgressProbeFunc, error) {
		d, err := proxies.DialerForGeneration(ctx, proxyID, serial)
		if err != nil {
			return nil, classify(err)
		}
		// Checked up front rather than at the first probe: a relay proxy that
		// matched id and generation still cannot carry raw IP, and saying so at
		// trace start gives the dedicated reason instead of probe_failed at TTL 1.
		if d.Spec.Type != pcfg.ProxyTypeWireGuard {
			return nil, fmt.Errorf("%w: %s cannot carry in-tunnel probes", traceroute.ErrEgressNotAvailable, d.Spec.Type)
		}
		return func(ctx context.Context, dest netip.Addr, ttl int, timeout time.Duration) (traceroute.EgressReply, error) {
			r, perr := d.TraceProbe(ctx, dest, ttl, timeout)
			if perr != nil {
				return traceroute.EgressReply{}, midSweepReason(ctx, proxies, proxyID, serial, perr)
			}
			return traceroute.EgressReply{
				Responder: r.Responder,
				Reached:   r.Reached,
				Timeout:   r.Timeout,
				RTTMs:     float64(r.RTT.Microseconds()) / 1000,
			}, nil
		}, nil
	}
}

// midSweepReason explains a probe that failed part-way through a sweep.
//
// The pin can be invalidated WHILE the trace runs: applying a config generation
// closes the superseded tunnel's device, and every in-flight probe then fails
// with a generic "device closed". Reporting that as probe_failed would blame the
// diagnostic machinery for what is really a rotated key — a fault with its own
// reason code and its own explanation in the console — so the pin is re-checked
// and the verdict restated whenever it no longer holds.
//
// A canceled context is left alone: the agent is shutting down or the session
// dropped, the manager is being torn down for that reason, and re-reading it
// would dress a shutdown up as an egress fault.
func midSweepReason(ctx context.Context, proxies *proxydial.Manager, proxyID string, serial int, probeErr error) error {
	if ctx.Err() != nil {
		return probeErr
	}
	if _, err := proxies.DialerForGeneration(ctx, proxyID, serial); err != nil {
		return classify(err)
	}
	return probeErr
}

// classify maps a manager lookup failure onto the sentinel whose reason code
// the console explains. A generation change is called out on its own because
// the operator's next question differs: a rotated tunnel means "re-run the
// diagnostic", a missing one means "the pin is gone".
func classify(err error) error {
	if errors.Is(err, proxydial.ErrProxyGeneration) {
		return fmt.Errorf("%w: %v", traceroute.ErrEgressGenerationMismatch, err)
	}
	return fmt.Errorf("%w: %v", traceroute.ErrEgressNotAvailable, err)
}
