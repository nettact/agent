package traceroute

// In-tunnel probing (DIAG-004). Unlike the platform probers this file carries no
// build tag: an egress trace runs entirely in userspace (the WireGuard mux
// injects the TTL'd echo and sniffs the replies), so it works on every platform
// — including ones whose host-stack probers are stubs — and needs no raw socket
// or elevation.
//
// The engine stays independent of proxydial: it consumes an injected
// EgressResolver, and the runtime bridges it to the proxy manager. What the
// resolver must guarantee is the fail-closed contract — a pinned {proxyID,
// configSerial} either resolves to the exact tunnel generation the diagnosed
// fault was observed on, or fails with one of the sentinel errors below. It
// must never substitute a newer generation or the host stack.

import (
	"context"
	"errors"
	"net/netip"
	"time"
)

// EgressReply is the outcome of one in-tunnel TTL'd echo, mirroring
// probeOutcome: Timeout marks a missing reply (never a broken path by itself),
// Reached is set only when the destination itself answered.
type EgressReply struct {
	Responder netip.Addr
	Reached   bool
	Timeout   bool
	RTTMs     float64
}

// EgressProbeFunc sends one TTL'd echo inside an already-resolved tunnel. An
// error is a hard, trace-terminating condition (tunnel torn down mid-run);
// everything softer must be a Timeout reply.
type EgressProbeFunc func(ctx context.Context, dest netip.Addr, ttl int, timeout time.Duration) (EgressReply, error)

// EgressResolver resolves a pinned egress reference to a live in-tunnel probe.
// Resolution may lazily stand the tunnel up — after a reconnect the device may
// not exist yet, and building it IS honoring the pinned generation.
type EgressResolver func(ctx context.Context, proxyID string, configSerial int) (EgressProbeFunc, error)

// Sentinel errors the resolver classifies its failures into; the engine maps
// them onto the dedicated fail-closed reason codes.
var (
	// ErrEgressGenerationMismatch: the proxy exists but at a different config
	// generation — its keys or routing were rotated after the fault.
	ErrEgressGenerationMismatch = errors.New("traceroute: egress generation mismatch")
	// ErrEgressNotAvailable: the pinned proxy is absent, failed to initialize,
	// or cannot carry in-tunnel probes at all.
	ErrEgressNotAvailable = errors.New("traceroute: egress not available")
)

// tunnelProber adapts a resolved egress probe to the prober signature walk
// consumes. The port is ignored — in-tunnel probing is ICMP echo only.
func tunnelProber(p EgressProbeFunc) prober {
	return func(ctx context.Context, dest netip.Addr, _ int, ttl int, timeout time.Duration) (probeOutcome, error) {
		r, err := p(ctx, dest, ttl, timeout)
		if err != nil {
			return probeOutcome{}, err
		}
		return probeOutcome{responder: r.Responder, reached: r.Reached, timeout: r.Timeout, rttMs: r.RTTMs}, nil
	}
}
