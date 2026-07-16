// Package traceroute runs a single incident traceroute (DIAG-001) toward one
// destination, entirely independent of the probe scheduler and the normal
// collectors. Distinct requests execute concurrently up to a bounded per-Agent
// limit; each request resolves its destination exactly once through the same
// netguard target-access policy the live probes use, clamps its own inputs, and
// obeys the absolute request deadline as its only validity window. ICMP and TCP
// are executed by dedicated TTL-aware platform paths (real on Windows/IPv4,
// precise-unsupported stubs elsewhere); there is never an automatic fallback
// between the two modes, and no queue grace, freshness, cooldown, or cross-
// request report reuse. Nothing here is persisted.
package traceroute

import (
	"context"
	"net/netip"
	"time"
)

// probeOutcome is one TTL probe's result. A timeout means no responder answered
// within the per-attempt budget (rendered as `*`): responder is zero and rttMs
// is 0. reached is set only when the destination itself answered (an ICMP echo
// reply, or a TCP SYN-ACK/RST), never for an intermediate TTL-expired responder.
type probeOutcome struct {
	responder netip.Addr
	reached   bool
	timeout   bool
	rttMs     float64
}

// prober runs one TTL probe toward dest (port is used by TCP only). It returns a
// hard error only for a platform/capability failure that should terminate the
// whole trace; an ordinary no-response is reported as probeOutcome{timeout:true},
// not an error.
type prober func(ctx context.Context, dest netip.Addr, port, ttl int, timeout time.Duration) (probeOutcome, error)

// capabilities reports which diagnostic modes this build+runtime can actually
// execute. ICMP is a platform fact (Windows IPv4 iphlpapi TTL echo, no admin);
// TCP additionally needs a raw ICMP socket to observe intermediate TTL-exceeded
// responders, so it is a runtime capability (admin) probed at startup.
type capabilities struct {
	ICMP bool
	TCP  bool
}
