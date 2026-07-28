//go:build !windows && !linux

package traceroute

import (
	"context"
	"net/netip"
	"time"
)

// The TTL-aware ICMP and TCP paths are implemented against Windows iphlpapi /
// Winsock and against Linux raw sockets. On the remaining platforms (macOS and
// anything else the agent cross-compiles for) they are precise-unsupported
// stubs: the capability probe reports neither mode, so the diagnostic
// permissions never become supported and the engine returns an unsupported
// terminal status before these are ever called. They exist only so the package
// compiles cross-platform.

// detectCapabilities reports no traceroute capability on platforms with no
// TTL-aware implementation.
func detectCapabilities() capabilities { return capabilities{} }

func icmpProbe(_ context.Context, _ netip.Addr, _ int, _ int, _ time.Duration) (probeOutcome, error) {
	return probeOutcome{}, errUnsupported
}

func tcpProbe(_ context.Context, _ netip.Addr, _ int, _ int, _ time.Duration) (probeOutcome, error) {
	return probeOutcome{}, errUnsupported
}
