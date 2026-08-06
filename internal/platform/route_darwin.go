//go:build darwin

package platform

import (
	"sync"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

// The sysctl(CTL_NET, PF_ROUTE, …) fetch layer behind routebsd.go's parsers.
// x/net/route.FetchRIB owns the raw dump (including the grow-and-retry dance a
// racing table update forces); the bytes it returns are handed to the untagged
// parsers so everything below this file stays testable on any GOOS.

// fetchRouteDump reads the full routing table (NET_RT_DUMP), both families.
func fetchRouteDump() ([]byte, error) {
	return route.FetchRIB(unix.AF_UNSPEC, route.RIBType(unix.NET_RT_DUMP), 0)
}

// fetchNeighborDump reads the link-layer entries (ARP for AF_INET, NDP for
// AF_INET6) via NET_RT_FLAGS + RTF_LLINFO — the same query `arp -an` and
// `ndp -an` make. macOS has no netlink-style single-dump for both families, so
// the caller queries each family separately.
func fetchNeighborDump(af int) ([]byte, error) {
	return route.FetchRIB(af, route.RIBType(unix.NET_RT_FLAGS), unix.RTF_LLINFO)
}

// neighborsAvailable probes the neighbor dump once. The routing sysctl needs no
// privilege, but a sandbox profile can still refuse it, and advertising a
// capability that always errors is worse than not advertising it (same stance
// as the Linux netlink probe).
var neighborsAvailable = sync.OnceValue(func() bool {
	_, err := fetchNeighborDump(unix.AF_INET)
	return err == nil
})
