//go:build linux

package platform

import (
	"fmt"
	"sync"
	"syscall"

	"github.com/nettact/protocol/permission"
)

// linuxPlatform is the native Linux HAL implementation. Interface enumeration and
// Wi-Fi come from the shared unix walk and nl80211; default gateways and the
// neighbor table come from netlink (netlink_linux.go); ICMP echo comes from a raw
// or unprivileged ping socket (icmp_linux.go).
//
// Everything privilege-dependent is probed once at startup and reported through
// Supports(), so `effective` reflects what this process can really do rather than
// what the build could theoretically do.
type linuxPlatform struct{}

func newPlatform() Platform { return linuxPlatform{} }

// neighborsAvailable probes the neighbor dump once. Netlink needs no privilege,
// but a container with a restrictive seccomp profile can still refuse the socket,
// and advertising a capability that always errors is worse than not advertising
// it.
var neighborsAvailable = sync.OnceValue(func() bool {
	_, err := netlinkDump(syscall.RTM_GETNEIGH)
	return err == nil
})

func (linuxPlatform) Supports() permission.Set {
	s := permission.NewSet(
		permission.NetIfaceStatusRead,
		permission.NetIfaceAddressRead,
	)
	for _, id := range wifiPermissions() {
		s.Add(id)
	}
	if neighborsAvailable() {
		s.Add(permission.NetNeighborRead)
		s.Add(permission.NetNeighborHostRead)
	}
	// Gateway probing is ICMP echo against the discovered default gateway, so it
	// lives or dies with the ICMP capability. Either socket type can send an echo.
	if icmpCapability() != icmpNone {
		s.Add(permission.ProbeICMP)
		s.Add(permission.NetworkGatewayProbe)
	}
	// The traceroute permissions are NOT added here: the traceroute engine owns
	// their capability probe on every OS (it needs to observe intermediate
	// Time-Exceeded replies, which is a stricter requirement than sending an
	// echo), and the runtime folds its answer into `supported`.
	return s
}

func (linuxPlatform) Interfaces(q IfaceQuery) ([]IfaceInfo, error) {
	out, index, err := baseInterfaces(q)
	if err != nil {
		return nil, err
	}
	if !q.Gateways && !q.DNS {
		return out, nil
	}

	// One netlink dump serves both fields: DNS is attached to the interfaces that
	// carry a default route (see resolv_linux.go for why).
	//
	// A failed dump is REPORTED, not swallowed. Leaving an empty route table
	// behind and returning success makes "this host has no gateway" and "the agent
	// could not read the routing table" — say, RTM_GETROUTE blocked by a seccomp
	// policy — arrive at the caller as the same answer, and an incident scene then
	// blames the LAN for a restriction on the agent itself. The interface list is
	// still complete and still returned, so callers that only need status and
	// addresses lose nothing.
	msgs, derr := netlinkDump(syscall.RTM_GETROUTE)
	if derr != nil {
		return out, fmt.Errorf("%w: %v", ErrRoutesUnreadable, derr)
	}
	routes := parseDefaultRoutes(msgs)
	var nameservers []string
	if q.DNS {
		nameservers = systemNameservers()
	}

	for i := range out {
		idx, ok := index[out[i].Name]
		if !ok {
			continue
		}
		if q.Gateways {
			if gws := routes.gateways[idx]; len(gws) > 0 {
				out[i].Gateways = gws
			}
		}
		// Carrying a default route is the condition for DNS, not having a gateway
		// ADDRESS: on a tunnel or point-to-point default there is no gateway to
		// report, yet that interface is still where the host's resolvers are reached.
		if q.DNS && routes.ifaces[idx] {
			out[i].DNS = nameservers
		}
	}
	return out, nil
}

func (linuxPlatform) Neighbors() ([]Neighbor, error) {
	msgs, err := netlinkDump(syscall.RTM_GETNEIGH)
	if err != nil {
		return nil, err
	}
	return parseNeighbors(msgs), nil
}
