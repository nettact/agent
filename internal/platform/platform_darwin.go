//go:build darwin

package platform

import (
	"context"
	"fmt"

	"golang.org/x/sys/unix"

	"github.com/nettact/protocol/permission"
)

// darwinPlatform is the native macOS HAL implementation. Interface enumeration
// comes from the shared unix walk and Wi-Fi from CoreWLAN (wifi_darwin.go);
// default gateways and the ARP/NDP neighbor table come from the PF_ROUTE
// sysctl (route_darwin.go + routebsd.go); ICMP echo comes from a raw or
// unprivileged datagram ICMP socket (icmp_unix.go — on macOS the datagram
// socket needs no privilege at all, there is no ping_group_range analogue).
//
// Everything privilege-dependent is probed once at startup and reported through
// Supports(), so `effective` reflects what this process can really do rather
// than what the build could theoretically do.
type darwinPlatform struct{}

func newPlatform() Platform { return darwinPlatform{} }

func (darwinPlatform) Supports() permission.Set {
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

func (darwinPlatform) Interfaces(q IfaceQuery) ([]IfaceInfo, error) {
	out, index, err := baseInterfaces(q)
	if err != nil {
		return nil, err
	}
	if !q.Gateways && !q.DNS {
		return out, nil
	}

	// One route dump serves both fields: DNS is attached to the interfaces that
	// carry a default route (see resolv_unix.go for why).
	//
	// A failed dump is REPORTED, not swallowed — the interface list is still
	// complete and still returned, but "no gateway" and "could not read the
	// routing table" must not arrive at the caller as the same answer (see
	// ErrRoutesUnreadable).
	buf, derr := fetchRouteDump()
	if derr != nil {
		return out, fmt.Errorf("%w: %v", ErrRoutesUnreadable, derr)
	}
	routes := parseBSDDefaultRoutes(buf)
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
			if best, ok := routes.best[idx]; ok {
				out[i].IPv4Default = &best
			}
		}
		// Carrying a default route is the condition for DNS, not having a gateway
		// ADDRESS: on a utun or point-to-point default there is no gateway to
		// report, yet that interface is still where the host's resolvers are
		// reached.
		if q.DNS && routes.ifaces[idx] {
			out[i].DNS = nameservers
		}
	}
	return out, nil
}

func (darwinPlatform) Ping(ctx context.Context, target string, opts PingOptions) (PingResult, error) {
	return icmpPing(ctx, target, opts)
}

func (darwinPlatform) Neighbors() ([]Neighbor, error) {
	// Two dumps because PF_ROUTE has no both-families neighbor query. IPv4 is
	// the load-bearing family for device discovery, so its failure is the
	// call's failure; a v6-only refusal degrades to ARP results rather than
	// discarding them.
	v4, err := fetchNeighborDump(unix.AF_INET)
	if err != nil {
		return nil, err
	}
	out := parseBSDNeighbors(v4)
	if v6, err := fetchNeighborDump(unix.AF_INET6); err == nil {
		out = append(out, parseBSDNeighbors(v6)...)
	}
	return out, nil
}
