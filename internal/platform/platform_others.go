//go:build !windows

package platform

import (
	"context"
	"errors"
	"net"

	"github.com/nettact/protocol/permission"
)

// genericPlatform is a stdlib-only fallback so the agent cross-compiles for
// Linux/darwin (the Docker Site-Agent target). Full ICMP via x/net/icmp and
// gateway/DNS discovery via /proc land in the M6 cross-platform work.
type genericPlatform struct{}

func newPlatform() Platform { return genericPlatform{} }

func (genericPlatform) Supports() permission.Set {
	s := permission.NewSet(
		permission.NetIfaceStatusRead,
		permission.NetIfaceAddressRead,
	)
	for _, id := range wifiPermissions() {
		s.Add(id)
	}
	return s
}

func (genericPlatform) Interfaces(q IfaceQuery) ([]IfaceInfo, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var out []IfaceInfo
	for _, ifc := range ifaces {
		info := IfaceInfo{
			ID:         ifc.Name, // name is the stable adapter key off Windows
			Name:       ifc.Name,
			Up:         ifc.Flags&net.FlagUp != 0,
			IsLoopback: ifc.Flags&net.FlagLoopback != 0,
			IsWireless: ifaceIsWireless(ifc.Name),
		}
		// Read unicast addresses only when requested — otherwise the per-interface
		// address syscall is never invoked for a denied scope.
		if q.Addrs {
			addrs, _ := ifc.Addrs()
			for _, a := range addrs {
				info.Addrs = append(info.Addrs, a.String())
			}
		}
		out = append(out, info)
	}
	return out, nil
}

func (genericPlatform) Ping(ctx context.Context, target string, opts PingOptions) (PingResult, error) {
	return PingResult{Target: target}, errors.New("icmp ping not yet implemented on this platform")
}

func (genericPlatform) Neighbors() ([]Neighbor, error) {
	// Linux would parse /proc/net/arp; deferred to the M6 cross-platform work.
	return nil, nil
}
