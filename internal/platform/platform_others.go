//go:build !windows

package platform

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/nettact/protocol/capability"
)

// genericPlatform is a stdlib-only fallback so the agent cross-compiles for
// Linux/darwin (the Docker Site-Agent target). Full ICMP via x/net/icmp and
// gateway/DNS discovery via /proc land in the M6 cross-platform work.
type genericPlatform struct{}

func newPlatform() Platform { return genericPlatform{} }

func (genericPlatform) Supports() []capability.Capability {
	return []capability.Capability{capability.NetIfaceRead}
}

func (genericPlatform) Interfaces() ([]IfaceInfo, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var out []IfaceInfo
	for _, ifc := range ifaces {
		info := IfaceInfo{
			Name:       ifc.Name,
			Up:         ifc.Flags&net.FlagUp != 0,
			IsLoopback: ifc.Flags&net.FlagLoopback != 0,
		}
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			info.Addrs = append(info.Addrs, a.String())
		}
		out = append(out, info)
	}
	return out, nil
}

func (genericPlatform) Ping(ctx context.Context, target string, timeout time.Duration) (PingResult, error) {
	return PingResult{Target: target}, errors.New("icmp ping not yet implemented on this platform")
}

func (genericPlatform) Neighbors() ([]Neighbor, error) {
	// Linux would parse /proc/net/arp; deferred to the M6 cross-platform work.
	return nil, nil
}
