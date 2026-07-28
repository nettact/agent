//go:build !windows && !linux

package platform

import (
	"context"
	"errors"

	"github.com/nettact/protocol/permission"
)

// genericPlatform is the stdlib-only fallback for the platforms with no native
// implementation yet (macOS and anything else the agent cross-compiles for). It
// reports only what it can actually do — interface status/addresses and Wi-Fi —
// so ICMP, gateway probing and neighbor discovery never enter `supported` and the
// console shows them as a platform gap rather than a silent failure.
//
// Windows has platform_windows.go and Linux has platform_linux.go; macOS route
// and neighbor tables need a different API again (sysctl over PF_ROUTE), which is
// still open work.
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
	// Gateways and DNS need per-OS route/resolver APIs this fallback does not
	// implement, so those fields stay empty even when requested.
	out, _, err := baseInterfaces(q)
	return out, err
}

func (genericPlatform) Ping(ctx context.Context, target string, opts PingOptions) (PingResult, error) {
	return PingResult{Target: target}, errors.New("icmp ping not implemented on this platform")
}

func (genericPlatform) Neighbors() ([]Neighbor, error) {
	return nil, nil
}
