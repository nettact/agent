//go:build !windows && !linux && !darwin

package platform

import (
	"context"
	"errors"

	"github.com/nettact/protocol/permission"
)

// genericPlatform is the stdlib-only fallback for the platforms with no native
// implementation (whatever else the agent cross-compiles for; Windows, Linux
// and macOS each have their own). It reports only what it can actually do —
// interface status/addresses and Wi-Fi — so ICMP, gateway probing and neighbor
// discovery never enter `supported` and the console shows them as a platform
// gap rather than a silent failure.
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
	if err != nil {
		return out, err
	}
	// Requesting gateways here yields an EMPTY list, which is not the same claim as
	// "this host has no gateway" — this fallback simply cannot read routes. Say so,
	// or a caller reads the silence as a LAN with no default route. (DNS is left
	// silent: an absent resolver list feeds no such misreading.)
	if q.Gateways {
		return out, ErrRoutesUnreadable
	}
	return out, nil
}

func (genericPlatform) Ping(ctx context.Context, target string, opts PingOptions) (PingResult, error) {
	return PingResult{Target: target}, errors.New("icmp ping not implemented on this platform")
}

func (genericPlatform) Neighbors() ([]Neighbor, error) {
	return nil, nil
}
