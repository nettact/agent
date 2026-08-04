//go:build lite

package proxydial

import (
	"context"

	pcfg "github.com/nettact/protocol/config"
)

// The lite build (OpenWrt routers) leaves out userspace WireGuard: wireguard-go
// and the gVisor netstack it dials through are together the largest single
// contributor to the binary, and a router with 8 MB of flash cannot afford them
// for a transport it will almost never use.
//
// The failure is deliberately an invalidConfig, which isDeterministicInitError
// recognizes: a lite agent handed a WireGuard proxy reports the problem once per
// config generation instead of re-attempting it every probe cycle. It never
// falls back to a direct dial — a probe pinned to a proxy that cannot be built
// must fail, not silently measure the wrong path.
func (m *Manager) newWireGuard(_ context.Context, spec pcfg.ProxySpec) (*Dialer, error) {
	return nil, invalidConfig("proxy %s: wireguard egress is not available in this lite agent build", spec.ID)
}
