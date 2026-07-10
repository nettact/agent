// Package platform is the agent's hardware/OS abstraction layer (architecture
// §3 HAL / §12 platform adapters). Collectors depend only on this interface;
// each OS provides an implementation behind a build tag. This keeps collector
// logic free of syscall details and lets capability detection reflect what the
// host can actually do.
package platform

import (
	"context"
	"time"

	"github.com/nettact/protocol/capability"
)

// IfaceInfo is a normalized view of one network interface.
type IfaceInfo struct {
	Name       string
	Addrs      []string // unicast IP addresses
	Gateways   []string // default gateway IPs on this interface
	DNS        []string // DNS server IPs configured on this interface
	Up         bool
	IsLoopback bool
}

// PingResult is the outcome of a single ICMP echo.
type PingResult struct {
	Target   string
	RTT      time.Duration
	Received bool
}

// Neighbor is one entry from the ARP/neighbor table (a LAN device).
type Neighbor struct {
	IP  string
	MAC string
}

// Platform is the per-OS capability surface used by collectors.
type Platform interface {
	// Interfaces enumerates NICs with their IPs, gateway and DNS servers.
	Interfaces() ([]IfaceInfo, error)
	// Ping sends one ICMP echo to target (IP or hostname) bounded by timeout.
	Ping(ctx context.Context, target string, timeout time.Duration) (PingResult, error)
	// Neighbors reads the ARP/neighbor table (passive LAN device discovery).
	Neighbors() ([]Neighbor, error)
	// Supports reports the capabilities this host actually implements.
	Supports() []capability.Capability
}

// New returns the platform implementation for the current OS.
func New() Platform { return newPlatform() }
