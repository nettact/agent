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
	// ID is a stable per-OS adapter key used to join Wi-Fi status onto the right
	// interface row: on Windows the adapter GUID (IpAdapterAddresses.AdapterName),
	// elsewhere the interface name. Never empty.
	ID         string
	Name       string
	Addrs      []string // unicast IP addresses
	Gateways   []string // default gateway IPs on this interface
	DNS        []string // DNS server IPs configured on this interface
	Up         bool
	IsLoopback bool
	// IsWireless marks known Wi-Fi hardware (Windows IfType==71, Linux
	// /sys/class/net/<name>/wireless, macOS a CoreWLAN-listed name matched during
	// snapshot assembly). True even when the adapter's Wi-Fi status is unreadable,
	// so wireless hardware never masquerades as a wired interface.
	IsWireless bool
}

// WiFiResult is the collection-level outcome of one WiFi() call: the Wi-Fi
// subsystem verdict plus every adapter's current status. There is no error
// return — the classification IS the result (architecture §4 wireless layer).
type WiFiResult struct {
	State    string // "ok" | "unreadable" (collection level)
	Reason   string // "permission" | "driver" when State=="unreadable"
	Adapters []WiFiStatus
}

// WiFiStatus is one wireless adapter's current status as read from the OS. State
// and Reason mirror the telemetry enums (open strings). Nil numeric pointers mean
// "unknown / not reported" — never a synthetic zero.
type WiFiStatus struct {
	ID        string // joins IfaceInfo.ID (GUID on Windows, name elsewhere)
	Name      string
	State     string // "connected" | "disconnected" | "unreadable"
	Reason    string // "permission" | "driver" when relevant
	SSID      string
	Band      string // "2.4" | "5" | "6" | ""
	Channel   int    // 0 unknown
	SignalDBm *int
	Quality   *int // 0-100 percent
	RxMbps    *float64
	TxMbps    *float64
}

// PingResult is the outcome of a single ICMP echo.
type PingResult struct {
	Target   string
	RTT      time.Duration
	Received bool
}

// PingOptions tunes a single ICMP echo. Zero values mean "use defaults", so an
// unconfigured caller behaves as before (2s timeout, small fixed payload).
type PingOptions struct {
	Timeout     time.Duration // per-echo timeout; 0 = 1s
	PayloadSize int           // ICMP payload bytes; 0 = default probe payload
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
	// Ping sends one ICMP echo to target (IP or hostname) per opts.
	Ping(ctx context.Context, target string, opts PingOptions) (PingResult, error)
	// Neighbors reads the ARP/neighbor table (passive LAN device discovery).
	Neighbors() ([]Neighbor, error)
	// WiFi reports the current Wi-Fi status of every wireless adapter plus a
	// collection-level verdict (no adapter vs unreadable). Wired-only or
	// unsupported hosts return WiFiResult{State:"ok"} with no adapters.
	WiFi() WiFiResult
	// Supports reports the capabilities this host actually implements.
	Supports() []capability.Capability
}

// New returns the platform implementation for the current OS.
func New() Platform { return newPlatform() }

// pingPayload builds an ICMP echo payload of the requested size. size <= 0 uses
// the default 13-byte probe marker; otherwise the marker is repeated/truncated
// to exactly size bytes (clamped to a sane maximum).
func pingPayload(size int) []byte {
	const marker = "nettact-probe"
	if size <= 0 {
		return []byte(marker)
	}
	if size > 65500 {
		size = 65500
	}
	buf := make([]byte, size)
	for i := range buf {
		buf[i] = marker[i%len(marker)]
	}
	return buf
}
