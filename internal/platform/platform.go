// Package platform is the agent's hardware/OS abstraction layer (architecture
// §3 HAL / §12 platform adapters). Collectors depend only on this interface;
// each OS provides an implementation behind a build tag. This keeps collector
// logic free of syscall details and lets capability detection reflect what the
// host can actually do.
package platform

import (
	"context"
	"time"

	"github.com/nettact/protocol/permission"
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
	// Reason classifies a non-received echo into a telemetry.ProbeReason* code
	// (Timeout / Unreachable / Other); 0 (ProbeReasonNone) when Received or when the
	// platform cannot classify (the non-Windows stub never sets it).
	Reason int
	// Detail is the OS's raw cause behind Reason (e.g. the IP_STATUS name on
	// Windows), human-readable and never localized; empty when Received or when the
	// platform cannot classify.
	Detail string
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

// IfaceQuery selects which per-interface fields the platform reads from the OS.
// The status fields (ID/Name/Up/IsLoopback/IsWireless) are always read; the
// address-bearing fields are read only when requested, so a scope the local
// policy denied never invokes the OS path that reads it (field-level no-call:
// the agent must not read a denied field then redact it).
type IfaceQuery struct {
	Addrs    bool // unicast IP addresses (network.interface.address.read)
	Gateways bool // default gateway IPs (address.read, or network.gateway.probe)
	DNS      bool // configured DNS server IPs (network.interface.address.read)
}

// Platform is the per-OS capability surface used by collectors.
type Platform interface {
	// Interfaces enumerates NICs. Address/gateway/DNS fields are populated only for
	// the field families requested in q; unrequested fields are never read from the
	// OS, keeping the field-level no-call boundary.
	Interfaces(q IfaceQuery) ([]IfaceInfo, error)
	// Ping sends one ICMP echo to target (IP or hostname) per opts.
	Ping(ctx context.Context, target string, opts PingOptions) (PingResult, error)
	// Neighbors reads the ARP/neighbor table (passive LAN device discovery).
	Neighbors() ([]Neighbor, error)
	// WiFi reports the current Wi-Fi status of every wireless adapter plus a
	// collection-level verdict (no adapter vs unreadable). Wired-only or
	// unsupported hosts return WiFiResult{State:"ok"} with no adapters. The SSID is
	// read from the OS only when includeSSID is true (network.wifi.ssid.read) — it
	// is never read then redacted.
	WiFi(includeSSID bool) WiFiResult
	// Supports reports the platform-dependent permissions this host actually
	// implements. Platform-independent probe permissions (dns/http/tcp/nat) are
	// added by the runtime, not here.
	Supports() permission.Set
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
