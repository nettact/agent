// Package platform is the agent's hardware/OS abstraction layer (architecture
// §3 HAL / §12 platform adapters). Collectors depend only on this interface;
// each OS provides an implementation behind a build tag. This keeps collector
// logic free of syscall details and lets capability detection reflect what the
// host can actually do.
package platform

import (
	"context"
	"errors"
	"net"
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

// ErrRoutesUnreadable reports that Interfaces enumerated the NICs fine but could
// not read the routing table, so IfaceInfo.Gateways is UNKNOWN rather than known
// to be empty. It is returned alongside a fully populated interface list, so a
// caller that only needs interface status/addresses should carry on; a caller
// that needs gateways must treat it as a failure to read, never as "this host has
// no gateway". Test it with errors.Is.
//
// Without this the two are indistinguishable: a Linux netlink route dump that
// fails under a restrictive seccomp policy left an empty route table behind and
// reported success, so an incident scene blamed the NIC for having no gateway
// when the agent had simply been unable to look.
var ErrRoutesUnreadable = errors.New("platform: routing table unreadable")

// New returns the platform implementation for the current OS.
func New() Platform { return newPlatform() }

// ResolveIPv4Gateway returns the first IPv4 gateway on the chosen interface, plus
// that interface's name. When iface is empty it falls back to the default: the
// first IPv4 gateway on any up, non-loopback interface. When iface is set but not
// found (or has no IPv4 gateway) it returns "", so the caller reports the gateway
// as unreachable rather than silently naming a different NIC's gateway.
//
// This is the ONE default-egress resolver in the agent. The gateway probe, the
// interface snapshot, and the incident-scene target resolution all call it, which
// is what guarantees that the gateway IP the console shows for an incident is the
// same one the monitor actually pinged.
func ResolveIPv4Gateway(ifaces []IfaceInfo, iface string) (gateway, interfaceName string) {
	for _, ifc := range ifaces {
		if ifc.IsLoopback || !ifc.Up {
			continue
		}
		if iface != "" && ifc.ID != iface && ifc.Name != iface {
			continue
		}
		for _, gw := range ifc.Gateways {
			if ip := net.ParseIP(gw); ip != nil && ip.To4() != nil {
				return gw, ifc.Name
			}
		}
	}
	return "", ""
}

// appendUnique appends v unless list already holds it, preserving order. The OS
// tables this package reads (neighbors, resolvers, per-adapter DNS) routinely
// repeat an entry across sources, and their order is meaningful.
func appendUnique(list []string, v string) []string {
	for _, x := range list {
		if x == v {
			return list
		}
	}
	return append(list, v)
}

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
