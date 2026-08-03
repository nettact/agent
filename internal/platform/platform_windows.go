//go:build windows

package platform

import (
	"context"
	"errors"
	"fmt"
	"net"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/nettact/protocol/permission"
	"github.com/nettact/protocol/telemetry"
)

// winPlatform implements Platform using CGO-free Windows syscalls (iphlpapi):
// GetAdaptersAddresses for interface/gateway/DNS enumeration and IcmpSendEcho
// for pings — the latter works WITHOUT Administrator, unlike raw sockets.
type winPlatform struct{}

func newPlatform() Platform { return winPlatform{} }

func (winPlatform) Supports() permission.Set {
	s := permission.NewSet(
		permission.NetIfaceStatusRead,
		permission.NetIfaceAddressRead,
		permission.NetworkGatewayProbe,
		permission.ProbeICMP,
		permission.NetNeighborRead,
		permission.NetNeighborHostRead,
		// Neither traceroute mode is advertised here: the traceroute engine owns
		// that capability probe on every OS (see agentrt). On Windows it reports
		// ICMP unconditionally — the iphlpapi TTL echo path needs no Administrator —
		// and TCP only for an elevated process.
	)
	for _, id := range wifiPermissions() {
		s.Add(id)
	}
	return s
}

// GetAdaptersAddresses flags / interface type not exported by x/sys.
const (
	gaaFlagSkipUnicast     = 0x0001
	gaaFlagSkipAnycast     = 0x0002
	gaaFlagSkipMulticast   = 0x0004
	gaaFlagSkipDNSServer   = 0x0008
	gaaFlagIncludeGateways = 0x0080
	ifTypeSoftwareLoopback = 24
	ifTypeIEEE80211        = 71 // IF_TYPE_IEEE80211 (native Wi-Fi)
)

// msVirtualWirelessAdapterMarkers are the driver-description fragments of the
// hidden virtual wireless adapters Windows spins up off a physical Wi-Fi NIC.
// All three come from the same inbox miniport driver (netvwifimp.inf, the vwifi
// bus): the base vwifimp device plus its SoftAP and Wi-Fi Direct children. These
// strings are the driver device descriptions, not the localized connection name
// ("本地连接* N"), so they are identical across OS display languages, and no real
// Wi-Fi client adapter is described this way — filtering on them can never hide
// genuine hardware.
var msVirtualWirelessAdapterMarkers = []string{
	"Wi-Fi Direct Virtual Adapter",   // vwifimp_wfd: mobile hotspot / Miracast P2P endpoint
	"Hosted Network Virtual Adapter", // vwifimp_sap: legacy soft-AP (netsh wlan hostednetwork)
	"Virtual WiFi Miniport Adapter",  // vwifimp: base bus-enumerated virtual miniport
}

// isHiddenVirtualWirelessAdapter reports whether an adapter description belongs
// to one of the OS-synthesized hidden Wi-Fi virtual adapters. It is the
// GetAdaptersAddresses-visible stand-in for the NDIS Hidden flag, which that API
// does not surface.
func isHiddenVirtualWirelessAdapter(desc string) bool {
	for _, m := range msVirtualWirelessAdapterMarkers {
		if strings.Contains(desc, m) {
			return true
		}
	}
	return false
}

// ipv4Route is one interface's cheapest IPv4 default route as the forwarding
// table reports it, before the adapter's interface metric is added.
type ipv4Route struct {
	gateway string
	metric  int
}

// ipv4DefaultRoutes reads the IPv4 forwarding table and returns each interface's
// cheapest default route, keyed by interface index.
//
// The routing table is the only place the pairing exists. GetAdaptersAddresses
// reports an adapter's gateway addresses and its interface metric, but nothing
// tying one to the other, and Windows ranks a route by its own metric PLUS the
// interface metric — so an adapter with the lower interface metric can still lose
// to one carrying a cheaper route, and a NIC with a manually added backup default
// has two gateways whose costs differ while the adapter reports one number for
// both.
func ipv4DefaultRoutes() (map[uint32]ipv4Route, error) {
	var table *windows.MibIpForwardTable2
	if err := windows.GetIpForwardTable2(windows.AF_INET, &table); err != nil {
		return nil, err
	}
	defer windows.FreeMibTable(unsafe.Pointer(table))

	out := map[uint32]ipv4Route{}
	for _, row := range table.Rows() {
		if row.DestinationPrefix.PrefixLength != 0 || row.NextHop.Family != windows.AF_INET {
			continue
		}
		ip := net.IP((*windows.RawSockaddrInet4)(unsafe.Pointer(&row.NextHop)).Addr[:])
		// An on-link default (next hop 0.0.0.0, e.g. a point-to-point WAN link)
		// still routes, but it names no gateway to report or ping.
		if ip.IsUnspecified() {
			continue
		}
		metric := int(row.Metric)
		if prev, ok := out[row.InterfaceIndex]; ok && prev.metric <= metric {
			continue
		}
		out[row.InterfaceIndex] = ipv4Route{gateway: ip.String(), metric: metric}
	}
	return out, nil
}

func (winPlatform) Interfaces(q IfaceQuery) ([]IfaceInfo, error) {
	// Field-level no-read: tell the OS to omit the denied structures entirely
	// rather than fetching them and skipping the iteration. A denied address or
	// DNS scope must not have its data populated into the buffer at all.
	flags := uint32(gaaFlagSkipAnycast | gaaFlagSkipMulticast)
	if !q.Addrs {
		flags |= gaaFlagSkipUnicast
	}
	if !q.DNS {
		flags |= gaaFlagSkipDNSServer
	}
	if q.Gateways {
		flags |= gaaFlagIncludeGateways
	}

	// An unreadable forwarding table is partial, not fatal: the adapter walk below
	// still fills in every interface's status, addresses and gateway addresses, and
	// only the default-route ranking is unknown. Saying so (rather than reporting
	// no default route) keeps "this host has no gateway" distinct from "the agent
	// could not look" — see ErrRoutesUnreadable.
	var routes map[uint32]ipv4Route
	var routesErr error
	if q.Gateways {
		if routes, routesErr = ipv4DefaultRoutes(); routesErr != nil {
			routesErr = fmt.Errorf("%w: %v", ErrRoutesUnreadable, routesErr)
		}
	}

	size := uint32(15000)
	var buf []byte
	var head *windows.IpAdapterAddresses
	for attempt := 0; attempt < 4; attempt++ {
		buf = make([]byte, size)
		head = (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0]))
		err := windows.GetAdaptersAddresses(windows.AF_UNSPEC, flags, 0, head, &size)
		if err == nil {
			break
		}
		if err == windows.ERROR_BUFFER_OVERFLOW {
			continue // size now holds the required length; retry with a bigger buffer
		}
		return nil, err
	}

	var out []IfaceInfo
	for aa := head; aa != nil; aa = aa.Next {
		// Drop the OS-synthesized hidden virtual wireless adapters (Wi-Fi Direct /
		// Hosted Network). Windows creates these off the physical Wi-Fi NIC for
		// mobile hotspot / Miracast; they surface as IF_TYPE_IEEE80211 rows here
		// (GetAdaptersAddresses does not expose the NDIS Hidden flag) yet never
		// appear in the Network Connections panel and carry no user-facing link.
		if isHiddenVirtualWirelessAdapter(windows.UTF16PtrToString(aa.Description)) {
			continue
		}
		info := IfaceInfo{
			ID:         strings.ToUpper(windows.BytePtrToString(aa.AdapterName)),
			Name:       windows.UTF16PtrToString(aa.FriendlyName),
			Up:         aa.OperStatus == windows.IfOperStatusUp,
			IsLoopback: aa.IfType == ifTypeSoftwareLoopback,
			IsWireless: aa.IfType == ifTypeIEEE80211,
		}
		// Address-bearing fields are read only when requested — a denied scope must
		// not have its data extracted from the OS structures at all.
		if q.Addrs {
			for ua := aa.FirstUnicastAddress; ua != nil; ua = ua.Next {
				if ip := ua.Address.IP(); ip != nil {
					info.Addrs = append(info.Addrs, ip.String())
				}
			}
		}
		if q.Gateways {
			for ga := aa.FirstGatewayAddress; ga != nil; ga = ga.Next {
				if ip := ga.Address.IP(); ip != nil {
					info.Gateways = append(info.Gateways, ip.String())
				}
			}
			if route, ok := routes[aa.IfIndex]; ok {
				// Windows ranks a route by its own metric plus the metric of the
				// interface it leaves by, so the sum is the comparable cost.
				metric := route.metric + int(aa.Ipv4Metric)
				info.IPv4Default = &IPv4Default{Gateway: route.gateway, Metric: &metric}
			}
		}
		if q.DNS {
			for da := aa.FirstDnsServerAddress; da != nil; da = da.Next {
				if ip := da.Address.IP(); ip != nil {
					info.DNS = append(info.DNS, ip.String())
				}
			}
		}
		out = append(out, info)
	}
	runtime.KeepAlive(buf)
	return out, routesErr
}

// iphlpapi ICMP echo + ARP table APIs (loaded lazily; no admin required).
var (
	iphlpapi            = windows.NewLazySystemDLL("iphlpapi.dll")
	procIcmpCreateFile  = iphlpapi.NewProc("IcmpCreateFile")
	procIcmpCloseHandle = iphlpapi.NewProc("IcmpCloseHandle")
	procIcmpSendEcho    = iphlpapi.NewProc("IcmpSendEcho")
	procGetIpNetTable   = iphlpapi.NewProc("GetIpNetTable")
)

// mibIPNetRow mirrors MIB_IPNETROW (IPv4 ARP entry, 24 bytes on amd64).
type mibIPNetRow struct {
	Index       uint32
	PhysAddrLen uint32
	PhysAddr    [8]byte
	Addr        uint32 // IPv4, network byte order
	Type        uint32 // 1 other, 2 invalid, 3 dynamic, 4 static
}

const errorInsufficientBuffer = 122

// Neighbors reads the IPv4 ARP table via GetIpNetTable (passive discovery; no
// packet capture / Npcap needed).
func (winPlatform) Neighbors() ([]Neighbor, error) {
	var size uint32
	_, _, _ = procGetIpNetTable.Call(0, uintptr(unsafe.Pointer(&size)), 0)
	if size == 0 {
		return nil, nil
	}
	buf := make([]byte, size)
	r0, _, _ := procGetIpNetTable.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 0)
	if r0 != 0 {
		if r0 == errorInsufficientBuffer {
			return nil, nil // table grew between calls; skip this round
		}
		return nil, errors.New("GetIpNetTable failed")
	}
	num := *(*uint32)(unsafe.Pointer(&buf[0]))
	rowSize := int(unsafe.Sizeof(mibIPNetRow{}))

	var out []Neighbor
	for i := 0; i < int(num); i++ {
		off := 4 + i*rowSize
		if off+rowSize > len(buf) {
			break
		}
		row := (*mibIPNetRow)(unsafe.Pointer(&buf[off]))
		if row.PhysAddrLen == 0 || row.Type == 2 { // skip incomplete/invalid
			continue
		}
		ip := net.IPv4(byte(row.Addr), byte(row.Addr>>8), byte(row.Addr>>16), byte(row.Addr>>24))
		mac := net.HardwareAddr(row.PhysAddr[:row.PhysAddrLen]).String()
		out = append(out, Neighbor{IP: ip.String(), MAC: mac})
	}
	runtime.KeepAlive(buf)
	return out, nil
}

// icmpEchoReply mirrors ICMP_ECHO_REPLY. Field order/alignment matches the C
// struct on amd64 (40 bytes); Go's natural alignment reproduces the C padding.
type icmpEchoReply struct {
	Address       uint32
	Status        uint32
	RoundTripTime uint32
	DataSize      uint16
	Reserved      uint16
	Data          uintptr
	Options       ipOptionInformation
}

type ipOptionInformation struct {
	TTL         uint8
	Tos         uint8
	Flags       uint8
	OptionsSize uint8
	OptionsData uintptr
}

func (winPlatform) Ping(ctx context.Context, target string, opts PingOptions) (PingResult, error) {
	res := PingResult{Target: target}
	timeout := opts.Timeout

	ip := net.ParseIP(target)
	if ip == nil {
		ips, err := net.DefaultResolver.LookupIP(ctx, "ip4", target)
		if err != nil || len(ips) == 0 {
			return res, errors.New("cannot resolve target: " + target)
		}
		ip = ips[0]
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return res, errors.New("only IPv4 ICMP is supported in P0")
	}

	handle, _, _ := procIcmpCreateFile.Call()
	if handle == 0 || handle == ^uintptr(0) { // 0 or INVALID_HANDLE_VALUE
		return res, errors.New("IcmpCreateFile failed")
	}
	defer procIcmpCloseHandle.Call(handle)

	dest := uint32(ip4[0]) | uint32(ip4[1])<<8 | uint32(ip4[2])<<16 | uint32(ip4[3])<<24
	reqData := pingPayload(opts.PayloadSize)
	replyBuf := make([]byte, int(unsafe.Sizeof(icmpEchoReply{}))+len(reqData)+64)

	to := uint32(timeout / time.Millisecond)
	if to == 0 {
		to = 1000
	}

	ret, _, callErr := procIcmpSendEcho.Call(
		handle,
		uintptr(dest),
		uintptr(unsafe.Pointer(&reqData[0])),
		uintptr(len(reqData)),
		0, // no IP options
		uintptr(unsafe.Pointer(&replyBuf[0])),
		uintptr(len(replyBuf)),
		uintptr(to),
	)
	runtime.KeepAlive(reqData)
	if ret == 0 {
		// No reply. GetLastError carries the extended IP_STATUS (timeout / unreachable);
		// classify it so a fully-lost cycle records WHY (an unclassifiable send defaults
		// to timeout — the echo got no answer within the deadline), and keep the raw
		// IP_STATUS name as the detail behind the classification.
		res.Reason = telemetry.ProbeReasonTimeout
		if errno, ok := callErr.(syscall.Errno); ok && errno != 0 {
			if r := mapWinIPStatus(uint32(errno)); r != telemetry.ProbeReasonNone {
				res.Reason = r
			}
			res.Detail = winIPStatusName(uint32(errno))
		}
		return res, nil
	}
	reply := (*icmpEchoReply)(unsafe.Pointer(&replyBuf[0]))
	if reply.Status != 0 { // IP_SUCCESS == 0
		res.Reason = mapWinIPStatus(reply.Status)
		if res.Reason == telemetry.ProbeReasonNone {
			res.Reason = telemetry.ProbeReasonTimeout
		}
		res.Detail = winIPStatusName(reply.Status)
		return res, nil
	}
	res.Received = true
	res.RTT = time.Duration(reply.RoundTripTime) * time.Millisecond
	return res, nil
}

// Win32 IP_STATUS codes (iphlpapi) for a failed ICMP echo.
const (
	ipDestNetUnreachable  = 11002
	ipDestHostUnreachable = 11003
	ipDestProtUnreachable = 11004
	ipDestPortUnreachable = 11005
	ipReqTimedOut         = 11010
)

// mapWinIPStatus maps a Win32 IP_STATUS to a telemetry.ProbeReason* code.
func mapWinIPStatus(status uint32) int {
	switch status {
	case ipReqTimedOut:
		return telemetry.ProbeReasonTimeout
	case ipDestNetUnreachable, ipDestHostUnreachable, ipDestProtUnreachable, ipDestPortUnreachable:
		return telemetry.ProbeReasonUnreachable
	case 0: // IP_SUCCESS
		return telemetry.ProbeReasonNone
	default:
		return telemetry.ProbeReasonOther
	}
}

// winIPStatusNames are the ipexport.h identifiers for the IP_STATUS codes an
// IcmpSendEcho failure can surface, so the detail label states the OS's own name
// rather than a bare number.
var winIPStatusNames = map[uint32]string{
	11001: "IP_BUF_TOO_SMALL",
	11002: "IP_DEST_NET_UNREACHABLE",
	11003: "IP_DEST_HOST_UNREACHABLE",
	11004: "IP_DEST_PROT_UNREACHABLE",
	11005: "IP_DEST_PORT_UNREACHABLE",
	11006: "IP_NO_RESOURCES",
	11007: "IP_BAD_OPTION",
	11008: "IP_HW_ERROR",
	11009: "IP_PACKET_TOO_BIG",
	11010: "IP_REQ_TIMED_OUT",
	11011: "IP_BAD_REQ",
	11012: "IP_BAD_ROUTE",
	11013: "IP_TTL_EXPIRED_TRANSIT",
	11014: "IP_TTL_EXPIRED_REASSEM",
	11015: "IP_PARAM_PROBLEM",
	11016: "IP_SOURCE_QUENCH",
	11017: "IP_OPTION_TOO_BIG",
	11018: "IP_BAD_DESTINATION",
	11050: "IP_GENERAL_FAILURE",
}

// winIPStatusName renders an IP_STATUS for the error_class detail label:
// "IP_DEST_HOST_UNREACHABLE (11003)" for a known code, the bare "IP_STATUS <n>"
// otherwise — the number alone is still the machine truth.
func winIPStatusName(status uint32) string {
	n := strconv.FormatUint(uint64(status), 10)
	if name, ok := winIPStatusNames[status]; ok {
		return name + " (" + n + ")"
	}
	return "IP_STATUS " + n
}
