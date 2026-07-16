//go:build windows

package platform

import (
	"context"
	"errors"
	"net"
	"runtime"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/nettact/protocol/permission"
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
		// ICMP traceroute uses the same iphlpapi TTL echo path as ProbeICMP and
		// needs no Administrator, so it is a platform capability here. TCP
		// traceroute needs a raw ICMP socket (Administrator) and is gated at runtime
		// by the traceroute engine, not advertised as a static platform capability.
		permission.DiagnosticTracerouteICMP,
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
	return out, nil
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

	ret, _, _ := procIcmpSendEcho.Call(
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
		return res, nil // no reply: timeout or unreachable (Received=false)
	}
	reply := (*icmpEchoReply)(unsafe.Pointer(&replyBuf[0]))
	if reply.Status != 0 { // IP_SUCCESS == 0
		return res, nil
	}
	res.Received = true
	res.RTT = time.Duration(reply.RoundTripTime) * time.Millisecond
	return res, nil
}
