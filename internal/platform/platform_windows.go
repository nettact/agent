//go:build windows

package platform

import (
	"context"
	"errors"
	"net"
	"runtime"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/nettact/protocol/capability"
)

// winPlatform implements Platform using CGO-free Windows syscalls (iphlpapi):
// GetAdaptersAddresses for interface/gateway/DNS enumeration and IcmpSendEcho
// for pings — the latter works WITHOUT Administrator, unlike raw sockets.
type winPlatform struct{}

func newPlatform() Platform { return winPlatform{} }

func (winPlatform) Supports() []capability.Capability {
	return []capability.Capability{
		capability.NetIfaceRead,
		capability.NetRouteRead,
		capability.ProbeICMP,
	}
}

// GetAdaptersAddresses flags / interface type not exported by x/sys.
const (
	gaaFlagSkipAnycast     = 0x0002
	gaaFlagSkipMulticast   = 0x0004
	gaaFlagIncludeGateways = 0x0080
	ifTypeSoftwareLoopback = 24
)

func (winPlatform) Interfaces() ([]IfaceInfo, error) {
	const flags = gaaFlagSkipAnycast | gaaFlagSkipMulticast | gaaFlagIncludeGateways

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
		info := IfaceInfo{
			Name:       windows.UTF16PtrToString(aa.FriendlyName),
			Up:         aa.OperStatus == windows.IfOperStatusUp,
			IsLoopback: aa.IfType == ifTypeSoftwareLoopback,
		}
		for ua := aa.FirstUnicastAddress; ua != nil; ua = ua.Next {
			if ip := ua.Address.IP(); ip != nil {
				info.Addrs = append(info.Addrs, ip.String())
			}
		}
		for ga := aa.FirstGatewayAddress; ga != nil; ga = ga.Next {
			if ip := ga.Address.IP(); ip != nil {
				info.Gateways = append(info.Gateways, ip.String())
			}
		}
		for da := aa.FirstDnsServerAddress; da != nil; da = da.Next {
			if ip := da.Address.IP(); ip != nil {
				info.DNS = append(info.DNS, ip.String())
			}
		}
		out = append(out, info)
	}
	runtime.KeepAlive(buf)
	return out, nil
}

// iphlpapi ICMP echo API (loaded lazily; no admin required).
var (
	iphlpapi            = windows.NewLazySystemDLL("iphlpapi.dll")
	procIcmpCreateFile  = iphlpapi.NewProc("IcmpCreateFile")
	procIcmpCloseHandle = iphlpapi.NewProc("IcmpCloseHandle")
	procIcmpSendEcho    = iphlpapi.NewProc("IcmpSendEcho")
)

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

func (winPlatform) Ping(ctx context.Context, target string, timeout time.Duration) (PingResult, error) {
	res := PingResult{Target: target}

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
	reqData := []byte("nettact-probe")
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
