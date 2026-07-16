//go:build windows

package traceroute

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"runtime"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// detectCapabilities reports the real Windows traceroute capability. ICMP TTL
// echo via iphlpapi (IcmpSendEcho with a per-request TTL) needs no Administrator,
// so it is always available. TCP additionally needs a raw ICMP socket to observe
// intermediate Time-Exceeded responders; opening one requires Administrator, so
// it is probed at startup and gates the dedicated TCP permission's supported view.
func detectCapabilities() capabilities {
	return capabilities{ICMP: true, TCP: rawICMPCapable()}
}

// rawICMPCapable reports whether a raw ICMP socket can be opened (Administrator).
func rawICMPCapable() bool {
	s, err := windows.Socket(windows.AF_INET, windows.SOCK_RAW, windows.IPPROTO_ICMP)
	if err != nil {
		return false
	}
	_ = windows.Closesocket(s)
	return true
}

// iphlpapi ICMP echo APIs (loaded lazily; no admin required), mirroring the
// interface-collector's proven pattern. The traceroute engine keeps its own
// handles so it never contends with the live ping collector.
var (
	iphlpapi            = windows.NewLazySystemDLL("iphlpapi.dll")
	procIcmpCreateFile  = iphlpapi.NewProc("IcmpCreateFile")
	procIcmpCloseHandle = iphlpapi.NewProc("IcmpCloseHandle")
	procIcmpSendEcho    = iphlpapi.NewProc("IcmpSendEcho")
)

// icmpEchoReply mirrors ICMP_ECHO_REPLY (40 bytes on amd64; Go's natural
// alignment reproduces the C padding).
type icmpEchoReply struct {
	Address       uint32
	Status        uint32
	RoundTripTime uint32
	DataSize      uint16
	Reserved      uint16
	Data          uintptr
	Options       ipOptionInformation
}

// ipOptionInformation mirrors IP_OPTION_INFORMATION. TTL is the field the
// traceroute path sets to elicit an intermediate Time-Exceeded reply.
type ipOptionInformation struct {
	TTL         uint8
	Tos         uint8
	Flags       uint8
	OptionsSize uint8
	OptionsData uintptr
}

// IP_STATUS codes returned in ICMP_ECHO_REPLY.Status.
const (
	ipStatusSuccess           = 0
	ipStatusReqTimedOut       = 11010
	ipStatusTTLExpiredTransit = 11013
	ipStatusTTLExpiredReassem = 11014
)

// icmpProbe sends one ICMP echo toward dest with the given TTL. An IP_SUCCESS
// reply means the destination itself answered (reached); IP_TTL_EXPIRED means an
// intermediate router responded (recorded, not reached); anything else with no
// usable responder is a timeout (rendered as `*`).
func icmpProbe(_ context.Context, dest netip.Addr, _ int, ttl int, timeout time.Duration) (probeOutcome, error) {
	if !dest.Is4() {
		return probeOutcome{}, errUnsupported
	}
	ip4 := dest.As4()

	handle, _, _ := procIcmpCreateFile.Call()
	if handle == 0 || handle == ^uintptr(0) { // 0 or INVALID_HANDLE_VALUE
		return probeOutcome{}, errors.New("IcmpCreateFile failed")
	}
	defer procIcmpCloseHandle.Call(handle)

	destAddr := uint32(ip4[0]) | uint32(ip4[1])<<8 | uint32(ip4[2])<<16 | uint32(ip4[3])<<24
	reqData := []byte("nettact-trace")
	replyBuf := make([]byte, int(unsafe.Sizeof(icmpEchoReply{}))+len(reqData)+64)
	opts := ipOptionInformation{TTL: uint8(ttl)}

	to := uint32(timeout / time.Millisecond)
	if to == 0 {
		to = 1000
	}

	ret, _, _ := procIcmpSendEcho.Call(
		handle,
		uintptr(destAddr),
		uintptr(unsafe.Pointer(&reqData[0])),
		uintptr(len(reqData)),
		uintptr(unsafe.Pointer(&opts)),
		uintptr(unsafe.Pointer(&replyBuf[0])),
		uintptr(len(replyBuf)),
		uintptr(to),
	)
	runtime.KeepAlive(reqData)
	runtime.KeepAlive(opts)
	if ret == 0 {
		return probeOutcome{timeout: true}, nil // timeout or unreachable, no reply
	}
	reply := (*icmpEchoReply)(unsafe.Pointer(&replyBuf[0]))
	responder := ipFromUint32(reply.Address)
	rtt := float64(reply.RoundTripTime)
	switch reply.Status {
	case ipStatusSuccess:
		return probeOutcome{responder: responder, reached: true, rttMs: rtt}, nil
	case ipStatusTTLExpiredTransit, ipStatusTTLExpiredReassem:
		return probeOutcome{responder: responder, rttMs: rtt}, nil
	case ipStatusReqTimedOut:
		return probeOutcome{timeout: true}, nil
	default:
		// A responder returned an unreachable/other status: record its address as an
		// intermediate hop (never reached, since only an echo reply marks arrival).
		if responder.IsValid() && responder != netip.AddrFrom4([4]byte{}) {
			return probeOutcome{responder: responder, rttMs: rtt}, nil
		}
		return probeOutcome{timeout: true}, nil
	}
}

// IP_TTL socket option (ws2ipdef.h). Defined locally so the code does not depend
// on the constant being exported by x/sys/windows.
const ipTTL = 4

// wsaeConnRefused is WSAECONNREFUSED — a destination RST, which for TCP
// traceroute still means the destination was reached.
const wsaeConnRefused = windows.Errno(10061)

// tcpProbe runs one TTL-aware TCP probe. It sets IP_TTL on a connect socket and,
// on a raw ICMP socket, watches for a Time-Exceeded whose quoted TCP header
// matches this probe (dst ip+port and our ephemeral src port). A completed
// connect (SYN-ACK) or a refusal (RST) means the destination answered (reached);
// a captured Time-Exceeded is an intermediate responder; neither within the
// budget is a timeout. It never falls back to ICMP.
func tcpProbe(ctx context.Context, dest netip.Addr, port, ttl int, timeout time.Duration) (probeOutcome, error) {
	if !dest.Is4() {
		return probeOutcome{}, errUnsupported
	}
	ip4 := dest.As4()

	raw, err := windows.Socket(windows.AF_INET, windows.SOCK_RAW, windows.IPPROTO_ICMP)
	if err != nil {
		return probeOutcome{}, errUnsupported // raw-socket capability lost since startup
	}
	defer windows.Closesocket(raw) //nolint:errcheck
	// Bind the raw socket to the local address that reaches dest, so it receives
	// the routers' ICMP; fall back to INADDR_ANY.
	local := localIPv4For(dest)
	if berr := windows.Bind(raw, &windows.SockaddrInet4{Addr: local}); berr != nil {
		return probeOutcome{}, errUnsupported
	}

	tcp, err := windows.Socket(windows.AF_INET, windows.SOCK_STREAM, windows.IPPROTO_TCP)
	if err != nil {
		return probeOutcome{}, err
	}
	// Bind to an ephemeral port so the ICMP quotation can be correlated to us.
	if berr := windows.Bind(tcp, &windows.SockaddrInet4{}); berr != nil {
		_ = windows.Closesocket(tcp)
		return probeOutcome{}, berr
	}
	srcPort := 0
	if sa, gerr := windows.Getsockname(tcp); gerr == nil {
		if s4, ok := sa.(*windows.SockaddrInet4); ok {
			srcPort = s4.Port
		}
	}
	if serr := windows.SetsockoptInt(tcp, windows.IPPROTO_IP, ipTTL, ttl); serr != nil {
		_ = windows.Closesocket(tcp)
		return probeOutcome{}, serr
	}

	start := time.Now()
	connCh := make(chan probeOutcome, 1)
	icmpCh := make(chan probeOutcome, 1)

	// Connect goroutine: a completed handshake or a refusal (RST) is the
	// destination answering. It stays blocked on other outcomes until the socket
	// is closed below, which unblocks it with an error (no result).
	go func() {
		cerr := windows.Connect(tcp, &windows.SockaddrInet4{Addr: ip4, Port: port})
		rtt := float64(time.Since(start).Microseconds()) / 1000.0
		if cerr == nil {
			connCh <- probeOutcome{responder: dest, reached: true, rttMs: rtt}
			return
		}
		var errno windows.Errno
		if errors.As(cerr, &errno) && errno == wsaeConnRefused {
			connCh <- probeOutcome{responder: dest, reached: true, rttMs: rtt}
			return
		}
		connCh <- probeOutcome{} // no usable result
	}()

	// ICMP capture goroutine: return the first Time-Exceeded/Unreachable that
	// quotes this probe. Closing the raw socket below unblocks Recvfrom.
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, rerr := windows.Recvfrom(raw, buf, 0)
			if rerr != nil {
				icmpCh <- probeOutcome{}
				return
			}
			if !matchICMPQuotation(buf[:n], ip4, port, srcPort) {
				continue
			}
			responder := responderAddr(from)
			icmpCh <- probeOutcome{responder: responder, rttMs: float64(time.Since(start).Microseconds()) / 1000.0}
			return
		}
	}()

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	var out probeOutcome
	select {
	case o := <-connCh:
		if o.reached {
			out = o
		} else {
			// Connect gave no clear reach; prefer an ICMP responder if one is ready.
			select {
			case oi := <-icmpCh:
				out = pickResponder(oi)
			default:
				out = probeOutcome{timeout: true}
			}
		}
	case o := <-icmpCh:
		out = pickResponder(o)
	case <-timer.C:
		out = probeOutcome{timeout: true}
	case <-ctx.Done():
		out = probeOutcome{timeout: true}
	}
	// Unblock both goroutines: closing tcp releases a blocked Connect; the deferred
	// raw close releases a blocked Recvfrom. Both send to cap-1 buffered channels,
	// so neither leaks.
	_ = windows.Closesocket(tcp)
	return out, nil
}

// pickResponder normalizes an ICMP goroutine result: a valid responder is an
// intermediate hop; an invalid one (socket closed) is a timeout.
func pickResponder(o probeOutcome) probeOutcome {
	if o.responder.IsValid() && o.responder != netip.AddrFrom4([4]byte{}) {
		return o
	}
	return probeOutcome{timeout: true}
}

// localIPv4For returns the local IPv4 the OS would use to reach dest, for binding
// the raw ICMP socket. A UDP "dial" sends no packets; on any failure it falls
// back to INADDR_ANY.
func localIPv4For(dest netip.Addr) [4]byte {
	c, err := net.Dial("udp4", net.JoinHostPort(dest.String(), "9"))
	if err != nil {
		return [4]byte{}
	}
	defer c.Close()
	if ua, ok := c.LocalAddr().(*net.UDPAddr); ok {
		if a, ok := netip.AddrFromSlice(ua.IP); ok {
			if a = a.Unmap(); a.Is4() {
				return a.As4()
			}
		}
	}
	return [4]byte{}
}

// responderAddr extracts the IPv4 responder address from a Recvfrom sockaddr.
func responderAddr(from windows.Sockaddr) netip.Addr {
	if s4, ok := from.(*windows.SockaddrInet4); ok {
		return netip.AddrFrom4(s4.Addr)
	}
	return netip.Addr{}
}

// matchICMPQuotation reports whether a received ICMP packet (starting at the IP
// header, as Windows raw sockets deliver it) is a Time-Exceeded or Destination-
// Unreachable that quotes this probe's TCP SYN: inner protocol TCP, inner dst ==
// dest:port, and inner src port == our ephemeral port. The correlation lets
// concurrent traces on the same host ignore each other's ICMP.
func matchICMPQuotation(pkt []byte, destIP [4]byte, destPort, srcPort int) bool {
	if len(pkt) < 20 {
		return false
	}
	ihl := int(pkt[0]&0x0f) * 4
	if ihl < 20 || len(pkt) < ihl+8 {
		return false
	}
	icmpType := pkt[ihl]
	if icmpType != 11 && icmpType != 3 { // Time Exceeded / Destination Unreachable
		return false
	}
	inner := pkt[ihl+8:] // original IP header + first 8 bytes of transport
	if len(inner) < 20 {
		return false
	}
	innerIHL := int(inner[0]&0x0f) * 4
	if innerIHL < 20 || len(inner) < innerIHL+8 {
		return false
	}
	if inner[9] != 6 { // inner protocol must be TCP
		return false
	}
	// Inner destination IP (bytes 16..20 of the inner IP header).
	if inner[16] != destIP[0] || inner[17] != destIP[1] || inner[18] != destIP[2] || inner[19] != destIP[3] {
		return false
	}
	tcpHdr := inner[innerIHL:]
	innerSrc := int(tcpHdr[0])<<8 | int(tcpHdr[1])
	innerDst := int(tcpHdr[2])<<8 | int(tcpHdr[3])
	return innerSrc == srcPort && innerDst == destPort
}

// ipFromUint32 converts a little-endian IPv4 (as iphlpapi returns) to a netip.Addr.
func ipFromUint32(a uint32) netip.Addr {
	return netip.AddrFrom4([4]byte{byte(a), byte(a >> 8), byte(a >> 16), byte(a >> 24)})
}
