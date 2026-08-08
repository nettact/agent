//go:build windows

package traceroute

import (
	"context"
	"errors"
	"net/netip"
	"runtime"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// detectCapabilities reports the real Windows traceroute capability. ICMP TTL
// echo via iphlpapi (IcmpSendEcho with a per-request TTL) needs no Administrator,
// so it is always available. TCP additionally needs a raw ICMP socket that can
// actually receive intermediate Time-Exceeded responses; see
// icmpErrorCaptureCapable for why that is a process-elevation check, not a
// socket-creation check. It is probed at startup and gates the dedicated TCP
// permission's supported view.
func detectCapabilities() capabilities {
	return capabilities{ICMP: true, TCP: icmpErrorCaptureCapable()}
}

// icmpErrorCaptureCapable reports whether this process can receive ICMP error
// messages (Time-Exceeded, Destination-Unreachable) on a raw ICMP socket, which
// TCP traceroute needs to see intermediate routers. Two conditions must both
// hold, and neither implies the other:
//
//   - The process token must be elevated. Windows specially permits
//     socket(AF_INET, SOCK_RAW, IPPROTO_ICMP) for non-elevated processes too,
//     but a non-elevated process's raw ICMP socket only ever receives echo
//     replies (type 0) — never Time-Exceeded/Unreachable from intermediate
//     hops — while the identical code in an elevated process (or a Windows
//     service running as SYSTEM, which counts as elevated) receives them
//     normally (measured behavior). Socket creation succeeding is therefore
//     not a usable capability signal on its own.
//   - The raw socket must actually be creatable: an elevated process can still
//     be denied raw sockets by host security policy, and tcpProbe cannot
//     observe intermediate responders without one.
func icmpErrorCaptureCapable() bool {
	if !windows.GetCurrentProcessToken().IsElevated() {
		return false
	}
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
	ipStatusBadRoute          = 11012
	ipStatusTTLExpiredTransit = 11013
	ipStatusTTLExpiredReassem = 11014
)

// Win32 routing failures IcmpSendEcho can surface through GetLastError instead of
// the IP_STATUS namespace. Defined locally, like wsaeConnRefused below, so the
// code does not depend on x/sys/windows exporting them.
const (
	errorNetworkUnreachable = 1231 // ERROR_NETWORK_UNREACHABLE
	errorHostUnreachable    = 1232 // ERROR_HOST_UNREACHABLE
)

// localSendFailureStatus reports whether an IcmpSendEcho failure code means this
// host could not emit the probe at all — no route, no reachable next hop.
//
// Only the codes the local routing lookup produces are listed. IP_DEST_NET_
// UNREACHABLE / IP_DEST_HOST_UNREACHABLE are deliberately absent even though a
// local failure can surface as either: the same two IP_STATUS values also carry
// a REMOTE router's ICMP unreachable, and with no reply record there is no
// responder address to tell the two apart. Treating those as local would let a
// router that refuses to forward abort the whole sweep under a verdict about
// the agent's own machine, so they fall through to a timeout instead — the same
// `*` this path produced before local failures were classified at all. The cost
// is that some Windows local failures are detected only by running the sweep
// out; the alternative is a confident wrong answer.
func localSendFailureStatus(code uintptr) bool {
	switch code {
	case ipStatusBadRoute, errorNetworkUnreachable, errorHostUnreachable:
		return true
	}
	return false
}

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

	ret, _, callErr := procIcmpSendEcho.Call(
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
		// No reply record at all. GetLastError separates "this host had nowhere to
		// send it" from an ordinary silent hop; only the former invalidates the
		// sweep, since no TTL would fare any better.
		var errno windows.Errno
		if errors.As(callErr, &errno) && localSendFailureStatus(uintptr(errno)) {
			return probeOutcome{localUnreachable: true}, nil
		}
		return probeOutcome{timeout: true}, nil
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
		// intermediate hop (never reached, since only an echo reply marks arrival) —
		// unless the address is one of ours, which means our own stack produced the
		// error and the probe never reached the wire (see isLocalAddr).
		if responder.IsValid() && responder != netip.AddrFrom4([4]byte{}) {
			if isLocalAddr(responder) {
				return probeOutcome{localUnreachable: true}, nil
			}
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
	//
	// No routing errno is classified here, unlike the unix path. There the check
	// sits on a NON-BLOCKING connect that returns before a SYN could leave, so
	// ENETUNREACH can only be the local routing decision. This connect blocks:
	// when a router on the path answers the SYN with an ICMP unreachable,
	// Winsock surfaces it as WSAENETUNREACH / WSAEHOSTUNREACH on this call, and
	// nothing in the errno says which of the two happened. Only the raw socket
	// knows, because it has the responder's address (see isLocalAddr below).
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
			if isLocalAddr(responder) {
				icmpCh <- probeOutcome{localUnreachable: true}
				return
			}
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

// responderAddr extracts the IPv4 responder address from a Recvfrom sockaddr.
func responderAddr(from windows.Sockaddr) netip.Addr {
	if s4, ok := from.(*windows.SockaddrInet4); ok {
		return netip.AddrFrom4(s4.Addr)
	}
	return netip.Addr{}
}

// ipFromUint32 converts a little-endian IPv4 (as iphlpapi returns) to a netip.Addr.
func ipFromUint32(a uint32) netip.Addr {
	return netip.AddrFrom4([4]byte{byte(a), byte(a >> 8), byte(a >> 16), byte(a >> 24)})
}
