package platform

import (
	"encoding/binary"
	"net"
	"net/netip"
)

// Routing-socket (PF_ROUTE) sysctl parsing for the two facts the stdlib does
// not expose on macOS: default gateways and the ARP/NDP neighbor table. The
// dumps come from sysctl(CTL_NET, PF_ROUTE, …) — NET_RT_DUMP for routes,
// NET_RT_FLAGS+RTF_LLINFO for neighbors — the same ground `netstat -rn`,
// `arp -an` and `ndp -an` stand on, and the macOS counterpart of the Linux
// netlink pair in netlink_linux.go.
//
// The fetch itself is darwin-only (route_darwin.go, via x/net/route.FetchRIB,
// which owns the ENOMEM retry dance). Everything here is a pure function over
// the returned bytes, deliberately built from hand-written offsets rather than
// darwin-tagged syscall types: this workspace develops on Windows, and keeping
// the parsers untagged is what lets the fixture tests run on every GOOS. The
// wire format is fixed — struct rt_msghdr is 92 bytes on both darwin
// architectures (amd64 and arm64, both little-endian LP64), and the sockaddr
// encodings below are ABI, not implementation detail.

// darwin struct rt_msghdr field offsets (92 bytes; see xnu net/route.h).
const (
	bsdRtMsghdrLen = 92
	bsdRTMVersion  = 5 // RTM_VERSION

	bsdRtmMsglenOff  = 0 // uint16
	bsdRtmVersionOff = 2 // uint8
	bsdRtmIndexOff   = 4 // uint16: interface index the route/entry is on
	bsdRtmFlagsOff   = 8 // uint32 (int, but flag bits only)
	bsdRtmAddrsOff   = 12 // uint32: RTA_* bitmask of the sockaddrs that follow
)

// Routing sockaddr slots (RTAX_*) and their presence bits (RTA_* = 1<<slot).
const (
	bsdRTAXDst     = 0
	bsdRTAXGateway = 1
	bsdRTAXNetmask = 2
	bsdRTAXMax     = 8
)

// Route flag bits (rtm_flags).
const (
	bsdRTFGateway = 0x2       // RTF_GATEWAY: next hop is a router address
	bsdRTFHost    = 0x4       // RTF_HOST: host route, never a default
	bsdRTFLLInfo  = 0x400     // RTF_LLINFO: entry carries link-layer info (ARP/NDP)
	bsdRTFIfscope = 0x1000000 // RTF_IFSCOPE: interface-scoped (secondary) route
)

// Address families as encoded in sockaddr sa_family.
const (
	bsdAFInet  = 2  // AF_INET
	bsdAFLink  = 18 // AF_LINK (sockaddr_dl)
	bsdAFInet6 = 30 // AF_INET6
)

// walkRouteMessages calls fn for each rt_msghdr record in a PF_ROUTE sysctl
// buffer, handing it the record's payload (the sockaddr run after the fixed
// header). Records of a foreign rtm_version are skipped — their layout is not
// ours to guess — and a record that overruns the buffer or is too short to
// carry the header ends the walk rather than failing it: a partially readable
// table is still better information than none (same stance as walkAttrs).
func walkRouteMessages(buf []byte, fn func(index int, flags uint32, addrs uint32, payload []byte)) {
	for len(buf) >= bsdRtMsghdrLen {
		msglen := int(binary.LittleEndian.Uint16(buf[bsdRtmMsglenOff : bsdRtmMsglenOff+2]))
		if msglen < bsdRtMsghdrLen || msglen > len(buf) {
			break
		}
		rec := buf[:msglen]
		if rec[bsdRtmVersionOff] == bsdRTMVersion {
			fn(
				int(binary.LittleEndian.Uint16(rec[bsdRtmIndexOff:bsdRtmIndexOff+2])),
				binary.LittleEndian.Uint32(rec[bsdRtmFlagsOff:bsdRtmFlagsOff+4]),
				binary.LittleEndian.Uint32(rec[bsdRtmAddrsOff:bsdRtmAddrsOff+4]),
				rec[bsdRtMsghdrLen:],
			)
		}
		buf = buf[msglen:]
	}
}

// splitRouteSockaddrs slices the sockaddr run that follows an rt_msghdr into
// its RTAX slots. Only slots whose RTA bit is set occupy bytes; each occupied
// slot spans max(4, roundup(sa_len, 4)) bytes — an sa_len of 0 (BSD's way of
// writing "an empty netmask") still consumes a 4-byte slot. A slot that
// overruns the payload ends the split; slots not present come back nil.
func splitRouteSockaddrs(addrs uint32, b []byte) [bsdRTAXMax][]byte {
	var out [bsdRTAXMax][]byte
	for slot := 0; slot < bsdRTAXMax; slot++ {
		if addrs&(1<<slot) == 0 {
			continue
		}
		if len(b) < 1 {
			break
		}
		saLen := int(b[0])
		step := (saLen + 3) &^ 3
		if step < 4 {
			step = 4
		}
		if step > len(b) {
			break
		}
		if saLen > len(b) {
			saLen = len(b)
		}
		out[slot] = b[:saLen]
		b = b[step:]
	}
	return out
}

// bsdSockaddrIP decodes an AF_INET or AF_INET6 routing sockaddr into an
// address. Routing sockaddrs may be truncated to their meaningful prefix
// (sa_len shorter than the full struct), so missing tail bytes read as zero.
// For IPv6 the KAME kernels embed a link-local address's scope id in address
// bytes 2..3; those are cleared so `fe80:0:7::1`-style artifacts never reach
// telemetry — the interface the entry belongs to is carried by rtm_index.
func bsdSockaddrIP(sa []byte) (netip.Addr, bool) {
	if len(sa) < 2 {
		return netip.Addr{}, false
	}
	switch sa[1] {
	case bsdAFInet:
		// sockaddr_in: len, family, port(2), addr(4) at offset 4.
		var raw [4]byte
		copy(raw[:], sliceFrom(sa, 4))
		return netip.AddrFrom4(raw), true
	case bsdAFInet6:
		// sockaddr_in6: len, family, port(2), flowinfo(4), addr(16) at offset 8.
		var raw [16]byte
		copy(raw[:], sliceFrom(sa, 8))
		if raw[0] == 0xfe && raw[1]&0xc0 == 0x80 || raw[0] == 0xff && raw[1]&0x0f <= 0x02 {
			raw[2], raw[3] = 0, 0
		}
		return netip.AddrFrom16(raw), true
	}
	return netip.Addr{}, false
}

// bsdSockaddrDLMAC extracts the Ethernet MAC from a sockaddr_dl. Entries whose
// link address is not Ethernet-shaped (alen != 6) report false — that covers
// both incomplete neighbor entries (alen 0, an unanswered resolution) and
// exotic link types telemetry cannot carry, the same two drops the Linux
// NDA_LLADDR path applies.
func bsdSockaddrDLMAC(sa []byte) (string, bool) {
	// sockaddr_dl: len, family, sdl_index(2), sdl_type, sdl_nlen, sdl_alen,
	// sdl_slen, then sdl_data: name (nlen bytes) followed by the link address.
	if len(sa) < 8 || sa[1] != bsdAFLink {
		return "", false
	}
	nlen, alen := int(sa[5]), int(sa[6])
	if alen != 6 || len(sa) < 8+nlen+6 {
		return "", false
	}
	return net.HardwareAddr(sa[8+nlen : 8+nlen+6]).String(), true
}

// sliceFrom returns b[off:], or nil when b is shorter — the caller's copy into
// a zero array then reads the missing bytes as zero, which is exactly what a
// truncated routing sockaddr means.
func sliceFrom(b []byte, off int) []byte {
	if len(b) <= off {
		return nil
	}
	return b[off:]
}

// bsdDefaultRoutes is what the route table says about reaching the rest of the
// world, in the same shape netlink_linux.go's defaultRoutes gives collectors:
// gateway addresses per interface index, which interfaces carry a default
// route at all (the DNS attachment condition — a gatewayless utun/PPP default
// still names the interface resolvers are reached through), and each
// interface's preferred gatewayed IPv4 default.
//
// macOS has no numeric route metric; its ranking is the scope flag. The
// unscoped default route is the one the kernel routes unbound traffic by, and
// RTF_IFSCOPE defaults are per-interface secondaries — so best carries rank 0
// for unscoped and 1 for scoped, which is what lets the shared
// ResolveIPv4Gateway pick the true primary on a Wi-Fi + Ethernet Mac instead
// of whichever interface enumerated first.
type bsdDefaultRoutes struct {
	gateways map[int][]string
	ifaces   map[int]bool
	best     map[int]IPv4Default
}

// noteBest keeps the best-ranked gatewayed IPv4 default per interface; ties go
// to the entry the dump listed first, matching the kernel's own ordering.
func (r bsdDefaultRoutes) noteBest(ifindex int, gateway netip.Addr, rank int) {
	if !gateway.Is4() {
		return
	}
	if prev, ok := r.best[ifindex]; ok && *prev.Metric <= rank {
		return
	}
	cost := rank
	r.best[ifindex] = IPv4Default{Gateway: gateway.String(), Metric: &cost}
}

// parseBSDDefaultRoutes extracts the default routes from a NET_RT_DUMP buffer.
// A default route is a non-host route whose destination is its family's
// unspecified address under an empty (or absent) netmask. The gateway is
// recorded only when it is an actual IP next hop: an AF_LINK gateway means an
// on-link default with no router address to report, and a gateway whose family
// contradicts the destination's is a decode gone wrong, not a route (the same
// guard as gatewayMatchesFamily on Linux).
func parseBSDDefaultRoutes(buf []byte) bsdDefaultRoutes {
	out := bsdDefaultRoutes{gateways: map[int][]string{}, ifaces: map[int]bool{}, best: map[int]IPv4Default{}}
	walkRouteMessages(buf, func(index int, flags uint32, addrs uint32, payload []byte) {
		if flags&bsdRTFHost != 0 || index == 0 || addrs&(1<<bsdRTAXDst) == 0 {
			return
		}
		sas := splitRouteSockaddrs(addrs, payload)
		gw, gwOK := bsdSockaddrIP(sas[bsdRTAXGateway])
		dst, dstOK := bsdSockaddrIP(sas[bsdRTAXDst])
		switch {
		case dstOK:
			if !dst.IsUnspecified() {
				return
			}
		case len(sas[bsdRTAXDst]) == 0 && gwOK:
			// A zero-length dst sockaddr (sa_len 0) is BSD's terse spelling of
			// "default" — the same encoding an empty netmask uses. It carries no
			// family byte, so borrow the family from the gateway; without an IP
			// gateway there is nothing to borrow from and the record is skipped
			// rather than guessed.
			dst = netip.IPv4Unspecified()
			if gw.Is6() {
				dst = netip.IPv6Unspecified()
			}
		default:
			return
		}
		if !bsdNetmaskIsEmpty(sas[bsdRTAXNetmask], addrs) {
			return
		}
		out.ifaces[index] = true
		if !gwOK || gw.IsUnspecified() || gw.Is4() != dst.Is4() {
			return
		}
		out.gateways[index] = appendUnique(out.gateways[index], gw.String())
		rank := 0
		if flags&bsdRTFIfscope != 0 {
			rank = 1
		}
		out.noteBest(index, gw, rank)
	})
	return out
}

// bsdNetmaskIsEmpty reports whether a default route's netmask slot means /0:
// the slot is absent entirely, sa_len is 0 (BSD's canonical empty mask), or
// every mask byte it does carry is zero. Routing netmasks are stored truncated
// to their last nonzero byte, so any nonzero content marks a real prefix.
func bsdNetmaskIsEmpty(sa []byte, addrs uint32) bool {
	if addrs&(1<<bsdRTAXNetmask) == 0 || len(sa) == 0 {
		return true
	}
	// Skip len and family; a mask's family byte is frequently garbage on BSD, so
	// only the address bytes are meaningful.
	for _, b := range sliceFrom(sa, 2) {
		if b != 0 {
			return false
		}
	}
	return true
}

// parseBSDNeighbors extracts ARP (AF_INET dump) and NDP (AF_INET6 dump)
// entries from a NET_RT_FLAGS+RTF_LLINFO buffer: destination IP from the dst
// sockaddr, MAC from the sockaddr_dl gateway. Entries without an
// Ethernet-shaped link address are dropped (incomplete resolutions included).
//
// What comes back is the kernel's table, not a curated device list: it also
// holds the permanent L2 mappings of multicast groups (224.0.0.22 →
// 01:00:5e:…, ff02::1 → 33:33:…). Deciding which rows count as discovered
// devices belongs to the ARP collector (collector.usableMAC), same as on the
// other platforms — duplicating that judgement here would give the OSes
// different definitions of "a device".
func parseBSDNeighbors(buf []byte) []Neighbor {
	var out []Neighbor
	walkRouteMessages(buf, func(index int, flags uint32, addrs uint32, payload []byte) {
		if flags&bsdRTFLLInfo == 0 {
			return
		}
		sas := splitRouteSockaddrs(addrs, payload)
		ip, ok := bsdSockaddrIP(sas[bsdRTAXDst])
		if !ok {
			return
		}
		mac, ok := bsdSockaddrDLMAC(sas[bsdRTAXGateway])
		if !ok {
			return
		}
		out = append(out, Neighbor{IP: ip.Unmap().String(), MAC: mac})
	})
	return out
}
