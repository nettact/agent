//go:build linux

package platform

import (
	"encoding/binary"
	"net"
	"net/netip"
	"syscall"

	"golang.org/x/sys/unix"
)

// Netlink (NETLINK_ROUTE) reads for the two facts the stdlib does not expose:
// default gateways and the ARP/NDP neighbor table. Netlink is the kernel's own
// API for both, covers IPv4 and IPv6 in one dump, and needs no privilege — the
// same ground `ip route` / `ip neigh` stand on, and the closest Linux equivalent
// of the Windows GetAdaptersAddresses / GetIpNetTable pair.
//
// The dump itself is syscall.NetlinkRIB (socket + bind + request + read until
// NLMSG_DONE). Attribute decoding is done here rather than with
// syscall.ParseNetlinkRouteAttr because that helper only knows link/addr/route
// messages and returns EINVAL for RTM_NEWNEIGH. Doing the walk ourselves also
// keeps every parser a pure function over bytes, so the table shapes are unit
// testable without a live kernel socket.

// nlAttr is one decoded netlink TLV.
type nlAttr struct {
	Type  uint16
	Value []byte
}

// rtaAlignTo is the netlink attribute alignment (NLA_ALIGNTO).
const rtaAlignTo = 4

func rtaAlign(n int) int { return (n + rtaAlignTo - 1) &^ (rtaAlignTo - 1) }

// walkAttrs decodes a run of netlink TLVs. A malformed or truncated attribute
// ends the walk rather than failing the whole dump: a partially readable table
// is still better information than none.
func walkAttrs(b []byte) []nlAttr {
	var out []nlAttr
	for len(b) >= syscall.SizeofRtAttr {
		length := int(binary.NativeEndian.Uint16(b[0:2]))
		typ := binary.NativeEndian.Uint16(b[2:4])
		if length < syscall.SizeofRtAttr || length > len(b) {
			break
		}
		out = append(out, nlAttr{Type: typ, Value: b[syscall.SizeofRtAttr:length]})
		step := rtaAlign(length)
		if step >= len(b) {
			break
		}
		b = b[step:]
	}
	return out
}

// netlinkAttrs walks the TLVs that follow a fixed-size family header (rtmsg,
// ndmsg, …) in a netlink message payload.
func netlinkAttrs(data []byte, headerLen int) []nlAttr {
	if len(data) < headerLen {
		return nil
	}
	return walkAttrs(data[headerLen:])
}

// sizeofRtNexthop is struct rtnexthop: len(2) flags(1) hops(1) ifindex(4).
const sizeofRtNexthop = 8

// nexthop is one leg of a multipath route.
type nexthop struct {
	ifindex int
	gateway string
}

// parseMultipath decodes an RTA_MULTIPATH payload: a run of rtnexthop records,
// each followed by its own nested attributes. An ECMP default route carries its
// gateways here instead of in the route's top-level RTA_GATEWAY/RTA_OIF, so a
// parser that only reads those reports such a host as having no gateway at all.
func parseMultipath(value []byte) []nexthop {
	var out []nexthop
	b := value
	for len(b) >= sizeofRtNexthop {
		length := int(binary.NativeEndian.Uint16(b[0:2]))
		if length < sizeofRtNexthop || length > len(b) {
			break
		}
		nh := nexthop{ifindex: int(int32(binary.NativeEndian.Uint32(b[4:8])))}
		for _, a := range walkAttrs(b[sizeofRtNexthop:length]) {
			if a.Type == syscall.RTA_GATEWAY {
				if ip, ok := netip.AddrFromSlice(a.Value); ok {
					nh.gateway = ip.Unmap().String()
				}
			}
		}
		out = append(out, nh)
		step := rtaAlign(length)
		if step >= len(b) {
			break
		}
		b = b[step:]
	}
	return out
}

// netlinkDump runs one RTM_GET* dump over NETLINK_ROUTE for both address
// families and returns the parsed messages.
func netlinkDump(proto int) ([]syscall.NetlinkMessage, error) {
	raw, err := syscall.NetlinkRIB(proto, syscall.AF_UNSPEC)
	if err != nil {
		return nil, err
	}
	return syscall.ParseNetlinkMessage(raw)
}

// rtmsg field offsets (struct rtmsg, 12 bytes: family, dst_len, src_len, tos,
// table, protocol, scope, type, flags).
const (
	rtmFamilyOff  = 0
	rtmDstLenOff  = 1
	rtmTableOff   = 4
	rtmTypeOff    = 7
	sizeofRtMsgGo = syscall.SizeofRtMsg
)

// defaultRoutes is what the route table says about reaching the rest of the
// world: the gateway addresses per output interface, and — separately — which
// interfaces carry a default route at all.
//
// The two are not the same thing. A point-to-point or tunnel default
// (`default dev tun0`) has no gateway address to report but is still the
// interface the host's traffic leaves by, which is where the system resolver
// list belongs. Collapsing them would drop DNS entirely on such a host.
type defaultRoutes struct {
	gateways map[int][]string
	ifaces   map[int]bool
}

// parseDefaultRoutes extracts the default routes (destination prefix length 0)
// of the main routing table.
//
// Only the main table is considered: policy tables installed by VPN clients or
// container runtimes also carry default routes, and reporting those as "the"
// gateway of an interface would be actively misleading.
func parseDefaultRoutes(msgs []syscall.NetlinkMessage) defaultRoutes {
	out := defaultRoutes{gateways: map[int][]string{}, ifaces: map[int]bool{}}
	for _, m := range msgs {
		if m.Header.Type != uint16(syscall.RTM_NEWROUTE) {
			continue
		}
		if len(m.Data) < sizeofRtMsgGo {
			continue
		}
		if m.Data[rtmDstLenOff] != 0 || m.Data[rtmTypeOff] != syscall.RTN_UNICAST {
			continue
		}
		family := m.Data[rtmFamilyOff]
		table := int(m.Data[rtmTableOff])

		var gw string
		oif := 0
		var hops []nexthop
		for _, a := range netlinkAttrs(m.Data, sizeofRtMsgGo) {
			switch a.Type {
			case syscall.RTA_GATEWAY:
				if ip, ok := netip.AddrFromSlice(a.Value); ok {
					gw = ip.Unmap().String()
				}
			case syscall.RTA_OIF:
				if len(a.Value) >= 4 {
					oif = int(binary.NativeEndian.Uint32(a.Value))
				}
			case syscall.RTA_TABLE:
				// Table ids above 255 do not fit rtmsg.table and arrive here instead.
				if len(a.Value) >= 4 {
					table = int(binary.NativeEndian.Uint32(a.Value))
				}
			case syscall.RTA_MULTIPATH:
				hops = parseMultipath(a.Value)
			}
		}
		if table != syscall.RT_TABLE_MAIN {
			continue
		}
		// An ECMP default has no top-level gateway/oif — every leg is a nexthop.
		if len(hops) > 0 {
			for _, nh := range hops {
				if nh.ifindex == 0 {
					continue
				}
				out.ifaces[nh.ifindex] = true
				if nh.gateway != "" && gatewayMatchesFamily(family, nh.gateway) {
					out.gateways[nh.ifindex] = appendUnique(out.gateways[nh.ifindex], nh.gateway)
				}
			}
			continue
		}
		if oif == 0 {
			continue
		}
		out.ifaces[oif] = true
		// Guard against a family/attribute mismatch producing a nonsense address.
		if gw != "" && gatewayMatchesFamily(family, gw) {
			out.gateways[oif] = appendUnique(out.gateways[oif], gw)
		}
	}
	return out
}

// gatewayMatchesFamily reports whether a decoded gateway address belongs to the
// address family the route claimed.
func gatewayMatchesFamily(family uint8, gw string) bool {
	return (family == unix.AF_INET) == (net.ParseIP(gw).To4() != nil)
}

// ndmsg field offsets (struct ndmsg, 12 bytes: family, pad1, pad2, ifindex,
// state, flags, type).
const (
	ndmIfindexOff = 4
	ndmStateOff   = 8
	sizeofNdMsgGo = unix.SizeofNdMsg
)

// neighborStateUsable reports whether an NUD state means the entry currently
// describes a real reachable device. INCOMPLETE and FAILED are in-flight or dead
// resolutions; NUD_NONE is an entry the kernel has not resolved at all.
//
// NUD_NONE is 0, so it has to be compared rather than masked — OR-ing zero into
// a bit mask tests nothing, and every NUD_NONE entry would pass.
func neighborStateUsable(state uint16) bool {
	if state == unix.NUD_NONE {
		return false
	}
	const dead = unix.NUD_INCOMPLETE | unix.NUD_FAILED
	return state&dead == 0
}

// parseNeighbors extracts ARP (IPv4) and NDP (IPv6) entries from an RTM_GETNEIGH
// dump. Entries with no link-layer address, or in a state that does not describe
// a reachable device, are dropped — the same two conditions the Windows reader
// applies to GetIpNetTable rows.
//
// What comes back is the kernel's table, not a curated device list: it also
// holds the permanent L2 mappings of multicast groups (224.0.0.22 → 01:00:5e:…,
// ff02::1 → 33:33:…). Deciding which rows count as discovered devices belongs to
// the ARP collector, which already drops multicast/broadcast link addresses for
// every platform (see collector.usableMAC) — duplicating that judgement here
// would give the two OSes two different definitions of "a device".
func parseNeighbors(msgs []syscall.NetlinkMessage) []Neighbor {
	var out []Neighbor
	for _, m := range msgs {
		if m.Header.Type != uint16(unix.RTM_NEWNEIGH) {
			continue
		}
		if len(m.Data) < sizeofNdMsgGo {
			continue
		}
		if !neighborStateUsable(binary.NativeEndian.Uint16(m.Data[ndmStateOff : ndmStateOff+2])) {
			continue
		}
		var ip, mac string
		for _, a := range netlinkAttrs(m.Data, sizeofNdMsgGo) {
			switch a.Type {
			case unix.NDA_DST:
				if addr, ok := netip.AddrFromSlice(a.Value); ok {
					ip = addr.Unmap().String()
				}
			case unix.NDA_LLADDR:
				// Ethernet-shaped link addresses only; anything else is not a MAC
				// the telemetry can carry.
				if len(a.Value) == 6 {
					mac = net.HardwareAddr(a.Value).String()
				}
			}
		}
		if ip == "" || mac == "" {
			continue
		}
		out = append(out, Neighbor{IP: ip, MAC: mac})
	}
	return out
}

