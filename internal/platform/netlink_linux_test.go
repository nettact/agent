//go:build linux

package platform

import (
	"encoding/binary"
	"net"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// Netlink dumps are binary tables from the kernel, so the parsers are exercised
// against hand-built messages: that is the only way to pin the shapes that
// actually matter (a policy-table default route, an unresolved neighbor) without
// needing a host that happens to have them.

// attr encodes one netlink TLV, padded to the 4-byte alignment the kernel uses.
func attr(typ uint16, value []byte) []byte {
	length := syscall.SizeofRtAttr + len(value)
	b := make([]byte, rtaAlign(length))
	binary.NativeEndian.PutUint16(b[0:2], uint16(length))
	binary.NativeEndian.PutUint16(b[2:4], typ)
	copy(b[4:], value)
	return b
}

func u32(v uint32) []byte {
	b := make([]byte, 4)
	binary.NativeEndian.PutUint32(b, v)
	return b
}

// routeMsg builds an RTM_NEWROUTE payload: rtmsg header + attributes.
func routeMsg(family, dstLen, table, rtype uint8, attrs ...[]byte) syscall.NetlinkMessage {
	data := make([]byte, syscall.SizeofRtMsg)
	data[rtmFamilyOff] = family
	data[rtmDstLenOff] = dstLen
	data[rtmTableOff] = table
	data[rtmTypeOff] = rtype
	for _, a := range attrs {
		data = append(data, a...)
	}
	return syscall.NetlinkMessage{
		Header: syscall.NlMsghdr{Type: uint16(syscall.RTM_NEWROUTE)},
		Data:   data,
	}
}

// neighMsg builds an RTM_NEWNEIGH payload: ndmsg header + attributes.
func neighMsg(family uint8, ifindex int32, state uint16, attrs ...[]byte) syscall.NetlinkMessage {
	data := make([]byte, unix.SizeofNdMsg)
	data[0] = family
	binary.NativeEndian.PutUint32(data[ndmIfindexOff:ndmIfindexOff+4], uint32(ifindex))
	binary.NativeEndian.PutUint16(data[ndmStateOff:ndmStateOff+2], state)
	for _, a := range attrs {
		data = append(data, a...)
	}
	return syscall.NetlinkMessage{
		Header: syscall.NlMsghdr{Type: uint16(unix.RTM_NEWNEIGH)},
		Data:   data,
	}
}

// nexthopRec encodes one struct rtnexthop plus its nested attributes, as an
// RTA_MULTIPATH payload carries them.
func nexthopRec(ifindex int32, attrs ...[]byte) []byte {
	body := []byte{}
	for _, a := range attrs {
		body = append(body, a...)
	}
	length := sizeofRtNexthop + len(body)
	b := make([]byte, sizeofRtNexthop)
	binary.NativeEndian.PutUint16(b[0:2], uint16(length))
	binary.NativeEndian.PutUint32(b[4:8], uint32(ifindex))
	b = append(b, body...)
	// Pad to the record alignment the kernel uses.
	for len(b) < rtaAlign(length) {
		b = append(b, 0)
	}
	return b
}

func TestParseDefaultRoutes(t *testing.T) {
	v4 := net.ParseIP("192.168.1.1").To4()
	v6 := net.ParseIP("fe80::1").To16()
	other := net.ParseIP("10.8.0.1").To4()

	msgs := []syscall.NetlinkMessage{
		// The real IPv4 default route on ifindex 2.
		routeMsg(unix.AF_INET, 0, syscall.RT_TABLE_MAIN, syscall.RTN_UNICAST,
			attr(syscall.RTA_GATEWAY, v4), attr(syscall.RTA_OIF, u32(2))),
		// An IPv6 default route on the same interface — both must be reported.
		routeMsg(unix.AF_INET6, 0, syscall.RT_TABLE_MAIN, syscall.RTN_UNICAST,
			attr(syscall.RTA_GATEWAY, v6), attr(syscall.RTA_OIF, u32(2))),
		// A non-default route: has a gateway but a /24 destination.
		routeMsg(unix.AF_INET, 24, syscall.RT_TABLE_MAIN, syscall.RTN_UNICAST,
			attr(syscall.RTA_GATEWAY, v4), attr(syscall.RTA_OIF, u32(2))),
		// A VPN's default route in a policy table: reporting this as the
		// interface's gateway would be actively misleading.
		routeMsg(unix.AF_INET, 0, 100, syscall.RTN_UNICAST,
			attr(syscall.RTA_GATEWAY, other), attr(syscall.RTA_OIF, u32(3))),
		// A link-scoped default route with no gateway address to report.
		routeMsg(unix.AF_INET, 0, syscall.RT_TABLE_MAIN, syscall.RTN_UNICAST,
			attr(syscall.RTA_OIF, u32(4))),
		// A blackhole default route is not a gateway.
		routeMsg(unix.AF_INET, 0, syscall.RT_TABLE_MAIN, syscall.RTN_BLACKHOLE,
			attr(syscall.RTA_GATEWAY, v4), attr(syscall.RTA_OIF, u32(5))),
	}

	got := parseDefaultRoutes(msgs)
	if len(got.gateways) != 1 {
		t.Fatalf("gateways = %v, want entries for ifindex 2 only", got.gateways)
	}
	want := []string{"192.168.1.1", "fe80::1"}
	if len(got.gateways[2]) != len(want) {
		t.Fatalf("ifindex 2 gateways = %v, want %v", got.gateways[2], want)
	}
	for i, w := range want {
		if got.gateways[2][i] != w {
			t.Fatalf("ifindex 2 gateways = %v, want %v", got.gateways[2], want)
		}
	}
	// The gatewayless main-table default still counts as a default route: it is
	// where the host's traffic leaves, so the resolver list belongs on it.
	if !got.ifaces[4] {
		t.Fatalf("ifindex 4 carries a gatewayless default route and must be listed: %v", got.ifaces)
	}
	if got.ifaces[3] {
		t.Fatalf("a policy-table default must not mark the interface: %v", got.ifaces)
	}
	if got.ifaces[5] {
		t.Fatalf("a blackhole default must not mark the interface: %v", got.ifaces)
	}
}

// The metric orders two interfaces that both carry a default route, so it has to
// survive the parse — RTA_PRIORITY when present, 0 (the kernel's best, and the
// value it omits the attribute for) when not — and it must stay attached to the
// gateway of the very route it came from. Metrics harvested across an
// interface's routes describe a path the kernel never takes.
func TestParseDefaultRoutesBest(t *testing.T) {
	primary := net.ParseIP("192.168.1.1").To4()
	backup := net.ParseIP("192.168.1.254").To4()
	other := net.ParseIP("172.16.1.1").To4()
	v6 := net.ParseIP("fe80::1").To16()

	got := parseDefaultRoutes([]syscall.NetlinkMessage{
		// A costly backup default listed BEFORE the cheap primary on the same NIC:
		// the winner must be the primary's gateway at the primary's cost, not one
		// route's address with the other's metric.
		routeMsg(unix.AF_INET, 0, syscall.RT_TABLE_MAIN, syscall.RTN_UNICAST,
			attr(syscall.RTA_GATEWAY, backup), attr(syscall.RTA_OIF, u32(2)), attr(syscall.RTA_PRIORITY, u32(100))),
		routeMsg(unix.AF_INET, 0, syscall.RT_TABLE_MAIN, syscall.RTN_UNICAST,
			attr(syscall.RTA_GATEWAY, primary), attr(syscall.RTA_OIF, u32(2)), attr(syscall.RTA_PRIORITY, u32(50))),
		// A gatewayless default is the cheapest route on ifindex 3, but it has no
		// address to lend to the gatewayed one beside it.
		routeMsg(unix.AF_INET, 0, syscall.RT_TABLE_MAIN, syscall.RTN_UNICAST,
			attr(syscall.RTA_OIF, u32(3)), attr(syscall.RTA_PRIORITY, u32(1))),
		// No RTA_PRIORITY at all — metric 0.
		routeMsg(unix.AF_INET, 0, syscall.RT_TABLE_MAIN, syscall.RTN_UNICAST,
			attr(syscall.RTA_GATEWAY, other), attr(syscall.RTA_OIF, u32(3))),
		// IPv6 only: it must not become ifindex 4's IPv4 default.
		routeMsg(unix.AF_INET6, 0, syscall.RT_TABLE_MAIN, syscall.RTN_UNICAST,
			attr(syscall.RTA_GATEWAY, v6), attr(syscall.RTA_OIF, u32(4)), attr(syscall.RTA_PRIORITY, u32(1))),
	})

	if b := got.best[2]; b.Gateway != "192.168.1.1" || b.Metric == nil || *b.Metric != 50 {
		t.Fatalf("ifindex 2 best = %+v, want 192.168.1.1 at metric 50", b)
	}
	if b := got.best[3]; b.Gateway != "172.16.1.1" || b.Metric == nil || *b.Metric != 0 {
		t.Fatalf("ifindex 3 best = %+v, want 172.16.1.1 at metric 0", b)
	}
	if _, ok := got.best[4]; ok {
		t.Fatalf("an IPv6-only default gave the interface an IPv4 route: %+v", got.best)
	}
}

// TestParseDefaultRoutesMultipath: an ECMP default carries its gateways inside
// RTA_MULTIPATH nexthop records rather than as top-level RTA_GATEWAY/RTA_OIF. A
// parser that reads only the top level reports such a host as having no gateway.
func TestParseDefaultRoutesMultipath(t *testing.T) {
	a := net.ParseIP("10.77.0.1").To4()
	b := net.ParseIP("10.88.0.1").To4()
	msgs := []syscall.NetlinkMessage{
		routeMsg(unix.AF_INET, 0, syscall.RT_TABLE_MAIN, syscall.RTN_UNICAST,
			attr(syscall.RTA_MULTIPATH, append(
				nexthopRec(2, attr(syscall.RTA_GATEWAY, a)),
				nexthopRec(3, attr(syscall.RTA_GATEWAY, b))...,
			))),
	}
	got := parseDefaultRoutes(msgs)
	if len(got.gateways[2]) != 1 || got.gateways[2][0] != "10.77.0.1" {
		t.Fatalf("nexthop 1 = %v, want 10.77.0.1 on ifindex 2", got.gateways)
	}
	if len(got.gateways[3]) != 1 || got.gateways[3][0] != "10.88.0.1" {
		t.Fatalf("nexthop 2 = %v, want 10.88.0.1 on ifindex 3", got.gateways)
	}
	if !got.ifaces[2] || !got.ifaces[3] {
		t.Fatalf("both nexthop interfaces carry the default route: %v", got.ifaces)
	}
}

// TestParseDefaultRoutesHighTableID: table ids above 255 do not fit the rtmsg
// byte and arrive in RTA_TABLE instead. A main-table route encoded that way must
// still be recognized, and a policy-table one must still be rejected.
func TestParseDefaultRoutesHighTableID(t *testing.T) {
	v4 := net.ParseIP("192.168.9.1").To4()
	msgs := []syscall.NetlinkMessage{
		routeMsg(unix.AF_INET, 0, syscall.RT_TABLE_UNSPEC, syscall.RTN_UNICAST,
			attr(syscall.RTA_GATEWAY, v4), attr(syscall.RTA_OIF, u32(7)),
			attr(syscall.RTA_TABLE, u32(syscall.RT_TABLE_MAIN))),
		routeMsg(unix.AF_INET, 0, syscall.RT_TABLE_UNSPEC, syscall.RTN_UNICAST,
			attr(syscall.RTA_GATEWAY, v4), attr(syscall.RTA_OIF, u32(8)),
			attr(syscall.RTA_TABLE, u32(1000))),
	}
	got := parseDefaultRoutes(msgs)
	if len(got.gateways[7]) != 1 || got.gateways[7][0] != "192.168.9.1" {
		t.Fatalf("main table via RTA_TABLE not picked up: %v", got.gateways)
	}
	if _, ok := got.gateways[8]; ok {
		t.Fatalf("table 1000 must not be reported as a default gateway: %v", got.gateways)
	}
}

func TestParseNeighbors(t *testing.T) {
	mac := []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	msgs := []syscall.NetlinkMessage{
		// A resolved IPv4 neighbor.
		neighMsg(unix.AF_INET, 2, unix.NUD_REACHABLE,
			attr(unix.NDA_DST, net.ParseIP("192.168.1.20").To4()), attr(unix.NDA_LLADDR, mac)),
		// A resolved IPv6 neighbor — netlink gives both families in one dump,
		// which is the whole reason for using it over /proc/net/arp.
		neighMsg(unix.AF_INET6, 2, unix.NUD_STALE,
			attr(unix.NDA_DST, net.ParseIP("fe80::20").To16()), attr(unix.NDA_LLADDR, mac)),
		// In-flight resolution: an address with no device behind it yet.
		neighMsg(unix.AF_INET, 2, unix.NUD_INCOMPLETE,
			attr(unix.NDA_DST, net.ParseIP("192.168.1.21").To4())),
		// A failed resolution must not be reported as a discovered device.
		neighMsg(unix.AF_INET, 2, unix.NUD_FAILED,
			attr(unix.NDA_DST, net.ParseIP("192.168.1.22").To4()), attr(unix.NDA_LLADDR, mac)),
		// A proxy/NOARP entry with no link address.
		neighMsg(unix.AF_INET, 2, unix.NUD_NOARP,
			attr(unix.NDA_DST, net.ParseIP("192.168.1.23").To4())),
		// NUD_NONE is zero, so it cannot be tested with a bit mask; an entry the
		// kernel never resolved must not be reported as a discovered device even
		// when it carries both attributes.
		neighMsg(unix.AF_INET, 2, unix.NUD_NONE,
			attr(unix.NDA_DST, net.ParseIP("192.168.1.24").To4()), attr(unix.NDA_LLADDR, mac)),
	}

	got := parseNeighbors(msgs)
	if len(got) != 2 {
		t.Fatalf("neighbors = %+v, want the two resolved entries only", got)
	}
	if got[0].IP != "192.168.1.20" || got[0].MAC != "aa:bb:cc:dd:ee:ff" {
		t.Fatalf("first neighbor = %+v", got[0])
	}
	if got[1].IP != "fe80::20" {
		t.Fatalf("second neighbor = %+v, want the IPv6 entry", got[1])
	}
}

// TestNetlinkAttrsStopsOnTruncation: a short read must yield what was parseable
// rather than panicking or looping — a partially readable table still beats none.
func TestNetlinkAttrsStopsOnTruncation(t *testing.T) {
	good := attr(syscall.RTA_OIF, u32(3))
	data := make([]byte, syscall.SizeofRtMsg)
	data = append(data, good...)
	data = append(data, 0xff, 0xff) // a fragment too short to be an attribute

	attrs := netlinkAttrs(data, syscall.SizeofRtMsg)
	if len(attrs) != 1 || attrs[0].Type != syscall.RTA_OIF {
		t.Fatalf("attrs = %+v, want just the one complete attribute", attrs)
	}

	// A length field claiming more than the buffer holds must also stop the walk.
	bogus := make([]byte, syscall.SizeofRtMsg+8)
	binary.NativeEndian.PutUint16(bogus[syscall.SizeofRtMsg:], 0xffff)
	if attrs := netlinkAttrs(bogus, syscall.SizeofRtMsg); len(attrs) != 0 {
		t.Fatalf("attrs = %+v, want none from an over-long length", attrs)
	}
}

// TestNeighborDumpAgainstLiveKernel is a smoke test: the dump must at least
// succeed and produce well-formed entries on a real kernel. It asserts nothing
// about the contents — a fresh WSL/container namespace can legitimately have an
// empty neighbor table.
func TestNeighborDumpAgainstLiveKernel(t *testing.T) {
	got, err := linuxPlatform{}.Neighbors()
	if err != nil {
		t.Skipf("neighbor dump unavailable in this environment: %v", err)
	}
	for _, n := range got {
		if net.ParseIP(n.IP) == nil {
			t.Fatalf("neighbor %+v has an unparseable IP", n)
		}
		if _, err := net.ParseMAC(n.MAC); err != nil {
			t.Fatalf("neighbor %+v has an unparseable MAC: %v", n, err)
		}
	}
}
