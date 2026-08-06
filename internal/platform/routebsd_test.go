package platform

import (
	"encoding/binary"
	"testing"
)

// Fixture builders for PF_ROUTE sysctl records, mirroring the netlink fixture
// style: hand-built bytes, no live route table.

// bsdSAIn4 builds a full sockaddr_in for ip (a 4-byte dotted quad).
func bsdSAIn4(a, b, c, d byte) []byte {
	sa := make([]byte, 16)
	sa[0] = 16
	sa[1] = bsdAFInet
	sa[4], sa[5], sa[6], sa[7] = a, b, c, d
	return sa
}

// bsdSAIn6 builds a full sockaddr_in6 around a 16-byte address.
func bsdSAIn6(addr [16]byte) []byte {
	sa := make([]byte, 28)
	sa[0] = 28
	sa[1] = bsdAFInet6
	copy(sa[8:24], addr[:])
	return sa
}

// bsdSADL builds a sockaddr_dl carrying an interface name and a link address.
func bsdSADL(name string, lladdr []byte) []byte {
	sa := make([]byte, 8+len(name)+len(lladdr))
	sa[0] = byte(len(sa))
	sa[1] = bsdAFLink
	sa[5] = byte(len(name))
	sa[6] = byte(len(lladdr))
	copy(sa[8:], name)
	copy(sa[8+len(name):], lladdr)
	return sa
}

// bsdSAEmpty is BSD's canonical empty netmask: sa_len 0, occupying one 4-byte
// slot.
func bsdSAEmpty() []byte { return []byte{0, 0, 0, 0} }

// bsdRouteRec assembles one rt_msghdr record. sas maps RTAX slot → sockaddr
// bytes; slots are emitted in slot order, each padded to its 4-byte boundary.
func bsdRouteRec(version byte, index uint16, flags uint32, sas map[int][]byte) []byte {
	var payload []byte
	var addrs uint32
	for slot := 0; slot < bsdRTAXMax; slot++ {
		sa, ok := sas[slot]
		if !ok {
			continue
		}
		addrs |= 1 << slot
		step := (len(sa) + 3) &^ 3
		if step < 4 {
			step = 4
		}
		padded := make([]byte, step)
		copy(padded, sa)
		payload = append(payload, padded...)
	}
	rec := make([]byte, bsdRtMsghdrLen, bsdRtMsghdrLen+len(payload))
	binary.LittleEndian.PutUint16(rec[bsdRtmMsglenOff:], uint16(bsdRtMsghdrLen+len(payload)))
	rec[bsdRtmVersionOff] = version
	binary.LittleEndian.PutUint16(rec[bsdRtmIndexOff:], index)
	binary.LittleEndian.PutUint32(rec[bsdRtmFlagsOff:], flags)
	binary.LittleEndian.PutUint32(rec[bsdRtmAddrsOff:], addrs)
	return append(rec, payload...)
}

func TestParseBSDDefaultRoutesRanksScopedBelowUnscoped(t *testing.T) {
	buf := append(
		// en0: the unscoped primary default.
		bsdRouteRec(bsdRTMVersion, 4, bsdRTFGateway, map[int][]byte{
			bsdRTAXDst:     bsdSAIn4(0, 0, 0, 0),
			bsdRTAXGateway: bsdSAIn4(192, 168, 1, 1),
			bsdRTAXNetmask: bsdSAEmpty(),
		}),
		// en1: an RTF_IFSCOPE secondary default.
		bsdRouteRec(bsdRTMVersion, 5, bsdRTFGateway|bsdRTFIfscope, map[int][]byte{
			bsdRTAXDst:     bsdSAIn4(0, 0, 0, 0),
			bsdRTAXGateway: bsdSAIn4(10, 0, 0, 1),
			bsdRTAXNetmask: bsdSAEmpty(),
		})...,
	)
	routes := parseBSDDefaultRoutes(buf)

	if got := routes.gateways[4]; len(got) != 1 || got[0] != "192.168.1.1" {
		t.Fatalf("en0 gateways = %v", got)
	}
	if got := routes.gateways[5]; len(got) != 1 || got[0] != "10.0.0.1" {
		t.Fatalf("en1 gateways = %v", got)
	}
	best4, ok := routes.best[4]
	if !ok || best4.Gateway != "192.168.1.1" || best4.Metric == nil || *best4.Metric != 0 {
		t.Fatalf("unscoped default must rank 0, got %+v", best4)
	}
	best5, ok := routes.best[5]
	if !ok || best5.Gateway != "10.0.0.1" || best5.Metric == nil || *best5.Metric != 1 {
		t.Fatalf("scoped default must rank 1, got %+v", best5)
	}
}

// A scoped default listed before the unscoped one on the SAME interface must
// lose: rank, not enumeration order, decides.
func TestParseBSDDefaultRoutesUnscopedWinsWithinInterface(t *testing.T) {
	buf := append(
		bsdRouteRec(bsdRTMVersion, 4, bsdRTFGateway|bsdRTFIfscope, map[int][]byte{
			bsdRTAXDst:     bsdSAIn4(0, 0, 0, 0),
			bsdRTAXGateway: bsdSAIn4(192, 168, 1, 254),
			bsdRTAXNetmask: bsdSAEmpty(),
		}),
		bsdRouteRec(bsdRTMVersion, 4, bsdRTFGateway, map[int][]byte{
			bsdRTAXDst:     bsdSAIn4(0, 0, 0, 0),
			bsdRTAXGateway: bsdSAIn4(192, 168, 1, 1),
			bsdRTAXNetmask: bsdSAEmpty(),
		})...,
	)
	best, ok := parseBSDDefaultRoutes(buf).best[4]
	if !ok || best.Gateway != "192.168.1.1" || *best.Metric != 0 {
		t.Fatalf("unscoped route must win, got %+v", best)
	}
}

// A tunnel default whose gateway is a sockaddr_dl (on-link, no router address)
// still marks its interface as carrying a default route — that is where DNS
// attaches — but must contribute no gateway address.
func TestParseBSDDefaultRoutesGatewaylessTunnelDefault(t *testing.T) {
	buf := bsdRouteRec(bsdRTMVersion, 9, 0, map[int][]byte{
		bsdRTAXDst:     bsdSAIn4(0, 0, 0, 0),
		bsdRTAXGateway: bsdSADL("utun3", nil),
		bsdRTAXNetmask: bsdSAEmpty(),
	})
	routes := parseBSDDefaultRoutes(buf)
	if !routes.ifaces[9] {
		t.Fatal("tunnel default must mark its interface")
	}
	if len(routes.gateways[9]) != 0 {
		t.Fatalf("tunnel default must report no gateway, got %v", routes.gateways[9])
	}
	if _, ok := routes.best[9]; ok {
		t.Fatal("tunnel default must not become a best IPv4 route")
	}
}

func TestParseBSDDefaultRoutesIPv6(t *testing.T) {
	var gw [16]byte
	gw[0], gw[1], gw[15] = 0xfe, 0x80, 0x01
	gw[2], gw[3] = 0x00, 0x07 // KAME-embedded scope id, must be cleared
	var zero [16]byte
	buf := bsdRouteRec(bsdRTMVersion, 4, bsdRTFGateway, map[int][]byte{
		bsdRTAXDst:     bsdSAIn6(zero),
		bsdRTAXGateway: bsdSAIn6(gw),
		bsdRTAXNetmask: bsdSAEmpty(),
	})
	routes := parseBSDDefaultRoutes(buf)
	if got := routes.gateways[4]; len(got) != 1 || got[0] != "fe80::1" {
		t.Fatalf("v6 gateway = %v, want [fe80::1] with scope bytes cleared", got)
	}
	if _, ok := routes.best[4]; ok {
		t.Fatal("a v6 default must not become the IPv4 best route")
	}
}

func TestParseBSDDefaultRoutesIgnoresNonDefaults(t *testing.T) {
	buf := append(append(
		// A host route to a real destination.
		bsdRouteRec(bsdRTMVersion, 4, bsdRTFGateway|bsdRTFHost, map[int][]byte{
			bsdRTAXDst:     bsdSAIn4(1, 1, 1, 1),
			bsdRTAXGateway: bsdSAIn4(192, 168, 1, 1),
		}),
		// A subnet route: zero-looking dst would need an empty mask to count.
		bsdRouteRec(bsdRTMVersion, 4, bsdRTFGateway, map[int][]byte{
			bsdRTAXDst:     bsdSAIn4(0, 0, 0, 0),
			bsdRTAXGateway: bsdSAIn4(192, 168, 1, 1),
			// Truncated netmask for /8: len 5, last meaningful byte 255.
			bsdRTAXNetmask: {5, 0, 0, 0, 255},
		})...),
		// A non-default destination.
		bsdRouteRec(bsdRTMVersion, 4, bsdRTFGateway, map[int][]byte{
			bsdRTAXDst:     bsdSAIn4(10, 20, 0, 0),
			bsdRTAXGateway: bsdSAIn4(10, 20, 0, 1),
			bsdRTAXNetmask: bsdSAEmpty(),
		})...,
	)
	routes := parseBSDDefaultRoutes(buf)
	if len(routes.gateways) != 0 || len(routes.ifaces) != 0 || len(routes.best) != 0 {
		t.Fatalf("non-default routes must be ignored, got %+v", routes)
	}
}

// A record of a foreign rtm_version is skipped without derailing the walk; a
// record that claims to extend past the buffer ends it.
func TestWalkRouteMessagesVersionAndTruncation(t *testing.T) {
	good := bsdRouteRec(bsdRTMVersion, 4, bsdRTFGateway, map[int][]byte{
		bsdRTAXDst:     bsdSAIn4(0, 0, 0, 0),
		bsdRTAXGateway: bsdSAIn4(192, 168, 1, 1),
		bsdRTAXNetmask: bsdSAEmpty(),
	})
	foreign := bsdRouteRec(bsdRTMVersion+1, 7, bsdRTFGateway, map[int][]byte{
		bsdRTAXDst:     bsdSAIn4(0, 0, 0, 0),
		bsdRTAXGateway: bsdSAIn4(10, 0, 0, 1),
		bsdRTAXNetmask: bsdSAEmpty(),
	})
	truncated := make([]byte, bsdRtMsghdrLen)
	binary.LittleEndian.PutUint16(truncated, uint16(bsdRtMsghdrLen+64)) // overruns
	truncated[bsdRtmVersionOff] = bsdRTMVersion

	routes := parseBSDDefaultRoutes(append(append(append([]byte{}, foreign...), good...), truncated...))
	if len(routes.gateways) != 1 || routes.gateways[4][0] != "192.168.1.1" {
		t.Fatalf("the well-formed record must survive its neighbors, got %+v", routes.gateways)
	}
	if routes.ifaces[7] {
		t.Fatal("a foreign-version record must not be decoded")
	}
}

// A zero-length dst sockaddr is BSD's terse spelling of "default": with an IP
// gateway to borrow the family from it decodes as that family's unspecified
// address; with only a link-layer gateway there is no family to borrow and the
// record is skipped rather than guessed.
func TestParseBSDDefaultRoutesEmptyDstSockaddr(t *testing.T) {
	buf := append(
		bsdRouteRec(bsdRTMVersion, 4, bsdRTFGateway, map[int][]byte{
			bsdRTAXDst:     bsdSAEmpty(),
			bsdRTAXGateway: bsdSAIn4(192, 168, 1, 1),
			bsdRTAXNetmask: bsdSAEmpty(),
		}),
		bsdRouteRec(bsdRTMVersion, 9, 0, map[int][]byte{
			bsdRTAXDst:     bsdSAEmpty(),
			bsdRTAXGateway: bsdSADL("utun3", nil),
			bsdRTAXNetmask: bsdSAEmpty(),
		})...,
	)
	routes := parseBSDDefaultRoutes(buf)
	if got := routes.gateways[4]; len(got) != 1 || got[0] != "192.168.1.1" {
		t.Fatalf("empty-dst default with an IP gateway = %v, want [192.168.1.1]", got)
	}
	if best, ok := routes.best[4]; !ok || *best.Metric != 0 {
		t.Fatalf("empty-dst default must still rank, got %+v", best)
	}
	if routes.ifaces[9] {
		t.Fatal("empty dst with no IP gateway has no family to borrow — must be skipped")
	}
}

func TestParseBSDNeighborsARP(t *testing.T) {
	buf := append(append(
		bsdRouteRec(bsdRTMVersion, 4, bsdRTFLLInfo|bsdRTFHost, map[int][]byte{
			bsdRTAXDst:     bsdSAIn4(192, 168, 1, 50),
			bsdRTAXGateway: bsdSADL("en0", []byte{0xaa, 0xbb, 0xcc, 0x00, 0x11, 0x22}),
		}),
		// Incomplete entry: resolution never answered, alen 0.
		bsdRouteRec(bsdRTMVersion, 4, bsdRTFLLInfo|bsdRTFHost, map[int][]byte{
			bsdRTAXDst:     bsdSAIn4(192, 168, 1, 66),
			bsdRTAXGateway: bsdSADL("en0", nil),
		})...),
		// Not a neighbor entry at all (no RTF_LLINFO).
		bsdRouteRec(bsdRTMVersion, 4, bsdRTFHost, map[int][]byte{
			bsdRTAXDst:     bsdSAIn4(192, 168, 1, 70),
			bsdRTAXGateway: bsdSADL("en0", []byte{0xde, 0xad, 0xbe, 0xef, 0x00, 0x01}),
		})...,
	)
	got := parseBSDNeighbors(buf)
	if len(got) != 1 || got[0].IP != "192.168.1.50" || got[0].MAC != "aa:bb:cc:00:11:22" {
		t.Fatalf("neighbors = %+v", got)
	}
}

func TestParseBSDNeighborsNDPClearsEmbeddedScope(t *testing.T) {
	var addr [16]byte
	addr[0], addr[1] = 0xfe, 0x80
	addr[2], addr[3] = 0x00, 0x04 // KAME scope embedding
	addr[15] = 0x2a
	buf := bsdRouteRec(bsdRTMVersion, 4, bsdRTFLLInfo|bsdRTFHost, map[int][]byte{
		bsdRTAXDst:     bsdSAIn6(addr),
		bsdRTAXGateway: bsdSADL("en0", []byte{0x02, 0x42, 0xac, 0x11, 0x00, 0x02}),
	})
	got := parseBSDNeighbors(buf)
	if len(got) != 1 || got[0].IP != "fe80::2a" {
		t.Fatalf("NDP entry = %+v, want scope-free fe80::2a", got)
	}
}

// An empty netmask (sa_len 0) must consume exactly one 4-byte slot so the
// sockaddrs after it still land in their right RTAX positions.
func TestSplitRouteSockaddrsEmptySlotAdvance(t *testing.T) {
	const rtaxIfp = 4
	dl := bsdSADL("en0", nil)
	payload := append(append(append([]byte{}, bsdSAIn4(0, 0, 0, 0)...), bsdSAEmpty()...), func() []byte {
		step := (len(dl) + 3) &^ 3
		padded := make([]byte, step)
		copy(padded, dl)
		return padded
	}()...)
	sas := splitRouteSockaddrs(1<<bsdRTAXDst|1<<bsdRTAXNetmask|1<<rtaxIfp, payload)
	if sas[rtaxIfp] == nil || sas[rtaxIfp][1] != bsdAFLink {
		t.Fatalf("slot after an empty netmask misparsed: %v", sas[rtaxIfp])
	}
	if len(sas[bsdRTAXNetmask]) != 0 {
		t.Fatalf("empty netmask must decode to no bytes, got %v", sas[bsdRTAXNetmask])
	}
}

// A truncated routing sockaddr reads its missing tail as zero rather than
// failing the record.
func TestBSDSockaddrIPTruncated(t *testing.T) {
	sa := []byte{8, bsdAFInet, 0, 0, 10, 1} // sa_len 8 but only 6 bytes survive
	ip, ok := bsdSockaddrIP(sa)
	if !ok || ip.String() != "10.1.0.0" {
		t.Fatalf("truncated sockaddr_in = %v %v, want 10.1.0.0", ip, ok)
	}
	if _, ok := bsdSockaddrIP([]byte{1}); ok {
		t.Fatal("a one-byte sockaddr must not decode")
	}
	if _, ok := bsdSockaddrIP(nil); ok {
		t.Fatal("nil must not decode")
	}
}
