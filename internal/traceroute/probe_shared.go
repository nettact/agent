package traceroute

import (
	"net"
	"net/netip"
)

// Platform-independent helpers shared by the Windows and Linux TTL probes. The
// wire-level correlation is identical on both: raw ICMP sockets deliver the full
// IP packet, and the quotation inside a Time-Exceeded is plain IPv4, so only the
// socket calls differ per OS.

// pickResponder normalizes an ICMP capture result: a valid responder is an
// intermediate hop; an invalid one (socket closed, nothing captured) is a timeout.
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

// matchQuotedEcho reports whether the quotation carried by an ICMP error (the
// original IP header plus the first 8 bytes of its payload, as icmp.ParseMessage
// hands it back) is this probe's own echo request. Without the check, one trace
// would attribute another concurrent trace's Time-Exceeded to itself.
func matchQuotedEcho(quoted []byte, id, seq int) bool {
	if len(quoted) < 20 {
		return false
	}
	ihl := int(quoted[0]&0x0f) * 4
	if ihl < 20 || len(quoted) < ihl+8 {
		return false
	}
	inner := quoted[ihl:]
	if inner[0] != 8 { // ICMP echo request
		return false
	}
	gotID := int(inner[4])<<8 | int(inner[5])
	gotSeq := int(inner[6])<<8 | int(inner[7])
	return gotID == id && gotSeq == seq
}

// matchICMPQuotation reports whether a received ICMP packet (starting at the IP
// header, as raw sockets deliver it on both Windows and Linux) is a Time-Exceeded
// or Destination-Unreachable that quotes this probe's TCP SYN: inner protocol
// TCP, inner dst == dest:port, and inner src port == our ephemeral port. The
// correlation lets concurrent traces on the same host ignore each other's ICMP.
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
