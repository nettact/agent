package platform

// trimIPv4Header strips a leading IPv4 header from b, returning the payload
// that follows it. Defensive by design: a buffer that does not start with a
// plausible IPv4 header (wrong version, IHL below the 20-byte minimum, or
// shorter than its own stated header length) is returned unchanged rather than
// truncated wrongly — the caller's ICMP parse then fails cleanly and the read
// loop moves on.
func trimIPv4Header(b []byte) []byte {
	if len(b) < 20 || b[0]>>4 != 4 {
		return b
	}
	ihl := int(b[0]&0x0f) * 4
	if ihl < 20 || len(b) < ihl {
		return b
	}
	return b[ihl:]
}
