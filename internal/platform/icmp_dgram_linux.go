//go:build linux

package platform

// datagramReplyHasIPHeader: a Linux ping socket delivers the bare ICMP message;
// the kernel strips the IPv4 header before the read returns.
const datagramReplyHasIPHeader = false
