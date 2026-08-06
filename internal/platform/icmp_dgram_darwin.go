//go:build darwin

package platform

// datagramReplyHasIPHeader: darwin's datagram ICMP socket (SOCK_DGRAM/
// IPPROTO_ICMP) delivers the full IP packet — IPv4 header first, then the ICMP
// message — unlike Linux, whose ping socket strips the header. The read loop
// must trim it before parsing or every reply fails to parse as ICMP.
const datagramReplyHasIPHeader = true
