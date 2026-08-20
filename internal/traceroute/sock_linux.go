//go:build linux

package traceroute

import "golang.org/x/sys/unix"

// sysSocket opens a close-on-exec socket. Linux takes the flag atomically at
// creation; darwin has no SOCK_CLOEXEC and sets it after the fact
// (sock_darwin.go).
func sysSocket(domain, typ, proto int) (int, error) {
	return unix.Socket(domain, typ|unix.SOCK_CLOEXEC, proto)
}

// datagramICMPUsable disables the unprivileged datagram ICMP fallback. Linux's
// ping socket looks like Darwin's but is not: it routes ICMP errors to the
// socket error queue rather than delivering them, so a probe on one could only
// ever report timeouts. Reporting no capability is the honest outcome, and
// lets the server downgrade or skip instead of filing a trace of pure silence.
const datagramICMPUsable = false
