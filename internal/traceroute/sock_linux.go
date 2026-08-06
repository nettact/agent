//go:build linux

package traceroute

import "golang.org/x/sys/unix"

// sysSocket opens a close-on-exec socket. Linux takes the flag atomically at
// creation; darwin has no SOCK_CLOEXEC and sets it after the fact
// (sock_darwin.go).
func sysSocket(domain, typ, proto int) (int, error) {
	return unix.Socket(domain, typ|unix.SOCK_CLOEXEC, proto)
}
