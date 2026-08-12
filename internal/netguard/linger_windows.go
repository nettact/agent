//go:build windows

package netguard

import "syscall"

// setLingerRST sets SO_LINGER {1,0} on the socket so it tears down with an RST
// instead of a FIN when closed — a fan-out's source ports must be reusable cycle
// after cycle, and a FIN close parks the tuple in TIME_WAIT where a pinned port
// refuses to rebind. On Windows the socket handle is a syscall.Handle.
func setLingerRST(fd uintptr) error {
	return syscall.SetsockoptLinger(syscall.Handle(fd), syscall.SOL_SOCKET, syscall.SO_LINGER,
		&syscall.Linger{Onoff: 1, Linger: 0})
}
