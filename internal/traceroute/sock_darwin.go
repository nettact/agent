//go:build darwin

package traceroute

import "golang.org/x/sys/unix"

// sysSocket opens a close-on-exec socket. darwin has no SOCK_CLOEXEC socket
// flag, so the bit is set after creation — the agent forks only the game
// sensor, on the main runtime's schedule, so the create-to-fcntl window is not
// a leak path worth a raw syscall dance here.
func sysSocket(domain, typ, proto int) (int, error) {
	fd, err := unix.Socket(domain, typ, proto)
	if err != nil {
		return fd, err
	}
	unix.CloseOnExec(fd)
	return fd, nil
}
