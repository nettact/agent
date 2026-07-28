// Package hostfs resolves the filesystem roots the agent reads host facts from.
//
// In a container the agent's own /proc, /sys and /etc describe the CONTAINER,
// not the machine an operator wants monitored. The conventional fix is to bind
// mount the host's copies elsewhere (/host/proc, …) and point the collector at
// them. gopsutil — which the agent already uses for every host.* metric — reads
// that redirection from the HOST_PROC / HOST_SYS / HOST_ETC environment
// variables, so this package deliberately honours the SAME variables rather than
// inventing NETTACT_* ones. One set of mounts then feeds both gopsutil's metrics
// and the agent's own route/resolver parsing, and an operator can never end up
// with host CPU numbers next to a container's default gateway.
//
// An unset (or blank) variable means "read the real root", which is what a
// native install always wants.
package hostfs

import (
	"os"
	"path"
	"strings"
)

// These are always Unix paths (procfs/sysfs exist nowhere else), so the package
// uses path, not path/filepath: filepath would rewrite "/host/proc" to
// "\host\proc" when the agent is merely COMPILED on Windows, which would make
// these helpers untestable there for no gain.

// root returns the directory named by env, or def when it is unset or blank.
func root(env, def string) string {
	if v := strings.TrimSpace(os.Getenv(env)); v != "" {
		return path.Clean(v)
	}
	return def
}

// Proc is the procfs root (HOST_PROC, default /proc).
func Proc() string { return root("HOST_PROC", "/proc") }

// Sys is the sysfs root (HOST_SYS, default /sys).
func Sys() string { return root("HOST_SYS", "/sys") }

// Etc is the system configuration root (HOST_ETC, default /etc).
func Etc() string { return root("HOST_ETC", "/etc") }

// ProcPath, SysPath and EtcPath join a relative path onto the corresponding
// root, e.g. ProcPath("net", "route") → /proc/net/route.
func ProcPath(elem ...string) string { return path.Join(append([]string{Proc()}, elem...)...) }
func SysPath(elem ...string) string  { return path.Join(append([]string{Sys()}, elem...)...) }
func EtcPath(elem ...string) string  { return path.Join(append([]string{Etc()}, elem...)...) }
