package hostfs

import "testing"

// TestRootsHonourHostEnv pins the contract that makes container monitoring
// coherent: the agent's own file reads follow the same HOST_* redirection
// gopsutil uses, so one set of bind mounts moves BOTH to the host. A blank value
// must behave as unset — an empty variable left over from a compose file should
// not send every read to the filesystem root.
func TestRootsHonourHostEnv(t *testing.T) {
	for _, tc := range []struct {
		name string
		env  string
		set  string
		got  func() string
		want string
	}{
		{"proc default", "HOST_PROC", "", Proc, "/proc"},
		{"proc override", "HOST_PROC", "/host/proc", Proc, "/host/proc"},
		{"proc blank is default", "HOST_PROC", "   ", Proc, "/proc"},
		{"proc trailing slash cleaned", "HOST_PROC", "/host/proc/", Proc, "/host/proc"},
		{"sys default", "HOST_SYS", "", Sys, "/sys"},
		{"sys override", "HOST_SYS", "/host/sys", Sys, "/host/sys"},
		{"etc default", "HOST_ETC", "", Etc, "/etc"},
		{"etc override", "HOST_ETC", "/host/etc", Etc, "/host/etc"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(tc.env, tc.set)
			if got := tc.got(); got != tc.want {
				t.Fatalf("%s=%q → %q, want %q", tc.env, tc.set, got, tc.want)
			}
		})
	}
}

func TestPathJoinsUseTheResolvedRoot(t *testing.T) {
	t.Setenv("HOST_PROC", "/host/proc")
	t.Setenv("HOST_ETC", "/host/etc")
	// Slash-joined regardless of the build host — these paths are consumed by the
	// Linux kernel's procfs, never by the compiling OS's path rules.
	if got, want := ProcPath("net", "route"), "/host/proc/net/route"; got != want {
		t.Fatalf("ProcPath = %q, want %q", got, want)
	}
	if got, want := EtcPath("resolv.conf"), "/host/etc/resolv.conf"; got != want {
		t.Fatalf("EtcPath = %q, want %q", got, want)
	}
}
