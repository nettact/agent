package collector

import (
	"runtime"
	"testing"

	"github.com/shirou/gopsutil/v3/disk"
)

// The mount table of a real iStoreOS 24.10 x86_64 router, captured from
// disk.Partitions(false) on the device. It is the case that motivated
// selectDiskMounts: the console showed "peak 100% · 4 disks" for a router with
// 0.9% of its writable space used, and reported 3.9 GB of capacity for the 2.0 GB
// it actually has.
var openWrtRouterMounts = []disk.PartitionStat{
	{Device: "/dev/root", Mountpoint: "/rom", Fstype: "squashfs", Opts: []string{"ro", "relatime"}},
	{Device: "/dev/sda3", Mountpoint: "/overlay", Fstype: "ext4", Opts: []string{"rw", "relatime"}},
	{Device: "/dev/sda1", Mountpoint: "/boot", Fstype: "ext4", Opts: []string{"rw", "noatime"}},
	{Device: "/dev/sda1", Mountpoint: "/boot", Fstype: "ext4", Opts: []string{"rw", "noatime", "bind"}},
	{Device: "/dev/sda3", Mountpoint: "/overlay/upper/opt/docker", Fstype: "ext4", Opts: []string{"rw", "relatime", "bind"}},
}

func mountpoints(parts []disk.PartitionStat) []string {
	out := make([]string, len(parts))
	for i, p := range parts {
		out[i] = p.Mountpoint
	}
	return out
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestSelectDiskMounts(t *testing.T) {
	tests := []struct {
		name string
		in   []disk.PartitionStat
		want []string
	}{
		{
			// The whole point: two real, writable filesystems out of five entries.
			name: "openwrt router",
			in:   openWrtRouterMounts,
			want: []string{"/boot", "/overlay"},
		},
		{
			// A squashfs image is exactly 100% full forever, so reporting it as a
			// fill level is reporting a number that can never mean anything.
			name: "read-only mount is dropped",
			in: []disk.PartitionStat{
				{Device: "/dev/root", Mountpoint: "/rom", Fstype: "squashfs", Opts: []string{"ro", "relatime"}},
			},
			want: []string{},
		},
		{
			// "ro" is not guaranteed to be the first option.
			name: "read-only detected anywhere in the option list",
			in: []disk.PartitionStat{
				{Device: "/dev/sr0", Mountpoint: "/media/cdrom", Fstype: "iso9660", Opts: []string{"nosuid", "nodev", "ro"}},
			},
			want: []string{},
		},
		{
			// "rw" must not be mistaken for "ro" by a prefix or substring test.
			name: "writable mount is kept",
			in: []disk.PartitionStat{
				{Device: "/dev/sda1", Mountpoint: "/", Fstype: "ext4", Opts: []string{"rw", "relatime"}},
			},
			want: []string{"/"},
		},
		{
			// The bind is the longer path, so the mount it was made from wins.
			name: "bind of the same device collapses to the shortest mountpoint",
			in: []disk.PartitionStat{
				{Device: "/dev/sda3", Mountpoint: "/overlay/upper/opt/docker", Fstype: "ext4", Opts: []string{"rw", "bind"}},
				{Device: "/dev/sda3", Mountpoint: "/overlay", Fstype: "ext4", Opts: []string{"rw"}},
			},
			want: []string{"/overlay"},
		},
		{
			// Two entries for one mountpoint would otherwise put two samples with
			// identical series identity in the same batch.
			name: "duplicate entries for one mountpoint collapse",
			in: []disk.PartitionStat{
				{Device: "/dev/sda1", Mountpoint: "/boot", Fstype: "ext4", Opts: []string{"rw", "noatime"}},
				{Device: "/dev/sda1", Mountpoint: "/boot", Fstype: "ext4", Opts: []string{"rw", "noatime", "bind"}},
			},
			want: []string{"/boot"},
		},
		{
			// Different devices are different storage even at sibling paths, and
			// separately mounted data disks are exactly what an operator wants to
			// see. Nothing here may be collapsed.
			name: "distinct devices are all kept",
			in: []disk.PartitionStat{
				{Device: "/dev/sdb1", Mountpoint: "/mnt/data", Fstype: "ext4", Opts: []string{"rw"}},
				{Device: "/dev/sdc1", Mountpoint: "/mnt/backup", Fstype: "xfs", Opts: []string{"rw"}},
				{Device: "/dev/sda1", Mountpoint: "/", Fstype: "ext4", Opts: []string{"rw"}},
			},
			want: []string{"/", "/mnt/backup", "/mnt/data"},
		},
		{
			// One device carrying two filesystems (a btrfs subvolume pair, say) is
			// not a bind, so the fstype is part of the identity.
			name: "same device with different fstypes stays separate",
			in: []disk.PartitionStat{
				{Device: "/dev/sda2", Mountpoint: "/", Fstype: "btrfs", Opts: []string{"rw"}},
				{Device: "/dev/sda2", Mountpoint: "/home", Fstype: "ext4", Opts: []string{"rw"}},
			},
			want: []string{"/", "/home"},
		},
		{
			name: "windows volumes pass through",
			in: []disk.PartitionStat{
				{Device: "C:", Mountpoint: "C:", Fstype: "NTFS", Opts: []string{"rw", "compress"}},
				{Device: "D:", Mountpoint: "D:", Fstype: "NTFS", Opts: []string{"rw"}},
				{Device: "E:", Mountpoint: "E:", Fstype: "UDF", Opts: []string{"ro"}},
			},
			want: []string{"C:", "D:"},
		},
		{
			name: "no partitions",
			in:   nil,
			want: []string{},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := mountpoints(selectDiskMounts(tc.in))
			if !equalStrings(got, tc.want) {
				t.Errorf("selectDiskMounts() mountpoints = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestSelectDiskMountsIsStable guards the ordering, which is not cosmetic: the
// result becomes one metric series per entry, and map iteration in Go is
// deliberately randomised.
func TestSelectDiskMountsIsStable(t *testing.T) {
	first := mountpoints(selectDiskMounts(openWrtRouterMounts))
	for i := range 50 {
		if got := mountpoints(selectDiskMounts(openWrtRouterMounts)); !equalStrings(got, first) {
			t.Fatalf("run %d returned %v, first run returned %v", i, got, first)
		}
	}
}

// TestSelectDiskMountsCollapsesDarwinMounts is the macOS counterpart of the
// bind-collapse test above, and states the server-visible consequence it
// protects: without collapseDarwinMounts, one 1 TB SSD reports as ~4 TB of
// disks (every APFS volume restates the whole container) plus a permanently
// full "/dev".
func TestSelectDiskMountsCollapsesDarwinMounts(t *testing.T) {
	// The mount table of a real macOS 15 Apple Silicon machine, captured from
	// disk.Partitions(false). It motivated collapseDarwinMounts: one 1 TB SSD
	// reported as the four writable APFS volumes of its boot container plus the
	// three of its recovery container (each boot-container volume restating the
	// same 994 GB), and a devfs /dev whose statfs has zero free bytes so
	// gopsutil reports it 100% full.
	macOSMounts := []disk.PartitionStat{
		{Device: "/dev/disk3s1s1", Mountpoint: "/", Fstype: "apfs", Opts: []string{"ro", "journaled", "multilabel"}},
		{Device: "devfs", Mountpoint: "/dev", Fstype: "devfs", Opts: []string{"rw", "nobrowse", "multilabel"}},
		{Device: "/dev/disk3s6", Mountpoint: "/System/Volumes/VM", Fstype: "apfs", Opts: []string{"rw", "noexec", "nobrowse", "journaled", "multilabel", "noatime"}},
		{Device: "/dev/disk3s2", Mountpoint: "/System/Volumes/Preboot", Fstype: "apfs", Opts: []string{"rw", "nobrowse", "journaled", "multilabel"}},
		{Device: "/dev/disk3s4", Mountpoint: "/System/Volumes/Update", Fstype: "apfs", Opts: []string{"rw", "nobrowse", "journaled", "multilabel"}},
		{Device: "/dev/disk1s2", Mountpoint: "/System/Volumes/xarts", Fstype: "apfs", Opts: []string{"rw", "noexec", "nobrowse", "journaled", "multilabel", "noatime"}},
		{Device: "/dev/disk1s1", Mountpoint: "/System/Volumes/iSCPreboot", Fstype: "apfs", Opts: []string{"rw", "nobrowse", "journaled", "multilabel"}},
		{Device: "/dev/disk1s3", Mountpoint: "/System/Volumes/Hardware", Fstype: "apfs", Opts: []string{"rw", "nobrowse", "journaled", "multilabel"}},
		{Device: "/dev/disk3s5", Mountpoint: "/System/Volumes/Data", Fstype: "apfs", Opts: []string{"rw", "nobrowse", "journaled", "multilabel"}},
		{Device: "map auto_home", Mountpoint: "/System/Volumes/Data/home", Fstype: "autofs", Opts: []string{"rw", "nobrowse", "automounted", "multilabel"}},
	}

	t.Run("boot + recovery container collapse to the Data volume", func(t *testing.T) {
		got := mountpoints(collapseDarwinMounts(macOSMounts))
		want := []string{"/System/Volumes/Data"}
		if !equalStrings(got, want) {
			t.Errorf("collapseDarwinMounts() = %v, want %v", got, want)
		}
	})

	t.Run("selectDiskMounts drops the devfs phantom 100%", func(t *testing.T) {
		// selectDiskMounts applies the darwin collapse first, then the read-only
		// and bind filtering. The whole real table must end as exactly the Data
		// volume: the ro System volume is dropped, devfs and every system APFS
		// volume are collapsed away, and the autofs home mount has zero total
		// (host.go skips those). No mountpoint here may report 100% used.
		//
		// collapseDarwinMounts is gated on runtime.GOOS inside selectDiskMounts,
		// so this full-pipeline assertion is darwin-only: on a Linux or Windows
		// runner selectDiskMounts legitimately leaves the table untouched (the
		// pure collapseDarwinMounts assertions above still run everywhere).
		if runtime.GOOS != "darwin" {
			t.Skip("selectDiskMounts collapses APFS containers only on darwin")
		}
		got := mountpoints(selectDiskMounts(macOSMounts))
		want := []string{"/System/Volumes/Data"}
		if !equalStrings(got, want) {
			t.Errorf("selectDiskMounts() = %v, want %v", got, want)
		}
	})

	t.Run("an external single-volume drive is kept", func(t *testing.T) {
		got := mountpoints(collapseDarwinMounts([]disk.PartitionStat{
			{Device: "/dev/disk4s2", Mountpoint: "/Volumes/Backup", Fstype: "apfs", Opts: []string{"rw"}},
		}))
		want := []string{"/Volumes/Backup"}
		if !equalStrings(got, want) {
			t.Errorf("collapseDarwinMounts() = %v, want %v", got, want)
		}
	})

	t.Run("a full external macOS install is shown as its Data volume", func(t *testing.T) {
		got := mountpoints(collapseDarwinMounts([]disk.PartitionStat{
			{Device: "/dev/disk6s1", Mountpoint: "/System/Volumes/Data", Fstype: "apfs", Opts: []string{"rw"}},
			{Device: "/dev/disk6s1s1", Mountpoint: "/", Fstype: "apfs", Opts: []string{"ro"}},
		}))
		want := []string{"/System/Volumes/Data"}
		if !equalStrings(got, want) {
			t.Errorf("collapseDarwinMounts() = %v, want %v", got, want)
		}
	})

	t.Run("a recovery-only container is dropped", func(t *testing.T) {
		got := mountpoints(collapseDarwinMounts([]disk.PartitionStat{
			{Device: "/dev/disk9s1", Mountpoint: "/System/Volumes/xarts", Fstype: "apfs", Opts: []string{"rw"}},
			{Device: "/dev/disk9s2", Mountpoint: "/System/Volumes/Hardware", Fstype: "apfs", Opts: []string{"rw"}},
		}))
		if len(got) != 0 {
			t.Errorf("collapseDarwinMounts() = %v, want none", got)
		}
	})

	t.Run("a user volume in the boot container still collapses to Data", func(t *testing.T) {
		got := mountpoints(collapseDarwinMounts([]disk.PartitionStat{
			{Device: "/dev/disk3s5", Mountpoint: "/System/Volumes/Data", Fstype: "apfs", Opts: []string{"rw"}},
			{Device: "/dev/disk3s7", Mountpoint: "/Volumes/Extra", Fstype: "apfs", Opts: []string{"rw"}},
		}))
		want := []string{"/System/Volumes/Data"}
		if !equalStrings(got, want) {
			t.Errorf("collapseDarwinMounts() = %v, want %v", got, want)
		}
	})

	t.Run("non-APFS mounts pass through untouched", func(t *testing.T) {
		// A Linux table applied to the darwin collapser must be a no-op: the
		// function keys on fstype == "apfs" and a device string with no container
		// separator, so nothing here can be regrouped or dropped.
		in := openWrtRouterMounts
		got := mountpoints(collapseDarwinMounts(in))
		if !equalStrings(got, mountpoints(in)) {
			t.Errorf("collapseDarwinMounts() changed a non-APFS table: got %v, want %v", got, mountpoints(in))
		}
	})

	t.Run("apfsContainer strips the volume suffix", func(t *testing.T) {
		cases := map[string]string{
			"/dev/disk3s5":      "/dev/disk3",
			"/dev/disk3s1s1":    "/dev/disk3",
			"/dev/disk4s2":      "/dev/disk4",
			"/dev/disk0s1":      "/dev/disk0",
			"/dev/disk7":        "/dev/disk7",
			"disk1s1":           "disk1",
		}
		for device, want := range cases {
			if got := apfsContainer(device); got != want {
				t.Errorf("apfsContainer(%q) = %q, want %q", device, got, want)
			}
		}
	})
}

// TestSelectDiskMountsCapacityIsNotDoubleCounted states the server-visible
// consequence, since that is the bug a reader of this test is most likely
// chasing: server-core sums Used and Total across every reported mount to show a
// host's capacity, so one bind of an existing device inflates the total by that
// whole device.
func TestSelectDiskMountsCapacityIsNotDoubleCounted(t *testing.T) {
	// Byte counts from the same router: sda3 is 2040373248, sda1 is 132075520,
	// and the squashfs image is 230686720.
	sizes := map[string]uint64{
		"/rom":                      230686720,
		"/overlay":                  2040373248,
		"/boot":                     132075520,
		"/overlay/upper/opt/docker": 2040373248,
	}

	var total uint64
	for _, pt := range selectDiskMounts(openWrtRouterMounts) {
		total += sizes[pt.Mountpoint]
	}

	const want = 2040373248 + 132075520 // sda3 + sda1, each counted once
	if total != want {
		t.Errorf("summed capacity = %d, want %d", total, want)
	}

	var unfiltered uint64
	for _, pt := range openWrtRouterMounts {
		unfiltered += sizes[pt.Mountpoint]
	}
	if unfiltered <= want {
		t.Fatalf("test is not exercising anything: unfiltered total %d should exceed %d", unfiltered, want)
	}
}
