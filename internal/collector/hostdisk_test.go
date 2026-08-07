package collector

import (
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
