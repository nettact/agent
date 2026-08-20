package collector

import (
	"runtime"
	"slices"
	"sort"
	"strings"

	"github.com/shirou/gopsutil/v3/disk"
)

// selectDiskMounts picks the mounts worth reporting as "disks" out of everything
// gopsutil hands back, and is the reason a router does not report a permanently
// full filesystem nobody can write to.
//
// The caller passes disk.Partitions(false), which already drops the pseudo
// filesystems (proc, sysfs, cgroup) and the memory-backed ones (tmpfs, devtmpfs)
// by keeping only fstypes the kernel lists as device-backed. Three things it does
// NOT drop, all of them observed on one ordinary OpenWrt router:
//
//   - /rom, a squashfs image. A read-only compressed image has no free blocks by
//     construction, so it reports exactly 100% forever. Summarised as "highest
//     mount", that reads as a router about to run out of space, and any disk
//     monitor built on it would sit permanently in breach. A filesystem nothing
//     can write to has no fill level worth watching, so it is not reported at all.
//
//   - /boot listed twice, once plainly and once as a bind. Same device, same
//     mountpoint, two entries — two identical samples per batch for one series.
//
//   - /overlay/upper/opt/docker, a bind of /overlay. Same device and same bytes
//     under a second path. The server sums Used and Total across mounts to show a
//     host's capacity, so a bind counts the same storage twice: this router
//     reported 3.9 GB of capacity for the 2.0 GB it has.
//
// The rule is one entry per (device, fstype), keeping the shortest mountpoint —
// the path a bind was made FROM is always shorter than the path it was made to,
// so the primary mount wins and its binds drop out.
//
// A deliberate non-goal: the merged overlay root (/) is absent on OpenWrt,
// because gopsutil classifies overlayfs as not device-backed. Adding it back
// would report the same bytes as /overlay a second time and re-create exactly the
// double count this function exists to remove. /overlay is that storage under the
// name df gives it, which is the honest one. Everywhere that is not an overlay
// root — ordinary Linux, macOS, Windows — / and C:\ are device-backed and arrive
// here normally.
//
// macOS needs a pass of its own first (collapseDarwinMounts, darwin only): one
// physical disk is an APFS container split into many volumes that each report
// the whole container's capacity, and gopsutil hands back every one of them plus
// pseudo-filesystems (devfs) that are not storage at all.
func selectDiskMounts(parts []disk.PartitionStat) []disk.PartitionStat {
	if runtime.GOOS == "darwin" {
		parts = collapseDarwinMounts(parts)
	}

	type key struct{ device, fstype string }

	best := make(map[key]disk.PartitionStat, len(parts))
	for _, pt := range parts {
		if isReadOnly(pt.Opts) {
			continue
		}
		k := key{pt.Device, pt.Fstype}
		cur, seen := best[k]
		if !seen || len(pt.Mountpoint) < len(cur.Mountpoint) {
			best[k] = pt
		}
	}

	out := make([]disk.PartitionStat, 0, len(best))
	for _, pt := range best {
		out = append(out, pt)
	}
	// Map iteration is random and these become metric series; a stable order
	// keeps one batch's samples in the same sequence as the next one's.
	sort.Slice(out, func(i, j int) bool { return out[i].Mountpoint < out[j].Mountpoint })
	return out
}

// isReadOnly reports whether a mount was mounted read-only. The flag is a bare
// "ro" option; "rw" appears on writable mounts and neither is guaranteed to be
// first, so the whole list is scanned rather than the head inspected.
//
// Windows fills Opts differently (gopsutil derives them from the volume flags and
// includes "ro" for a read-only volume such as a mounted ISO), which is the same
// meaning and the same correct outcome.
func isReadOnly(opts []string) bool {
	return slices.Contains(opts, "ro")
}

// collapseDarwinMounts is the macOS half of selectDiskMounts (called only on
// darwin; it is written as a plain function so it can be unit-tested on any
// host). gopsutil's Partitions(false) ignores its `all` argument on darwin and
// returns the whole mount table, and a modern Mac is built out of entries that
// are not "disks" at all:
//
//   - One physical disk is an APFS container split into many volumes — Data,
//     VM, Preboot, Update, and the sealed System volume on the boot container,
//     plus xarts, iSCPreboot and Hardware on the recovery container. Every
//     volume's statfs reports the whole container's capacity, so reporting each
//     separately shows one 1 TB SSD as ~4 TB of disks and double/triple-counts
//     capacity in any host-level sum. They must be collapsed to one disk per
//     container.
//
//   - The volumes a user can actually watch are the Data volume of the boot
//     container (all of their files live under it, via firmlinks) and anything
//     mounted outside /System/Volumes (external drives, extra volumes). The
//     rest — VM, Preboot, Update, and the whole recovery container — is
//     system-reserved, so a container that is only those is dropped rather than
//     reported as an always-tiny disk.
//
//   - devfs is a pseudo-filesystem with no real bytes: its statfs reports a
//     handful of blocks and zero free, so gopsutil computes 100% used for a
//     mount that is not storage. Dropping it here is what keeps an ordinary Mac
//     from showing a permanently-full "/dev" disk.
func collapseDarwinMounts(parts []disk.PartitionStat) []disk.PartitionStat {
	out := make([]disk.PartitionStat, 0, len(parts))
	byContainer := make(map[string][]disk.PartitionStat)
	for _, pt := range parts {
		// devfs has real-looking but empty stats (gopsutil reports it 100% full),
		// and the autofs home mount is a synthetic directory with zero total;
		// neither is storage. host.go's `total == 0` guard already skips autofs,
		// but dropping both here keeps the darwin filter self-contained.
		if pt.Fstype == "devfs" || pt.Fstype == "autofs" {
			continue
		}
		if pt.Fstype != "apfs" {
			// Non-APFS mounts (exFAT/NTFS/HFS+ externals, network shares) are
			// genuinely separate storage and go through unchanged.
			out = append(out, pt)
			continue
		}
		c := apfsContainer(pt.Device)
		byContainer[c] = append(byContainer[c], pt)
	}
	for _, vols := range byContainer {
		if rep, ok := darwinRepresentative(vols); ok {
			out = append(out, rep)
		}
	}
	return out
}

// darwinRepresentative picks the single APFS volume that stands in for its
// container in the disk list. All volumes of one container report the same
// container-wide used/total, so one representative carries the honest numbers
// and the rest would only repeat them.
//
// The Data volume is the answer whenever it exists — it is the writable volume
// that holds the user's files, and its statfs is the container's real usage. A
// container without one (an external drive with a single volume, a user-created
// extra volume) is represented by its most top-level mount. A container made up
// entirely of /System/Volumes volumes (the recovery container) has no user
// storage and is reported as absent.
func darwinRepresentative(vols []disk.PartitionStat) (disk.PartitionStat, bool) {
	for _, v := range vols {
		if v.Mountpoint == "/System/Volumes/Data" {
			return v, true
		}
	}
	var best disk.PartitionStat
	found := false
	for _, v := range vols {
		if strings.HasPrefix(v.Mountpoint, "/System/Volumes/") {
			continue
		}
		if !found || len(v.Mountpoint) < len(best.Mountpoint) {
			best, found = v, true
		}
	}
	return best, found
}

// apfsContainer returns the container device an APFS volume lives on: the diskN
// of /dev/disk3s5 and of /dev/disk3s1s1 (the sealed System volume) is
// /dev/disk3. All volumes sharing that device share the container's capacity
// and statfs totals, which is exactly why they must be collapsed into one.
//
// The cut is at the first non-digit after "disk", never at "s" itself — the
// word "disk" already contains one. /dev/rdisk3s1 is the raw node for the same
// container as /dev/disk3, so the leading r is folded away.
func apfsContainer(device string) string {
	i := strings.Index(device, "disk")
	if i < 0 {
		return device
	}
	j := i + len("disk")
	for j < len(device) && device[j] >= '0' && device[j] <= '9' {
		j++
	}
	if j == len(device) {
		return device // a bare container node, no volume suffix
	}
	if i > 0 && device[i-1] == 'r' {
		return device[:i-1] + device[i:j]
	}
	return device[:j]
}
