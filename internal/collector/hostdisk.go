package collector

import (
	"slices"
	"sort"

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
func selectDiskMounts(parts []disk.PartitionStat) []disk.PartitionStat {
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
