package collector

import (
	"context"
	"strconv"
	"time"

	"github.com/nettact/protocol/telemetry"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	pshost "github.com/shirou/gopsutil/v3/host"
	"github.com/shirou/gopsutil/v3/load"
	"github.com/shirou/gopsutil/v3/mem"
	psnet "github.com/shirou/gopsutil/v3/net"
)

// HostMetricsCollector reports this machine's own CPU / memory / disk / load /
// uptime / network-I/O / temperature as ordinary time-series metrics
// (LayerLocal), modeled on the NeoHtop dashboard. Each metric family is gated on
// its own permission (host.cpu.read, host.memory.read, …); a denied family
// invokes no gopsutil operation and emits nothing.
//
// CPU utilization is measured as the delta since the previous Collect (interval
// 0 in gopsutil), which fits the regular scheduler tier. Network rates are
// computed from the byte-counter delta between successive Collects.
type HostMetricsCollector struct {
	cpu, mem, disk, load, uptime, netio, temp bool

	lastNetRx uint64
	lastNetTx uint64
	lastNetAt time.Time
	primed    bool
}

// NewHostMetricsCollector builds the collector with each metric family gated on
// its permission. Only granted families are ever sampled.
func NewHostMetricsCollector(cpuOn, memOn, diskOn, loadOn, uptimeOn, netioOn, tempOn bool) *HostMetricsCollector {
	c := &HostMetricsCollector{
		cpu: cpuOn, mem: memOn, disk: diskOn,
		load: loadOn, uptime: uptimeOn, netio: netioOn, temp: tempOn,
	}
	// Prime CPU baselines so the first real Collect reports a delta, not a
	// since-boot average. Errors here are non-fatal.
	if cpuOn {
		_, _ = cpu.Percent(0, false)
		_, _ = cpu.Percent(0, true)
	}
	if netioOn {
		if io, err := psnet.IOCounters(false); err == nil && len(io) > 0 {
			c.lastNetRx = io[0].BytesRecv
			c.lastNetTx = io[0].BytesSent
			c.lastNetAt = time.Now()
		}
	}
	return c
}

func (c *HostMetricsCollector) Name() string { return "host" }

func (c *HostMetricsCollector) Tier() Tier { return TierRegular }

func (c *HostMetricsCollector) Collect(ctx context.Context) (Result, error) {
	now := time.Now().UTC()
	var res Result
	// The time-series store keys a series by (agent, kind, target) and does not
	// store labels, so anything that varies per instance (per-core CPU, per-mount
	// disk) must be distinguished by Target, not Labels.
	add := func(kind telemetry.MetricKind, target string, value float64, unit string) {
		res.Metrics = append(res.Metrics, telemetry.Metric{
			TS: now, Kind: kind, Target: target, Layer: telemetry.LayerLocal,
			Value: value, Unit: unit,
		})
	}

	// CPU: overall (target "host") + per-core (target "core0", "core1", …).
	if c.cpu {
		if pcts, err := cpu.Percent(0, false); err == nil && len(pcts) > 0 {
			add(telemetry.HostCPUPct, "host", pcts[0], telemetry.UnitPct)
		}
		if pcts, err := cpu.Percent(0, true); err == nil {
			for i, p := range pcts {
				add(telemetry.HostCPUCorePct, "core"+strconv.Itoa(i), p, telemetry.UnitPct)
			}
		}
	}

	// Memory.
	if c.mem {
		if vm, err := mem.VirtualMemory(); err == nil {
			add(telemetry.HostMemPct, "host", vm.UsedPercent, telemetry.UnitPct)
			add(telemetry.HostMemTotal, "host", float64(vm.Total), telemetry.UnitBytes)
			add(telemetry.HostMemUsed, "host", float64(vm.Used), telemetry.UnitBytes)
			add(telemetry.HostMemFree, "host", float64(vm.Available), telemetry.UnitBytes)
		}
	}

	// Disk: one series per physical mount (Target = mountpoint).
	if c.disk {
		if parts, err := disk.Partitions(false); err == nil {
			for _, pt := range parts {
				us, err := disk.Usage(pt.Mountpoint)
				if err != nil || us.Total == 0 {
					continue
				}
				mp := pt.Mountpoint
				add(telemetry.HostDiskPct, mp, us.UsedPercent, telemetry.UnitPct)
				add(telemetry.HostDiskTotal, mp, float64(us.Total), telemetry.UnitBytes)
				add(telemetry.HostDiskUsed, mp, float64(us.Used), telemetry.UnitBytes)
				add(telemetry.HostDiskFree, mp, float64(us.Free), telemetry.UnitBytes)
			}
		}
	}

	// Load average. On Windows gopsutil synthesizes this from the processor
	// queue length and reads ~0 until it has samples; skip on error.
	if c.load {
		if avg, err := load.Avg(); err == nil {
			add(telemetry.HostLoad1, "host", avg.Load1, telemetry.UnitLoad)
			add(telemetry.HostLoad5, "host", avg.Load5, telemetry.UnitLoad)
			add(telemetry.HostLoad15, "host", avg.Load15, telemetry.UnitLoad)
		}
	}

	// Uptime.
	if c.uptime {
		if up, err := pshostUptime(ctx); err == nil {
			add(telemetry.HostUptime, "host", float64(up), telemetry.UnitSec)
		}
	}

	// Network I/O rate (bytes/s) from the aggregate counter delta.
	if c.netio {
		if io, err := psnet.IOCounters(false); err == nil && len(io) > 0 {
			if c.primed || !c.lastNetAt.IsZero() {
				elapsed := time.Since(c.lastNetAt).Seconds()
				if elapsed > 0 {
					rx := deltaRate(io[0].BytesRecv, c.lastNetRx, elapsed)
					tx := deltaRate(io[0].BytesSent, c.lastNetTx, elapsed)
					add(telemetry.HostNetRxBps, "host", rx, telemetry.UnitBps)
					add(telemetry.HostNetTxBps, "host", tx, telemetry.UnitBps)
				}
			}
			c.lastNetRx = io[0].BytesRecv
			c.lastNetTx = io[0].BytesSent
			c.lastNetAt = time.Now()
			c.primed = true
		}
	}

	// Temperature: one series per sensor, plus the hottest reading as the "host"
	// aggregate — the same aggregate/detail split as CPU, and the series the
	// console overview graphs. A machine with no readable sensor emits nothing,
	// leaving a gap in the chart rather than a synthetic zero.
	if c.temp {
		hottest, any := 0.0, false
		for _, r := range collectTemps(ctx) {
			add(telemetry.HostTempSensorC, r.target, r.celsius, telemetry.UnitCelsius)
			if !any || r.celsius > hottest {
				hottest, any = r.celsius, true
			}
		}
		if any {
			add(telemetry.HostTempC, "host", hottest, telemetry.UnitCelsius)
		}
	}

	return res, nil
}

// pshostUptime is a thin wrapper so the host package alias is only referenced
// once (keeps the import obvious).
func pshostUptime(ctx context.Context) (uint64, error) {
	return pshost.UptimeWithContext(ctx)
}

// deltaRate returns (cur-prev)/elapsed, guarding against counter resets.
func deltaRate(cur, prev uint64, elapsed float64) float64 {
	if cur < prev {
		return 0
	}
	return float64(cur-prev) / elapsed
}
