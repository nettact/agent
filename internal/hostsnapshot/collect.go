// Package hostsnapshot builds the ephemeral, pull-on-demand process and network
// connection lists (protocol/telemetry.HostSnapshot). It is invoked only when
// the server sets a config.SnapshotRequest AND the agent was started with the
// matching --report-processes / --report-connections flag. Nothing here is
// persisted; the agent attaches the result to its next upload and discards it.
package hostsnapshot

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/nettact/protocol/telemetry"

	"github.com/shirou/gopsutil/v3/process"

	psnet "github.com/shirou/gopsutil/v3/net"
)

// cpuSampleWindow is how long we wait between the two per-process CPU samples
// used to compute a current CPU% (gopsutil measures the delta between calls on
// the same Process object).
const cpuSampleWindow = 300 * time.Millisecond

// Collect gathers a live snapshot. wantProcesses / wantConnections come straight
// from the agent's own startup flags — the caller must pass false for any
// capability the agent did not opt into, so disabled data is never gathered.
func Collect(ctx context.Context, requestID string, wantProcesses, wantConnections bool) telemetry.HostSnapshot {
	snap := telemetry.HostSnapshot{TS: time.Now().UTC(), RequestID: requestID}

	// Process names are also needed to label connections, so gather the process
	// table first when either list is requested. ProcessTotal is only disclosed
	// when processes were opted into, so a connections-only request never leaks a
	// process count across the separate --report-processes boundary.
	var procObjs []*process.Process
	if wantProcesses || wantConnections {
		if ps, err := process.ProcessesWithContext(ctx); err == nil {
			procObjs = ps
			if wantProcesses {
				snap.ProcessTotal = len(ps)
			}
		}
	}

	if wantProcesses {
		snap.Processes = collectProcesses(ctx, procObjs)
	}
	if wantConnections {
		snap.Connections = collectConnections(ctx, procObjs)
	}
	return snap
}

func collectProcesses(ctx context.Context, procs []*process.Process) []telemetry.ProcessInfo {
	// Prime per-process CPU counters, wait, then read the delta.
	for _, p := range procs {
		_, _ = p.PercentWithContext(ctx, 0)
	}
	select {
	case <-ctx.Done():
		return nil
	case <-time.After(cpuSampleWindow):
	}

	now := time.Now()
	out := make([]telemetry.ProcessInfo, 0, len(procs))
	for _, p := range procs {
		pi := telemetry.ProcessInfo{PID: p.Pid}
		if name, err := p.NameWithContext(ctx); err == nil {
			pi.Name = name
		}
		if user, err := p.UsernameWithContext(ctx); err == nil {
			pi.User = user
		}
		if st, err := p.StatusWithContext(ctx); err == nil && len(st) > 0 {
			pi.Status = statusLabel(st[0])
		}
		if cpuPct, err := p.PercentWithContext(ctx, 0); err == nil {
			pi.CPUPct = cpuPct
		}
		if mi, err := p.MemoryInfoWithContext(ctx); err == nil && mi != nil {
			pi.RSSBytes = mi.RSS
			pi.VirtBytes = mi.VMS
		}
		if io, err := p.IOCountersWithContext(ctx); err == nil && io != nil {
			pi.DiskReadBytes = io.ReadBytes
			pi.DiskWriteBytes = io.WriteBytes
		}
		if ct, err := p.CreateTimeWithContext(ctx); err == nil && ct > 0 {
			pi.RunTimeSeconds = now.Sub(time.UnixMilli(ct)).Seconds()
		}
		out = append(out, pi)
	}
	return out
}

func collectConnections(ctx context.Context, procs []*process.Process) []telemetry.ConnectionInfo {
	conns, err := psnet.ConnectionsWithContext(ctx, "all")
	if err != nil {
		return nil
	}
	// pid -> process name, for labeling.
	names := make(map[int32]string, len(procs))
	for _, p := range procs {
		if n, err := p.NameWithContext(ctx); err == nil {
			names[p.Pid] = n
		}
	}
	out := make([]telemetry.ConnectionInfo, 0, len(conns))
	for _, c := range conns {
		ci := telemetry.ConnectionInfo{
			Proto:       proto(c),
			LocalAddr:   addr(c.Laddr.IP, c.Laddr.Port),
			RemoteAddr:  addr(c.Raddr.IP, c.Raddr.Port),
			State:       c.Status,
			PID:         c.Pid,
			ProcessName: names[c.Pid],
		}
		out = append(out, ci)
	}
	return out
}

func addr(ip string, port uint32) string {
	if ip == "" && port == 0 {
		return ""
	}
	if strings.Contains(ip, ":") { // IPv6 literal
		return fmt.Sprintf("[%s]:%d", ip, port)
	}
	return fmt.Sprintf("%s:%d", ip, port)
}

// proto derives tcp/tcp6/udp/udp6 from the socket type and address family.
func proto(c psnet.ConnectionStat) string {
	base := "tcp"
	if c.Type == 2 { // SOCK_DGRAM
		base = "udp"
	}
	if strings.Contains(c.Laddr.IP, ":") || strings.Contains(c.Raddr.IP, ":") {
		base += "6"
	}
	return base
}

// statusLabel maps gopsutil's short status codes to readable labels matching the
// dashboard (Running / Sleeping / …), tolerating already-long values.
func statusLabel(s string) string {
	switch s {
	case "R", process.Running:
		return "Running"
	case "S", process.Sleep:
		return "Sleeping"
	case "I", process.Idle:
		return "Idle"
	case "T", process.Stop:
		return "Stopped"
	case "Z", process.Zombie:
		return "Zombie"
	case "":
		return ""
	default:
		return s
	}
}
