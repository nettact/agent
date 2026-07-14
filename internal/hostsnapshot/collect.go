// Package hostsnapshot builds the ephemeral, pull-on-demand process and network
// connection lists (protocol/telemetry.HostSnapshot). It is invoked only when
// the server sets a config.SnapshotRequest, and only for the scopes the agent's
// effective policy grants. Collection is scope-gated: an OS/gopsutil operation is
// invoked ONLY for a granted scope — the agent never enumerates-then-redacts (it
// does not, for example, enumerate processes to label connections unless the
// connection-owner scope is granted). Nothing here is persisted.
package hostsnapshot

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/nettact/protocol/permission"
	"github.com/nettact/protocol/telemetry"

	"github.com/shirou/gopsutil/v3/process"

	psnet "github.com/shirou/gopsutil/v3/net"
)

// cpuSampleWindow is how long we wait between the two per-process CPU samples
// used to compute a current CPU% (gopsutil measures the delta between calls on
// the same Process object).
const cpuSampleWindow = 300 * time.Millisecond

// Collect gathers a live snapshot for exactly the granted scopes in `collect`.
// The returned Scopes carries a per-scope result for each granted scope: it is
// `collected` when the underlying gopsutil enumeration succeeded, or `failed`
// (with a safe reason) when the process/connection enumeration errored or the
// snapshot context expired. Scopes whose family collected successfully stay
// available even when the other family failed. gopsutil is invoked only for a
// granted scope.
func Collect(ctx context.Context, requestID string, collect permission.Set) telemetry.HostSnapshot {
	snap := telemetry.HostSnapshot{TS: time.Now().UTC(), RequestID: requestID}

	needProcBasic := collect.Has(permission.HostProcessBasicRead)
	needProcOwner := collect.Has(permission.HostProcessOwnerRead)
	needProcResource := collect.Has(permission.HostProcessResourceRead)
	needProcIO := collect.Has(permission.HostProcessIORead)

	needConnSummary := collect.Has(permission.HostConnectionSummaryRead)
	needConnLocal := collect.Has(permission.HostConnectionLocalRead)
	needConnRemote := collect.Has(permission.HostConnectionRemoteRead)
	needConnOwner := collect.Has(permission.HostConnectionOwnerRead)

	// Track a failure reason per scope family; empty means the family collected.
	procFail := ""
	connFail := ""
	// connOwnerFail is set when the connection-owner scope was requested but the
	// process table (needed for process names) could not be enumerated. The other
	// connection scopes (summary/local/remote) do not depend on the process table
	// and stay collected; only the owner scope is failed.
	connOwnerFail := ""

	// Enumerate the process table only when a process scope is collected OR the
	// connection-owner scope needs process names — never merely to label
	// connections without owner access.
	var procObjs []*process.Process
	if needProcBasic || needConnOwner {
		if ps, err := process.ProcessesWithContext(ctx); err == nil {
			procObjs = ps
			if needProcBasic {
				total := len(ps)
				snap.ProcessTotal = &total
			}
		} else {
			reason := failReason(ctx, err)
			if needProcBasic {
				procFail = reason
				snap.ProcessTotal = nil
			}
			if needConnOwner {
				// Owner names come from the process table; without it the owner scope
				// cannot be honestly reported as collected.
				connOwnerFail = reason
			}
		}
	}

	if needProcBasic && procFail == "" {
		rows, err := collectProcesses(ctx, procObjs, needProcOwner, needProcResource, needProcIO)
		if err != nil {
			procFail = failReason(ctx, err)
			snap.Processes = nil
			snap.ProcessTotal = nil
		} else {
			snap.Processes = rows
		}
	}
	if needConnSummary {
		// Populate owner fields only when the process table is available; otherwise
		// the owner scope is reported failed and its fields are left absent.
		rows, err := collectConnections(ctx, procObjs, needConnLocal, needConnRemote, needConnOwner && connOwnerFail == "")
		if err != nil {
			connFail = failReason(ctx, err)
		} else {
			snap.Connections = rows
		}
	}

	// One result per granted scope (canonical order): collected, or failed if its
	// family's enumeration errored.
	for _, id := range collect.Sorted() {
		res := telemetry.SnapshotScopeResult{Scope: string(id), Status: telemetry.ScopeCollected}
		switch {
		case isProcessScope(id) && procFail != "":
			res.Status, res.Reason = telemetry.ScopeFailed, procFail
		case isConnectionScope(id) && connFail != "":
			res.Status, res.Reason = telemetry.ScopeFailed, connFail
		case id == permission.HostConnectionOwnerRead && connOwnerFail != "":
			res.Status, res.Reason = telemetry.ScopeFailed, connOwnerFail
		}
		snap.Scopes = append(snap.Scopes, res)
	}
	return snap
}

// failReason maps a collection error to a safe, non-leaking reason token.
func failReason(ctx context.Context, err error) string {
	if ctx.Err() == context.DeadlineExceeded || errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	if ctx.Err() == context.Canceled || errors.Is(err, context.Canceled) {
		return "canceled"
	}
	return "collection_failed"
}

// isProcessScope / isConnectionScope classify a granted scope into its family so
// a family-wide enumeration failure marks exactly the affected scopes.
func isProcessScope(id permission.ID) bool {
	switch id {
	case permission.HostProcessBasicRead, permission.HostProcessOwnerRead,
		permission.HostProcessResourceRead, permission.HostProcessIORead:
		return true
	}
	return false
}

func isConnectionScope(id permission.ID) bool {
	switch id {
	case permission.HostConnectionSummaryRead, permission.HostConnectionLocalRead,
		permission.HostConnectionRemoteRead, permission.HostConnectionOwnerRead:
		return true
	}
	return false
}

func collectProcesses(ctx context.Context, procs []*process.Process, owner, resource, io bool) ([]telemetry.ProcessInfo, error) {
	if resource {
		// Prime per-process CPU counters, wait, then read the delta.
		for _, p := range procs {
			_, _ = p.PercentWithContext(ctx, 0)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(cpuSampleWindow):
		}
	}

	now := time.Now()
	out := make([]telemetry.ProcessInfo, 0, len(procs))
	for _, p := range procs {
		pi := telemetry.ProcessInfo{PID: p.Pid}
		if name, err := p.NameWithContext(ctx); err == nil {
			pi.Name = name
		}
		if st, err := p.StatusWithContext(ctx); err == nil && len(st) > 0 {
			pi.Status = statusLabel(st[0])
		}
		if owner {
			if user, err := p.UsernameWithContext(ctx); err == nil {
				pi.User = ptr(user)
			}
		}
		if resource {
			if cpuPct, err := p.PercentWithContext(ctx, 0); err == nil {
				pi.CPUPct = ptr(cpuPct)
			}
			if mi, err := p.MemoryInfoWithContext(ctx); err == nil && mi != nil {
				pi.RSSBytes = ptr(mi.RSS)
				pi.VirtBytes = ptr(mi.VMS)
			}
			if ct, err := p.CreateTimeWithContext(ctx); err == nil && ct > 0 {
				pi.RunTimeSeconds = ptr(now.Sub(time.UnixMilli(ct)).Seconds())
			}
		}
		if io {
			if ioc, err := p.IOCountersWithContext(ctx); err == nil && ioc != nil {
				pi.DiskReadBytes = ptr(ioc.ReadBytes)
				pi.DiskWriteBytes = ptr(ioc.WriteBytes)
			}
		}
		out = append(out, pi)
	}
	return out, nil
}

func collectConnections(ctx context.Context, procs []*process.Process, local, remote, owner bool) ([]telemetry.ConnectionInfo, error) {
	conns, err := psnet.ConnectionsWithContext(ctx, "all")
	if err != nil {
		return nil, err
	}
	// pid -> process name, only when the owner scope is granted (the process table
	// is enumerated for us in that case).
	var names map[int32]string
	if owner {
		names = make(map[int32]string, len(procs))
		for _, p := range procs {
			if n, err := p.NameWithContext(ctx); err == nil {
				names[p.Pid] = n
			}
		}
	}
	out := make([]telemetry.ConnectionInfo, 0, len(conns))
	for _, c := range conns {
		ci := telemetry.ConnectionInfo{
			Proto: proto(c),
			State: c.Status,
		}
		if local {
			ci.LocalAddr = ptr(addr(c.Laddr.IP, c.Laddr.Port))
		}
		if remote {
			ci.RemoteAddr = ptr(addr(c.Raddr.IP, c.Raddr.Port))
		}
		if owner {
			pid := c.Pid
			ci.PID = &pid
			name := names[c.Pid]
			ci.ProcessName = &name
		}
		out = append(out, ci)
	}
	return out, nil
}

// ptr returns a pointer to v (generic presence helper).
func ptr[T any](v T) *T { return &v }

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
