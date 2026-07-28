// Package incidentscene collects the agent's allowlisted incident-scene evidence
// for one config.IncidentSnapshotRequest (INCIDENT-002). It answers exactly the
// typed field groups the protocol defines — local network context, the agent's
// own identity/version, a basic CPU/memory summary, and per-target resolution —
// and NOTHING else: it never reads process lists, user names, file paths,
// credentials, request/response headers or bodies, or connection lists.
//
// Each group is classified independently (collected/denied/unsupported/failed)
// against the agent's existing effective/granted/supported permission views and
// the platform's real capabilities, so a partial snapshot completes immediately
// instead of waiting on a denied or unsupported group. The whole collection is
// bounded by the request's budget; the returned IncidentSnapshot always carries
// the request/incident id and one result per attempted group, even when every
// group is denied. Nothing here is persisted.
package incidentscene

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/nettact/agent/internal/netguard"
	"github.com/nettact/agent/internal/platform"
	pcfg "github.com/nettact/protocol/config"
	"github.com/nettact/protocol/permission"
	"github.com/nettact/protocol/telemetry"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/mem"
)

// cpuSampleWindow is the short busy-window used to turn gopsutil's since-last
// counter into a current CPU%. It is skipped when the deadline is too close, so
// CPU stays absent rather than delaying the snapshot.
const cpuSampleWindow = 250 * time.Millisecond

// targetResolveConcurrency bounds simultaneous per-target DNS resolutions so a
// many-target incident does not fan out an unbounded number of lookups.
const targetResolveConcurrency = 4

// Stable per-group reason codes for a non-collected group.
const (
	reasonPermissionDenied = "permission_denied"
	reasonUnsupported      = "unsupported_platform"
	reasonCollectionFailed = "collection_failed"
	reasonTimeout          = "timeout"
)

// Stable per-target error classes (SnapshotTargetResult.ErrorClass). These
// describe the TARGET's resolution outcome, so an agent-side condition that
// prevented the lookup from ever happening must never borrow errClassDNS —
// reporting a DNS failure the target does not have sends the reader after the
// wrong layer.
const (
	errClassInvalidTarget = "invalid_target" // the target string carries no resolvable host
	errClassPolicyDenied  = "policy_denied"  // the agent's own target-access policy blocked it
	errClassDNS           = "dns_error"      // the resolver answered, and the answer was a failure
	errClassTimeout       = "timeout"        // the collection budget ran out before the resolver answered
	errClassCanceled      = "canceled"       // the session ended before the resolver answered
)

// Identity is the detecting agent's own identity/version, fixed into the
// snapshot at collection time so later renames never rewrite history.
type Identity struct {
	AgentID  string
	Hostname string
	OS       string // runtime.GOOS
	Version  string
}

// Deps are the agent-side capabilities the collector reuses — the same platform
// HAL, target-access guard, and permission views the live probes run under. No
// new capability surface is introduced.
type Deps struct {
	Platform  platform.Platform
	Guard     *netguard.Guard
	Effective permission.Set
	Granted   permission.Set
	Supported permission.Set
	Identity  Identity
}

// Collect gathers the allowlisted incident-scene snapshot for req, bounded by
// ctx (the caller derives ctx from req.BudgetMs). It always returns a snapshot
// carrying the request/incident id and a result for every attempted group.
func Collect(ctx context.Context, req pcfg.IncidentSnapshotRequest, deps Deps) telemetry.IncidentSnapshot {
	snap := telemetry.IncidentSnapshot{
		RequestID:   req.RequestID,
		IncidentID:  req.IncidentID,
		CollectedAt: time.Now().UTC(),
	}

	// Each group is attempted and classified independently. Denied/unsupported
	// groups return instantly (no OS work), so they never delay the collected ones.
	net, netRes := collectNetwork(ctx, deps)
	snap.Network = net
	snap.Groups = append(snap.Groups, netRes)

	agent, agentRes := collectAgent(deps)
	snap.Agent = agent
	snap.Groups = append(snap.Groups, agentRes)

	resources, resRes := collectResources(ctx, deps)
	snap.Resources = resources
	snap.Groups = append(snap.Groups, resRes)

	targets, tgtRes := collectTargets(ctx, deps, req.Targets)
	snap.Targets = targets
	snap.Groups = append(snap.Groups, tgtRes)

	snap.CollectedAt = time.Now().UTC()
	return snap
}

// groupResult builds a SnapshotGroupResult with the current agent clock.
func groupResult(group, status, reason string) telemetry.SnapshotGroupResult {
	return telemetry.SnapshotGroupResult{
		Group:       group,
		Status:      status,
		Reason:      reason,
		CollectedAt: time.Now().UTC(),
	}
}

// permStatus classifies a single permission id into a group status+reason: an
// effective id is collected; a supported-but-not-granted id is denied
// (permission_denied); an unsupported id is unsupported (unsupported_platform).
func permStatus(id permission.ID, deps Deps) (status, reason string) {
	if deps.Effective.Has(id) {
		return telemetry.ScopeCollected, ""
	}
	if !deps.Supported.Has(id) {
		return telemetry.ScopeUnsupported, reasonUnsupported
	}
	return telemetry.ScopeDenied, reasonPermissionDenied
}

// collectNetwork reads local interface status/addresses, the default route, and
// configured DNS servers, each field family gated by its own permission (a
// denied family is simply omitted, never read then redacted). The group is gated
// on interface-status read; address/gateway/DNS enrich it when their scopes are
// effective.
func collectNetwork(ctx context.Context, deps Deps) (*telemetry.SnapshotNetwork, telemetry.SnapshotGroupResult) {
	status, reason := permStatus(permission.NetIfaceStatusRead, deps)
	if status != telemetry.ScopeCollected {
		return nil, groupResult(telemetry.SnapshotGroupNetwork, status, reason)
	}
	if err := ctx.Err(); err != nil {
		return nil, groupResult(telemetry.SnapshotGroupNetwork, telemetry.ScopeFailed, ctxReason(ctx))
	}

	addrOK := deps.Effective.Has(permission.NetIfaceAddressRead)
	gwOK := addrOK || deps.Effective.Has(permission.NetworkGatewayProbe)
	q := platform.IfaceQuery{Addrs: addrOK, Gateways: gwOK, DNS: addrOK}

	ifaces, err := deps.Platform.Interfaces(q)
	if err != nil {
		return nil, groupResult(telemetry.SnapshotGroupNetwork, telemetry.ScopeFailed, reasonCollectionFailed)
	}

	out := &telemetry.SnapshotNetwork{}
	dnsSeen := map[string]struct{}{}
	for _, ifc := range ifaces {
		out.Interfaces = append(out.Interfaces, telemetry.SnapshotInterface{
			Name:       ifc.Name,
			Addrs:      append([]string(nil), ifc.Addrs...),
			Up:         ifc.Up,
			IsWireless: ifc.IsWireless,
		})
		// First non-loopback interface carrying a gateway defines the default route.
		if gwOK && out.DefaultRoute == nil && !ifc.IsLoopback && len(ifc.Gateways) > 0 {
			out.DefaultRoute = &telemetry.SnapshotRoute{Gateway: ifc.Gateways[0], Interface: ifc.Name}
		}
		if addrOK {
			for _, d := range ifc.DNS {
				if _, ok := dnsSeen[d]; ok {
					continue
				}
				dnsSeen[d] = struct{}{}
				out.DNSServers = append(out.DNSServers, d)
			}
		}
	}
	return out, groupResult(telemetry.SnapshotGroupNetwork, telemetry.ScopeCollected, "")
}

// collectAgent returns the detecting agent's own identity/version. It needs no
// permission and cannot fail, so it is always collected.
func collectAgent(deps Deps) (*telemetry.SnapshotAgentInfo, telemetry.SnapshotGroupResult) {
	info := &telemetry.SnapshotAgentInfo{
		AgentID:      deps.Identity.AgentID,
		Hostname:     deps.Identity.Hostname,
		Platform:     deps.Identity.OS,
		AgentVersion: deps.Identity.Version,
	}
	return info, groupResult(telemetry.SnapshotGroupAgent, telemetry.ScopeCollected, "")
}

// collectResources reads a basic CPU/memory summary via gopsutil, each value
// gated on its own permission. The group is denied only when neither CPU nor
// memory is effective; with at least one effective it is collected (values are
// pointers, so an unreadable one stays absent), or failed if every attempted
// read errored.
func collectResources(ctx context.Context, deps Deps) (*telemetry.SnapshotResources, telemetry.SnapshotGroupResult) {
	cpuOK := deps.Effective.Has(permission.HostCPURead)
	memOK := deps.Effective.Has(permission.HostMemoryRead)
	if !cpuOK && !memOK {
		// Both denied: report the stronger of the two reasons (unsupported only when
		// neither is even supported, which never happens for these stdlib metrics).
		if !deps.Supported.Has(permission.HostCPURead) && !deps.Supported.Has(permission.HostMemoryRead) {
			return nil, groupResult(telemetry.SnapshotGroupResources, telemetry.ScopeUnsupported, reasonUnsupported)
		}
		return nil, groupResult(telemetry.SnapshotGroupResources, telemetry.ScopeDenied, reasonPermissionDenied)
	}
	if err := ctx.Err(); err != nil {
		return nil, groupResult(telemetry.SnapshotGroupResources, telemetry.ScopeFailed, ctxReason(ctx))
	}

	out := &telemetry.SnapshotResources{}
	attempted, ok := 0, 0
	if cpuOK {
		attempted++
		if v, err := sampleCPU(ctx); err == nil {
			out.CPUPercent = &v
			ok++
		}
	}
	if memOK {
		attempted++
		if vm, err := mem.VirtualMemoryWithContext(ctx); err == nil && vm != nil {
			total := vm.Total
			used := vm.Used
			out.MemoryTotalBytes = &total
			out.MemoryUsedBytes = &used
			ok++
		}
	}
	if attempted > 0 && ok == 0 {
		return nil, groupResult(telemetry.SnapshotGroupResources, telemetry.ScopeFailed, ctxReason(ctx))
	}
	return out, groupResult(telemetry.SnapshotGroupResources, telemetry.ScopeCollected, "")
}

// sampleCPU returns instantaneous total CPU%. It uses a short busy-window only
// when the deadline comfortably allows it; otherwise it takes gopsutil's
// since-last reading so the snapshot is never delayed for a CPU sample.
func sampleCPU(ctx context.Context) (float64, error) {
	window := cpuSampleWindow
	if dl, ok := ctx.Deadline(); ok && time.Until(dl) < 2*cpuSampleWindow {
		window = 0
	}
	pcts, err := cpu.PercentWithContext(ctx, window, false)
	if err != nil || len(pcts) == 0 {
		if err == nil {
			err = errors.New("no cpu sample")
		}
		return 0, err
	}
	return pcts[0], nil
}

// collectTargets resolves each requested monitor target from this agent's vantage
// point through the SAME netguard policy the live probes use, reporting the
// resolved IPs, the endpoints it would probe, and a coarse error class. It never
// opens a connection or reads any request/response content. The group is always
// collected (resolution outcomes live per target); an empty target list yields an
// empty, collected group.
func collectTargets(ctx context.Context, deps Deps, refs []pcfg.SnapshotTargetRef) ([]telemetry.SnapshotTargetResult, telemetry.SnapshotGroupResult) {
	if len(refs) == 0 {
		return nil, groupResult(telemetry.SnapshotGroupTargets, telemetry.ScopeCollected, "")
	}

	out := make([]telemetry.SnapshotTargetResult, len(refs))
	sem := make(chan struct{}, targetResolveConcurrency)
	var wg sync.WaitGroup
	for i, ref := range refs {
		wg.Add(1)
		go func(i int, ref pcfg.SnapshotTargetRef) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			out[i] = resolveTarget(ctx, deps.Guard, ref)
		}(i, ref)
	}
	wg.Wait()
	return out, groupResult(telemetry.SnapshotGroupTargets, telemetry.ScopeCollected, "")
}

// resolveTarget resolves one target's host and derives its probe endpoints and a
// coarse error class, all through the target-access guard so a policy-denied
// destination is reported as such rather than probed.
func resolveTarget(ctx context.Context, guard *netguard.Guard, ref pcfg.SnapshotTargetRef) telemetry.SnapshotTargetResult {
	res := telemetry.SnapshotTargetResult{
		MonitorID: ref.MonitorID,
		Kind:      ref.Kind,
		Target:    ref.Target,
	}
	host, port := deriveHostPort(ref)
	if host == "" {
		res.ErrorClass = errClassInvalidTarget
		return res
	}

	ips, errClass := resolveHost(ctx, guard, host)
	res.ErrorClass = errClass
	for _, ip := range ips {
		res.ResolvedIPs = append(res.ResolvedIPs, ip.String())
	}
	if port > 0 {
		if len(ips) > 0 {
			for _, ip := range ips {
				res.Endpoints = append(res.Endpoints, netip.AddrPortFrom(ip, uint16(port)).String())
			}
		} else {
			res.Endpoints = append(res.Endpoints, net.JoinHostPort(host, strconv.Itoa(port)))
		}
	}
	return res
}

// resolveHost runs one host through the guard exactly once: a literal IP is
// policy-checked directly; a hostname is pre-checked then vetted-resolved. It
// returns the vetted addresses and a coarse error class ("" on success).
//
// A dead collection context short-circuits before any lookup, and a lookup that
// fails because the context died is classified by that context — not as
// errClassDNS. The stdlib resolver wraps a context timeout in a *net.DNSError, so
// treating every resolve error as a DNS failure would report "DNS resolution
// failed" for a target whose name resolves perfectly well, whenever the snapshot
// budget was already spent when collection began.
func resolveHost(ctx context.Context, guard *netguard.Guard, host string) ([]netip.Addr, string) {
	if a, err := netip.ParseAddr(host); err == nil {
		a = a.Unmap()
		if dec := guard.CheckAddr(a); !dec.Allowed {
			return nil, errClassPolicyDenied
		}
		return []netip.Addr{a}, ""
	}
	if ctx.Err() != nil {
		return nil, ctxErrorClass(ctx)
	}
	hd := guard.CheckHost(host)
	if hd.Denied {
		return nil, errClassPolicyDenied
	}
	vetted, err := guard.ResolveVetted(ctx, host, hd.NameAuthorized)
	if err != nil {
		var be *netguard.BlockedError
		switch {
		case errors.As(err, &be):
			return nil, errClassPolicyDenied
		case ctx.Err() != nil:
			return nil, ctxErrorClass(ctx)
		}
		return nil, errClassDNS
	}
	sort.Slice(vetted, func(i, j int) bool { return vetted[i].Less(vetted[j]) })
	return vetted, ""
}

// ctxErrorClass maps a dead collection context to the target error class that
// explains why no answer was obtained: budget exhaustion vs session teardown.
func ctxErrorClass(ctx context.Context) string {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return errClassTimeout
	}
	return errClassCanceled
}

// deriveHostPort extracts the host and probe port from a target ref. HTTP targets
// carry a URL (host + explicit or scheme-default port); other kinds use the
// literal target and the ref's own port.
func deriveHostPort(ref pcfg.SnapshotTargetRef) (string, int) {
	if ref.Kind == "http" {
		return httpHostPort(ref)
	}
	return ref.Target, ref.Port
}

// httpHostPort parses an HTTP monitor URL into host + port, preferring an
// explicit ref port, then the URL's port, then the scheme default.
func httpHostPort(ref pcfg.SnapshotTargetRef) (string, int) {
	u, err := url.Parse(ref.Target)
	if err != nil || u.Hostname() == "" {
		return "", 0
	}
	port := ref.Port
	if port == 0 {
		if p := u.Port(); p != "" {
			port, _ = strconv.Atoi(p)
		}
	}
	if port == 0 {
		if u.Scheme == "https" {
			port = 443
		} else {
			port = 80
		}
	}
	return u.Hostname(), port
}

// ctxReason maps a context state to a stable group reason (timeout vs a generic
// collection failure).
func ctxReason(ctx context.Context) string {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return reasonTimeout
	}
	return reasonCollectionFailed
}
