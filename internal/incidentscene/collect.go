//go:build !lite

// Package incidentscene collects the agent's allowlisted incident-scene evidence
// (INCIDENT-005). It answers exactly the typed field groups the protocol defines
// — local network context, the agent's own identity/version, a basic CPU/memory
// summary, and per-target resolution — and NOTHING else: it never reads process
// lists, user names, file paths, credentials, request/response headers or
// bodies, or connection lists.
//
// Each group is classified independently (collected/denied/unsupported/failed)
// against the agent's existing effective/granted/supported permission views and
// the platform's real capabilities, so a partial scene completes immediately
// instead of waiting on a denied or unsupported group. The whole collection is
// bounded by the caller's context. Nothing here is persisted.
//
// The collector answers no request: scenetrigger decides when to call it, from
// fault edges this agent detected itself, and stamps the report identity and the
// triggers onto what comes back. See telemetry.SceneReport for why that
// inversion was necessary.
//
// It is excluded from the lite build. Collection is cheap in CPU but the report
// is large next to a router's whole outbox budget, and a device with 5000 rows
// of memory for its telemetry should spend them on measurements.
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
	errClassInvalidTarget    = "invalid_target"    // the target string carries no resolvable host
	errClassPolicyDenied     = "policy_denied"     // the agent's own target-access policy blocked it
	errClassDNS              = "dns_error"         // the resolver answered, and the answer was a failure
	errClassTimeout          = "timeout"           // the collection budget ran out before the resolver answered
	errClassCanceled         = "canceled"          // the session ended before the resolver answered
	errClassNoGateway        = "no_gateway"        // kind=gateway: the routing table has no IPv4 gateway on the selected NIC
	errClassRouteUnreadable  = "route_unreadable"  // kind=gateway: the routing table itself could not be read
	errClassPermissionDenied = "permission_denied" // the agent lacks the permission needed to resolve this kind
)

// Identity is the detecting agent's own identity/version, fixed into the
// snapshot at collection time so later renames never rewrite history.
type Identity struct {
	AgentID  string
	Hostname string
	OS       string // runtime.GOOS
	Version  string
}

// TargetRef identifies one monitor target the scene should resolve. It carries
// enough to key the result by monitor id, choose the probe semantics (Kind), and
// reconstruct the endpoint (Target + Port).
//
// Kind decides how Target is interpreted, and NOT every kind carries a
// resolvable host: gateway monitors carry the server-normalized sentinel
// "gateway" and are resolved from the agent's routing table (via Iface), never
// through DNS. Host-anchor monitors never appear here at all — they name a
// metric series ("host", "*", "C:"), not a network destination.
type TargetRef struct {
	MonitorID string // stable server-side monitor id (probe_tasks.id)
	Kind      string // "icmp" | "dns" | "http" | "tcp" | "nat" | "gateway"
	Target    string // literal/host/URL as configured; the sentinel "gateway" for kind=gateway
	Port      int    // TCP/UDP port when the kind carries one
	Iface     string // kind=gateway only: the NIC to resolve the gateway from; "" = default NIC
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

// Collect gathers the allowlisted scene, bounded by ctx, resolving refs as the
// target group. It always returns a report with a result for every attempted
// group; the caller stamps on the report id and the triggers that caused it.
//
// An empty refs omits the target group entirely rather than reporting an empty
// collected one. The two are different statements — "these targets resolved to
// nothing" versus "no target was in question" — and the disconnect trigger is
// the second: the probes were fine and only the uplink was not, so a line
// claiming the targets were surveyed would be an answer to a question nobody
// asked.
func Collect(ctx context.Context, deps Deps, refs []TargetRef) telemetry.SceneReport {
	var scene telemetry.SceneReport

	// Each group is attempted and classified independently. Denied/unsupported
	// groups return instantly (no OS work), so they never delay the collected ones.
	net, netRes := collectNetwork(ctx, deps)
	scene.Network = net
	scene.Groups = append(scene.Groups, netRes)

	agent, agentRes := collectAgent(deps)
	scene.Agent = agent
	scene.Groups = append(scene.Groups, agentRes)

	resources, resRes := collectResources(ctx, deps)
	scene.Resources = resources
	scene.Groups = append(scene.Groups, resRes)

	if len(refs) > 0 {
		targets, tgtRes := collectTargets(ctx, deps, refs)
		scene.Targets = targets
		scene.Groups = append(scene.Groups, tgtRes)
	}

	scene.CollectedAt = time.Now().UTC()
	return scene
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

	// An unreadable routing table is partial, not fatal: the interface list is
	// fully populated, so the group is still collected and only DefaultRoute stays
	// absent (there is nothing below to find). Failing the whole group would throw
	// away the interface and address evidence over one missing field.
	ifaces, err := deps.Platform.Interfaces(q)
	if err != nil {
		if !errors.Is(err, platform.ErrRoutesUnreadable) {
			return nil, groupResult(telemetry.SnapshotGroupNetwork, telemetry.ScopeFailed, reasonCollectionFailed)
		}
		// Routes are UNKNOWN, so no gateway read from this table can be trusted —
		// suppress the default route explicitly rather than relying on the platform
		// to have left the field empty. Publishing a stale one would name an egress
		// the host may no longer have.
		gwOK = false
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
	// The default route comes from the shared resolver, not from "first interface
	// with any gateway": that took a down adapter's stale route or an IPv6 one,
	// and a gateway target in the same snapshot — resolved through
	// ResolveIPv4Gateway — would then name a different address than the network
	// group printed for the very same host.
	if gwOK {
		if gw, name := platform.ResolveIPv4Gateway(ifaces, ""); gw != "" {
			out.DefaultRoute = &telemetry.SnapshotRoute{Gateway: gw, Interface: name}
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
// collected (resolution outcomes live per target); Collect skips it entirely
// when there is no target in question.
func collectTargets(ctx context.Context, deps Deps, refs []TargetRef) ([]telemetry.SnapshotTargetResult, telemetry.SnapshotGroupResult) {
	out := make([]telemetry.SnapshotTargetResult, len(refs))
	sem := make(chan struct{}, targetResolveConcurrency)
	var wg sync.WaitGroup
	for i, ref := range refs {
		wg.Add(1)
		go func(i int, ref TargetRef) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			out[i] = resolveTarget(ctx, deps, ref)
		}(i, ref)
	}
	wg.Wait()
	return out, groupResult(telemetry.SnapshotGroupTargets, telemetry.ScopeCollected, "")
}

// resolveTarget resolves one target's host and derives its probe endpoints and a
// coarse error class, all through the target-access guard so a policy-denied
// destination is reported as such rather than probed.
//
// Not every kind resolves through DNS. A gateway monitor's target is the
// server-normalized sentinel "gateway", which no resolver can or should answer —
// it is resolved from the routing table instead. Handing the sentinel to the
// resolver would report "DNS resolution failed" for an incident whose real cause
// is a dead LAN, sending the reader after a layer that is working fine.
func resolveTarget(ctx context.Context, deps Deps, ref TargetRef) telemetry.SnapshotTargetResult {
	res := telemetry.SnapshotTargetResult{
		MonitorID: ref.MonitorID,
		Kind:      ref.Kind,
		Target:    ref.Target,
	}
	if ref.Kind == "gateway" {
		gw, errClass := resolveGateway(deps, ref.Iface)
		res.ErrorClass = errClass
		if gw != "" {
			res.ResolvedIPs = []string{gw}
		}
		return res
	}

	host, port := deriveHostPort(ref)
	if host == "" {
		res.ErrorClass = errClassInvalidTarget
		return res
	}

	ips, errClass := resolveHost(ctx, deps.Guard, host)
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

// resolveGateway resolves a gateway monitor's actual target from the routing
// table — the same lookup the gateway probe itself performs, through the shared
// platform.ResolveIPv4Gateway, so the address reported here is the address that
// was pinged. iface is the monitor's NIC selection ("" = default NIC).
//
// The permission gate is address-read OR gateway-probe, matching collectNetwork's
// gwOK exactly. Either one authorizes disclosing the gateway, and requiring only
// the probe permission would let one snapshot print the default route in its
// network group while this target claimed permission was denied for the very same
// address.
//
// Every failure gets its own class: no permission, an unreadable routing table,
// and a NIC that genuinely has no IPv4 gateway are three different faults, and
// collapsing them (or borrowing errClassDNS) would point the reader at the wrong
// layer. A gateway the guard denies is reported as policy_denied, matching what
// the live probe does with the same address.
func resolveGateway(deps Deps, iface string) (string, string) {
	if !deps.Effective.Has(permission.NetIfaceAddressRead) && !deps.Effective.Has(permission.NetworkGatewayProbe) {
		return "", errClassPermissionDenied
	}
	ifaces, err := deps.Platform.Interfaces(platform.IfaceQuery{Gateways: true})
	if err != nil {
		return "", errClassRouteUnreadable
	}
	gw, _ := platform.ResolveIPv4Gateway(ifaces, iface)
	if gw == "" {
		return "", errClassNoGateway
	}
	if a, perr := netip.ParseAddr(gw); perr == nil {
		if dec := deps.Guard.CheckGateway(a.Unmap(), osGateways(ifaces)); !dec.Allowed {
			return "", errClassPolicyDenied
		}
	}
	return gw, ""
}

// osGateways flattens every gateway address the OS reports across all interfaces,
// which is what CheckGateway needs to confirm the address really is a gateway.
func osGateways(ifaces []platform.IfaceInfo) []netip.Addr {
	var out []netip.Addr
	for _, ifc := range ifaces {
		for _, gw := range ifc.Gateways {
			if a, err := netip.ParseAddr(gw); err == nil {
				out = append(out, a.Unmap())
			}
		}
	}
	return out
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
func deriveHostPort(ref TargetRef) (string, int) {
	if ref.Kind == "http" {
		return httpHostPort(ref)
	}
	return ref.Target, ref.Port
}

// httpHostPort parses an HTTP monitor URL into host + port, preferring an
// explicit ref port, then the URL's port, then the scheme default.
func httpHostPort(ref TargetRef) (string, int) {
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
