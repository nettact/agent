package tracetrigger

import (
	"errors"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/nettact/agent/internal/traceroute"
	pcfg "github.com/nettact/protocol/config"
	"github.com/nettact/protocol/permission"
	"github.com/nettact/protocol/telemetry"
)

// evidence is one failing round's facts, as far as plan derivation is concerned.
// It is taken from the round that CONFIRMED the streak, not re-read from live
// config: a target retyped between the failure and the trace must not redirect
// the diagnostic at an endpoint the failing probes never touched.
type evidence struct {
	probeKind  string
	targetAddr string
	targetPort int
	// reasonCode is the probe.<kind>.error_class classification. It is what
	// separates "the tunnel is down" from "the tunnel is up and the target is
	// down" — two faults with identical destinations and opposite conclusions.
	reasonCode int

	resolverAddr     string
	resolverProtocol string
	stunAddr         string
	stunTransport    string

	proxyID   string
	proxyType string
	// proxyAddr is "host:port" for socks5/http and the peer endpoint for
	// wireguard.
	proxyAddr string
	// proxyConfigSerial is the pin's generation at failure time — what an
	// in-tunnel plan pins its egress to, so a proxy re-keyed between the fault
	// and the diagnostic can never be the one that carries the probes.
	proxyConfigSerial int
}

// plan is a resolved traceroute plan: everything about the report except the
// execution. terminal/reason are set when the inputs cannot produce a runnable
// trace, in which case the report is emitted in that terminal state and no
// packet is ever sent — silence would be indistinguishable from a trace nobody
// asked for.
type plan struct {
	mode     string
	destKey  string
	destHost string
	port     int

	subjectKind   string
	subjectReason string

	pathScope          string
	egressID           string
	egressConfigSerial int

	fallbackFrom   string
	fallbackReason string

	terminal string
	reason   string
}

// cohortKey identifies the physical question a trace answers: the probe mode,
// the destination (and port) it walks toward, and the path it takes to get
// there. Dedupe and cooldown key on it rather than on destKey alone — an ICMP
// walk and a TCP:443 walk to one host are different probes, and a direct path
// and a WireGuard-inner path to one address are different paths, so collapsing
// them would silently drop the second diagnosis. The subject is deliberately
// NOT part of the key: a resolver fault and a target fault that point the same
// probe down the same path would produce two copies of one answer.
//
// The egress pin contributes its GENERATION as well as its id, because that is
// what pinning means everywhere else in this agent: a re-keyed proxy is a new
// dialer, not the old one reconfigured, and the trace it carries is pinned to
// the exact generation the failing round ran under. A fault after a re-pin is
// therefore a new path question — suppressing it under the previous
// generation's cooldown would withhold the diagnosis of the edit's own
// consequences, which is exactly when someone is looking.
func (p plan) cohortKey() string {
	return p.destKey + "|" + p.mode + "|" + strconv.Itoa(p.port) + "|" + p.pathScope + "|" +
		p.egressID + "|" + strconv.Itoa(p.egressConfigSerial)
}

// Stable denial reason codes, shared with the server's vocabulary so an
// agent-reported outcome and a server-side read speak one language.
const (
	reasonNoDestination = "no_destination"
	reasonNoTCPPort     = "no_tcp_port"
	reasonBadURL        = "bad_url"

	reasonPermissionDenied     = "permission_denied"
	reasonRawSocketUnavailable = "raw_socket_unavailable"

	// The subject exists but has no traceable address. Distinct from
	// no_destination, which means the monitored target itself was unknown.
	reasonResolverUnknown  = "resolver_unknown"  // the probe could not name the resolver it used
	reasonResolverLoopback = "resolver_loopback" // the resolver is a local stub; the path is zero hops
	reasonProxyUnknown     = "proxy_unknown"     // the pinned proxy has no usable address
	reasonNoSTUNServer     = "no_stun_server"    // the STUN endpoint was never recorded
)

// TraceEligibleKind reports whether a probe kind's availability fault is worth a
// path diagnostic at all: icmp/tcp/http/dns/nat qualify; gateway, host and
// wireless never do.
//
// dns and nat qualify because their probe DOES dial a network endpoint — a
// resolver, a STUN server — even though it is not the monitored target. What
// they diagnose is chosen in derivePlan; see the traceSubject vocabulary in
// protocol/telemetry.
func TraceEligibleKind(probeKind string) bool {
	switch probeKind {
	case "icmp", "tcp", "http", "dns", "nat":
		return true
	}
	return false
}

// traceModeForKind maps a directly-dialed probe kind to its natural traceroute
// mode. ICMP monitors run ICMP traceroute; TCP and HTTP monitors run TCP
// traceroute. dns/nat are absent on purpose: their mode follows the resolver
// protocol / STUN transport, not the kind.
func traceModeForKind(kind string) (string, bool) {
	switch kind {
	case "icmp":
		return pcfg.TraceModeICMP, true
	case "tcp", "http":
		return pcfg.TraceModeTCP, true
	}
	return "", false
}

// derivePlan resolves the traceroute plan from one failing round's evidence and
// then gates it on this server's traceroute permissions.
//
// The plan answers "what carried this probe", not "what was being monitored" —
// those diverge for every indirect probe:
//
//	pinned to socks5/http  → the PROXY (agent→proxy→target; a direct trace to the
//	                         target measures a path the probe never used, and the
//	                         relay protocols cannot carry a hop-by-hop diagnostic)
//	pinned to wireguard    → INSIDE the tunnel toward the failing destination when
//	                         the tunnel carried the probe and the target failed
//	                         beyond it; the peer ENDPOINT's physical path when the
//	                         tunnel itself failed, was never attempted, or the
//	                         in-tunnel destination cannot be derived
//	dns                    → the RESOLVER (the queried name is dialed by nobody)
//	nat                    → the STUN SERVER (which is the monitored target, but only
//	                         the probe knows the port and transport it used)
//	otherwise              → the target itself
//
// A TCP plan whose agent lacks the TCP permission falls back to ICMP when the
// ICMP permission is held (recorded in fallbackFrom/fallbackReason so the
// console explains the downgrade); a non-derivable destination or a fully
// missing permission yields a terminal plan rather than an execution. No
// auto-elevation, ever.
func derivePlan(evd evidence, views permission.Set, granted, supported permission.Set) (plan, bool) {
	p, ok := planFor(evd)
	if !ok {
		return plan{}, false
	}
	if p.terminal != "" {
		return p, true
	}

	// An in-tunnel plan is gated on GRANTED, not effective. Its probes never
	// touch the host stack — they are built in userspace and injected into the
	// WireGuard device — so the raw-socket capability that shapes supported (and
	// through it effective) is irrelevant, and demanding it would deny a path the
	// agent can always take. This mirrors the engine's own egress gate.
	if p.pathScope == telemetry.TracePathWireGuardInner {
		if !granted.Has(permission.DiagnosticTracerouteICMP) {
			p.terminal, p.reason = telemetry.TraceStatusUnsupported, reasonPermissionDenied
		}
		return p, true
	}
	switch {
	case p.mode == pcfg.TraceModeTCP && !views.Has(permission.DiagnosticTracerouteTCP):
		if views.Has(permission.DiagnosticTracerouteICMP) {
			p.mode = pcfg.TraceModeICMP
			p.fallbackFrom = pcfg.TraceModeTCP
			p.fallbackReason = tcpDenialReason(granted, supported)
		} else {
			p.terminal = telemetry.TraceStatusUnsupported
			p.reason = tcpDenialReason(granted, supported)
		}
	case p.mode == pcfg.TraceModeICMP && !views.Has(permission.DiagnosticTracerouteICMP):
		p.terminal, p.reason = telemetry.TraceStatusUnsupported, reasonPermissionDenied
	}
	return p, true
}

// planFor picks the diagnosis subject, destination and mode from the round's
// evidence alone — no permissions, no I/O, no clock. Returns ok=false for a kind
// with no diagnosable path at all, which TraceEligibleKind already excludes.
func planFor(evd evidence) (plan, bool) {
	// An egress pin wins over the probe kind: whatever the monitor asked about,
	// the packets went to the proxy first, and a fault on that leg has nothing to
	// do with the target's own path.
	if evd.proxyID != "" {
		return planProxy(evd)
	}
	switch evd.probeKind {
	case "dns":
		return planResolver(evd)
	case "nat":
		return planSTUN(evd)
	}

	mode, ok := traceModeForKind(evd.probeKind)
	if !ok {
		return plan{}, false
	}
	p := plan{mode: mode, subjectKind: telemetry.TraceSubjectTarget, pathScope: telemetry.TracePathDirect}
	switch evd.probeKind {
	case "icmp":
		if evd.targetAddr == "" {
			return terminalPlan(mode, telemetry.TraceSubjectTarget, "", reasonNoDestination), true
		}
		p.destKey, p.destHost = CanonicalDest(evd.targetAddr)
	case "tcp":
		if evd.targetAddr == "" {
			return terminalPlan(mode, telemetry.TraceSubjectTarget, "", reasonNoDestination), true
		}
		if evd.targetPort < 1 || evd.targetPort > 65535 {
			return terminalPlan(mode, telemetry.TraceSubjectTarget, "", reasonNoTCPPort), true
		}
		p.destKey, p.destHost = CanonicalDest(evd.targetAddr)
		p.port = evd.targetPort
	case "http":
		// The monitored URL is the evidence; host and port are decoded from it
		// (explicit port, else scheme default) so both describe the failing dial.
		host, hport, err := hostPortFromURL(evd.targetAddr)
		if err != nil {
			return terminalPlan(mode, telemetry.TraceSubjectTarget, "", reasonBadURL), true
		}
		p.destKey, p.destHost = CanonicalDest(host)
		p.port = hport
	}
	return p, true
}

// planProxy diagnoses the egress a pinned monitor dialed.
//
// For socks5/http that is the proxy's own listener: the probe path is
// agent→proxy→target, the relay protocols cannot carry a hop-by-hop diagnostic
// through to the target, and a direct trace from the host would measure a path
// the probe never used. There is deliberately no direct-to-target control trace:
// it reads as "the real path" to anyone skimming the report, which is the exact
// misreading this whole feature exists to prevent.
//
// For wireguard the plan follows the failure's classification. When the tunnel
// carried the probe and the TARGET failed beyond it, the fault's own path is the
// in-tunnel one, and that is what gets traced: ICMP probes injected inside the
// tunnel toward the failing destination, pinned to the exact egress generation
// the round ran under. When the tunnel itself failed or was never attempted — or,
// degenerately, the in-tunnel destination cannot be derived — the peer's
// physical endpoint is traced over the host stack instead, with the subject
// reason saying which question that answers.
func planProxy(evd evidence) (plan, bool) {
	switch evd.proxyType {
	case pcfg.ProxyTypeWireGuard:
		if wgSubjectReason(evd.reasonCode) == telemetry.TraceSubjectTunnelTargetUnreachable {
			if host, ok := innerDest(evd); ok {
				// The subject is the target itself — the path scope is what marks the
				// hops as in-tunnel ones, so the subject vocabulary stays intact.
				p := plan{
					mode:               pcfg.TraceModeICMP,
					subjectKind:        telemetry.TraceSubjectTarget,
					subjectReason:      telemetry.TraceSubjectTunnelTargetUnreachable,
					pathScope:          telemetry.TracePathWireGuardInner,
					egressID:           evd.proxyID,
					egressConfigSerial: evd.proxyConfigSerial,
				}
				p.destKey, p.destHost = CanonicalDest(host)
				return p, true
			}
			// No derivable in-tunnel destination: fall through to the physical
			// endpoint trace — coarse, but honestly labelled as nearest evidence.
		}
		host, _, err := net.SplitHostPort(strings.TrimSpace(evd.proxyAddr))
		if err != nil {
			// A bare host is a legitimate endpoint spelling; only an empty one is
			// undiagnosable.
			host = strings.TrimSpace(evd.proxyAddr)
		}
		if host == "" {
			return terminalPlan(pcfg.TraceModeICMP, telemetry.TraceSubjectWGEndpoint, "", reasonProxyUnknown), true
		}
		// The peer endpoint is a UDP listener, so only its ICMP path is traceable —
		// a TCP trace to it would report a closed port on a perfectly healthy tunnel.
		p := plan{
			mode:          pcfg.TraceModeICMP,
			subjectKind:   telemetry.TraceSubjectWGEndpoint,
			subjectReason: wgSubjectReason(evd.reasonCode),
			pathScope:     telemetry.TracePathWireGuardPhysical,
		}
		p.destKey, p.destHost = CanonicalDest(host)
		return p, true
	case pcfg.ProxyTypeSOCKS5, pcfg.ProxyTypeHTTP:
		host, portStr, err := net.SplitHostPort(strings.TrimSpace(evd.proxyAddr))
		if err != nil {
			return terminalPlan(pcfg.TraceModeTCP, telemetry.TraceSubjectProxy, "", reasonProxyUnknown), true
		}
		port, perr := strconv.Atoi(portStr)
		if host == "" || perr != nil || port < 1 || port > 65535 {
			return terminalPlan(pcfg.TraceModeTCP, telemetry.TraceSubjectProxy, "", reasonProxyUnknown), true
		}
		p := plan{mode: pcfg.TraceModeTCP, subjectKind: telemetry.TraceSubjectProxy, port: port, pathScope: telemetry.TracePathDirect}
		p.destKey, p.destHost = CanonicalDest(host)
		return p, true
	}
	// A pin with no recognizable type — a spec the push never carried, or one this
	// build does not know. The fault is real but its path is unnameable, so say so
	// rather than falling back to a direct trace describing a path nothing took.
	return terminalPlan(pcfg.TraceModeTCP, telemetry.TraceSubjectProxy, "", reasonProxyUnknown), true
}

// wgSubjectReason reads the failure classification to say which question a
// WireGuard fault's trace answers.
//
// Codes 81-84 each describe a real attempt that did not get through the tunnel
// (unreachable peer, rejected credentials, a name the far side could not
// resolve, a refused relay), so the peer's reachability IS the fault. ProxyConfig
// (85) is deliberately NOT among them: it means the probe never dialed at all
// because the pinned proxy was absent, disabled, unusable or uninitializable, so
// no packet ever tested the tunnel and calling it unreachable would assert an
// outage nobody observed. Another classified cause means the tunnel carried the
// probe and the target failed beyond it — the fault's own path is the in-tunnel
// one.
//
// ProbeReasonNone on a FAILING round means the round carries no classification
// at all — a NAT monitor never produces one, and any probe can lose its
// error_class sample. No verdict may be asserted then: claiming the tunnel worked
// would be a fabrication in exactly the case where it is most likely the culprit.
func wgSubjectReason(reasonCode int) string {
	switch {
	case reasonCode >= telemetry.ProbeReasonProxyConnect && reasonCode <= telemetry.ProbeReasonProxyRefused:
		return telemetry.TraceSubjectTunnelUnreachable
	case reasonCode == telemetry.ProbeReasonProxyConfig:
		return telemetry.TraceSubjectTunnelNotAttempted
	case reasonCode == telemetry.ProbeReasonNone:
		return ""
	}
	return telemetry.TraceSubjectTunnelTargetUnreachable
}

// innerDest derives the in-tunnel destination for a tunnel_target_unreachable
// fault: the endpoint the probe dialed THROUGH the tunnel. It mirrors the
// per-kind subject selection of the direct planners — icmp/tcp dial the target,
// http its URL's host, dns its resolver, nat its STUN server — because that
// endpoint, not the monitor's nominal name, is where the failing packets went.
func innerDest(evd evidence) (string, bool) {
	switch evd.probeKind {
	case "icmp", "tcp":
		if evd.targetAddr == "" {
			return "", false
		}
		return evd.targetAddr, true
	case "http":
		host, _, err := hostPortFromURL(evd.targetAddr)
		if err != nil {
			return "", false
		}
		return host, true
	case "dns":
		addr := strings.TrimSpace(evd.resolverAddr)
		if addr == "" {
			return "", false
		}
		if evd.resolverProtocol == "doh" {
			host, _, err := hostPortFromURL(addr)
			if err != nil {
				return "", false
			}
			return host, true
		}
		host, _, err := splitHostPortDefault(addr, resolverDefaultPort(evd.resolverProtocol))
		if err != nil {
			return "", false
		}
		return host, true
	case "nat":
		addr := strings.TrimSpace(evd.stunAddr)
		if addr == "" {
			return "", false
		}
		host, _, err := splitHostPortDefault(addr, stunDefaultPort(evd.stunTransport))
		if err != nil {
			return "", false
		}
		return host, true
	}
	return "", false
}

// planResolver diagnoses the DNS server a failing lookup used, which answers the
// question the target's own name cannot: is the resolver unreachable, or
// reachable but not answering? The queried name is dialed by nobody, so it has
// no path to trace.
//
// The mode follows the resolver's protocol, because that is the port the probe's
// own traffic used: plain UDP has no TCP port worth probing (ICMP), DoT/DoH/TCP
// each have theirs.
//
// A conclusive rcode (NXDOMAIN/SERVFAIL) still traces the resolver. That is
// intentional: a clean path to a resolver that answers SERVFAIL is itself the
// finding — the network is fine and the DNS service is not.
func planResolver(evd evidence) (plan, bool) {
	addr := strings.TrimSpace(evd.resolverAddr)
	if addr == "" {
		// No resolver was named: a system-resolver monitor on a platform that
		// cannot report one. Guessing the host's current resolver could name a
		// server this query never used, so the diagnostic reports itself
		// unavailable instead.
		return terminalPlan(pcfg.TraceModeICMP, telemetry.TraceSubjectResolver, "", reasonResolverUnknown), true
	}

	var host string
	var port int
	switch evd.resolverProtocol {
	case "doh":
		var err error
		host, port, err = hostPortFromURL(addr)
		if err != nil {
			return terminalPlan(pcfg.TraceModeTCP, telemetry.TraceSubjectResolver, "", reasonBadURL), true
		}
	default:
		var err error
		host, port, err = splitHostPortDefault(addr, resolverDefaultPort(evd.resolverProtocol))
		if err != nil {
			return terminalPlan(pcfg.TraceModeICMP, telemetry.TraceSubjectResolver, "", reasonNoDestination), true
		}
	}

	// A local stub resolver (systemd-resolved's 127.0.0.53, a container sidecar)
	// has no path: every hop of it is inside this host. Tracing it would return
	// one meaningless hop and imply the network was examined when it was not —
	// the upstream the stub forwards to is invisible from here.
	if isLoopbackHost(host) {
		return terminalPlan(pcfg.TraceModeICMP, telemetry.TraceSubjectResolver, "", reasonResolverLoopback), true
	}

	mode := pcfg.TraceModeICMP
	if evd.resolverProtocol != "" && evd.resolverProtocol != "udp" {
		mode = pcfg.TraceModeTCP
	}
	p := plan{mode: mode, subjectKind: telemetry.TraceSubjectResolver, pathScope: telemetry.TracePathDirect}
	p.destKey, p.destHost = CanonicalDest(host)
	if mode == pcfg.TraceModeTCP {
		p.port = port
	}
	return p, true
}

// resolverDefaultPort is the port a resolver protocol uses when the probe did not
// record one. Mirrors the DNS collector's defaults.
func resolverDefaultPort(protocol string) int {
	if protocol == "dot" {
		return 853
	}
	return 53
}

// planSTUN diagnoses the STUN server a NAT probe exchanged with. Unlike DNS,
// that server IS the monitored target — but only the probe knows which port and
// transport it actually used, so the plan is built from the reported endpoint
// rather than from the configured target string.
func planSTUN(evd evidence) (plan, bool) {
	addr := strings.TrimSpace(evd.stunAddr)
	if addr == "" {
		return terminalPlan(pcfg.TraceModeICMP, telemetry.TraceSubjectSTUNServer, "", reasonNoSTUNServer), true
	}
	// UDP and DTLS are datagram transports with no connectable TCP port, so their
	// path is traced with ICMP; TCP/TLS trace to the port the probe connected to.
	mode := pcfg.TraceModeICMP
	switch evd.stunTransport {
	case "tcp", "tls":
		mode = pcfg.TraceModeTCP
	}
	host, port, err := splitHostPortDefault(addr, stunDefaultPort(evd.stunTransport))
	if err != nil {
		return terminalPlan(mode, telemetry.TraceSubjectSTUNServer, "", reasonNoDestination), true
	}
	p := plan{mode: mode, subjectKind: telemetry.TraceSubjectSTUNServer, pathScope: telemetry.TracePathDirect}
	p.destKey, p.destHost = CanonicalDest(host)
	if mode == pcfg.TraceModeTCP {
		p.port = port
	}
	return p, true
}

// stunDefaultPort mirrors the NAT collector's port defaults (RFC 5389/5928):
// 5349 for the TLS-wrapped transports, 3478 otherwise.
func stunDefaultPort(transport string) int {
	switch transport {
	case "tls", "dtls":
		return 5349
	}
	return 3478
}

// terminalPlan is a plan created in a terminal state that never sends a packet.
// The subject is still recorded: "no path diagnostic for the resolver" is a
// different statement from "no path diagnostic for the target", and the console
// renders the difference. The scope is direct — no probe will ever travel, so
// the honest claim is the zero one.
func terminalPlan(mode, subjectKind, subjectReason, reason string) plan {
	return plan{
		mode: mode, subjectKind: subjectKind, subjectReason: subjectReason,
		pathScope: telemetry.TracePathDirect,
		terminal:  telemetry.TraceStatusFailed, reason: reason,
	}
}

// tcpDenialReason classifies why the effective set lacks the TCP traceroute
// permission, using the same stable codes as the engine's own capabilityReason:
// granted by policy but absent from supported is a runtime capability gap — the
// raw socket TCP tracing needs is unavailable without Administrator privileges
// (raw_socket_unavailable); otherwise the policy never granted the mode.
func tcpDenialReason(granted, supported permission.Set) string {
	if granted.Has(permission.DiagnosticTracerouteTCP) && !supported.Has(permission.DiagnosticTracerouteTCP) {
		return reasonRawSocketUnavailable
	}
	return reasonPermissionDenied
}

// CanonicalDest returns the destination key and display host for a raw host/IP.
// An IP literal keys as "ip:<canonical-ip>"; anything else keys as
// "host:<lowercased-host>" — the hostname stands in until the trace resolves an
// address, which is the same rule the server files reports under.
//
// The agent computes it rather than leaving the server to re-derive it from a
// display string, because the key is what a later fault claims the report by:
// two parties normalizing independently is two chances to disagree about whether
// "Example.com" and "example.com" are one destination.
func CanonicalDest(host string) (destKey, destHost string) {
	host = strings.TrimSpace(host)
	if ip := net.ParseIP(host); ip != nil {
		c := ip.String()
		return "ip:" + c, c
	}
	lower := strings.ToLower(host)
	return "host:" + lower, lower
}

// splitHostPortDefault splits a "host:port" endpoint, accepting a bare host and
// supplying def for it. An empty host is an error — the caller must not trace a
// destination it cannot name.
func splitHostPortDefault(addr string, def int) (string, int, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		if addr == "" {
			return "", 0, errors.New("no host")
		}
		return addr, def, nil
	}
	if host == "" {
		return "", 0, errors.New("no host")
	}
	port, perr := strconv.Atoi(portStr)
	if perr != nil || port < 1 || port > 65535 {
		port = def
	}
	return host, port, nil
}

// isLoopbackHost reports whether a destination resolves to this host by
// definition — a loopback literal or the loopback name.
func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	return addr.IsLoopback()
}

// hostPortFromURL extracts the host and the correct TCP port from an HTTP
// monitor target: an explicit port when present, else 443 for https and 80 for
// http.
func hostPortFromURL(raw string) (string, int, error) {
	raw = strings.TrimSpace(raw)
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "", 0, errors.New("bad url")
	}
	host := u.Hostname()
	if host == "" {
		return "", 0, errors.New("no host")
	}
	if p := u.Port(); p != "" {
		n, perr := strconv.Atoi(p)
		if perr != nil || n < 1 || n > 65535 {
			return "", 0, errors.New("bad port")
		}
		return host, n, nil
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
		return host, 443, nil
	case "http":
		return host, 80, nil
	}
	return "", 0, errors.New("unsupported scheme")
}

// request turns a plan plus the policy bounds into the engine request.
func (p plan) request(reportID string, pol Policy, streak int, firstFailedAt time.Time) traceroute.Request {
	return traceroute.Request{
		ReportID: reportID,

		Mode:     p.mode,
		DestKey:  p.destKey,
		DestHost: p.destHost,
		Port:     p.port,

		SubjectKind:   p.subjectKind,
		SubjectReason: p.subjectReason,

		FallbackFrom:   p.fallbackFrom,
		FallbackReason: p.fallbackReason,

		TriggerReason: telemetry.TraceTriggerConsecutiveFailures,
		TriggerStreak: streak,
		FirstFailedAt: firstFailedAt,

		MaxHops:         pol.MaxHops,
		AttemptsPerHop:  pol.Attempts,
		TotalTimeoutMs:  pol.BudgetMs,
		PerHopTimeoutMs: pol.PerHopTimeoutMs,

		EgressProxyID:      p.egressID,
		EgressConfigSerial: p.egressConfigSerial,
	}
}

// terminalResult is the report a plan that can never run still produces. It is
// emitted rather than dropped because "this fault has no diagnosable path" is a
// finding — silence would be indistinguishable from a trigger that never fired.
func (p plan) terminalResult(reportID string, pol Policy, streak int, firstFailedAt, now time.Time) telemetry.TraceResult {
	return telemetry.TraceResult{
		ReportID: reportID,
		Mode:     p.mode,

		DestKey:  p.destKey,
		DestHost: p.destHost,
		Port:     p.port,

		SubjectKind:   p.subjectKind,
		SubjectReason: p.subjectReason,
		PathScope:     p.pathScope,

		FallbackFrom:   p.fallbackFrom,
		FallbackReason: p.fallbackReason,

		TriggerReason: telemetry.TraceTriggerConsecutiveFailures,
		TriggerStreak: streak,
		FirstFailedAt: firstFailedAt,

		MaxHops:        pol.MaxHops,
		AttemptsPerHop: pol.Attempts,

		Status:      p.terminal,
		Reason:      p.reason,
		StartedAt:   now,
		CompletedAt: now,
	}
}
