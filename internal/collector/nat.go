package collector

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pion/dtls/v3"
	"github.com/pion/stun/v3"

	"github.com/nettact/agent/internal/netguard"
	"github.com/nettact/agent/internal/proxydial"
	pcfg "github.com/nettact/protocol/config"
	"github.com/nettact/protocol/telemetry"
)

// NATCollector discovers the NAT type in front of the agent using STUN behavior
// discovery (RFC 5780 / RFC 4787) against a server-configured STUN server. It is
// a self-scheduling collector (like tcp.go): each target runs on its own
// interval via schedState, with a long fallback because a full discovery is
// several round-trips and only interesting occasionally.
//
// Transports (nat_transport param): udp does the full discovery — binding test,
// mapping behavior, filtering behavior, and the classic NAT-type classification.
// tcp/tls/dtls do the binding test only (reachability + the reflexive public
// address): mapping and filtering are only well-defined and reliably measurable
// over UDP, so they are not emitted for the connection/session transports.
type NATCollector struct {
	sched   *schedState
	guard   *netguard.Guard
	proxies *proxydial.Manager

	mu         sync.Mutex
	lastMapped map[string]string // target -> last reflexive addr, so we only event on change
}

func NewNATCollector(guard *netguard.Guard, proxies *proxydial.Manager) *NATCollector {
	// 30-min fallback: NAT type changes rarely and a full run is multi-RTT, so we
	// avoid probing every self-tick when a target sets no interval_seconds.
	return &NATCollector{guard: guard, proxies: proxies, sched: newSchedState(pcfg.DefaultNATInterval), lastMapped: map[string]string{}}
}

// SetTargets replaces the NAT target list from a DesiredState update.
func (c *NATCollector) SetTargets(targets []pcfg.ProbeTarget) {
	var nat []pcfg.ProbeTarget
	for _, t := range targets {
		if t.Kind == "nat" && t.Target != "" {
			nat = append(nat, t)
		}
	}
	c.sched.set(nat)
}

func (c *NATCollector) Name() string { return "nat" }

func (c *NATCollector) Tier() Tier { return TierRegular }

func (c *NATCollector) Collect(ctx context.Context) (Result, error) {
	targets := c.sched.due(time.Now())
	if len(targets) == 0 {
		return Result{}, nil
	}
	now := time.Now().UTC()
	var res Result
	for _, t := range targets {
		// A pass aborted by run cancellation (agent shutdown) must not fabricate
		// binding failures — they would replay from the WAL as a false WAN outage
		// on the next start (probeNAT drops its own aborted results too).
		if ctx.Err() != nil {
			break
		}
		c.probeNAT(ctx, now, t, &res)
	}
	return res, nil
}

// Behavior codes (mirrored into telemetry so a higher code is a "worse" NAT and a
// rule can fire with gte). Kept in sync with protocol/telemetry/metric.go.
const (
	natUnknown                 = 0
	natEndpointIndependent     = 1
	natAddressDependent        = 2
	natAddressAndPortDependent = 3
)

// NAT-type codes (kept in sync with protocol/telemetry/metric.go).
const (
	natTypeUnknown            = 0
	natTypeOpen               = 1
	natTypeFullCone           = 2
	natTypeRestrictedCone     = 3
	natTypePortRestrictedCone = 4
	natTypeSymmetric          = 5
)

const (
	defaultSTUNPort  = 3478 // STUN over UDP/TCP
	defaultSTUNSPort = 5349 // STUN over TLS/DTLS (RFC 7350)
)

// stunDefaultPort is the IANA-registered default port for the given transport.
func stunDefaultPort(transport string) int {
	if transport == "tls" || transport == "dtls" {
		return defaultSTUNSPort
	}
	return defaultSTUNPort
}

var errTimeout = errors.New("stun: no response")

// probeNAT runs one target and appends its metrics/events to res.
func (c *NATCollector) probeNAT(ctx context.Context, now time.Time, t pcfg.ProbeTarget, res *Result) {
	transport := t.Params.NATTransport
	if transport == "" {
		transport = "udp"
	}
	server := stunHostPort(t.Target, t.Params.Port, stunDefaultPort(transport))

	perReq := time.Duration(t.Params.TimeoutMs) * time.Millisecond
	if perReq <= 0 {
		perReq = pcfg.DefaultNATPerRequestTimeout
	}
	global := time.Duration(t.Params.GlobalTimeoutMs) * time.Millisecond
	if global <= 0 {
		global = pcfg.DefaultNATCycleDeadline // room for filtering + mapping with a couple of retries
	}
	rctx, cancel := context.WithTimeout(ctx, global)
	defer cancel()

	base := map[string]string{"transport": transport, "server": server}

	// Resolve the pinned egress proxy. A pin that cannot be honored means no probe:
	// discovering the NAT in front of the HOST when the operator asked about the path
	// through a tunnel would be an answer to a different question.
	//
	// This kind has no error_class metric (a NAT result is categorical, not a
	// failure taxonomy), so the failure is reported through emitBinding's ok=0 +
	// probe-failed event, with the proxy cause in the message.
	proxy, prerr := resolveProxy(ctx, c.proxies, t)
	if prerr != nil {
		c.emitBinding(ctx, now, t, res, base, "", 0, prerr)
		return
	}

	if transport != "udp" {
		// tcp/tls/dtls: binding test only.
		reflexive, rtt, err := streamBinding(rctx, c.guard, proxy, transport, server, t.Params.IgnoreTLS, perReq)
		c.emitBinding(ctx, now, t, res, base, reflexive, rtt, err)
		return
	}

	// UDP: full RFC 5780 discovery over one unconnected socket so every round trip
	// leaves from the same local port (required for mapping/filtering). A proxied
	// target opens that socket through the proxy — a SOCKS5 UDP association or a
	// tunnel's netstack socket, both of which preserve the one-port property.
	var rt *udpRoundTripper
	var err error
	if proxy != nil {
		rt, err = newProxyUDPRoundTripper(proxy, c.guard)
	} else {
		rt, err = newUDPRoundTripper(c.guard)
	}
	if err != nil {
		c.emitBinding(ctx, now, t, res, base, "", 0, err)
		return
	}
	defer rt.close()

	// Test I: plain binding to the primary server.
	t0 := time.Now()
	resp, _, err := rt.do(rctx, server, perReq, 0)
	if err != nil {
		// emitBinding routes a *netguard.BlockedError to res.Blocked (no metric).
		c.emitBinding(ctx, now, t, res, base, "", 0, err)
		return
	}
	rtt := float64(time.Since(t0).Microseconds()) / 1000.0

	var xor stun.XORMappedAddress
	if xor.GetFrom(resp) != nil {
		c.emitBinding(ctx, now, t, res, base, "", rtt, errors.New("no XOR-MAPPED-ADDRESS in response"))
		return
	}
	reflexive := net.JoinHostPort(xor.IP.String(), strconv.Itoa(xor.Port))

	var other stun.OtherAddress
	hasOther := other.GetFrom(resp) == nil

	// Filtering behavior + classic NAT type require an RFC 5780 server that returns
	// OTHER-ADDRESS (so it can answer from an alternate IP/port). Without it the
	// filtering probes would just time out and be misread as "blocked", so we skip
	// them and report unknown rather than misleading data.
	if !hasOther {
		mapping, merr := mappingBehavior(rctx, rt, server, xor, other, hasOther, t.Params.STUNServer2, perReq)
		if be := asBlockedProbe(t, merr); be != nil {
			// A denied second STUN server is a target-policy block for the monitor;
			// emit no synthetic NAT metric, route it to the status tracker.
			res.Blocked = append(res.Blocked, *be)
			return
		}
		if ctx.Err() != nil {
			return // discovery aborted by the cancelled run: not an "unknown" verdict
		}
		c.emitBinding(ctx, now, t, res, base, reflexive, rtt, nil)
		res.Metrics = append(res.Metrics, natMetric(now, t, telemetry.NATMapping, mapping,
			map[string]string{"transport": transport, "behavior": mappingLabel(mapping)}))
		res.Events = append(res.Events, telemetry.Event{
			ID: newID(), TS: now, Type: telemetry.EventProbeFailed, Layer: telemetry.LayerWAN,
			Severity: telemetry.SeverityInfo,
			Message:  "NAT discovery inconclusive: STUN server " + server + " lacks OTHER-ADDRESS (RFC 5780)",
			Attrs:    base,
		})
		res.Metrics = append(res.Metrics, natMetric(now, t, telemetry.NATType, natTypeUnknown,
			map[string]string{"transport": transport, "type": natTypeLabel(natTypeUnknown)}))
		return
	}

	// Filtering runs FIRST, before the mapping tests contact the server's alternate
	// address. A NAT that filters at the WAN-IP level (opening an external peer for
	// the whole public IP once any internal socket has sent to it, rather than
	// per-mapping) would otherwise already have the alternate address opened by the
	// mapping probes, and the filtering reply would arrive and read as a false
	// endpoint-independent (full cone). At this point only the primary server has
	// been contacted (by the binding test), so the filtering test is uncontaminated.
	filtering, ferr := filteringBehavior(rctx, c.guard, proxy, server, perReq)
	if be := asBlockedProbe(t, ferr); be != nil {
		res.Blocked = append(res.Blocked, *be)
		return
	}

	// A Test II/III reply can be lost or rate-limited on flaky STUN servers, which
	// would report a transient "unknown". Since the server did return OTHER-ADDRESS,
	// a real answer exists — retry a couple of times, spaced out to dodge rate limits,
	// before accepting unknown.
	mapping, merr := mappingBehavior(rctx, rt, server, xor, other, hasOther, t.Params.STUNServer2, perReq)
	for attempt := 0; mapping == natUnknown && merr == nil && attempt < 2 && rctx.Err() == nil; attempt++ {
		select {
		case <-rctx.Done():
		case <-time.After(400 * time.Millisecond):
		}
		mapping, merr = mappingBehavior(rctx, rt, server, xor, other, hasOther, t.Params.STUNServer2, perReq)
	}
	if be := asBlockedProbe(t, merr); be != nil {
		res.Blocked = append(res.Blocked, *be)
		return
	}

	if ctx.Err() != nil {
		return // discovery aborted by the cancelled run: not an "unknown" verdict
	}
	// No block anywhere in the discovery: emit the binding + behavior metrics.
	c.emitBinding(ctx, now, t, res, base, reflexive, rtt, nil)
	res.Metrics = append(res.Metrics, natMetric(now, t, telemetry.NATMapping, mapping,
		map[string]string{"transport": transport, "behavior": mappingLabel(mapping)}))
	res.Metrics = append(res.Metrics, natMetric(now, t, telemetry.NATFiltering, filtering,
		map[string]string{"transport": transport, "behavior": mappingLabel(filtering)}))

	natType := classify(reflexive, mapping, filtering, tunnelLocalAddrs(proxy))
	res.Metrics = append(res.Metrics, natMetric(now, t, telemetry.NATType, natType,
		map[string]string{"transport": transport, "type": natTypeLabel(natType)}))
}

// asBlockedProbe converts a policy-block error from a NAT sub-probe into a
// BlockedProbe for the monitor (carrying the target's generation), or nil for any
// non-block error.
func asBlockedProbe(t pcfg.ProbeTarget, err error) *BlockedProbe {
	var be *netguard.BlockedError
	if errors.As(err, &be) {
		bp := blockedFromErr(t, be)
		return &bp
	}
	return nil
}

// emitBinding appends the ok/rtt metrics and, on failure, a probe-failed event.
// On success it emits a WAN-IP-changed event only when the reflexive/mapped public
// address differs from the last one seen for this target — the metrics store does
// not persist sample labels, so this event is how the mapped address surfaces, and
// gating on change keeps it from spamming the timeline every run.
func (c *NATCollector) emitBinding(ctx context.Context, now time.Time, t pcfg.ProbeTarget, res *Result, base map[string]string, reflexive string, rtt float64, err error) {
	if err != nil {
		// A policy block on the STUN server is a target-policy block, not a binding
		// failure: emit no metric/event, route it to the monitor-status tracker.
		var be *netguard.BlockedError
		if errors.As(err, &be) {
			res.Blocked = append(res.Blocked, blockedFromErr(t, be))
			return
		}
		if ctx.Err() != nil {
			return // the exchange was aborted by the cancelled run, not the NAT
		}
		res.Metrics = append(res.Metrics, telemetry.Metric{
			TS: now, Kind: telemetry.NATOK, Target: t.Target, Layer: telemetry.LayerWAN,
			Value: 0, Unit: telemetry.UnitBool, Labels: base, MonitorID: t.MonitorID, ConfigSerial: t.ConfigSerial,
		})
		res.Events = append(res.Events, telemetry.Event{
			ID: newID(), TS: now, Type: telemetry.EventProbeFailed, Layer: telemetry.LayerWAN,
			Severity: telemetry.SeverityWarn,
			Message:  "NAT binding failed (" + base["transport"] + ") " + base["server"] + ": " + err.Error(),
			Attrs:    base,
		})
		return
	}
	okLabels := map[string]string{"transport": base["transport"], "server": base["server"], "mapped_addr": reflexive}
	res.Metrics = append(res.Metrics,
		telemetry.Metric{TS: now, Kind: telemetry.NATOK, Target: t.Target, Layer: telemetry.LayerWAN,
			Value: 1, Unit: telemetry.UnitBool, Labels: okLabels, MonitorID: t.MonitorID, ConfigSerial: t.ConfigSerial})
	if rtt > 0 {
		res.Metrics = append(res.Metrics,
			telemetry.Metric{TS: now, Kind: telemetry.NATRTTms, Target: t.Target, Layer: telemetry.LayerWAN,
				Value: rtt, Unit: telemetry.UnitMs, Labels: base, MonitorID: t.MonitorID, ConfigSerial: t.ConfigSerial})
	}

	// The change-gate is per monitor: two monitors probing the same server must
	// each track their own last mapped address.
	key := t.MonitorID + "|" + base["transport"] + "|" + t.Target
	c.mu.Lock()
	changed := c.lastMapped[key] != reflexive
	c.lastMapped[key] = reflexive
	c.mu.Unlock()
	if changed && reflexive != "" {
		res.Events = append(res.Events, telemetry.Event{
			ID: newID(), TS: now, Type: telemetry.EventWANIPChanged, Layer: telemetry.LayerWAN,
			Severity: telemetry.SeverityInfo,
			Message:  "NAT mapped address " + reflexive + " (" + base["transport"] + ")",
			Attrs:    okLabels,
		})
	}
}

func natMetric(now time.Time, t pcfg.ProbeTarget, kind telemetry.MetricKind, code int, labels map[string]string) telemetry.Metric {
	return telemetry.Metric{
		TS: now, Kind: kind, Target: t.Target, Layer: telemetry.LayerWAN,
		Value: float64(code), Unit: telemetry.UnitCode, Labels: labels, MonitorID: t.MonitorID, ConfigSerial: t.ConfigSerial,
	}
}

// mappingBehavior implements RFC 5780 §4.3. Test I is already done (its response
// gives xor + other). Test II sends to the OTHER-ADDRESS IP but the primary port;
// Test III sends to the full OTHER-ADDRESS. When the server returns no
// OTHER-ADDRESS but a second STUN server is configured, a coarse fallback compares
// the reflexive address against that server (endpoint-independent vs "hard").
//
// It returns the behavior code plus a non-nil error only when a destination
// (second STUN server, or a server-supplied OTHER-ADDRESS) is denied by policy —
// that block must be reported as a target block, never collapsed into a synthetic
// natUnknown metric. Ordinary timeouts/losses stay natUnknown with a nil error.
func mappingBehavior(ctx context.Context, rt *udpRoundTripper, primary string, xor stun.XORMappedAddress, other stun.OtherAddress, hasOther bool, server2 string, timeout time.Duration) (int, error) {
	if !hasOther {
		if server2 == "" {
			return natUnknown, nil
		}
		resp, _, err := rt.do(ctx, stunHostPort(server2, 0, defaultSTUNPort), timeout, 0)
		if err != nil {
			return natUnknown, asBlock(err)
		}
		var x2 stun.XORMappedAddress
		if x2.GetFrom(resp) != nil {
			return natUnknown, nil
		}
		if x2.IP.Equal(xor.IP) && x2.Port == xor.Port {
			return natEndpointIndependent, nil
		}
		// Different reflexive address from a different server: not endpoint
		// independent. Without OTHER-ADDRESS we cannot separate address- from
		// address-and-port-dependent, so report the conservative "hardest" value.
		return natAddressAndPortDependent, nil
	}

	_, primaryPort, _ := net.SplitHostPort(primary)
	pport, _ := strconv.Atoi(primaryPort)

	// Test II: other IP, primary port. If its reflexive matches Test I the mapping
	// is endpoint-independent. Test III's classification is defined relative to Test
	// II's reflexive (RFC 5780 §4.3), so if Test II is lost or carries no
	// XOR-MAPPED-ADDRESS we have no valid baseline and must report unknown rather than
	// derive a result from the wrong address.
	testII := net.JoinHostPort(other.IP.String(), strconv.Itoa(pport))
	resp, _, err := rt.do(ctx, testII, timeout, 0)
	if err != nil {
		return natUnknown, asBlock(err)
	}
	var x2 stun.XORMappedAddress
	if x2.GetFrom(resp) != nil {
		return natUnknown, nil
	}
	if x2.IP.Equal(xor.IP) && x2.Port == xor.Port {
		return natEndpointIndependent, nil
	}

	// Test III: other IP, other port. Compared against Test II's reflexive: equal
	// means the mapping depends only on the destination address → address-dependent;
	// different means it also depends on the port.
	resp, _, err = rt.do(ctx, testIII(other), timeout, 0)
	if err != nil {
		return natUnknown, asBlock(err)
	}
	var x3 stun.XORMappedAddress
	if x3.GetFrom(resp) != nil {
		return natUnknown, nil
	}
	if x3.IP.Equal(x2.IP) && x3.Port == x2.Port {
		return natAddressDependent, nil
	}
	return natAddressAndPortDependent, nil
}

// asBlock returns err when it carries a *netguard.BlockedError (a policy block to
// be reported as a target block), or nil for any other error (an ordinary
// timeout/loss that stays a natUnknown result).
func asBlock(err error) error {
	var be *netguard.BlockedError
	if errors.As(err, &be) {
		return err
	}
	return nil
}

// testIII builds the Test III destination (other IP + other port).
func testIII(other stun.OtherAddress) string {
	return net.JoinHostPort(other.IP.String(), strconv.Itoa(other.Port))
}

// filteringBehavior implements RFC 5780 §4.4 (UDP only). Test II asks the server to
// answer from a changed IP and port (CHANGE-REQUEST 0x06); a reply means the NAT
// lets in packets from any endpoint. Test III asks for a changed port only (0x02).
//
// It runs on a FRESH socket that has only ever sent to the primary server. The
// mapping tests probe the server's alternate address, which opens NAT pinholes for
// that address; reusing that socket would let a change-request reply from the
// alternate address pass and be misread as endpoint-independent filtering (false
// full-cone). Each reply is also checked to have genuinely come from a changed
// source, so a server that ignores CHANGE-REQUEST and answers from its primary
// address is not counted as a pass.
// The socket is deliberately FRESH (not the mapping round tripper's) so the
// filtering probes leave from a port that has not yet contacted the alternate
// address — but it must still leave through the PINNED egress. Opening a host-stack
// socket here would both leak direct STUN traffic despite the pin and combine the
// host's filtering behaviour with the proxy egress's mapping behaviour, producing a
// NATFiltering and derived NATType that describe no single path.
func filteringBehavior(ctx context.Context, guard *netguard.Guard, proxy *proxydial.Dialer, primary string, timeout time.Duration) (int, error) {
	var rt *udpRoundTripper
	var err error
	if proxy != nil {
		rt, err = newProxyUDPRoundTripper(proxy, guard)
	} else {
		rt, err = newUDPRoundTripper(guard)
	}
	if err != nil {
		return natUnknown, nil
	}
	defer rt.close()

	// Vet+pin the primary to a concrete address once and send to that exact address
	// (not the hostname). Otherwise a round-robin DNS name (many public STUN servers
	// have several A records) could be re-resolved to a different IP inside do(), so
	// a reply from the address we actually contacted would compare unequal to `pa`
	// and be misread as a changed source → false endpoint-independent. Using the
	// guard keeps the host:/deny semantics and IP pinning consistent.
	pa, err := guard.VetUDPAddr(ctx, primary)
	if err != nil {
		return natUnknown, asBlock(err)
	}

	if _, from, err := rt.doAddr(ctx, pa, timeout, 0x06); err == nil && sourceChanged(from, pa, true) {
		return natEndpointIndependent, nil
	} else if be := asBlock(err); be != nil {
		return natUnknown, be
	}
	if _, from, err := rt.doAddr(ctx, pa, timeout, 0x02); err == nil && sourceChanged(from, pa, false) {
		return natAddressDependent, nil
	} else if be := asBlock(err); be != nil {
		return natUnknown, be
	}
	return natAddressAndPortDependent, nil
}

// sourceChanged reports whether a change-request reply actually came from a changed
// server source: change-IP-and-port must arrive from a different IP; change-port-only
// must arrive from the same IP but a different port.
func sourceChanged(from net.Addr, primary *net.UDPAddr, ipChanged bool) bool {
	ua, ok := from.(*net.UDPAddr)
	if !ok {
		return false
	}
	if ipChanged {
		return !ua.IP.Equal(primary.IP)
	}
	return ua.IP.Equal(primary.IP) && ua.Port != primary.Port
}

// classify maps mapping + filtering behavior to a classic NAT type (RFC 3489).
//
// extraLocal carries addresses that are ours but are not OS interfaces — the
// in-tunnel addresses of a userspace WireGuard proxy. Without them a tunnelled probe
// whose reflexive address IS its tunnel address (no NAT on the tunnelled path) would
// be misreported as full-cone or another mapped type, because isLocalIP only sees
// net.InterfaceAddrs and a netstack address appears on no OS interface.
func classify(reflexive string, mapping, filtering int, extraLocal []netip.Addr) int {
	if host, _, err := net.SplitHostPort(reflexive); err == nil {
		if ip := net.ParseIP(host); ip != nil && (isLocalIP(ip) || matchesAddr(ip, extraLocal)) {
			return natTypeOpen // reflexive address is our own → no NAT
		}
	}
	switch {
	case mapping == natEndpointIndependent && filtering == natEndpointIndependent:
		return natTypeFullCone
	case mapping == natEndpointIndependent && filtering == natAddressDependent:
		return natTypeRestrictedCone
	case mapping == natEndpointIndependent && filtering == natAddressAndPortDependent:
		return natTypePortRestrictedCone
	case mapping >= natAddressDependent:
		return natTypeSymmetric
	default:
		return natTypeUnknown
	}
}

// matchesAddr reports whether ip is one of addrs.
func matchesAddr(ip net.IP, addrs []netip.Addr) bool {
	a, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	a = a.Unmap()
	for _, want := range addrs {
		if want.Unmap() == a {
			return true
		}
	}
	return false
}

// tunnelLocalAddrs returns a proxy's in-tunnel addresses, which are ours but belong
// to no OS interface. Empty for the relay transports, whose reflexive address is the
// relay's mapping and never one of ours.
func tunnelLocalAddrs(proxy *proxydial.Dialer) []netip.Addr {
	if proxy == nil || proxy.Spec.Type != pcfg.ProxyTypeWireGuard {
		return nil
	}
	var out []netip.Addr
	for _, part := range strings.Split(proxy.Spec.WGLocalAddrs, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if pfx, err := netip.ParsePrefix(part); err == nil {
			out = append(out, pfx.Addr().Unmap())
			continue
		}
		if a, err := netip.ParseAddr(part); err == nil {
			out = append(out, a.Unmap())
		}
	}
	return out
}

func isLocalIP(ip net.IP) bool {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok && n.IP.Equal(ip) {
			return true
		}
	}
	return false
}

// ---- UDP round tripper ----

// udpRoundTripper owns one unconnected UDP socket. do() sends a binding request to
// an arbitrary destination and returns the matching response, so mapping/filtering
// tests all leave from the same local port.
// conn is a net.PacketConn rather than a *net.UDPConn so the same RFC 5780
// discovery runs unchanged over the host stack and over a WireGuard tunnel's
// netstack socket. Both are unconnected sockets that send from ONE local port,
// which is what makes the mapping and filtering tests meaningful at all.
type udpRoundTripper struct {
	conn  net.PacketConn
	guard *netguard.Guard
}

func newUDPRoundTripper(guard *netguard.Guard) (*udpRoundTripper, error) {
	// Dual-stack socket so a STUN server (or its OTHER-ADDRESS) that vets to an
	// IPv6 address is reachable; net.IP.Equal in sourceChanged treats the v4/v4-in-v6
	// forms as equal, so the filtering comparison is unaffected.
	conn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, err
	}
	return &udpRoundTripper{conn: conn, guard: guard}, nil
}

// newProxyUDPRoundTripper opens the discovery socket through a proxy that can carry
// datagrams: a SOCKS5 UDP association, or a WireGuard tunnel's netstack socket. Both
// give one unconnected socket that can address several destinations, which is what the
// mapping and filtering tests require. HTTP CONNECT cannot, which is why the capability
// matrix refuses NAT-over-udp for it.
//
// A caveat worth knowing when reading the result: through a proxy this measures the
// NAT in front of the PROXY's egress, not the agent's. That is the honest answer for
// the configured path — the same is true of a tunnel — but it is a different question
// than "what NAT is in front of this agent".
func newProxyUDPRoundTripper(d *proxydial.Dialer, guard *netguard.Guard) (*udpRoundTripper, error) {
	conn, err := d.ListenPacket()
	if err != nil {
		return nil, err
	}
	return &udpRoundTripper{conn: conn, guard: guard}, nil
}

func (u *udpRoundTripper) close() { _ = u.conn.Close() }

// do vets the destination (host or literal IP, IPv4/IPv6) through the guard —
// applying CheckHost/vetted-resolution/deny-precedence and pinning the returned
// address — then sends the binding request. A denied destination is returned as a
// *netguard.BlockedError and no datagram is sent.
func (u *udpRoundTripper) do(ctx context.Context, addr string, timeout time.Duration, changeReq byte) (*stun.Message, net.Addr, error) {
	dst, err := u.guard.VetUDPAddr(ctx, addr)
	if err != nil {
		return nil, nil, err
	}
	return u.doAddr(ctx, dst, timeout, changeReq)
}

// doAddr sends a binding request to an already-vetted destination. When changeReq
// is non-zero, a CHANGE-REQUEST attribute with that flag byte is added (0x06
// change IP+port, 0x02 change port). It returns the first response carrying the
// request's transaction ID. The destination must already have passed the guard
// (via do or VetUDPAddr) so the vetted address stays pinned to the send.
func (u *udpRoundTripper) doAddr(ctx context.Context, dst *net.UDPAddr, timeout time.Duration, changeReq byte) (*stun.Message, net.Addr, error) {
	req := stun.MustBuild(stun.TransactionID, stun.BindingRequest)
	if changeReq != 0 {
		req.Add(stun.AttrChangeRequest, []byte{0x00, 0x00, 0x00, changeReq})
	}

	overall := time.Now().Add(timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(overall) {
		overall = d
	}
	// Retransmit the same request (same transaction ID) on loss, STUN-style, until
	// the overall deadline: a single dropped datagram must not be misread as
	// "no response" and yield a false unknown/inconclusive result.
	perAttempt := timeout / 3
	if perAttempt < 500*time.Millisecond {
		perAttempt = 500 * time.Millisecond
	}
	buf := make([]byte, 1500)
	for {
		if _, err := u.conn.WriteTo(req.Raw, dst); err != nil {
			return nil, nil, err
		}
		readUntil := time.Now().Add(perAttempt)
		if readUntil.After(overall) {
			readUntil = overall
		}
		_ = u.conn.SetReadDeadline(readUntil)
		for {
			n, from, err := u.conn.ReadFrom(buf)
			if err != nil {
				break // this attempt's window elapsed — retransmit if budget remains
			}
			resp := &stun.Message{Raw: append([]byte(nil), buf[:n]...)}
			if resp.Decode() != nil {
				continue
			}
			if resp.TransactionID == req.TransactionID {
				return resp, from, nil
			}
		}
		if !time.Now().Before(overall) {
			return nil, nil, errTimeout
		}
	}
}

// ---- connection/session binding (tcp/tls/dtls) ----

// streamBinding performs a single STUN binding exchange over a connected transport
// and returns the reflexive (mapped) address and round-trip latency (ms).
func streamBinding(ctx context.Context, guard *netguard.Guard, proxy *proxydial.Dialer, transport, server string, ignoreTLS bool, timeout time.Duration) (string, float64, error) {
	deadline := time.Now().Add(timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}

	conn, datagram, err := dialSTUN(ctx, guard, proxy, transport, server, ignoreTLS, timeout)
	if err != nil {
		return "", 0, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(deadline)

	req := stun.MustBuild(stun.TransactionID, stun.BindingRequest)
	t0 := time.Now()
	if _, err := conn.Write(req.Raw); err != nil {
		return "", 0, err
	}
	resp, err := readSTUN(conn, datagram)
	if err != nil {
		return "", 0, err
	}
	rtt := float64(time.Since(t0).Microseconds()) / 1000.0

	var xor stun.XORMappedAddress
	if xor.GetFrom(resp) != nil {
		return "", rtt, errors.New("no XOR-MAPPED-ADDRESS in response")
	}
	return net.JoinHostPort(xor.IP.String(), strconv.Itoa(xor.Port)), rtt, nil
}

// dialSTUN opens a connection for the tcp/tls/dtls transports. datagram is true for
// dtls (one Read returns a whole record) so readSTUN uses datagram framing.
//
// A non-nil proxy routes the TCP-framed transports through the tunnel/relay. dtls is
// datagram-based, so proxied it arrives over a SOCKS5 UDP association or a WireGuard
// tunnel; the capability matrix refuses it for HTTP, whose only command is CONNECT.
func dialSTUN(ctx context.Context, guard *netguard.Guard, proxy *proxydial.Dialer, transport, server string, ignoreTLS bool, timeout time.Duration) (conn net.Conn, datagram bool, err error) {
	host, _, _ := net.SplitHostPort(server)
	// proxyDialFunc keeps the guard's address check alive through the proxy: in local
	// DNS mode the STUN endpoint is resolved and vetted here and the proxy is handed
	// the approved literal, instead of a hostname it would resolve unseen.
	dial := proxyDialFunc(guard, proxy)
	switch transport {
	case "tcp":
		c, err := dial(ctx, "tcp", server)
		return c, false, err
	case "tls":
		raw, err := dial(ctx, "tcp", server)
		if err != nil {
			return nil, false, err
		}
		tc := tls.Client(raw, &tls.Config{ServerName: host, InsecureSkipVerify: ignoreTLS}) //nolint:gosec // opt-in via ignore_tls
		if err := tc.HandshakeContext(ctx); err != nil {
			_ = raw.Close()
			return nil, false, err
		}
		return tc, false, nil
	case "dtls":
		// Vet+pin the DTLS destination through the guard (host:/deny semantics, IPv6,
		// resolved-address privacy) before opening the socket.
		raddr, err := guard.VetUDPAddr(ctx, server)
		if err != nil {
			return nil, true, err
		}
		// dtls.Client returns immediately without handshaking (the handshake would
		// otherwise run lazily on first I/O under context.Background(), unbounded by
		// any deadline). Own the UDP socket and drive a cancellable HandshakeContext
		// so a timeout actually aborts the handshake and releases the socket — no
		// leaked goroutine or connection on an unresponsive endpoint.
		// A tunnelled DTLS binding must send its datagrams inside the tunnel, so the
		// socket comes from the tunnel's stack rather than the host's.
		var pconn net.PacketConn
		if proxy != nil {
			pconn, err = proxy.ListenPacket()
		} else {
			pconn, err = net.ListenUDP("udp", nil)
		}
		if err != nil {
			return nil, true, err
		}
		dc, err := dtls.Client(pconn, raddr, &dtls.Config{InsecureSkipVerify: true}) //nolint:gosec // STUN over DTLS to a config-supplied server
		if err != nil {
			_ = pconn.Close()
			return nil, true, err
		}
		hctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		if err := dc.HandshakeContext(hctx); err != nil {
			_ = dc.Close() // closes pconn
			return nil, true, err
		}
		return dc, true, nil
	default:
		return nil, false, errors.New("unsupported nat transport: " + transport)
	}
}

// readSTUN reads one STUN message. For stream transports it frames on the 20-byte
// header length; for datagram transports (dtls) it reads a whole record at once.
func readSTUN(r io.Reader, datagram bool) (*stun.Message, error) {
	if datagram {
		buf := make([]byte, 1500)
		n, err := r.Read(buf)
		if err != nil {
			return nil, err
		}
		m := &stun.Message{Raw: append([]byte(nil), buf[:n]...)}
		if err := m.Decode(); err != nil {
			return nil, err
		}
		return m, nil
	}
	header := make([]byte, 20)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, err
	}
	msgLen := int(binary.BigEndian.Uint16(header[2:4]))
	raw := make([]byte, 20+msgLen)
	copy(raw, header)
	if _, err := io.ReadFull(r, raw[20:]); err != nil {
		return nil, err
	}
	m := &stun.Message{Raw: raw}
	if err := m.Decode(); err != nil {
		return nil, err
	}
	return m, nil
}

// stunHostPort returns host:port for a STUN target, applying the port param (or def,
// the transport's default STUN port) when the target has no port of its own.
func stunHostPort(target string, port, def int) string {
	if _, _, err := net.SplitHostPort(target); err == nil {
		return target
	}
	if port <= 0 {
		port = def
	}
	return net.JoinHostPort(target, strconv.Itoa(port))
}

func mappingLabel(code int) string {
	switch code {
	case natEndpointIndependent:
		return "endpoint-independent"
	case natAddressDependent:
		return "address-dependent"
	case natAddressAndPortDependent:
		return "address-and-port-dependent"
	default:
		return "unknown"
	}
}

func natTypeLabel(code int) string {
	switch code {
	case natTypeOpen:
		return "open"
	case natTypeFullCone:
		return "full-cone"
	case natTypeRestrictedCone:
		return "restricted-cone"
	case natTypePortRestrictedCone:
		return "port-restricted-cone"
	case natTypeSymmetric:
		return "symmetric"
	default:
		return "unknown"
	}
}

// SetMinInterval applies the local per-target probe-interval floor (stability limit).
func (c *NATCollector) SetMinInterval(d time.Duration) { c.sched.SetMinInterval(d) }
