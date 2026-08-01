package collector

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/nettact/agent/internal/netguard"
	"github.com/nettact/agent/internal/platform"
	"github.com/nettact/agent/internal/proxydial"
	pcfg "github.com/nettact/protocol/config"
	"github.com/nettact/protocol/permission"
	"github.com/nettact/protocol/telemetry"
)

// DNSCollector resolves a server-configured set of names and reports resolve
// latency + success (architecture §4 DNS layer). Each name carries its own
// per-target params (timeout, interval, record type, resolver protocol) and is
// probed on its own schedule via schedState. Supported resolver protocols:
// plain UDP/TCP (custom nameserver or system), DoT (DNS over TLS), and DoH
// (DNS over HTTPS).
//
// The target-access policy governs the CUSTOM resolver/DoT/DoH endpoint that the
// probe actually dials (never the queried name, which the DNS probe does not
// itself dial). The system default resolver is OS-owned ambient config and is
// exempt, like the agent's own control connection.
type DNSCollector struct {
	resolver   *net.Resolver
	httpClient *http.Client // used for DoH queries on a direct (unproxied) target
	sched      *schedState
	guard      *netguard.Guard
	proxies    *proxydial.Manager
	// effective gates naming the SYSTEM resolver. Discovering it means reading the
	// host's configured DNS servers — the very data network.interface.address.read
	// governs — so an operator who granted DNS probing while withholding that
	// permission must not have their resolver configuration reported anyway.
	// A resolver the server itself configured is exempt: echoing it back discloses
	// nothing the server did not already know.
	effective permission.Set

	// dohClients caches a DoH client per proxy generation, so a re-keyed proxy gets a
	// fresh transport instead of keeping pooled connections on the replaced egress
	// path. Guarded by mu.
	mu         sync.Mutex
	dohClients map[string]*http.Client

	// sysResolvers caches the OS resolver list, refreshed at most every
	// sysResolverTTL: naming the system resolver costs a file read on Linux and an
	// adapter-table walk on Windows, and it is needed once per failing cycle of
	// every system-resolver monitor. Guarded by mu.
	sysResolvers   []string
	sysResolversAt time.Time
}

// sysResolverTTL bounds how stale a cached system-resolver list may be. The value
// only has to beat an operator noticing a DNS reconfiguration, and every failing
// cycle would otherwise re-read the OS.
const sysResolverTTL = time.Minute

func NewDNSCollector(guard *netguard.Guard, proxies *proxydial.Manager, effective permission.Set) *DNSCollector {
	// DoH transport: environment proxy disabled, dials routed through the guard so
	// the resolver endpoint (and any redirect) is policy-checked and IP-pinned.
	doh := &http.Transport{Proxy: nil, DialContext: guard.DialContext, ForceAttemptHTTP2: true}
	return &DNSCollector{
		resolver:   net.DefaultResolver,
		httpClient: &http.Client{Transport: doh},
		sched:      newSchedState(pcfg.DefaultDNSInterval),
		guard:      guard,
		proxies:    proxies,
		effective:  effective,
		dohClients: map[string]*http.Client{},
	}
}

// dohClientFor returns the DoH client for a target's egress: the shared direct
// client, or a per-proxy-generation one that tunnels its dials.
func (c *DNSCollector) dohClientFor(proxy *proxydial.Dialer) *http.Client {
	if proxy == nil {
		return c.httpClient
	}
	key := proxy.Spec.ID + "@" + strconv.Itoa(proxy.Spec.ConfigSerial)
	c.mu.Lock()
	defer c.mu.Unlock()
	if cl, ok := c.dohClients[key]; ok {
		return cl
	}
	// proxyDialFunc, NOT proxy.DialContext: the DoH resolver endpoint is a destination
	// like any other, so in the default local-DNS mode it must be resolved and vetted
	// here and the proxy handed the approved literal. Using the raw dial let a DoH
	// hostname (and any redirect hop) be resolved on the far side, where no
	// ip:/cidr:/scope: rule could apply — the same bypass the other DNS paths had.
	//
	// IdleConnTimeout bounds how long a tunnelled connection can sit idle. Without it
	// an authenticated tunnel stayed open indefinitely, so a rotated proxy left its
	// predecessor's connection alive.
	cl := &http.Client{Transport: &http.Transport{
		Proxy:             nil,
		DialContext:       proxyDialFunc(c.guard, proxy),
		ForceAttemptHTTP2: true,
		IdleConnTimeout:   90 * time.Second,
	}}
	// Evict the generations this one replaces and close their idle connections, so a
	// proxy edit does not accumulate live tunnels and file descriptors. The manager
	// tears down its own dialers on Apply; this is the collector's matching half.
	c.evictDoHClientsLocked(proxy.Spec.ID, key)
	c.dohClients[key] = cl
	return cl
}

// evictDoHClientsLocked drops every cached DoH client for a proxy id except keep,
// closing its idle connections. Caller holds mu.
func (c *DNSCollector) evictDoHClientsLocked(proxyID, keep string) {
	prefix := proxyID + "@"
	for k, cl := range c.dohClients {
		if k == keep || !strings.HasPrefix(k, prefix) {
			continue
		}
		if tr, ok := cl.Transport.(*http.Transport); ok {
			tr.CloseIdleConnections()
		}
		delete(c.dohClients, k)
	}
}

// dialFor returns the dial function a DNS query should use. proxyDialFunc keeps the
// guard's address check alive through a proxy: in the default local-DNS mode the
// resolver endpoint is resolved and vetted here and the proxy is handed the approved
// literal, rather than a hostname it would resolve unseen.
func (c *DNSCollector) dialFor(proxy *proxydial.Dialer) proxydial.DialFunc {
	return proxyDialFunc(c.guard, proxy)
}

// systemResolver returns the resolver address the OS would answer through, or ""
// when the local policy withholds it or this platform cannot name it. Cached for
// sysResolverTTL.
//
// Only the FIRST entry is reported. The stdlib resolver may fail over to a later
// server, so this is the resolver a query most likely used, not a certainty —
// which is why the server treats it as evidence to aim a diagnostic at, never as
// proof of which server answered.
func (c *DNSCollector) systemResolver() string {
	// Field-level no-call: a denied scope must not have its data read from the OS
	// at all, not read and then withheld. Checked before the lookup, never after.
	if !c.effective.Has(permission.NetIfaceAddressRead) {
		return ""
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.sysResolversAt.IsZero() || time.Since(c.sysResolversAt) > sysResolverTTL {
		c.sysResolvers = platform.SystemResolvers()
		c.sysResolversAt = time.Now()
	}
	if len(c.sysResolvers) == 0 {
		return ""
	}
	return c.sysResolvers[0]
}

// resolverLabels names the resolver endpoint a target's query actually dials, for
// the error_class sample the server freezes onto fault evidence and aims its path
// diagnostic at (DIAG-003). The branches MIRROR Collect's protocol switch — a
// divergence here would name an endpoint the query never touched, which is worse
// than naming none, so both must change together.
//
// servedBy overrides the configured DoH URL with the endpoint that actually
// answered, which differs when the client followed a redirect; empty means the
// configured endpoint is the only one involved. Callers that run BEFORE any query
// (an egress that failed to resolve) pass empty.
//
// A fresh map per call: withDetail returns its input unchanged when the detail is
// empty, so a shared map would let one cycle's detail leak onto another's labels.
// Returns nil when the endpoint is unnameable (system resolver on a platform that
// cannot report one, or one the local policy withholds) — the server renders that
// as an unavailable diagnostic rather than tracing a guess.
func (c *DNSCollector) resolverLabels(t pcfg.ProbeTarget, servedBy string) map[string]string {
	server := strings.TrimSpace(t.Params.ResolverServer)
	proto := t.Params.ResolverProtocol
	var addr string
	switch proto {
	case "doh":
		// The endpoint that answered, else the normalized query URL — either way a
		// URL the server can read a host and port off the same way the probe did.
		if addr = strings.TrimSpace(servedBy); addr == "" {
			addr = dohURL(server, t.Params.ResolverPort)
		}
	case "dot":
		addr = net.JoinHostPort(server, strconv.Itoa(resolverPortOr(t.Params.ResolverPort, 853)))
	case "tcp":
		if server == "" {
			addr, proto = c.systemResolverAddr()
			break
		}
		addr = net.JoinHostPort(server, strconv.Itoa(resolverPortOr(t.Params.ResolverPort, 53)))
	default:
		if server == "" {
			addr, proto = c.systemResolverAddr()
			break
		}
		addr, proto = net.JoinHostPort(server, strconv.Itoa(resolverPortOr(t.Params.ResolverPort, 53))), "udp"
	}
	if addr == "" {
		return nil
	}
	return map[string]string{
		telemetry.DNSResolverLabel:         addr,
		telemetry.DNSResolverProtocolLabel: proto,
	}
}

// systemResolverAddr is the system-resolver arm of resolverLabels: the OS server
// on port 53, always plain UDP (the stdlib resolver's own transport choice is not
// observable, and it starts on UDP).
func (c *DNSCollector) systemResolverAddr() (string, string) {
	ns := c.systemResolver()
	if ns == "" {
		return "", ""
	}
	return net.JoinHostPort(ns, "53"), "udp"
}

// resolverPortOr applies a protocol's default resolver port.
func resolverPortOr(port, def int) int {
	if port <= 0 {
		return def
	}
	return port
}

func (c *DNSCollector) SetTargets(targets []pcfg.ProbeTarget) {
	var names []pcfg.ProbeTarget
	for _, t := range targets {
		if t.Kind == "dns" && t.Target != "" {
			names = append(names, t)
		}
	}
	c.sched.set(names)
}

func (c *DNSCollector) Name() string { return "dns" }

func (c *DNSCollector) Tier() Tier { return TierRegular }

func (c *DNSCollector) Collect(ctx context.Context) (Result, error) {
	targets := c.sched.due(time.Now())
	if len(targets) == 0 {
		return Result{}, nil
	}

	now := time.Now().UTC()
	var res Result
	for _, t := range targets {
		// A pass aborted by run cancellation (agent shutdown) must not fabricate
		// resolve failures — they would replay from the WAL as a false DNS outage
		// on the next start.
		if ctx.Err() != nil {
			break
		}
		timeout := time.Duration(t.Params.TimeoutMs) * time.Millisecond
		if timeout <= 0 {
			timeout = pcfg.DefaultDNSTimeout
		}

		// Resolve the pinned egress proxy. A pin that cannot be honored means the query
		// is not sent at all (fail-closed): resolving through the default path instead
		// would answer from a resolver the operator deliberately routed away from.
		proxy, prerr := resolveProxy(ctx, c.proxies, t)
		if prerr != nil {
			res.Metrics = append(res.Metrics, proxyFailureMetrics(now, t, telemetry.DNSOK, telemetry.DNSErrorClass, c.resolverLabels(t, ""), prerr)...)
			res.Events = append(res.Events, proxyFailureEvent(now, t, "DNS query not attempted"))
			continue
		}
		// A pinned monitor with no resolver endpoint has nothing a proxy could relay to:
		// the system resolver is OS-owned ambient config, and the branches below would
		// fall through to net.DefaultResolver — sending the query straight off the host,
		// then reporting SUCCESS while the configured egress is down. That is the exact
		// fail-open the pin exists to prevent, so it fails closed instead.
		//
		// ProxyCapable refuses the combination at save time, so this is the defensive
		// half: a drift there must not silently leak the query.
		if proxy != nil && strings.TrimSpace(t.Params.ResolverServer) == "" {
			// No resolver labels here on purpose: the monitor has no configured resolver,
			// and naming the HOST's system resolver would point the diagnostic at a server
			// this query was specifically routed away from.
			res.Metrics = append(res.Metrics, proxyFailureMetrics(now, t, telemetry.DNSOK, telemetry.DNSErrorClass, nil,
				fmt.Errorf("%w: a proxied DNS monitor needs an explicit resolver server (the system resolver cannot be relayed)",
					proxydial.ErrProxyKindUnsupported))...)
			res.Events = append(res.Events, proxyFailureEvent(now, t, "DNS query not attempted"))
			continue
		}
		dial := c.dialFor(proxy)

		cctx, cancel := context.WithTimeout(ctx, timeout)
		t0 := time.Now()
		var ok bool
		var reason int
		var detail string
		var derr error
		// The endpoint a DoH query was actually served by, when a redirect moved it
		// off the configured URL. Empty for every other protocol and whenever no
		// response came back.
		var servedBy string
		switch t.Params.ResolverProtocol {
		case "doh":
			// DNS over HTTPS: resolver_server is an https URL or a host we turn into
			// the conventional /dns-query endpoint.
			ok, reason, detail, servedBy, derr = c.lookupDoH(cctx, c.dohClientFor(proxy), t.Params.ResolverServer, t.Params.ResolverPort, t.Params.RecordType, t.Target)
		case "dot":
			// DNS over TLS on port 853 (default). Done explicitly over a TLS stream —
			// net.Resolver cannot be forced onto TCP framing reliably.
			ok, reason, detail, derr = c.lookupStream(cctx, dial, t.Params.ResolverServer, t.Params.ResolverPort, 853, t.Params.RecordType, t.Target, timeout, true, t.Params.IgnoreTLS)
		case "tcp":
			// Plain DNS over TCP to a specific nameserver, likewise done explicitly.
			if t.Params.ResolverServer != "" {
				ok, reason, detail, derr = c.lookupStream(cctx, dial, t.Params.ResolverServer, t.Params.ResolverPort, 53, t.Params.RecordType, t.Target, timeout, false, false)
			} else {
				ok, reason, detail = lookupRecord(cctx, c.resolver, t.Params.RecordType, t.Target)
			}
		default:
			// Plain UDP: a per-target resolver override sends the query to a specific
			// nameserver (dialed through the guard, so a denied endpoint is returned as
			// a *netguard.BlockedError, not a silent DNS failure); otherwise use the
			// process default resolver (OS-owned ambient config, exempt from policy).
			//
			// A proxied UDP query reaches here over a SOCKS5 UDP association or a
			// WireGuard tunnel; the capability matrix refuses it for HTTP, whose only
			// command is CONNECT. The system-resolver path is never proxied either way —
			// it is OS-owned ambient config with no address for a proxy to relay to.
			if t.Params.ResolverServer != "" {
				ok, reason, detail, derr = c.lookupUDP(cctx, dial, t.Params.ResolverServer, t.Params.ResolverPort, t.Params.RecordType, t.Target, timeout)
			} else {
				ok, reason, detail = lookupRecord(cctx, c.resolver, t.Params.RecordType, t.Target)
			}
		}
		cancel()

		// A proxy failure reached through any of the paths above is an EGRESS failure,
		// not a resolver verdict: re-classify so a dead proxy is never reported as a
		// broken nameserver.
		if pr, atTarget, isProxy := proxydial.ProxyReason(derr); isProxy && !atTarget {
			reason = pr
			detail = errText(derr)
		}

		// A policy block on the custom resolver endpoint is not a DNS failure.
		var be *netguard.BlockedError
		if errors.As(derr, &be) {
			res.Blocked = append(res.Blocked, blockedFromErr(t, be))
			continue
		}
		if !ok && ctx.Err() != nil {
			break // the lookup was aborted by the cancelled run, not by the resolver
		}

		okv := 0.0
		if ok {
			okv = 1.0
		}
		// error_class every cycle (ProbeReasonNone on success): refined within the
		// DNS family where the resolver said why (NXDOMAIN/SERVFAIL/no-record),
		// REFUSED→refused, deadline→timeout; the raw rcode/OS text rides as the
		// detail label. The server freezes both onto a fired alert's evidence so the
		// notice states WHY, not just "解析失败".
		ec := telemetry.Metric{
			TS: now, Kind: telemetry.DNSErrorClass, Target: t.Target, Layer: telemetry.LayerDNS,
			Value: float64(reason), Unit: telemetry.UnitCode,
			MonitorID: t.MonitorID, ConfigSerial: t.ConfigSerial,
		}
		// A failing cycle also names the resolver it dialed, so the server can freeze it
		// and aim the path diagnostic at the DNS server rather than at the queried name
		// (which nothing dials). Success cycles stay label-free, like the detail label:
		// only the evidence behind a fault is worth storing per sample.
		if reason != telemetry.ProbeReasonNone {
			ec.Labels = withDetail(c.resolverLabels(t, servedBy), detail)
		}
		res.Metrics = append(res.Metrics, telemetry.Metric{
			TS: now, Kind: telemetry.DNSOK, Target: t.Target, Layer: telemetry.LayerDNS, Value: okv, Unit: telemetry.UnitBool,
			MonitorID: t.MonitorID, ConfigSerial: t.ConfigSerial,
		}, ec)
		if ok {
			res.Metrics = append(res.Metrics, telemetry.Metric{
				TS: now, Kind: telemetry.DNSResolve, Target: t.Target, Layer: telemetry.LayerDNS,
				Value: float64(time.Since(t0).Microseconds()) / 1000.0, Unit: telemetry.UnitMs,
				MonitorID: t.MonitorID, ConfigSerial: t.ConfigSerial,
			})
		} else {
			res.Events = append(res.Events, telemetry.Event{
				ID: newID(), TS: now, Type: telemetry.EventProbeFailed, Layer: telemetry.LayerDNS,
				Severity: telemetry.SeverityWarn, Message: "DNS resolve failed: " + t.Target,
			})
		}
	}
	return res, nil
}

// lookupUDP performs a DNS query over UDP to a specific nameserver, dialed
// through the guard so the resolver endpoint is policy-checked and IP-pinned and
// a denied endpoint is returned as a *netguard.BlockedError (net.Resolver cannot
// be used here because it flattens the guard's typed dial error into an opaque
// *net.DNSError, which would misreport a policy block as an ordinary DNS
// failure). Returns true when the response is NOERROR with an answer of the
// requested record type; a failure carries its ProbeReason* code plus the raw
// cause (network error text or rcode) for the detail label.
func (c *DNSCollector) lookupUDP(ctx context.Context, dial proxydial.DialFunc, server string, port int, recordType, name string, timeout time.Duration) (bool, int, string, error) {
	if port <= 0 {
		port = 53
	}
	query, err := buildDNSQuery(name, recordType)
	if err != nil {
		return false, telemetry.ProbeReasonOther, errText(err), nil
	}
	addr := net.JoinHostPort(server, strconv.Itoa(port))
	conn, err := dial(ctx, "udp", addr)
	if err != nil {
		return false, classifyNetError(err), errText(err), err
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	} else {
		_ = conn.SetDeadline(time.Now().Add(timeout))
	}
	if _, err := conn.Write(query); err != nil {
		return false, classifyNetError(err), errText(err), nil
	}
	respb := make([]byte, 4096)
	n, err := conn.Read(respb)
	if err != nil {
		return false, classifyNetError(err), errText(err), nil
	}
	var msg dnsmessage.Message
	if err := msg.Unpack(respb[:n]); err != nil {
		return false, telemetry.ProbeReasonOther, errText(err), nil
	}
	ok, reason, detail := dnsResult(&msg, recordType)
	return ok, reason, detail, nil
}

// lookupStream performs a DNS query over a TCP stream, optionally wrapped in TLS
// (DoT). The raw TCP connection is dialed through the guard (policy-checked,
// IP-pinned); TLS uses ServerName=server so certificate verification stays
// against the intended host. Returns true when the response is NOERROR and
// contains at least one answer of the requested record type; a failure carries
// its ProbeReason* code plus the raw cause for the detail label; a policy block
// is returned as a *netguard.BlockedError.
func (c *DNSCollector) lookupStream(ctx context.Context, dial proxydial.DialFunc, server string, port, defaultPort int, recordType, name string, timeout time.Duration, useTLS, ignoreTLS bool) (bool, int, string, error) {
	if port <= 0 {
		port = defaultPort
	}
	query, err := buildDNSQuery(name, recordType)
	if err != nil {
		return false, telemetry.ProbeReasonOther, errText(err), nil
	}
	addr := net.JoinHostPort(server, strconv.Itoa(port))

	raw, err := dial(ctx, "tcp", addr)
	if err != nil {
		return false, classifyNetError(err), errText(err), err
	}
	var conn net.Conn = raw
	if useTLS {
		tconn := tls.Client(raw, &tls.Config{ServerName: server, InsecureSkipVerify: ignoreTLS}) //nolint:gosec // opt-in via ignore_tls
		if herr := tconn.HandshakeContext(ctx); herr != nil {
			_ = raw.Close()
			// The failing phase IS the handshake, so an error the classifier cannot
			// refine still lands in the TLS family (expired/untrusted/hostname otherwise).
			reason := telemetry.ProbeReasonTLS
			if code, tlsShaped := classifyTLSError(herr); tlsShaped {
				reason = code
			}
			return false, reason, errText(herr), nil
		}
		conn = tconn
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	} else {
		_ = conn.SetDeadline(time.Now().Add(timeout))
	}

	// 2-byte big-endian length prefix + message.
	framed := make([]byte, 2+len(query))
	framed[0] = byte(len(query) >> 8)
	framed[1] = byte(len(query))
	copy(framed[2:], query)
	if _, err := conn.Write(framed); err != nil {
		return false, classifyNetError(err), errText(err), nil
	}

	var lenb [2]byte
	if _, err := io.ReadFull(conn, lenb[:]); err != nil {
		return false, classifyNetError(err), errText(err), nil
	}
	n := int(lenb[0])<<8 | int(lenb[1])
	if n <= 0 || n > 65535 {
		return false, telemetry.ProbeReasonOther, "malformed DNS response length", nil
	}
	respb := make([]byte, n)
	if _, err := io.ReadFull(conn, respb); err != nil {
		return false, classifyNetError(err), errText(err), nil
	}
	var msg dnsmessage.Message
	if err := msg.Unpack(respb); err != nil {
		return false, telemetry.ProbeReasonOther, errText(err), nil
	}
	ok, reason, detail := dnsResult(&msg, recordType)
	return ok, reason, detail, nil
}

// dnsResult reports whether a parsed DNS response is a successful answer for the
// requested record type, plus a telemetry.ProbeReason* code and its raw-cause
// detail for a failure. Checking the type (not just answer count) means a
// response carrying only a CNAME for an A/AAAA query is correctly treated as a
// failure, matching the plain-resolver LookupIP path. A non-NOERROR rcode maps to
// its reason (NXDOMAIN→dns-nxdomain, SERVFAIL→dns-servfail, REFUSED→refused,
// else other) with the rcode mnemonic as detail; NOERROR with no matching record
// is its own refined failure (the name exists — a different fix than NXDOMAIN).
// A truncated answer proves nothing about absence, so it never becomes
// no-record: the queries carry no EDNS0 buffer, so a large TXT/MX answer comes
// back with TC set and the records cut off, and calling that "no record" would
// report a missing record that is actually there.
func dnsResult(msg *dnsmessage.Message, recordType string) (bool, int, string) {
	if msg.Header.RCode != dnsmessage.RCodeSuccess {
		reason := telemetry.ProbeReasonOther // FORMERR, NOTIMP, …
		switch msg.Header.RCode {
		case dnsmessage.RCodeNameError:
			reason = telemetry.ProbeReasonDNSNXDomain
		case dnsmessage.RCodeServerFailure:
			reason = telemetry.ProbeReasonDNSServFail
		case dnsmessage.RCodeRefused:
			reason = telemetry.ProbeReasonRefused
		}
		return false, reason, rcodeText(msg.Header.RCode)
	}
	want := dohType(recordType)
	for _, a := range msg.Answers {
		if a.Header.Type == want {
			return true, telemetry.ProbeReasonNone, ""
		}
	}
	if msg.Header.Truncated {
		return false, telemetry.ProbeReasonDNS, "truncated response (TC set), answer incomplete"
	}
	return false, telemetry.ProbeReasonDNSNoRecord, "no " + recordTypeLabel(recordType) + " record"
}

// rcodeText renders a DNS rcode for the detail label: the standard mnemonic for
// the codes a resolver actually returns, the bare number otherwise.
func rcodeText(rc dnsmessage.RCode) string {
	switch rc {
	case dnsmessage.RCodeFormatError:
		return "FORMERR"
	case dnsmessage.RCodeServerFailure:
		return "SERVFAIL"
	case dnsmessage.RCodeNameError:
		return "NXDOMAIN"
	case dnsmessage.RCodeNotImplemented:
		return "NOTIMP"
	case dnsmessage.RCodeRefused:
		return "REFUSED"
	default:
		return "RCODE " + strconv.Itoa(int(rc))
	}
}

// recordTypeLabel names the queried record type for detail text, mirroring
// dohType's defaulting (empty/unknown queries A).
func recordTypeLabel(recordType string) string {
	switch recordType {
	case "AAAA", "CNAME", "MX", "TXT", "NS":
		return recordType
	default:
		return "A"
	}
}

// dnsRecordResult turns a (hasMatchingRecord, err) pair from the system resolver
// into an (ok, ProbeReason*, detail) triple: an error classifies via
// classifyNetError with the raw resolver error as detail (a timeout stays a
// timeout; "no such host" stays the DNS family code because the stdlib cannot
// separate a missing name from a missing record); a clean lookup with no record
// is the no-record failure for the queried type.
func dnsRecordResult(has bool, err error, recordType string) (bool, int, string) {
	if err != nil {
		return false, classifyNetError(err), errText(err)
	}
	if !has {
		return false, telemetry.ProbeReasonDNSNoRecord, "no " + recordTypeLabel(recordType) + " record"
	}
	return true, telemetry.ProbeReasonNone, ""
}

// lookupDoH resolves name over DNS-over-HTTPS (RFC 8484). server may be a full
// https URL or a bare host, in which case the conventional /dns-query endpoint is
// used. The DoH transport dials through the guard, so a denied endpoint is
// returned as a *netguard.BlockedError. Returns true when the response is NOERROR
// with at least one answer; a failure carries its ProbeReason* code plus the raw
// cause (transport error text, "DoH HTTP <n>", or rcode) for the detail label.
//
// endpoint is the URL that actually SERVED the request, which differs from the
// configured one when the client followed a redirect. The diagnostic is aimed at
// it, so a redirected resolver is diagnosed where the failure happened rather
// than at a first hop that was merely passed through. It is empty when no
// response was obtained at all — the configured URL is then the only endpoint
// involved, and the caller falls back to it.
func (c *DNSCollector) lookupDoH(ctx context.Context, client *http.Client, server string, port int, recordType, name string) (ok bool, reason int, detail, endpoint string, err error) {
	query, err := buildDNSQuery(name, recordType)
	if err != nil {
		return false, telemetry.ProbeReasonOther, errText(err), "", nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, dohURL(server, port), bytes.NewReader(query))
	if err != nil {
		return false, telemetry.ProbeReasonOther, errText(err), "", nil
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	resp, err := client.Do(req)
	if err != nil {
		var be *netguard.BlockedError
		if errors.As(err, &be) {
			return false, telemetry.ProbeReasonOther, "", "", err
		}
		// The error is returned (not dropped) so the caller's ProxyReason check can see
		// a typed proxy failure. Previously this returned nil here, which made a dead or
		// rejecting proxy on a DoH monitor report as a generic resolver timeout — the one
		// thing the proxy_* family exists to prevent. classifyNetError stays as the
		// fallback for an ordinary transport error.
		return false, classifyNetError(err), errText(err), "", err
	}
	defer resp.Body.Close()
	// resp.Request is the request that produced this response — the redirected one
	// when the client followed redirects.
	if resp.Request != nil && resp.Request.URL != nil {
		endpoint = resp.Request.URL.String()
	}
	if resp.StatusCode != http.StatusOK {
		return false, telemetry.ProbeReasonOther, "DoH HTTP " + strconv.Itoa(resp.StatusCode), endpoint, nil
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 65535))
	if err != nil {
		return false, classifyNetError(err), errText(err), endpoint, nil
	}
	var msg dnsmessage.Message
	if err := msg.Unpack(body); err != nil {
		return false, telemetry.ProbeReasonOther, errText(err), endpoint, nil
	}
	ok, reason, detail = dnsResult(&msg, recordType)
	return ok, reason, detail, endpoint, nil
}

// dohURL normalizes a DoH server into a query URL. A value starting with http is
// used verbatim; otherwise it becomes https://<host>[:port]/dns-query.
func dohURL(server string, port int) string {
	if strings.HasPrefix(server, "http://") || strings.HasPrefix(server, "https://") {
		return server
	}
	host := server
	if port > 0 && port != 443 {
		host = net.JoinHostPort(server, strconv.Itoa(port))
	}
	return "https://" + host + "/dns-query"
}

// buildDNSQuery packs a single-question DNS query for the given name/type.
func buildDNSQuery(name, recordType string) ([]byte, error) {
	if !strings.HasSuffix(name, ".") {
		name += "."
	}
	qname, err := dnsmessage.NewName(name)
	if err != nil {
		return nil, err
	}
	msg := dnsmessage.Message{
		Header:    dnsmessage.Header{RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: qname, Type: dohType(recordType), Class: dnsmessage.ClassINET}},
	}
	return msg.Pack()
}

// dohType maps a record-type string to a dnsmessage type (default A).
func dohType(recordType string) dnsmessage.Type {
	switch recordType {
	case "AAAA":
		return dnsmessage.TypeAAAA
	case "CNAME":
		return dnsmessage.TypeCNAME
	case "MX":
		return dnsmessage.TypeMX
	case "TXT":
		return dnsmessage.TypeTXT
	case "NS":
		return dnsmessage.TypeNS
	default:
		return dnsmessage.TypeA
	}
}

// lookupRecord issues the appropriate lookup for the requested record type and
// reports whether at least one record came back, plus a telemetry.ProbeReason*
// code and its raw-cause detail for a failure. A/AAAA (and empty = either) go
// through LookupIP; CNAME/MX/TXT/NS use their dedicated lookups.
func lookupRecord(ctx context.Context, r *net.Resolver, recordType, name string) (bool, int, string) {
	switch recordType {
	case "CNAME":
		cname, err := r.LookupCNAME(ctx, name)
		return dnsRecordResult(cname != "", err, recordType)
	case "MX":
		mx, err := r.LookupMX(ctx, name)
		return dnsRecordResult(len(mx) > 0, err, recordType)
	case "TXT":
		txt, err := r.LookupTXT(ctx, name)
		return dnsRecordResult(len(txt) > 0, err, recordType)
	case "NS":
		ns, err := r.LookupNS(ctx, name)
		return dnsRecordResult(len(ns) > 0, err, recordType)
	default:
		network := "ip"
		switch recordType {
		case "A":
			network = "ip4"
		case "AAAA":
			network = "ip6"
		}
		addrs, err := r.LookupIP(ctx, network, name)
		return dnsRecordResult(len(addrs) > 0, err, recordType)
	}
}

// SetMinInterval applies the local per-target probe-interval floor (stability limit).
func (c *DNSCollector) SetMinInterval(d time.Duration) { c.sched.SetMinInterval(d) }
