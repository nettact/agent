package collector

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/nettact/agent/internal/netguard"
	pcfg "github.com/nettact/protocol/config"
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
	httpClient *http.Client // used for DoH queries
	sched      *schedState
	guard      *netguard.Guard
}

func NewDNSCollector(guard *netguard.Guard) *DNSCollector {
	// DoH transport: environment proxy disabled, dials routed through the guard so
	// the resolver endpoint (and any redirect) is policy-checked and IP-pinned.
	doh := &http.Transport{Proxy: nil, DialContext: guard.DialContext, ForceAttemptHTTP2: true}
	return &DNSCollector{
		resolver:   net.DefaultResolver,
		httpClient: &http.Client{Transport: doh},
		sched:      newSchedState(pcfg.DefaultDNSInterval),
		guard:      guard,
	}
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

		cctx, cancel := context.WithTimeout(ctx, timeout)
		t0 := time.Now()
		var ok bool
		var derr error
		switch t.Params.ResolverProtocol {
		case "doh":
			// DNS over HTTPS: resolver_server is an https URL or a host we turn into
			// the conventional /dns-query endpoint.
			ok, derr = c.lookupDoH(cctx, t.Params.ResolverServer, t.Params.ResolverPort, t.Params.RecordType, t.Target)
		case "dot":
			// DNS over TLS on port 853 (default). Done explicitly over a TLS stream —
			// net.Resolver cannot be forced onto TCP framing reliably.
			ok, derr = c.lookupStream(cctx, t.Params.ResolverServer, t.Params.ResolverPort, 853, t.Params.RecordType, t.Target, timeout, true, t.Params.IgnoreTLS)
		case "tcp":
			// Plain DNS over TCP to a specific nameserver, likewise done explicitly.
			if t.Params.ResolverServer != "" {
				ok, derr = c.lookupStream(cctx, t.Params.ResolverServer, t.Params.ResolverPort, 53, t.Params.RecordType, t.Target, timeout, false, false)
			} else {
				ok = lookupRecord(cctx, c.resolver, t.Params.RecordType, t.Target)
			}
		default:
			// Plain UDP: a per-target resolver override sends the query to a specific
			// nameserver (dialed through the guard, so a denied endpoint is returned as
			// a *netguard.BlockedError, not a silent DNS failure); otherwise use the
			// process default resolver (OS-owned ambient config, exempt from policy).
			if t.Params.ResolverServer != "" {
				ok, derr = c.lookupUDP(cctx, t.Params.ResolverServer, t.Params.ResolverPort, t.Params.RecordType, t.Target, timeout)
			} else {
				ok = lookupRecord(cctx, c.resolver, t.Params.RecordType, t.Target)
			}
		}
		cancel()

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
		res.Metrics = append(res.Metrics, telemetry.Metric{
			TS: now, Kind: telemetry.DNSOK, Target: t.Target, Layer: telemetry.LayerDNS, Value: okv, Unit: telemetry.UnitBool,
			MonitorID: t.MonitorID, ConfigSerial: t.ConfigSerial,
		})
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
// requested record type.
func (c *DNSCollector) lookupUDP(ctx context.Context, server string, port int, recordType, name string, timeout time.Duration) (bool, error) {
	if port <= 0 {
		port = 53
	}
	query, err := buildDNSQuery(name, recordType)
	if err != nil {
		return false, nil
	}
	addr := net.JoinHostPort(server, strconv.Itoa(port))
	conn, err := c.guard.DialContext(ctx, "udp", addr)
	if err != nil {
		return false, err
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	} else {
		_ = conn.SetDeadline(time.Now().Add(timeout))
	}
	if _, err := conn.Write(query); err != nil {
		return false, nil
	}
	respb := make([]byte, 4096)
	n, err := conn.Read(respb)
	if err != nil {
		return false, nil
	}
	var msg dnsmessage.Message
	if err := msg.Unpack(respb[:n]); err != nil {
		return false, nil
	}
	return dnsAnswerOK(&msg, recordType), nil
}

// lookupStream performs a DNS query over a TCP stream, optionally wrapped in TLS
// (DoT). The raw TCP connection is dialed through the guard (policy-checked,
// IP-pinned); TLS uses ServerName=server so certificate verification stays
// against the intended host. Returns true when the response is NOERROR and
// contains at least one answer of the requested record type; a policy block is
// returned as a *netguard.BlockedError.
func (c *DNSCollector) lookupStream(ctx context.Context, server string, port, defaultPort int, recordType, name string, timeout time.Duration, useTLS, ignoreTLS bool) (bool, error) {
	if port <= 0 {
		port = defaultPort
	}
	query, err := buildDNSQuery(name, recordType)
	if err != nil {
		return false, nil
	}
	addr := net.JoinHostPort(server, strconv.Itoa(port))

	raw, err := c.guard.DialContext(ctx, "tcp", addr)
	if err != nil {
		return false, err
	}
	var conn net.Conn = raw
	if useTLS {
		tconn := tls.Client(raw, &tls.Config{ServerName: server, InsecureSkipVerify: ignoreTLS}) //nolint:gosec // opt-in via ignore_tls
		if herr := tconn.HandshakeContext(ctx); herr != nil {
			_ = raw.Close()
			return false, nil
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
		return false, nil
	}

	var lenb [2]byte
	if _, err := io.ReadFull(conn, lenb[:]); err != nil {
		return false, nil
	}
	n := int(lenb[0])<<8 | int(lenb[1])
	if n <= 0 || n > 65535 {
		return false, nil
	}
	respb := make([]byte, n)
	if _, err := io.ReadFull(conn, respb); err != nil {
		return false, nil
	}
	var msg dnsmessage.Message
	if err := msg.Unpack(respb); err != nil {
		return false, nil
	}
	return dnsAnswerOK(&msg, recordType), nil
}

// dnsAnswerOK reports whether a parsed DNS response is a successful answer for
// the requested record type. Checking the type (not just answer count) means a
// response carrying only a CNAME for an A/AAAA query is correctly treated as a
// failure, matching the plain-resolver LookupIP path.
func dnsAnswerOK(msg *dnsmessage.Message, recordType string) bool {
	if msg.Header.RCode != dnsmessage.RCodeSuccess {
		return false
	}
	want := dohType(recordType)
	for _, a := range msg.Answers {
		if a.Header.Type == want {
			return true
		}
	}
	return false
}

// lookupDoH resolves name over DNS-over-HTTPS (RFC 8484). server may be a full
// https URL or a bare host, in which case the conventional /dns-query endpoint is
// used. The DoH transport dials through the guard, so a denied endpoint is
// returned as a *netguard.BlockedError. Returns true when the response is NOERROR
// with at least one answer.
func (c *DNSCollector) lookupDoH(ctx context.Context, server string, port int, recordType, name string) (bool, error) {
	query, err := buildDNSQuery(name, recordType)
	if err != nil {
		return false, nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, dohURL(server, port), bytes.NewReader(query))
	if err != nil {
		return false, nil
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		var be *netguard.BlockedError
		if errors.As(err, &be) {
			return false, err
		}
		return false, nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false, nil
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 65535))
	if err != nil {
		return false, nil
	}
	var msg dnsmessage.Message
	if err := msg.Unpack(body); err != nil {
		return false, nil
	}
	return dnsAnswerOK(&msg, recordType), nil
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
// reports whether at least one record came back. A/AAAA (and empty = either) go
// through LookupIP; CNAME/MX/TXT/NS use their dedicated lookups.
func lookupRecord(ctx context.Context, r *net.Resolver, recordType, name string) bool {
	switch recordType {
	case "CNAME":
		cname, err := r.LookupCNAME(ctx, name)
		return err == nil && cname != ""
	case "MX":
		mx, err := r.LookupMX(ctx, name)
		return err == nil && len(mx) > 0
	case "TXT":
		txt, err := r.LookupTXT(ctx, name)
		return err == nil && len(txt) > 0
	case "NS":
		ns, err := r.LookupNS(ctx, name)
		return err == nil && len(ns) > 0
	default:
		network := "ip"
		switch recordType {
		case "A":
			network = "ip4"
		case "AAAA":
			network = "ip6"
		}
		addrs, err := r.LookupIP(ctx, network, name)
		return err == nil && len(addrs) > 0
	}
}

// SetMinInterval applies the local per-target probe-interval floor (stability limit).
func (c *DNSCollector) SetMinInterval(d time.Duration) { c.sched.SetMinInterval(d) }
