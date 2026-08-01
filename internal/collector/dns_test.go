package collector

import (
	"context"
	"errors"
	"net"
	"net/http"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/nettact/agent/internal/netguard"
	"github.com/nettact/agent/probepolicy"
	pcfg "github.com/nettact/protocol/config"
	"github.com/nettact/protocol/permission"
	"github.com/nettact/protocol/telemetry"
)

// rcodeMsg builds a minimal response carrying only an rcode, optionally with
// answers of the given types — all dnsResult reads.
func rcodeMsg(rc dnsmessage.RCode, answerTypes ...dnsmessage.Type) *dnsmessage.Message {
	msg := &dnsmessage.Message{Header: dnsmessage.Header{Response: true, RCode: rc}}
	for _, at := range answerTypes {
		msg.Answers = append(msg.Answers, dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Type: at}})
	}
	return msg
}

// truncated marks a response as cut short (TC), as a resolver does for an answer
// too large for the 512-byte non-EDNS0 UDP limit.
func truncated(msg *dnsmessage.Message) *dnsmessage.Message {
	msg.Header.Truncated = true
	return msg
}

func TestDNSResult(t *testing.T) {
	cases := []struct {
		name       string
		msg        *dnsmessage.Message
		recordType string
		wantOK     bool
		wantReason int
		wantDetail string
	}{
		{"nxdomain", rcodeMsg(dnsmessage.RCodeNameError), "A", false, telemetry.ProbeReasonDNSNXDomain, "NXDOMAIN"},
		{"servfail", rcodeMsg(dnsmessage.RCodeServerFailure), "A", false, telemetry.ProbeReasonDNSServFail, "SERVFAIL"},
		{"refused", rcodeMsg(dnsmessage.RCodeRefused), "A", false, telemetry.ProbeReasonRefused, "REFUSED"},
		{"formerr", rcodeMsg(dnsmessage.RCodeFormatError), "A", false, telemetry.ProbeReasonOther, "FORMERR"},
		{"notimp", rcodeMsg(dnsmessage.RCodeNotImplemented), "A", false, telemetry.ProbeReasonOther, "NOTIMP"},
		{"unknown rcode", rcodeMsg(dnsmessage.RCode(11)), "A", false, telemetry.ProbeReasonOther, "RCODE 11"},
		{"answered", rcodeMsg(dnsmessage.RCodeSuccess, dnsmessage.TypeA), "A", true, telemetry.ProbeReasonNone, ""},
		// NOERROR with only a CNAME for an AAAA query: the name exists but has no
		// record of the queried type — a different failure than NXDOMAIN.
		{"no record of queried type", rcodeMsg(dnsmessage.RCodeSuccess, dnsmessage.TypeCNAME), "AAAA", false, telemetry.ProbeReasonDNSNoRecord, "no AAAA record"},
		{"no record default type", rcodeMsg(dnsmessage.RCodeSuccess), "", false, telemetry.ProbeReasonDNSNoRecord, "no A record"},
		// A cut-short answer proves nothing about absence: the records may well be
		// in the part that was dropped, so it must never read as "no record".
		{"truncated is not no-record", truncated(rcodeMsg(dnsmessage.RCodeSuccess)), "TXT", false, telemetry.ProbeReasonDNS, "truncated response (TC set), answer incomplete"},
		{"truncated with only other types", truncated(rcodeMsg(dnsmessage.RCodeSuccess, dnsmessage.TypeCNAME)), "MX", false, telemetry.ProbeReasonDNS, "truncated response (TC set), answer incomplete"},
		// Truncation is irrelevant once the requested record is actually present.
		{"truncated but answered", truncated(rcodeMsg(dnsmessage.RCodeSuccess, dnsmessage.TypeA)), "A", true, telemetry.ProbeReasonNone, ""},
		// An explicit rcode outranks truncation — it is a conclusive answer.
		{"truncated nxdomain keeps rcode", truncated(rcodeMsg(dnsmessage.RCodeNameError)), "A", false, telemetry.ProbeReasonDNSNXDomain, "NXDOMAIN"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ok, reason, detail := dnsResult(c.msg, c.recordType)
			if ok != c.wantOK || reason != c.wantReason || detail != c.wantDetail {
				t.Fatalf("dnsResult = (%v, %d, %q), want (%v, %d, %q)",
					ok, reason, detail, c.wantOK, c.wantReason, c.wantDetail)
			}
		})
	}
}

func TestDNSRecordResult(t *testing.T) {
	// The system resolver reports NXDOMAIN and NODATA as the same IsNotFound
	// error, so it may only claim the DNS family — the raw text carries the truth.
	t.Run("resolver error classifies with its text", func(t *testing.T) {
		err := &net.DNSError{Err: "no such host", Name: "gone.example", IsNotFound: true}
		ok, reason, detail := dnsRecordResult(false, err, "A")
		if ok || reason != telemetry.ProbeReasonDNS || detail != err.Error() {
			t.Fatalf("got (%v, %d, %q)", ok, reason, detail)
		}
	})
	t.Run("clean lookup with no record", func(t *testing.T) {
		ok, reason, detail := dnsRecordResult(false, nil, "MX")
		if ok || reason != telemetry.ProbeReasonDNSNoRecord || detail != "no MX record" {
			t.Fatalf("got (%v, %d, %q)", ok, reason, detail)
		}
	})
	t.Run("success carries nothing", func(t *testing.T) {
		ok, reason, detail := dnsRecordResult(true, nil, "A")
		if !ok || reason != telemetry.ProbeReasonNone || detail != "" {
			t.Fatalf("got (%v, %d, %q)", ok, reason, detail)
		}
	})
}

// TestResolverLabelsNameTheDialedEndpoint pins the labels a failing DNS cycle
// carries so the server can aim its path diagnostic at the resolver rather than
// at the queried name (DIAG-003). The branches here must stay in lockstep with
// Collect's protocol switch: a label naming an endpoint the query never dialed
// would send the diagnostic somewhere the fault never was.
func TestResolverLabelsNameTheDialedEndpoint(t *testing.T) {
	cases := []struct {
		name     string
		params   pcfg.ProbeParams
		wantAddr string
		wantProt string
	}{
		{"udp default port", pcfg.ProbeParams{ResolverServer: "1.1.1.1"}, "1.1.1.1:53", "udp"},
		{"udp explicit port", pcfg.ProbeParams{ResolverServer: "1.1.1.1", ResolverPort: 5353}, "1.1.1.1:5353", "udp"},
		{"tcp default port", pcfg.ProbeParams{ResolverServer: "9.9.9.9", ResolverProtocol: "tcp"}, "9.9.9.9:53", "tcp"},
		{"dot default port", pcfg.ProbeParams{ResolverServer: "dns.example", ResolverProtocol: "dot"}, "dns.example:853", "dot"},
		{"dot explicit port", pcfg.ProbeParams{ResolverServer: "dns.example", ResolverProtocol: "dot", ResolverPort: 8853}, "dns.example:8853", "dot"},
		{"doh bare host normalizes to the query URL", pcfg.ProbeParams{ResolverServer: "doh.example", ResolverProtocol: "doh"},
			"https://doh.example/dns-query", "doh"},
		{"doh url passes through", pcfg.ProbeParams{ResolverServer: "https://doh.example/q", ResolverProtocol: "doh"},
			"https://doh.example/q", "doh"},
	}
	c := NewDNSCollector(netguard.New(probepolicy.Policy{}, true), nil, nil)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := c.resolverLabels(pcfg.ProbeTarget{Kind: "dns", Target: "example.com", Params: tc.params}, "")
			if got[telemetry.DNSResolverLabel] != tc.wantAddr ||
				got[telemetry.DNSResolverProtocolLabel] != tc.wantProt {
				t.Fatalf("resolverLabels = %v, want resolver=%q protocol=%q", got, tc.wantAddr, tc.wantProt)
			}
		})
	}
}

// A DoH query that followed a redirect must name the endpoint that ANSWERED, not
// the one configured: diagnosing the configured host could report a healthy path
// while the endpoint that actually failed goes unexamined.
func TestResolverLabelsFollowDoHRedirect(t *testing.T) {
	c := NewDNSCollector(netguard.New(probepolicy.Policy{}, true), nil, nil)
	target := pcfg.ProbeTarget{Kind: "dns", Target: "example.com",
		Params: pcfg.ProbeParams{ResolverServer: "https://doh.example/dns-query", ResolverProtocol: "doh"}}

	got := c.resolverLabels(target, "https://redirected.example/dns-query")
	if got[telemetry.DNSResolverLabel] != "https://redirected.example/dns-query" {
		t.Fatalf("resolver label = %v, want the endpoint that served the request", got)
	}
	// No endpoint could be observed at all: the configured URL is the only one
	// known to be involved, so it stands.
	got = c.resolverLabels(target, "")
	if got[telemetry.DNSResolverLabel] != "https://doh.example/dns-query" {
		t.Fatalf("resolver label = %v, want the configured endpoint", got)
	}
}

// A DoH request that fails AFTER following a redirect must still name the host it
// was attempting. url.Error carries that final URL, and without it the label
// falls back to the configured redirector — a host that answered fine — sending
// the diagnostic to the wrong place in exactly the case it is needed.
func TestDoHFailureNamesTheAttemptedEndpoint(t *testing.T) {
	c := NewDNSCollector(netguard.New(probepolicy.Policy{}, true), nil, nil)

	// A client whose transport fails, reporting the redirected URL as url.Error does.
	failing := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return nil, errors.New("connection refused")
	})}
	_, _, _, endpoint, err := c.lookupDoH(context.Background(), failing,
		"https://doh.example/dns-query", 0, "A", "example.com")
	if err == nil {
		t.Fatal("expected a transport error")
	}
	if endpoint != "https://doh.example/dns-query" {
		t.Fatalf("endpoint = %q, want the URL the request was attempting", endpoint)
	}
}

// roundTripFunc adapts a function to http.RoundTripper.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// TestResolverLabelsForSystemResolver covers the system-resolver arm. The label
// appears only when the host configures exactly ONE resolver, because only then
// is it certain which server answered: the stdlib walks the list on failure (and
// may start anywhere under `options rotate`), and a failing lookup — the only
// kind labelled here — is exactly when that happens. Naming the first would aim
// the diagnostic at a server that answered fine.
func TestResolverLabelsForSystemResolver(t *testing.T) {
	c := NewDNSCollector(netguard.New(probepolicy.Policy{}, true), nil,
		permission.FromStrings([]string{string(permission.NetIfaceAddressRead)}))
	target := pcfg.ProbeTarget{Kind: "dns", Target: "example.com"}

	c.sysResolvers = []string{"192.0.2.53"}
	c.sysResolversAt = time.Now()
	got := c.resolverLabels(target, "")
	if got[telemetry.DNSResolverLabel] != "192.0.2.53:53" || got[telemetry.DNSResolverProtocolLabel] != "udp" {
		t.Fatalf("system resolver labels = %v, want the sole server on udp/53", got)
	}

	c.sysResolvers = []string{"192.0.2.53", "192.0.2.54"}
	c.sysResolversAt = time.Now()
	if got := c.resolverLabels(target, ""); got != nil {
		t.Fatalf("ambiguous system resolver produced labels %v, want none — the query may "+
			"have failed over to any of them", got)
	}

	c.sysResolvers = nil
	c.sysResolversAt = time.Now()
	if got := c.resolverLabels(target, ""); got != nil {
		t.Fatalf("unnameable system resolver produced labels %v, want none", got)
	}
}

// Naming the system resolver means reading the host's configured DNS servers,
// which network.interface.address.read governs. An operator who grants DNS
// probing while withholding that permission must not get their resolver
// configuration reported through the diagnostic label instead.
func TestSystemResolverRequiresAddressReadPermission(t *testing.T) {
	// Probing is granted; address read is not.
	c := NewDNSCollector(netguard.New(probepolicy.Policy{}, true), nil,
		permission.FromStrings([]string{string(permission.ProbeDNS)}))
	// Even with a discovery result already cached, the label must not appear.
	c.sysResolvers = []string{"192.0.2.53"}
	c.sysResolversAt = time.Now()

	if got := c.resolverLabels(pcfg.ProbeTarget{Kind: "dns", Target: "example.com"}, ""); got != nil {
		t.Fatalf("system resolver leaked without address-read permission: %v", got)
	}

	// A resolver the SERVER configured is exempt: echoing it back tells the server
	// only what it already sent down.
	got := c.resolverLabels(pcfg.ProbeTarget{Kind: "dns", Target: "example.com",
		Params: pcfg.ProbeParams{ResolverServer: "1.1.1.1"}}, "")
	if got[telemetry.DNSResolverLabel] != "1.1.1.1:53" {
		t.Fatalf("configured resolver was withheld: %v", got)
	}
}

// TestResolverLabelsAreNotShared guards the aliasing hazard in withDetail: it
// returns its input UNCHANGED when the detail is empty, so a cached/shared map
// would let one cycle's detail leak onto another cycle's labels.
func TestResolverLabelsAreNotShared(t *testing.T) {
	c := NewDNSCollector(netguard.New(probepolicy.Policy{}, true), nil, nil)
	target := pcfg.ProbeTarget{Kind: "dns", Target: "example.com", Params: pcfg.ProbeParams{ResolverServer: "1.1.1.1"}}
	first := c.resolverLabels(target, "")
	withDetail(first, "SERVFAIL") // a cycle that had a cause
	second := c.resolverLabels(target, "")
	if _, leaked := second[telemetry.ProbeReasonDetailLabel]; leaked {
		t.Fatalf("detail leaked into a later cycle's labels: %v", second)
	}
	first[telemetry.DNSResolverLabel] = "mutated"
	if second[telemetry.DNSResolverLabel] != "1.1.1.1:53" {
		t.Fatalf("labels share backing storage across cycles: %v", second)
	}
}
