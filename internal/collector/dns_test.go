package collector

import (
	"net"
	"testing"

	"golang.org/x/net/dns/dnsmessage"

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
