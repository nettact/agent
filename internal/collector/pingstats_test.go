package collector

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/url"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/nettact/protocol/telemetry"
)

func TestPingStats(t *testing.T) {
	ms := func(v int) time.Duration { return time.Duration(v) * time.Millisecond }

	t.Run("no samples", func(t *testing.T) {
		avg, mn, mx, jit, have := pingStats(nil)
		if have || avg != 0 || mn != 0 || mx != 0 || jit != 0 {
			t.Fatalf("empty: got avg=%v min=%v max=%v jit=%v have=%v", avg, mn, mx, jit, have)
		}
	})

	t.Run("single sample has no jitter", func(t *testing.T) {
		avg, mn, mx, jit, have := pingStats([]time.Duration{ms(20)})
		if have {
			t.Fatalf("single sample must not produce jitter")
		}
		if avg != 20 || mn != 20 || mx != 20 || jit != 0 {
			t.Fatalf("single: got avg=%v min=%v max=%v jit=%v", avg, mn, mx, jit)
		}
	})

	t.Run("distribution and IPDV", func(t *testing.T) {
		// diffs: |14-10|=4, |12-14|=2 → mean = 6/2 = 3ms
		avg, mn, mx, jit, have := pingStats([]time.Duration{ms(10), ms(14), ms(12)})
		if !have {
			t.Fatalf("expected jitter with 3 samples")
		}
		if avg != 12 || mn != 10 || mx != 14 || jit != 3 {
			t.Fatalf("got avg=%v min=%v max=%v jit=%v; want 12/10/14/3", avg, mn, mx, jit)
		}
	})
}

type fakeTimeout struct{}

func (fakeTimeout) Error() string   { return "i/o timeout" }
func (fakeTimeout) Timeout() bool   { return true }
func (fakeTimeout) Temporary() bool { return true }

func TestClassifyNetError(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want int
	}{
		{"nil", nil, telemetry.ProbeReasonNone},
		{"refused", syscall.ECONNREFUSED, telemetry.ProbeReasonRefused},
		{"host unreachable", syscall.EHOSTUNREACH, telemetry.ProbeReasonUnreachable},
		{"net unreachable", syscall.ENETUNREACH, telemetry.ProbeReasonUnreachable},
		{"deadline", context.DeadlineExceeded, telemetry.ProbeReasonTimeout},
		{"errno timeout", syscall.ETIMEDOUT, telemetry.ProbeReasonTimeout},
		{"net timeout", fakeTimeout{}, telemetry.ProbeReasonTimeout},
		// "no such host" stays the DNS family: the stdlib reports NXDOMAIN and
		// NODATA (name exists, no record of the queried type) identically, so
		// refining to NXDOMAIN here would misreport a missing record as a missing
		// domain. Only a readable rcode (dnsResult) may assert NXDOMAIN.
		{"dns not found stays family", &net.DNSError{Err: "no such host", IsNotFound: true}, telemetry.ProbeReasonDNS},
		{"dns unclassified", &net.DNSError{Err: "server misbehaving"}, telemetry.ProbeReasonDNS},
		{"dns timeout wins over not found", &net.DNSError{Err: "i/o timeout", IsTimeout: true, IsNotFound: true}, telemetry.ProbeReasonTimeout},
		{"wrapped refused", &net.OpError{Op: "dial", Err: syscall.ECONNREFUSED}, telemetry.ProbeReasonRefused},
		{"wrapped reset", &net.OpError{Op: "read", Err: syscall.ECONNRESET}, telemetry.ProbeReasonReset},
		{"broken pipe", syscall.EPIPE, telemetry.ProbeReasonReset},
		// Winsock codes as the OS reports them on Windows (the portable syscall.E*
		// values are invented there and never appear in a real chain).
		{"winsock refused", &net.OpError{Op: "dial", Err: &os.SyscallError{Syscall: "connectex", Err: wsaeConnRefused}}, telemetry.ProbeReasonRefused},
		{"winsock reset", &net.OpError{Op: "read", Err: &os.SyscallError{Syscall: "wsarecv", Err: wsaeConnReset}}, telemetry.ProbeReasonReset},
		{"winsock host unreachable", &os.SyscallError{Syscall: "connectex", Err: wsaeHostUnreach}, telemetry.ProbeReasonUnreachable},
		{"winsock timed out", &os.SyscallError{Syscall: "connectex", Err: wsaeTimedOut}, telemetry.ProbeReasonTimeout},
		// TLS refinement, wrapped the way the https transport surfaces it
		// (*url.Error → *tls.CertificateVerificationError → concrete x509 type).
		{"expired cert", x509.CertificateInvalidError{Reason: x509.Expired}, telemetry.ProbeReasonTLSExpired},
		{"expired cert wrapped", &url.Error{Op: "Get", URL: "https://e", Err: &tls.CertificateVerificationError{Err: x509.CertificateInvalidError{Reason: x509.Expired}}}, telemetry.ProbeReasonTLSExpired},
		{"invalid cert non-expiry stays family", x509.CertificateInvalidError{Reason: x509.NotAuthorizedToSign}, telemetry.ProbeReasonTLS},
		{"untrusted chain wrapped", &tls.CertificateVerificationError{Err: x509.UnknownAuthorityError{}}, telemetry.ProbeReasonTLSUntrusted},
		{"hostname mismatch", &url.Error{Op: "Get", URL: "https://e", Err: x509.HostnameError{Certificate: &x509.Certificate{}, Host: "e"}}, telemetry.ProbeReasonTLSHostname},
		{"record header", tls.RecordHeaderError{Msg: "first record does not look like a TLS handshake"}, telemetry.ProbeReasonTLS},
		{"other", errors.New("boom"), telemetry.ProbeReasonOther},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := classifyNetError(c.err); got != c.want {
				t.Fatalf("classifyNetError(%v) = %d, want %d", c.err, got, c.want)
			}
		})
	}
}

func TestCycleReason(t *testing.T) {
	const (
		to = telemetry.ProbeReasonTimeout
		un = telemetry.ProbeReasonUnreachable
		ot = telemetry.ProbeReasonOther
	)
	cases := []struct {
		name       string
		received   int
		reasons    []int
		details    []string
		wantReason int
		wantDetail string
	}{
		{"any received echo is none", 2, []int{to}, []string{"IP_REQ_TIMED_OUT (11010)"}, telemetry.ProbeReasonNone, ""},
		{"no classification stays none", 0, nil, nil, telemetry.ProbeReasonNone, ""},
		{"unreachable beats timeout", 0, []int{to, un}, []string{"IP_REQ_TIMED_OUT (11010)", "IP_DEST_HOST_UNREACHABLE (11003)"}, un, "IP_DEST_HOST_UNREACHABLE (11003)"},
		{"diagnostic beats bare timeout", 0, []int{to, ot}, []string{"t", "IP_BAD_ROUTE (11012)"}, ot, "IP_BAD_ROUTE (11012)"},
		{"unreachable beats other diagnostics", 0, []int{ot, un}, []string{"o", "u"}, un, "u"},
		{"first winning echo's detail", 0, []int{to, to}, []string{"first", "second"}, to, "first"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			reason, detail := cycleReason(c.received, c.reasons, c.details)
			if reason != c.wantReason || detail != c.wantDetail {
				t.Fatalf("cycleReason = (%d, %q), want (%d, %q)", reason, detail, c.wantReason, c.wantDetail)
			}
		})
	}
}

func TestTruncDetail(t *testing.T) {
	if got := truncDetail("  read tcp\n1.2.3.4:80:\t connection reset  "); got != "read tcp 1.2.3.4:80: connection reset" {
		t.Fatalf("whitespace not collapsed: %q", got)
	}
	long := strings.Repeat("界", 300)
	if got := truncDetail(long); len([]rune(got)) != 256 {
		t.Fatalf("cap = %d runes, want 256", len([]rune(got)))
	}
}
