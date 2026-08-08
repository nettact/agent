package conn

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/nettact/protocol/wire"
)

// TestClassify pins the reason vocabulary to the error shapes that actually
// reach it. Every case is wrapped the way the real path wraps it — a bare
// x509 error is not what a failed dial returns — because the wrapping is
// exactly what the errors.As chain has to see through.
func TestClassify(t *testing.T) {
	// dialWrap mimics the layers a dial failure arrives in: our own "dial: %w"
	// over *url.Error over *net.OpError.
	dialWrap := func(inner error) error {
		return fmt.Errorf("dial: %w", &url.Error{
			Op:  "Get",
			URL: "https://nettact.example.com",
			Err: &net.OpError{Op: "dial", Net: "tcp", Err: inner},
		})
	}

	cases := []struct {
		name string
		err  error
		want Reason
	}{
		{"nil", nil, ""},
		{
			"superseded close",
			fmt.Errorf("read: %w", &wire.CloseError{Code: wire.CloseSuperseded, Reason: "superseded"}),
			ReasonSuperseded,
		},
		{
			"schema close",
			fmt.Errorf("read: %w", &wire.CloseError{Code: wire.CloseUnsupportedSchema}),
			ReasonSchemaMismatch,
		},
		{
			"revoked close",
			fmt.Errorf("read: %w", &wire.CloseError{Code: wire.CloseRevoked}),
			ReasonRevoked,
		},
		{
			"auth rejected",
			fmt.Errorf("dial: %w (HTTP 401): bad handshake", ErrAuthRejected),
			ReasonAuth,
		},
		{
			"ack timeout",
			fmt.Errorf("ack timeout for seq=%d: %w", 7, errAckTimeout),
			ReasonAckTimeout,
		},
		{
			"expired certificate",
			dialWrap(&tls.CertificateVerificationError{
				Err: x509.CertificateInvalidError{Reason: x509.Expired},
			}),
			ReasonTLSCertExpired,
		},
		{
			"certificate not yet valid for another reason",
			dialWrap(&tls.CertificateVerificationError{
				Err: x509.CertificateInvalidError{Reason: x509.CANotAuthorizedForThisName},
			}),
			ReasonTLS,
		},
		{
			"untrusted chain",
			dialWrap(&tls.CertificateVerificationError{Err: x509.UnknownAuthorityError{}}),
			ReasonTLSCertUntrusted,
		},
		{
			"wrong hostname",
			dialWrap(&tls.CertificateVerificationError{
				Err: x509.HostnameError{Host: "nettact.example.com"},
			}),
			ReasonTLSHostname,
		},
		{
			"https against a plaintext port",
			dialWrap(tls.RecordHeaderError{Msg: "first record does not look like a TLS handshake"}),
			ReasonTLS,
		},
		{
			"handshake alert",
			dialWrap(tls.AlertError(40)), // handshake_failure
			ReasonTLS,
		},
		{
			"no mutually supported protocol version",
			// crypto/tls reports this as a plain error with no exported type;
			// its "tls: " prefix is the only thing left to match on.
			dialWrap(errors.New("tls: server selected unsupported protocol version 303")),
			ReasonTLS,
		},
		{
			"dns failure",
			fmt.Errorf("dial: %w", &url.Error{
				Op:  "Get",
				URL: "https://nowhere.invalid",
				Err: &net.OpError{Op: "dial", Err: &net.DNSError{Err: "no such host", IsNotFound: true}},
			}),
			ReasonDNS,
		},
		{
			"connection refused (posix errno)",
			dialWrap(os.NewSyscallError("connect", syscall.ECONNREFUSED)),
			ReasonRefused,
		},
		{
			"connection refused (winsock errno)",
			dialWrap(os.NewSyscallError("connect", wsaeConnRefused)),
			ReasonRefused,
		},
		{
			"dial deadline",
			fmt.Errorf("dial: %w", context.DeadlineExceeded),
			ReasonTimeout,
		},
		{
			"i/o timeout",
			dialWrap(&timeoutErr{}),
			ReasonTimeout,
		},
		{
			"anything else",
			fmt.Errorf("dial: %w", errors.New("connection reset by peer")),
			ReasonNetwork,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Classify(tc.err); got != tc.want {
				t.Errorf("Classify(%v) = %q, want %q", tc.err, got, tc.want)
			}
		})
	}
}

// TestClassifyDNSTimeoutPrefersDNS: a name lookup that timed out satisfies both
// the DNS and the timeout test. The step that stalled is the useful answer, so
// ordering must keep DNS ahead of the generic timeout check.
func TestClassifyDNSTimeoutPrefersDNS(t *testing.T) {
	err := fmt.Errorf("dial: %w", &net.DNSError{Err: "i/o timeout", IsTimeout: true})
	if got := Classify(err); got != ReasonDNS {
		t.Errorf("Classify(dns timeout) = %q, want %q", got, ReasonDNS)
	}
}

// TestClassifyRealPlaintextPort dials a real plaintext listener over https,
// which is what "I typed https:// and the server is on http" actually looks
// like. It is here because the constructed cases above prove only that the
// types are matched, not that these are the types the path produces — the
// original bug was a classification that read plausibly and never fired.
func TestClassifyRealPlaintextPort(t *testing.T) {
	// A plain TCP listener that says something decidedly not-TLS. It must hold
	// the connection open afterwards: closing immediately resets the peer
	// before it has read the record header, and the client then reports an
	// aborted connection — which is a truthful "network", not the TLS mistake
	// this test is about.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	done := make(chan struct{})
	defer close(done)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close() //nolint:errcheck
				_, _ = c.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
				<-done
			}()
		}
	}()

	opts := testOptions("https://"+ln.Addr().String(), wire.SubprotocolJSON)
	dial, err := wsDialer(opts)
	if err != nil {
		t.Fatalf("wsDialer: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err = dial(ctx, "token"); err == nil {
		t.Fatal("dialing a plaintext port over https succeeded")
	}
	if got := Classify(err); got != ReasonTLS {
		t.Errorf("Classify(%v) = %q, want %q", err, got, ReasonTLS)
	}
}

// timeoutErr is a net.Error that only reports a timeout, standing in for the
// deadline errors the runtime produces at a lower layer.
type timeoutErr struct{}

func (*timeoutErr) Error() string { return "i/o timeout" }
func (*timeoutErr) Timeout() bool { return true }
func (*timeoutErr) Temporary() bool {
	return true
}
