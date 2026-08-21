package conn

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"strings"
	"syscall"

	"github.com/nettact/protocol/wire"
)

// Reason is a stable, machine-readable classification of why a connection
// attempt ended. It exists because "the agent is not connected" is useless on
// its own: an expired certificate, a spent credential and an unplugged cable
// all present as a silent retry loop, and the three have nothing in common in
// what the operator has to do next.
//
// The codes are a UI contract, not an internal detail. The LuCI status page
// translates them into a sentence per code, and the docs table them against
// fixes, so renaming one silently degrades a router panel to an untranslated
// string. Nothing in Go switches on them — the error values remain the truth
// for control flow (see the terminal sentinels above) — which is exactly why
// they can stay a closed, hand-curated vocabulary rather than growing one
// entry per errno.
//
// The classification is always paired with the raw error text at the surface
// that shows it: the code says which kind of broken this is, the text says
// which host and which certificate.
type Reason string

const (
	// ReasonDNS: the server's hostname did not resolve.
	ReasonDNS Reason = "dns"
	// ReasonRefused: the host answered, nothing was listening on the port.
	ReasonRefused Reason = "refused"
	// ReasonTimeout: the dial or the handshake ran out the clock — the usual
	// shape of a firewall that drops instead of rejecting.
	ReasonTimeout Reason = "timeout"
	// ReasonTLSCertExpired: the server's certificate is outside its validity
	// window. On a router this is as often a wrong clock as a stale cert, which
	// is why it is worth separating from every other TLS failure.
	ReasonTLSCertExpired Reason = "tls_cert_expired"
	// ReasonTLSCertUntrusted: the certificate chain does not reach a trusted
	// root — self-signed, or a CA bundle the device does not carry.
	ReasonTLSCertUntrusted Reason = "tls_cert_untrusted"
	// ReasonTLSHostname: a valid certificate for a different name than the URL
	// asks for.
	ReasonTLSHostname Reason = "tls_hostname"
	// ReasonTLS: any other TLS handshake failure (version, cipher, a peer that
	// is not speaking TLS at all).
	ReasonTLS Reason = "tls"
	// ReasonAuth: the server refused the agent credential on the upgrade
	// request. Distinct from the terminal revocation below: this is a 401/403
	// the runner keeps retrying against, because the fix may be at the server.
	ReasonAuth Reason = "auth"
	// ReasonAckTimeout: the session stayed open but stopped acknowledging
	// packets — a link that swallows traffic, which is as dead as a closed one.
	ReasonAckTimeout Reason = "ack_timeout"
	// ReasonSuperseded: another process connected with this credential.
	ReasonSuperseded Reason = "superseded"
	// ReasonSchemaMismatch: the server rejected this agent's schema version.
	ReasonSchemaMismatch Reason = "schema_mismatch"
	// ReasonUnsupportedSubprotocol: the server would not accept either wire
	// format this agent offered on the upgrade. Retryable like any pairing
	// problem — nothing here is broken and the credential is fine — but it needs
	// its own name: it is a configuration mismatch with a specific fix, and left
	// as a generic session failure it reads as an unreliable network and sends
	// the operator to look at cables.
	ReasonUnsupportedSubprotocol Reason = "unsupported_subprotocol"
	// ReasonProtocolError: the server refused a frame as not allowed at that
	// point in the session. Also retryable, and named for the same reason: it
	// says the fault is in one side's implementation or in the pairing of the
	// two versions, not in the link, and that is the one thing an anonymous
	// reconnect loop cannot tell anybody.
	ReasonProtocolError Reason = "protocol_error"
	// ReasonRevoked: the agent was deleted server-side; it must re-enroll.
	ReasonRevoked Reason = "revoked"
	// ReasonNetwork is the catch-all: something below the application layer
	// failed and none of the specific shapes matched. The raw error text is the
	// only thing that helps here, so surfaces must always show it alongside.
	ReasonNetwork Reason = "network"
)

// wsaeConnRefused is Winsock's WSAECONNREFUSED. Windows surfaces a refused
// connection as this raw Winsock number, and syscall.ECONNREFUSED on Windows is
// a placeholder from a different numbering scheme entirely — so the obvious
// errors.Is against it never matches there, and neither does a substring test
// ("the target machine actively refused it" shares no wording with the POSIX
// message). Comparing the number directly is the only check that works on both,
// and it is safe to run everywhere: no POSIX errno reaches five digits.
const wsaeConnRefused = syscall.Errno(10061)

// Classify maps a session or dial error to its Reason.
//
// Order is significant and runs most-specific first: an expired certificate
// reaches us wrapped in a *url.Error inside a *net.OpError and would answer
// yes to a plain "is this a network error" test, so the typed checks have to
// come before the generic ones. The final fallback is deliberately vague
// rather than a guess.
func Classify(err error) Reason {
	if err == nil {
		return ""
	}

	// Application close codes first: the server told us exactly what happened,
	// and CloseStatus sees through %w for both the WebSocket and pipe links.
	switch wire.CloseStatus(err) {
	case wire.CloseSuperseded:
		return ReasonSuperseded
	case wire.CloseUnsupportedSchema:
		return ReasonSchemaMismatch
	case wire.CloseUnsupportedSubprotocol:
		return ReasonUnsupportedSubprotocol
	case wire.CloseProtocolError:
		return ReasonProtocolError
	case wire.CloseRevoked:
		return ReasonRevoked
	}

	// Sentinels we attach ourselves, where the transport error alone would be
	// misleading (an HTTP 401 arrives as a generic dial failure).
	switch {
	case errors.Is(err, ErrAuthRejected):
		return ReasonAuth
	case errors.Is(err, errAckTimeout):
		return ReasonAckTimeout
	}

	// TLS. Go wraps verification failures in *tls.CertificateVerificationError,
	// which unwraps to the x509 error underneath, so errors.As reaches them.
	var certInvalid x509.CertificateInvalidError
	if errors.As(err, &certInvalid) {
		if certInvalid.Reason == x509.Expired {
			return ReasonTLSCertExpired
		}
		return ReasonTLS
	}
	var unknownAuthority x509.UnknownAuthorityError
	if errors.As(err, &unknownAuthority) {
		return ReasonTLSCertUntrusted
	}
	var hostnameErr x509.HostnameError
	if errors.As(err, &hostnameErr) {
		return ReasonTLSHostname
	}

	// Non-certificate TLS failures: an https:// URL pointed at a plaintext
	// port, or a handshake the two sides could not agree on. Both are
	// configuration mistakes with an obvious fix, and reporting them as "the
	// server could not be reached" sends the operator to look at the network
	// instead.
	//
	// The plaintext-port case arrives as ErrSchemeMismatch, not as a TLS error:
	// net/http recognises an HTTP response on a TLS connection and substitutes
	// its own error, so the tls.RecordHeaderError underneath never surfaces.
	// The record error is still matched below for the paths that do not go
	// through net/http.
	if errors.Is(err, http.ErrSchemeMismatch) {
		return ReasonTLS
	}
	var recordErr tls.RecordHeaderError
	if errors.As(err, &recordErr) {
		return ReasonTLS
	}
	var alertErr tls.AlertError
	if errors.As(err, &alertErr) {
		return ReasonTLS
	}
	// The typed checks above do not cover everything: crypto/tls reports most
	// local handshake failures — an unsupported protocol version, no mutually
	// acceptable cipher suite — as plain errors.New values with no exported
	// type to match. Their one reliable marker is the package's own "tls: "
	// prefix, which it puts on every error it constructs. Matching text is a
	// last resort, and it is safe only here: every certificate error has
	// already been classified more precisely above, so nothing this catches
	// could have been named better.
	if strings.Contains(err.Error(), "tls: ") {
		return ReasonTLS
	}

	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return ReasonDNS
	}

	var errno syscall.Errno
	if errors.As(err, &errno) && (errno == syscall.ECONNREFUSED || errno == wsaeConnRefused) {
		return ReasonRefused
	}

	// Timeouts last among the specifics: a DNS lookup or a TLS handshake that
	// timed out is better reported as the step that stalled, and both were
	// already matched above.
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return ReasonTimeout
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return ReasonTimeout
	}

	return ReasonNetwork
}
