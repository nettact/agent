package proxydial

import (
	"errors"

	"github.com/nettact/protocol/telemetry"
)

// ProxyError carries a probe failure that happened on the EGRESS PATH, together
// with the telemetry reason code the collector should emit.
//
// It exists so the classification is made once, where the protocol detail is (a
// SOCKS5 reply byte, an HTTP CONNECT status, a WireGuard handshake timeout), and
// not re-derived from an opaque error string by each collector. The distinction it
// preserves is the whole point of the feature: "the proxy is down" and "the
// monitored service is down" lead to opposite actions, and every collector's
// generic classifyNetError would flatten both into a timeout.
type ProxyError struct {
	// Reason is the telemetry.ProbeReason* code to report.
	Reason int
	// AtTarget marks the rare case where the proxy successfully reached the target
	// and the TARGET is what failed (a SOCKS5 "connection refused" reply). Reason
	// then carries the target's own reason rather than a proxy_* one, and callers
	// must not describe the failure as a proxy problem.
	AtTarget bool
	Err      error
}

func (e *ProxyError) Error() string {
	if e.Err == nil {
		return "proxy error"
	}
	return e.Err.Error()
}

func (e *ProxyError) Unwrap() error { return e.Err }

// ProxyReason extracts the reason code from a proxy failure. ok is false when err
// is not a proxy failure at all, so callers fall through to their own
// classifyNetError instead of mislabeling an ordinary transport error.
func ProxyReason(err error) (reason int, atTarget bool, ok bool) {
	var pe *ProxyError
	if errors.As(err, &pe) {
		return pe.Reason, pe.AtTarget, true
	}
	// A pin that could not be honored at all never reached the wire. It is a probe
	// failure — reported as such rather than retried directly — because falling back
	// would change the egress path the operator chose.
	if errors.Is(err, ErrUnknownProxy) || errors.Is(err, ErrProxyInit) || errors.Is(err, ErrProxyKindUnsupported) {
		return telemetry.ProbeReasonProxyConfig, false, true
	}
	return 0, false, false
}
