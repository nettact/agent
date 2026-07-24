package collector

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"syscall"
	"time"

	"github.com/nettact/protocol/telemetry"
)

// msSince returns milliseconds elapsed since t0 at microsecond resolution.
func msSince(t0 time.Time) float64 {
	return float64(time.Since(t0).Microseconds()) / 1000.0
}

// sleepCtx sleeps for d unless ctx is cancelled first. It returns true if the
// full duration elapsed, false if the context ended early — used to space ICMP
// echoes within a cycle without ignoring a shutdown/deadline.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// pingStats is the single口径 for the ICMP stability metrics, shared by the
// public-ping and gateway collectors. rtts holds ONLY the echoes actually
// received, in send order, so losses are already excluded (never counted as a
// zero RTT). It returns the average / minimum / maximum RTT in ms and the IPDV
// jitter: the mean absolute difference of adjacent received RTTs. Jitter needs at
// least two samples to exist, so haveJitter is false for 0 or 1 received — the
// caller then emits NO jitter sample (a chart gap, not a synthetic 0).
func pingStats(rtts []time.Duration) (avgMs, minMs, maxMs, jitterMs float64, haveJitter bool) {
	n := len(rtts)
	if n == 0 {
		return 0, 0, 0, 0, false
	}
	toMs := func(d time.Duration) float64 { return float64(d.Microseconds()) / 1000.0 }
	sum, lo, hi := time.Duration(0), rtts[0], rtts[0]
	for _, r := range rtts {
		sum += r
		if r < lo {
			lo = r
		}
		if r > hi {
			hi = r
		}
	}
	avgMs = toMs(sum) / float64(n)
	minMs = toMs(lo)
	maxMs = toMs(hi)
	if n >= 2 {
		var diff time.Duration
		for i := 1; i < n; i++ {
			d := rtts[i] - rtts[i-1]
			if d < 0 {
				d = -d
			}
			diff += d
		}
		jitterMs = toMs(diff) / float64(n-1)
		haveJitter = true
	}
	return
}

// classifyNetError maps a network-level error (TCP connect, HTTP transport, or a
// DNS system-resolver failure) to a stable telemetry.ProbeReason* code, shared by
// the tcp / http / dns collectors so the meaning never drifts. The order separates
// a fast active refusal ("port closed", host up) from a deadline ("no answer",
// host/network down), from no-route, from a TLS-handshake/certificate failure, so
// the code tells the operator which failure they have.
func classifyNetError(err error) int {
	if err == nil {
		return telemetry.ProbeReasonNone
	}
	// A resolution failure classifies as DNS (an https transport surfaces this as a
	// wrapped *net.DNSError; a literal-IP dial the guard could not honor can too).
	// A lookup that TIMED OUT is a timeout, not a name failure — check that first.
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		if dnsErr.IsTimeout {
			return telemetry.ProbeReasonTimeout
		}
		return telemetry.ProbeReasonDNS
	}
	switch {
	case errors.Is(err, syscall.ECONNREFUSED):
		return telemetry.ProbeReasonRefused
	case errors.Is(err, syscall.EHOSTUNREACH), errors.Is(err, syscall.ENETUNREACH):
		return telemetry.ProbeReasonUnreachable
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, syscall.ETIMEDOUT):
		return telemetry.ProbeReasonTimeout
	}
	// A TLS handshake / certificate failure (the https transport merges all phases
	// into one error, so unlike the TCP collector we detect TLS by error type here).
	if isTLSError(err) {
		return telemetry.ProbeReasonTLS
	}
	// Any net timeout that did not match a concrete errno above (e.g. the dialer's
	// own deadline) is still a timeout.
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return telemetry.ProbeReasonTimeout
	}
	return telemetry.ProbeReasonOther
}

// isTLSError reports whether err is a TLS-handshake or certificate-verification
// failure (the reasons an https request fails after the TCP connect succeeds).
func isTLSError(err error) bool {
	var (
		certInvalid   x509.CertificateInvalidError
		unknownAuth   x509.UnknownAuthorityError
		hostnameErr   x509.HostnameError
		recordHdr     tls.RecordHeaderError
		certVerifyErr *tls.CertificateVerificationError
	)
	if errors.As(err, &certInvalid) || errors.As(err, &unknownAuth) ||
		errors.As(err, &hostnameErr) || errors.As(err, &recordHdr) ||
		errors.As(err, &certVerifyErr) {
		return true
	}
	// A handshake rejected via a TLS alert (unsupported protocol/cipher, required
	// client cert, …) surfaces as a *net.OpError whose Op is "remote error" (peer
	// alert) or "local error" (our side aborting) — both minted only by crypto/tls;
	// the wrapped alert type itself is unexported, so match on the Op.
	var opErr *net.OpError
	if errors.As(err, &opErr) && (opErr.Op == "remote error" || opErr.Op == "local error") {
		return true
	}
	return false
}

// cycleReason folds the per-echo failure reasons of one ping cycle into a single
// cycle reason. Any received echo means there is no hard failure (None). With no
// echo received, the most diagnostic reason wins — Unreachable > Other > Timeout —
// so a concrete no-route beats a bare deadline. Empty reasons (e.g. a platform
// that cannot classify) stay None: we never fabricate a class the OS didn't give.
func cycleReason(received int, reasons []int) int {
	if received > 0 {
		return telemetry.ProbeReasonNone
	}
	best := telemetry.ProbeReasonNone
	for _, r := range reasons {
		if pingReasonRank(r) > pingReasonRank(best) {
			best = r
		}
	}
	return best
}

func pingReasonRank(code int) int {
	switch code {
	case telemetry.ProbeReasonUnreachable:
		return 3
	case telemetry.ProbeReasonOther:
		return 2
	case telemetry.ProbeReasonTimeout:
		return 1
	default: // None and anything a raw echo can't produce
		return 0
	}
}

// pingCycleResult is one ICMP probe cycle summarized: the loss and the RTT
// distribution over the received echoes. Emitted as several Metric rows sharing
// one TS+Target+MonitorID (loss + samples always; avg/min/max only when any echo
// was received; jitter only when >=2 were).
type pingCycleResult struct {
	Loss       float64 // percent over the configured packet count
	Sent       int
	Received   int
	AvgMs      float64
	MinMs      float64
	MaxMs      float64
	JitterMs   float64
	HaveJitter bool
	// Reason classifies a fully-failed cycle (Received==0) into a
	// telemetry.ProbeReason* code; ProbeReasonNone whenever any echo returned.
	Reason int
}

// appendICMPMetrics emits the shared ICMP metric set for one cycle result. loss
// and samples are always emitted (samples=0 is an honest "0 of N received", not a
// fake latency); avg/min/max only when at least one echo returned; jitter only
// when the distribution has >=2 samples.
func appendICMPMetrics(res *Result, now time.Time, monitorID string, configSerial int, target string, layer telemetry.HealthLayer, labels map[string]string, r pingCycleResult) {
	mk := func(kind telemetry.MetricKind, v float64, unit string) telemetry.Metric {
		return telemetry.Metric{TS: now, Kind: kind, Target: target, Layer: layer, Value: v, Unit: unit, Labels: labels, MonitorID: monitorID, ConfigSerial: configSerial}
	}
	res.Metrics = append(res.Metrics,
		mk(telemetry.ICMPLoss, r.Loss, telemetry.UnitPct),
		mk(telemetry.ICMPSamples, float64(r.Received), telemetry.UnitCount),
		// error_class every cycle (ProbeReasonNone when any echo returned), mirroring
		// the TCP collector — the server freezes this onto a fired alert's evidence.
		mk(telemetry.ICMPErrorClass, float64(r.Reason), telemetry.UnitCode),
	)
	if r.Received > 0 {
		res.Metrics = append(res.Metrics,
			mk(telemetry.ICMPRTTms, r.AvgMs, telemetry.UnitMs),
			mk(telemetry.ICMPRTTMin, r.MinMs, telemetry.UnitMs),
			mk(telemetry.ICMPRTTMax, r.MaxMs, telemetry.UnitMs),
		)
		if r.HaveJitter {
			res.Metrics = append(res.Metrics, mk(telemetry.ICMPJitter, r.JitterMs, telemetry.UnitMs))
		}
	}
}
