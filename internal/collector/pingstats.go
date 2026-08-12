package collector

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"math"
	"net"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/nettact/protocol/telemetry"
)

// msSince returns milliseconds elapsed since t0 at microsecond resolution.
func msSince(t0 time.Time) float64 {
	return float64(time.Since(t0).Microseconds()) / 1000.0
}

// sleepCtx sleeps for d unless ctx is cancelled first. It returns true if the
// full duration elapsed, false if the context ended early — used to pace ICMP
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

// Winsock error codes (WSAE*). On Windows the portable syscall.E* constants are
// invented APPLICATION_ERROR-range values that never appear in a real error
// chain — the OS reports these Winsock codes instead — so the classifier must
// match both or every refused/unreachable/reset dial on Windows would land in
// "other". syscall.Errno exists on every platform and no Unix errno reaches the
// 10000 range, so the extra comparisons are safe without build tags.
const (
	wsaeAddrInUse    = syscall.Errno(10048) // WSAEADDRINUSE (the local source port is taken)
	wsaeNetUnreach   = syscall.Errno(10051) // WSAENETUNREACH
	wsaeConnAborted  = syscall.Errno(10053) // WSAECONNABORTED (aborted mid-exchange)
	wsaeConnReset    = syscall.Errno(10054) // WSAECONNRESET
	wsaeTimedOut     = syscall.Errno(10060) // WSAETIMEDOUT
	wsaeConnRefused  = syscall.Errno(10061) // WSAECONNREFUSED
	wsaeHostUnreach  = syscall.Errno(10065) // WSAEHOSTUNREACH
)

// isAddrInUse reports whether err is a local bind failure (the source port is
// already taken). Both errno spellings are matched — syscall.EADDRINUSE on Unix,
// WSAEADDRINUSE on Windows — and errors.Is unwraps *net.OpError /
// *os.SyscallError to reach the Errno, so a wrapped dial error still matches.
func isAddrInUse(err error) bool {
	return errors.Is(err, syscall.EADDRINUSE) || errors.Is(err, wsaeAddrInUse)
}

// classifyNetError maps a network-level error (TCP connect, HTTP transport, or a
// DNS system-resolver failure) to a stable telemetry.ProbeReason* code, shared by
// the tcp / http / dns collectors so the meaning never drifts. The order separates
// a fast active refusal ("port closed", host up) from a mid-exchange reset, from a
// deadline ("no answer", host/network down), from no-route, from a
// TLS-handshake/certificate failure, so the code tells the operator which failure
// they have. Where the error type discriminates finer (NXDOMAIN, an expired
// certificate) the refined family-member code is returned; consumers must treat an
// unknown code as at least its code/10 family.
func classifyNetError(err error) int {
	if err == nil {
		return telemetry.ProbeReasonNone
	}
	// A resolution failure classifies as DNS (an https transport surfaces this as a
	// wrapped *net.DNSError; a literal-IP dial the guard could not honor can too).
	// A lookup that TIMED OUT is a timeout, not a name failure — check that first.
	// It stays the DNS FAMILY code even for IsNotFound: the stdlib collapses
	// NXDOMAIN and NODATA (name exists, no record of the queried type) into the
	// same "no such host" / IsNotFound error, so claiming ProbeReasonDNSNXDomain
	// here would tell an operator the domain is gone when only a record is
	// missing. NXDOMAIN is asserted only where the rcode is readable (dnsResult).
	// The raw resolver text still rides along as the detail label.
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		if dnsErr.IsTimeout {
			return telemetry.ProbeReasonTimeout
		}
		return telemetry.ProbeReasonDNS
	}
	switch {
	case errors.Is(err, syscall.ECONNREFUSED), errors.Is(err, wsaeConnRefused):
		return telemetry.ProbeReasonRefused
	case errors.Is(err, syscall.EHOSTUNREACH), errors.Is(err, syscall.ENETUNREACH),
		errors.Is(err, wsaeHostUnreach), errors.Is(err, wsaeNetUnreach):
		return telemetry.ProbeReasonUnreachable
	case errors.Is(err, syscall.ECONNRESET), errors.Is(err, syscall.EPIPE),
		errors.Is(err, wsaeConnReset), errors.Is(err, wsaeConnAborted):
		return telemetry.ProbeReasonReset
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, syscall.ETIMEDOUT),
		errors.Is(err, wsaeTimedOut):
		return telemetry.ProbeReasonTimeout
	}
	// A TLS handshake / certificate failure (the https transport merges all phases
	// into one error, so unlike the TCP collector we detect TLS by error type here).
	if code, ok := classifyTLSError(err); ok {
		return code
	}
	// Any net timeout that did not match a concrete errno above (e.g. the dialer's
	// own deadline) is still a timeout.
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return telemetry.ProbeReasonTimeout
	}
	return telemetry.ProbeReasonOther
}

// classifyTLSError maps a TLS-handshake or certificate-verification failure (the
// reasons an https request fails after the TCP connect succeeds) to the finest
// telemetry.ProbeReason* TLS code; ok is false when err is not TLS-shaped at all.
// The concrete x509 types must be checked before the tls wrappers: errors.As
// unwraps *tls.CertificateVerificationError to reach them, and matching the
// wrapper first would flatten every certificate failure to the family code.
func classifyTLSError(err error) (int, bool) {
	var certInvalid x509.CertificateInvalidError
	if errors.As(err, &certInvalid) {
		// Only Expired has a dedicated code; the other invalidity reasons (bad
		// constraints, too many intermediates, …) stay the family code rather than
		// borrowing a wrong refined meaning.
		if certInvalid.Reason == x509.Expired {
			return telemetry.ProbeReasonTLSExpired, true
		}
		return telemetry.ProbeReasonTLS, true
	}
	var hostnameErr x509.HostnameError
	if errors.As(err, &hostnameErr) {
		return telemetry.ProbeReasonTLSHostname, true
	}
	var unknownAuth x509.UnknownAuthorityError
	if errors.As(err, &unknownAuth) {
		return telemetry.ProbeReasonTLSUntrusted, true
	}
	var (
		recordHdr     tls.RecordHeaderError
		certVerifyErr *tls.CertificateVerificationError
	)
	if errors.As(err, &recordHdr) || errors.As(err, &certVerifyErr) {
		return telemetry.ProbeReasonTLS, true
	}
	// A handshake rejected via a TLS alert (unsupported protocol/cipher, required
	// client cert, …) surfaces as a *net.OpError whose Op is "remote error" (peer
	// alert) or "local error" (our side aborting) — both minted only by crypto/tls;
	// the wrapped alert type itself is unexported, so match on the Op.
	var opErr *net.OpError
	if errors.As(err, &opErr) && (opErr.Op == "remote error" || opErr.Op == "local error") {
		return telemetry.ProbeReasonTLS, true
	}
	return telemetry.ProbeReasonNone, false
}

// truncDetail normalizes a raw failure cause for the error_class detail label:
// runs of whitespace (including newlines a multi-line OS error may carry)
// collapse to single spaces and the result is capped at 256 runes, so a label
// value stays a bounded single line. The text is never localized — the code
// carries the translated meaning, the detail carries the machine truth.
func truncDetail(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if r := []rune(s); len(r) > 256 {
		return string(r[:256])
	}
	return s
}

// errText renders err for the detail label (nil → "").
func errText(err error) string {
	if err == nil {
		return ""
	}
	return truncDetail(err.Error())
}

// withDetail returns a copy of labels carrying the normalized raw cause under
// telemetry.ProbeReasonDetailLabel. Collectors share one label map across a
// cycle's metrics, so the copy keeps the detail on ONLY the error_class sample.
// An empty detail returns labels unchanged: no cause is never an empty label.
func withDetail(labels map[string]string, detail string) map[string]string {
	detail = truncDetail(detail)
	if detail == "" {
		return labels
	}
	out := make(map[string]string, len(labels)+1)
	for k, v := range labels {
		out[k] = v
	}
	out[telemetry.ProbeReasonDetailLabel] = detail
	return out
}

// cycleReason folds the per-echo failure reasons of one ping cycle into a single
// cycle reason plus that reason's raw cause. Any received echo means there is no
// hard failure (None, no detail). With no echo received, the most diagnostic
// reason wins — Unreachable > any other classified failure > bare Timeout — so a
// concrete no-route beats a bare deadline. reasons and details are parallel (one
// entry per lost echo); the detail returned is the one attached to the first echo
// that failed with the winning code. Empty reasons (e.g. a platform that cannot
// classify) stay None: we never fabricate a class the OS didn't give.
func cycleReason(received int, reasons []int, details []string) (int, string) {
	if received > 0 {
		return telemetry.ProbeReasonNone, ""
	}
	best := telemetry.ProbeReasonNone
	for _, r := range reasons {
		if pingReasonRank(r) > pingReasonRank(best) {
			best = r
		}
	}
	if best == telemetry.ProbeReasonNone {
		return best, ""
	}
	for i, r := range reasons {
		if r == best && i < len(details) {
			return best, details[i]
		}
	}
	return best, ""
}

func pingReasonRank(code int) int {
	switch code {
	case telemetry.ProbeReasonUnreachable:
		return 3
	case telemetry.ProbeReasonTimeout:
		return 1
	case telemetry.ProbeReasonNone:
		return 0
	default:
		// Any classified failure that is not a bare deadline (Other, a refined
		// platform code, …) is more diagnostic than a timeout, less than no-route.
		return 2
	}
}

// classifySizeSweep classifies whether ICMP loss rises with payload size, from the
// smallest and largest swept sizes the cycle actually sent. The caller picks those
// two sizes and passes their per-size loss percentages and echo counts. Codes:
//
//	2 = insufficient evidence — either compared size had fewer than two echoes sent
//	1 = size-correlated — large payloads lose far more than small ones (the
//	    physical-layer fingerprint: optics / CRC / FEC / ASIC / policer)
//	0 = flat — loss not size-correlated (the congestion / queuing signature)
//
// The rule is deliberately conservative so a noisy small-sample uptick can never
// be read as physical-layer degradation: correlation requires the large size to
// lose at least twice the small's rate, OR at least 25 points more, AND at least
// 20% on its own.
func classifySizeSweep(lossSmall, lossLarge float64, countSmall, countLarge int) int {
	if countSmall < 2 || countLarge < 2 {
		return 2
	}
	if lossLarge >= math.Max(2.0*lossSmall, lossSmall+25.0) && lossLarge >= 20.0 {
		return 1
	}
	return 0
}

// sizeSweepSample reduces a cycle's per-size tally to the probe.icmp.size_sweep
// sample's value and label set. It returns ok=false when the cycle carries no
// evidence — no swept size was actually attempted — in which case the caller
// emits no sample: a classification over nothing would be a fabricated verdict.
func sizeSweepSample(sweep []sizeSweepFact) (code int, labels map[string]string, ok bool) {
	var (
		sSmall, sLarge   int
		sentS, sentL     int
		recvS, recvL     int
		haveSmall, haveLarge bool
	)
	for _, f := range sweep {
		if f.Sent == 0 {
			continue // only sizes actually sent are evidence
		}
		if !haveSmall || f.Size < sSmall {
			sSmall, sentS, recvS, haveSmall = f.Size, f.Sent, f.Received, true
		}
		if !haveLarge || f.Size > sLarge {
			sLarge, sentL, recvL, haveLarge = f.Size, f.Sent, f.Received, true
		}
	}
	if !haveSmall || !haveLarge {
		return 0, nil, false
	}
	lossSmall := float64(sentS-recvS) / float64(sentS) * 100.0
	lossLarge := float64(sentL-recvL) / float64(sentL) * 100.0
	code = classifySizeSweep(lossSmall, lossLarge, sentS, sentL)
	labels = map[string]string{
		telemetry.SizeSmallLabel:  strconv.Itoa(sSmall),
		telemetry.SizeLargeLabel:  strconv.Itoa(sLarge),
		telemetry.LossSmallLabel:  fmt.Sprintf("%.1f", lossSmall),
		telemetry.LossLargeLabel:  fmt.Sprintf("%.1f", lossLarge),
		telemetry.CountSmallLabel: strconv.Itoa(sentS),
		telemetry.CountLargeLabel: strconv.Itoa(sentL),
	}
	return code, labels, true
}

// pingCycleResult is one ICMP probe cycle summarized: the loss and the RTT
// distribution over the received echoes. Emitted as several Metric rows sharing
// one TS+Target+MonitorID (loss + sent + samples always; avg/min/max only when
// any echo was received; jitter only when >=2 were).
type pingCycleResult struct {
	Loss float64 // percent over the echoes actually SENT
	// Sent is how many echoes the cycle attempted. Normally the configured
	// packet count; less when the machine's probe budget could not admit them all
	// inside the cycle's timing budget, and zero when it admitted none — which
	// the caller turns into no Result at all rather than a fabricated failure.
	// The synthetic-failure paths (an unusable proxy pin, a resolve failure, no
	// gateway on the NIC) set it to the configured count: those are complete
	// verdicts about the target, not truncated measurements.
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
	// Detail is the raw underlying cause behind Reason (OS error text, IP_STATUS
	// name); empty when Reason is None or the platform could not say more.
	Detail string
	// Sweep carries the per-size tally of a size-sweeping cycle (ProbeParams.SizeSweep),
	// one entry per swept size in pcfg.SweepSizes order. Nil when the sweep is off or
	// the result was built without running echoes (the synthetic-failure paths): those
	// never emit a size_sweep sample, because a classification over nothing would be a
	// fabricated verdict about the target.
	Sweep []sizeSweepFact
}

// sizeSweepFact is one swept size's tally within a single cycle: how many echoes
// of that size were actually attempted and how many came back. A sweeping cycle
// round-robins its echoes across pcfg.SweepSizes, so each swept size gets a sample
// the size-correlation classifier (classifySizeSweep) can compare.
type sizeSweepFact struct {
	Size     int
	Sent     int
	Received int
}

// appendICMPMetrics emits the shared ICMP metric set for one cycle result. loss,
// sent and samples are always emitted (samples=0 is an honest "0 of N received",
// not a fake latency); avg/min/max only when at least one echo returned; jitter
// only when the distribution has >=2 samples.
func appendICMPMetrics(res *Result, now time.Time, monitorID string, configSerial int, target string, layer telemetry.HealthLayer, labels map[string]string, r pingCycleResult) {
	mk := func(kind telemetry.MetricKind, v float64, unit string) telemetry.Metric {
		return telemetry.Metric{TS: now, Kind: kind, Target: target, Layer: layer, Value: v, Unit: unit, Labels: labels, MonitorID: monitorID, ConfigSerial: configSerial}
	}
	// error_class every cycle (ProbeReasonNone when any echo returned), mirroring
	// the TCP collector — the server freezes this onto a fired alert's evidence.
	// The raw cause rides only on this sample, on its own label map: the shared
	// labels the other cycle metrics alias must never carry a failure detail.
	ec := mk(telemetry.ICMPErrorClass, float64(r.Reason), telemetry.UnitCode)
	if r.Reason != telemetry.ProbeReasonNone {
		ec.Labels = withDetail(labels, r.Detail)
	}
	res.Metrics = append(res.Metrics,
		mk(telemetry.ICMPLoss, r.Loss, telemetry.UnitPct),
		// Sent travels with every round so the server can tell a complete round
		// from one the agent's probe budget truncated, and refuse to move
		// availability state on the latter.
		mk(telemetry.ICMPSent, float64(r.Sent), telemetry.UnitCount),
		mk(telemetry.ICMPSamples, float64(r.Received), telemetry.UnitCount),
		ec,
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
	// A size-sweeping cycle (ProbeParams.SizeSweep) adds one size_sweep sample with
	// the size-correlation classification and the compared sizes' evidence as labels.
	// The facts ride on their own label map: the shared labels the other cycle
	// metrics alias must never pick them up.
	if len(r.Sweep) > 0 {
		if code, sl, ok := sizeSweepSample(r.Sweep); ok {
			merged := make(map[string]string, len(labels)+len(sl))
			for k, v := range labels {
				merged[k] = v
			}
			for k, v := range sl {
				merged[k] = v
			}
			ss := mk(telemetry.ICMPSizeSweep, float64(code), telemetry.UnitCode)
			ss.Labels = merged
			res.Metrics = append(res.Metrics, ss)
		}
	}
}
