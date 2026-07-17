package collector

import (
	"context"
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

// classifyConnectError maps a TCP connect-phase error to a stable
// telemetry.TCPErr* code. It is only called for the raw connect (DNS and TLS
// failures are classified by phase at the call site, so they never reach here).
// The order separates a fast active refusal ("port closed", host up) from a
// deadline ("no answer", host/network down) and from no-route, so the code tells
// the operator which failure they have.
func classifyConnectError(err error) int {
	if err == nil {
		return telemetry.TCPErrNone
	}
	// A resolution failure can still surface here defensively (e.g. a literal-IP
	// dial that the guard could not honor); classify it as DNS.
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return telemetry.TCPErrDNS
	}
	switch {
	case errors.Is(err, syscall.ECONNREFUSED):
		return telemetry.TCPErrRefused
	case errors.Is(err, syscall.EHOSTUNREACH), errors.Is(err, syscall.ENETUNREACH):
		return telemetry.TCPErrUnreachable
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, syscall.ETIMEDOUT):
		return telemetry.TCPErrTimeout
	}
	// Any net timeout that did not match a concrete errno above (e.g. the dialer's
	// own deadline) is still a timeout.
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return telemetry.TCPErrTimeout
	}
	return telemetry.TCPErrOther
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
