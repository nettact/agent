package collector

import (
	"context"
	"errors"
	"net"
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
		{"dns", &net.DNSError{Err: "no such host", IsNotFound: true}, telemetry.ProbeReasonDNS},
		{"wrapped refused", &net.OpError{Op: "dial", Err: syscall.ECONNREFUSED}, telemetry.ProbeReasonRefused},
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
