package traceroute

import (
	"context"
	"net/netip"
	"testing"
	"time"

	pcfg "github.com/nettact/protocol/config"
	"github.com/nettact/protocol/permission"
	"github.com/nettact/protocol/telemetry"
)

func TestRunRejectsInvalidAndExpiredRequestsWithoutProbing(t *testing.T) {
	e := New(nil, permission.Set{}, permission.Set{}, permission.Set{}, 1)
	for _, tc := range []struct {
		name   string
		req    pcfg.TraceRequest
		status string
		reason string
	}{
		{"mode", pcfg.TraceRequest{ReportID: "bad-mode", Mode: "udp", DestinationHost: "1.1.1.1"}, telemetry.TraceStatusFailed, reasonInvalidMode},
		{"destination", pcfg.TraceRequest{ReportID: "bad-dest", Mode: pcfg.TraceModeICMP}, telemetry.TraceStatusFailed, reasonInvalidDestination},
		{"port", pcfg.TraceRequest{ReportID: "bad-port", Mode: pcfg.TraceModeTCP, DestinationHost: "1.1.1.1"}, telemetry.TraceStatusFailed, reasonInvalidPort},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := e.Run(context.Background(), tc.req)
			if got.Status != tc.status || got.Reason != tc.reason {
				t.Fatalf("result = %s/%s, want %s/%s", got.Status, got.Reason, tc.status, tc.reason)
			}
		})
	}

	granted := permission.FromStrings([]string{string(permission.DiagnosticTracerouteICMP)})
	e = New(nil, granted, granted, granted, 1)
	got := e.Run(context.Background(), pcfg.TraceRequest{
		ReportID: "expired", Mode: pcfg.TraceModeICMP, DestinationHost: "1.1.1.1", Deadline: time.Now().Add(-time.Second),
	})
	if got.Status != telemetry.TraceStatusTimedOut || got.Reason != reasonDeadlineExceeded {
		t.Fatalf("expired result = %s/%s", got.Status, got.Reason)
	}
}

func TestWalkContinuesPastTimeoutHopAndStopsAtDestination(t *testing.T) {
	e := &Engine{}
	dest := netip.MustParseAddr("192.0.2.10")
	probe := func(_ context.Context, _ netip.Addr, _ int, ttl int, _ time.Duration) (probeOutcome, error) {
		switch ttl {
		case 1:
			return probeOutcome{timeout: true}, nil
		case 2:
			return probeOutcome{responder: netip.MustParseAddr("192.0.2.1"), rttMs: 2.5}, nil
		default:
			return probeOutcome{responder: dest, reached: true, rttMs: 3.5}, nil
		}
	}
	out := e.walk(context.Background(), context.Background(), probe, dest, 0, 8, 1, time.Second, time.Now().Add(time.Minute))
	if out.status != telemetry.TraceStatusSucceeded || !out.reached || out.reachedTTL != 3 || len(out.hops) != 3 {
		t.Fatalf("walk = %+v", out)
	}
	if !out.hops[0].Attempts[0].Timeout || out.hops[1].Attempts[0].ResponderAddr != "192.0.2.1" {
		t.Fatalf("hop attempts = %+v", out.hops)
	}
}

func TestTraceBoundsClampDeterministically(t *testing.T) {
	if got := clampInt(1000, defaultMaxHops, 1, maxHopsCeiling); got != maxHopsCeiling {
		t.Fatalf("max hops clamp = %d", got)
	}
	if got := clampTotalTimeout(999999); got != maxTotalTimeout {
		t.Fatalf("timeout clamp = %v", got)
	}
	if got := perAttemptBudget(time.Second, 64); got != minPerAttempt {
		t.Fatalf("minimum per-attempt budget = %v", got)
	}
	if got := perAttemptBudget(time.Hour, 1); got != maxPerAttempt {
		t.Fatalf("maximum per-attempt budget = %v", got)
	}
}
