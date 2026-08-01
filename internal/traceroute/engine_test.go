package traceroute

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/nettact/agent/internal/netguard"
	"github.com/nettact/agent/probepolicy"
	pcfg "github.com/nettact/protocol/config"
	"github.com/nettact/protocol/permission"
	"github.com/nettact/protocol/telemetry"
)

func TestRunRejectsInvalidAndExpiredRequestsWithoutProbing(t *testing.T) {
	e := New(nil, permission.Set{}, permission.Set{}, permission.Set{}, 1, nil)
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
			got := e.Run(context.Background(), tc.req, time.Now())
			if got.Status != tc.status || got.Reason != tc.reason {
				t.Fatalf("result = %s/%s, want %s/%s", got.Status, got.Reason, tc.status, tc.reason)
			}
		})
	}

	granted := permission.FromStrings([]string{string(permission.DiagnosticTracerouteICMP)})
	e = New(nil, granted, granted, granted, 1, nil)
	// A spent budget (the server pushed a window the trace can no longer fit in) is
	// terminal-at-start, and never sends a probe.
	for _, budgetMs := range []int{0, -1} {
		got := e.Run(context.Background(), pcfg.TraceRequest{
			ReportID: "expired", Mode: pcfg.TraceModeICMP, DestinationHost: "1.1.1.1", BudgetMs: budgetMs,
		}, time.Now())
		if got.Status != telemetry.TraceStatusTimedOut || got.Reason != reasonDeadlineExceeded {
			t.Fatalf("budget %dms result = %s/%s, want %s/%s", budgetMs,
				got.Status, got.Reason, telemetry.TraceStatusTimedOut, reasonDeadlineExceeded)
		}
	}

	// The budget runs from receivedAt, not from entry into Run: a request whose
	// window already elapsed before the worker was scheduled must not be handed a
	// fresh window just because it started late.
	got := e.Run(context.Background(), pcfg.TraceRequest{
		ReportID: "stale", Mode: pcfg.TraceModeICMP, DestinationHost: "1.1.1.1", BudgetMs: 1_000,
	}, time.Now().Add(-2*time.Second))
	if got.Status != telemetry.TraceStatusTimedOut || got.Reason != reasonDeadlineExceeded {
		t.Fatalf("stale receivedAt result = %s/%s, want %s/%s",
			got.Status, got.Reason, telemetry.TraceStatusTimedOut, reasonDeadlineExceeded)
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

// egressRequest is a well-formed in-tunnel trace request; the engine must
// honor or fail-close it depending on what the resolver says.
func egressRequest() pcfg.TraceRequest {
	return pcfg.TraceRequest{
		ReportID: "egress-1", Mode: pcfg.TraceModeICMP, DestinationHost: "192.0.2.10",
		MaxHops: 8, AttemptsPerHop: 1, TotalTimeoutMs: 5_000, BudgetMs: 30_000,
		EgressProxyID: "prx_wg", EgressConfigSerial: 4,
	}
}

// assertAttestation checks the fail-closed invariant: every terminal result of
// an egress request — successful or refused — attests the in-tunnel plan.
func assertAttestation(t *testing.T, res telemetry.TraceResult) {
	t.Helper()
	if res.PathScope != telemetry.TracePathWireGuardInner {
		t.Fatalf("PathScope = %q, want %q", res.PathScope, telemetry.TracePathWireGuardInner)
	}
	if res.EgressProxyID != "prx_wg" || res.EgressConfigSerial != 4 {
		t.Fatalf("egress attestation = %s/%d, want prx_wg/4", res.EgressProxyID, res.EgressConfigSerial)
	}
}

func TestRunEgressTraceSucceedsThroughScriptedTunnel(t *testing.T) {
	guard := netguard.New(probepolicy.Policy{}, true)
	granted := permission.FromStrings([]string{string(permission.DiagnosticTracerouteICMP)})

	var resolvedID string
	var resolvedSerial int
	resolver := func(_ context.Context, proxyID string, serial int) (EgressProbeFunc, error) {
		resolvedID, resolvedSerial = proxyID, serial
		return func(_ context.Context, d netip.Addr, ttl int, _ time.Duration) (EgressReply, error) {
			switch ttl {
			case 1:
				return EgressReply{Responder: netip.MustParseAddr("10.7.0.1"), RTTMs: 1.5}, nil
			case 2:
				return EgressReply{Timeout: true}, nil
			default:
				return EgressReply{Responder: d, Reached: true, RTTMs: 9.25}, nil
			}
		}, nil
	}
	// supported/effective deliberately EMPTY: the host stack cannot trace at all,
	// and the in-tunnel path must not care.
	e := New(guard, permission.Set{}, granted, permission.Set{}, 1, resolver)

	res := e.Run(context.Background(), egressRequest(), time.Now())
	if res.Status != telemetry.TraceStatusSucceeded {
		t.Fatalf("result = %s/%s, want succeeded", res.Status, res.Reason)
	}
	if resolvedID != "prx_wg" || resolvedSerial != 4 {
		t.Fatalf("resolver got %s/%d, want prx_wg/4", resolvedID, resolvedSerial)
	}
	if !res.Reached || res.ReachedTTL != 3 || len(res.Hops) != 3 {
		t.Fatalf("hops = %+v (reached=%v ttl=%d)", res.Hops, res.Reached, res.ReachedTTL)
	}
	if res.Hops[0].Attempts[0].ResponderAddr != "10.7.0.1" || !res.Hops[1].Attempts[0].Timeout {
		t.Fatalf("hop detail = %+v", res.Hops)
	}
	assertAttestation(t, res)
}

func TestRunEgressTraceFailsClosed(t *testing.T) {
	guard := netguard.New(probepolicy.Policy{}, true)
	granted := permission.FromStrings([]string{string(permission.DiagnosticTracerouteICMP)})

	for _, tc := range []struct {
		name     string
		resolver EgressResolver
		reason   string
	}{
		{"generation_mismatch", func(context.Context, string, int) (EgressProbeFunc, error) {
			return nil, fmt.Errorf("%w: prx_wg is at generation 5, not 4", ErrEgressGenerationMismatch)
		}, reasonEgressGenerationMismatch},
		{"not_available", func(context.Context, string, int) (EgressProbeFunc, error) {
			return nil, fmt.Errorf("%w: unknown proxy", ErrEgressNotAvailable)
		}, reasonEgressNotAvailable},
		{"unclassified_resolver_error", func(context.Context, string, int) (EgressProbeFunc, error) {
			return nil, errors.New("boom")
		}, reasonEgressNotAvailable},
		{"nil_resolver", nil, reasonEgressNotAvailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := New(guard, granted, granted, granted, 1, tc.resolver)
			res := e.Run(context.Background(), egressRequest(), time.Now())
			if res.Status != telemetry.TraceStatusFailed || res.Reason != tc.reason {
				t.Fatalf("result = %s/%s, want failed/%s", res.Status, res.Reason, tc.reason)
			}
			// Fail-closed results still attest which plan they refused.
			assertAttestation(t, res)
		})
	}
}

func TestRunEgressPermissionAndModeGates(t *testing.T) {
	guard := netguard.New(probepolicy.Policy{}, true)
	granted := permission.FromStrings([]string{string(permission.DiagnosticTracerouteICMP)})
	neverResolve := func(context.Context, string, int) (EgressProbeFunc, error) {
		return nil, errors.New("resolver must not be reached")
	}

	// The same granted-but-unsupported permission set: a HOST-stack request is
	// unsupported (the platform cannot execute it), while the egress request
	// above proves the tunnel path skips that capability gate. Regression pin
	// for the granted-vs-effective split.
	e := New(guard, permission.Set{}, granted, permission.Set{}, 1, neverResolve)
	host := egressRequest()
	host.EgressProxyID, host.EgressConfigSerial = "", 0
	res := e.Run(context.Background(), host, time.Now())
	if res.Status != telemetry.TraceStatusUnsupported {
		t.Fatalf("host-stack result = %s/%s, want unsupported", res.Status, res.Reason)
	}
	if res.PathScope != telemetry.TracePathDirect {
		t.Fatalf("host-stack PathScope = %q, want direct", res.PathScope)
	}

	// No grant at all: the egress request is a policy denial, resolver untouched.
	e = New(guard, permission.Set{}, permission.Set{}, permission.Set{}, 1, neverResolve)
	res = e.Run(context.Background(), egressRequest(), time.Now())
	if res.Status != telemetry.TraceStatusUnsupported || res.Reason != reasonPermissionDenied {
		t.Fatalf("ungranted result = %s/%s, want unsupported/permission_denied", res.Status, res.Reason)
	}
	assertAttestation(t, res)

	// TCP through a tunnel is not plannable; a request claiming it is malformed.
	e = New(guard, granted, granted, granted, 1, neverResolve)
	bad := egressRequest()
	bad.Mode, bad.TCPPort = pcfg.TraceModeTCP, 443
	res = e.Run(context.Background(), bad, time.Now())
	if res.Status != telemetry.TraceStatusFailed || res.Reason != reasonInvalidMode {
		t.Fatalf("tcp egress result = %s/%s, want failed/invalid_mode", res.Status, res.Reason)
	}
	assertAttestation(t, res)
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
