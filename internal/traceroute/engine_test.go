package traceroute

import (
	"context"
	"errors"
	"fmt"
	"net"
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
	e := New(nil, permission.Set{}, permission.Set{}, permission.Set{}, NewLimiter(1), nil)
	for _, tc := range []struct {
		name   string
		req    Request
		status string
		reason string
	}{
		{"mode", Request{ReportID: "bad-mode", Mode: "udp", DestHost: "1.1.1.1"}, telemetry.TraceStatusFailed, reasonInvalidMode},
		{"destination", Request{ReportID: "bad-dest", Mode: pcfg.TraceModeICMP}, telemetry.TraceStatusFailed, reasonInvalidDestination},
		{"port", Request{ReportID: "bad-port", Mode: pcfg.TraceModeTCP, DestHost: "1.1.1.1"}, telemetry.TraceStatusFailed, reasonInvalidPort},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := e.Run(context.Background(), tc.req, time.Now())
			if got.Status != tc.status || got.Reason != tc.reason {
				t.Fatalf("result = %s/%s, want %s/%s", got.Status, got.Reason, tc.status, tc.reason)
			}
		})
	}

	granted := permission.FromStrings([]string{string(permission.DiagnosticTracerouteICMP)})
	e = New(nil, granted, granted, granted, NewLimiter(1), nil)
	// The window runs from decidedAt, not from entry into Run: a trace whose whole
	// budget elapsed while it waited for a goroutine or a concurrency slot must not
	// be handed a fresh window just because it started late. Otherwise a backlog
	// would produce hops describing a network minutes past the fault.
	got := e.Run(context.Background(), Request{
		ReportID: "stale", Mode: pcfg.TraceModeICMP, DestHost: "1.1.1.1", TotalTimeoutMs: 1_000,
	}, time.Now().Add(-2*time.Second))
	if got.Status != telemetry.TraceStatusTimedOut || got.Reason != reasonDeadlineExceeded {
		t.Fatalf("stale decidedAt result = %s/%s, want %s/%s",
			got.Status, got.Reason, telemetry.TraceStatusTimedOut, reasonDeadlineExceeded)
	}
}

// A terminal-at-planning refusal still has to say what it was about: the server
// keeps no plan to fill the description in from, so a result that drops the
// subject or the trigger is a report nobody can file or explain.
func TestRunEchoesTheReportDescriptionOnEveryTerminalResult(t *testing.T) {
	e := New(nil, permission.Set{}, permission.Set{}, permission.Set{}, NewLimiter(1), nil)
	firstFail := time.Now().Add(-time.Minute).UTC()
	got := e.Run(context.Background(), Request{
		ReportID: "described", Mode: "udp", DestHost: "1.1.1.1",
		DestKey: "ip:1.1.1.1", Port: 53,
		SubjectKind: telemetry.TraceSubjectResolver, SubjectReason: "",
		FallbackFrom: pcfg.TraceModeTCP, FallbackReason: "raw_socket_unavailable",
		TriggerReason: telemetry.TraceTriggerConsecutiveFailures, TriggerStreak: 4,
		FirstFailedAt: firstFail,
	}, time.Now())
	if got.Status != telemetry.TraceStatusFailed {
		t.Fatalf("status = %s, want %s", got.Status, telemetry.TraceStatusFailed)
	}
	if got.DestKey != "ip:1.1.1.1" || got.DestHost != "1.1.1.1" || got.Port != 53 {
		t.Fatalf("destination = %s/%s/%d", got.DestKey, got.DestHost, got.Port)
	}
	if got.SubjectKind != telemetry.TraceSubjectResolver {
		t.Fatalf("subject = %q", got.SubjectKind)
	}
	if got.FallbackFrom != pcfg.TraceModeTCP || got.FallbackReason != "raw_socket_unavailable" {
		t.Fatalf("fallback = %s/%s", got.FallbackFrom, got.FallbackReason)
	}
	if got.TriggerReason != telemetry.TraceTriggerConsecutiveFailures || got.TriggerStreak != 4 || !got.FirstFailedAt.Equal(firstFail) {
		t.Fatalf("trigger = %s/%d/%s", got.TriggerReason, got.TriggerStreak, got.FirstFailedAt)
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
func egressRequest() Request {
	return Request{
		ReportID: "egress-1", Mode: pcfg.TraceModeICMP, DestHost: "192.0.2.10",
		MaxHops: 8, AttemptsPerHop: 1, TotalTimeoutMs: 30_000,
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
	e := New(guard, permission.Set{}, granted, permission.Set{}, NewLimiter(1), resolver)

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
			e := New(guard, granted, granted, granted, NewLimiter(1), tc.resolver)
			res := e.Run(context.Background(), egressRequest(), time.Now())
			if res.Status != telemetry.TraceStatusFailed || res.Reason != tc.reason {
				t.Fatalf("result = %s/%s, want failed/%s", res.Status, res.Reason, tc.reason)
			}
			// Fail-closed results still attest which plan they refused.
			assertAttestation(t, res)
		})
	}
}

func TestRunEgressSentinelMidSweepKeepsItsOwnReason(t *testing.T) {
	// A generation can rotate WHILE the sweep runs: the manager closes the
	// superseded tunnel and the in-flight probe fails. The sentinel must survive
	// that path too — reporting probe_failed would blame the machinery for a
	// re-keyed tunnel, which is a different answer to "what do I do next".
	guard := netguard.New(probepolicy.Policy{}, true)
	granted := permission.FromStrings([]string{string(permission.DiagnosticTracerouteICMP)})

	for _, tc := range []struct {
		name   string
		err    error
		reason string
	}{
		{"generation_mismatch", ErrEgressGenerationMismatch, reasonEgressGenerationMismatch},
		{"not_available", ErrEgressNotAvailable, reasonEgressNotAvailable},
		{"unclassified", errors.New("tunnel device closed"), reasonProbeFailed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resolver := func(context.Context, string, int) (EgressProbeFunc, error) {
				return func(_ context.Context, d netip.Addr, ttl int, _ time.Duration) (EgressReply, error) {
					if ttl == 1 {
						return EgressReply{Responder: netip.MustParseAddr("10.7.0.1"), RTTMs: 1}, nil
					}
					return EgressReply{}, fmt.Errorf("%w: mid-sweep", tc.err)
				}, nil
			}
			e := New(guard, granted, granted, granted, NewLimiter(1), resolver)
			res := e.Run(context.Background(), egressRequest(), time.Now())
			if res.Status != telemetry.TraceStatusFailed || res.Reason != tc.reason {
				t.Fatalf("result = %s/%s, want failed/%s", res.Status, res.Reason, tc.reason)
			}
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
	e := New(guard, permission.Set{}, granted, permission.Set{}, NewLimiter(1), neverResolve)
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
	e = New(guard, permission.Set{}, permission.Set{}, permission.Set{}, NewLimiter(1), neverResolve)
	res = e.Run(context.Background(), egressRequest(), time.Now())
	if res.Status != telemetry.TraceStatusUnsupported || res.Reason != reasonPermissionDenied {
		t.Fatalf("ungranted result = %s/%s, want unsupported/permission_denied", res.Status, res.Reason)
	}
	assertAttestation(t, res)

	// TCP through a tunnel is not plannable; a request claiming it is malformed.
	e = New(guard, granted, granted, granted, NewLimiter(1), neverResolve)
	bad := egressRequest()
	bad.Mode, bad.Port = pcfg.TraceModeTCP, 443
	res = e.Run(context.Background(), bad, time.Now())
	if res.Status != telemetry.TraceStatusFailed || res.Reason != reasonInvalidMode {
		t.Fatalf("tcp egress result = %s/%s, want failed/invalid_mode", res.Status, res.Reason)
	}
	assertAttestation(t, res)
}

func TestTraceBoundsClampDeterministically(t *testing.T) {
	if got := clampTotalTimeout(0); got != 300*time.Second {
		t.Fatalf("default timeout = %v, want 300s", got)
	}
	if got := clampInt(1000, defaultMaxHops, 1, maxHopsCeiling); got != maxHopsCeiling {
		t.Fatalf("max hops clamp = %d", got)
	}
	if got := clampTotalTimeout(999999); got != 600*time.Second {
		t.Fatalf("timeout clamp = %v, want 600s", got)
	}
	if got := perAttemptBudget(0, time.Second, 64, 3); got != minPerAttempt {
		t.Fatalf("minimum per-attempt budget = %v", got)
	}
	if got := perAttemptBudget(0, time.Hour, 1, 1); got != maxPerAttempt {
		t.Fatalf("maximum per-attempt budget = %v", got)
	}
	// The derivation counts every probe the sweep will send, not just the hops:
	// with 3 attempts each, the default budget has to cover 90 of them.
	if got := perAttemptBudget(0, 90*time.Second, 30, 3); got != time.Second {
		t.Fatalf("derived per-attempt budget = %v, want 1s", got)
	}
	// An explicit per-hop timeout overrides the derivation but is clamped by the
	// same window: a policy cannot ask for a 10ms probe or a 30s one.
	if got := perAttemptBudget(1200, time.Hour, 30, 3); got != 1200*time.Millisecond {
		t.Fatalf("explicit per-hop budget = %v", got)
	}
	if got := perAttemptBudget(10, time.Hour, 30, 3); got != minPerAttempt {
		t.Fatalf("explicit per-hop budget below the floor = %v", got)
	}
	if got := perAttemptBudget(9000, time.Hour, 30, 3); got != maxPerAttempt {
		t.Fatalf("explicit per-hop budget above the ceiling = %v", got)
	}
}

// A probe this host could not send is not a hop: the local kernel names itself as
// the ICMP responder, so accepting it would fabricate one identical router per
// TTL. The sweep must stop at the first one and say what actually happened.
func TestWalkStopsAtLocalSendFailureWithoutInventingHops(t *testing.T) {
	e := &Engine{}
	dest := netip.MustParseAddr("192.0.2.10")
	sent := 0
	probe := func(_ context.Context, _ netip.Addr, _ int, _ int, _ time.Duration) (probeOutcome, error) {
		sent++
		return probeOutcome{localUnreachable: true}, nil
	}
	out := e.walk(context.Background(), context.Background(), probe, dest, 0, 30, 3, time.Second, time.Now().Add(time.Minute))
	if out.status != telemetry.TraceStatusFailed || out.reason != reasonLocalNoRoute {
		t.Fatalf("walk = %s/%s, want %s/%s", out.status, out.reason, telemetry.TraceStatusFailed, reasonLocalNoRoute)
	}
	if out.reached || len(out.hops) != 0 {
		t.Fatalf("hops = %+v, reached = %v; want no hops and no reach", out.hops, out.reached)
	}
	if sent != 1 {
		t.Fatalf("probes sent = %d, want 1 — the sweep must not retry a local failure", sent)
	}
}

// Hops measured before the route went away are real evidence and are kept, even
// though the TTL they were measured on ends the sweep.
func TestWalkKeepsHopsMeasuredBeforeALocalFailure(t *testing.T) {
	e := &Engine{}
	dest := netip.MustParseAddr("192.0.2.10")
	probe := func(_ context.Context, _ netip.Addr, _ int, ttl int, _ time.Duration) (probeOutcome, error) {
		if ttl == 1 {
			return probeOutcome{responder: netip.MustParseAddr("192.0.2.1"), rttMs: 1.5}, nil
		}
		return probeOutcome{localUnreachable: true}, nil
	}
	out := e.walk(context.Background(), context.Background(), probe, dest, 0, 30, 1, time.Second, time.Now().Add(time.Minute))
	if out.status != telemetry.TraceStatusFailed || out.reason != reasonLocalNoRoute {
		t.Fatalf("walk = %s/%s", out.status, out.reason)
	}
	if len(out.hops) != 1 || out.hops[0].Attempts[0].ResponderAddr != "192.0.2.1" {
		t.Fatalf("hops = %+v, want the one real hop preserved", out.hops)
	}
}

// isLocalAddr is the whole basis for telling our own kernel's unreachable from a
// router's, so it has to recognize this host's own addresses and nothing else.
func TestIsLocalAddrRecognizesThisHostOnly(t *testing.T) {
	if !isLocalAddr(netip.MustParseAddr("127.0.0.1")) {
		t.Fatal("loopback must count as local")
	}
	if isLocalAddr(netip.Addr{}) || isLocalAddr(netip.MustParseAddr("0.0.0.0")) {
		t.Fatal("invalid/unspecified addresses must not count as local")
	}
	// 192.0.2.0/24 is TEST-NET-1: reserved for documentation, so no interface on
	// any real machine carries it.
	if isLocalAddr(netip.MustParseAddr("192.0.2.1")) {
		t.Fatal("a documentation-range address must not count as local")
	}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Skipf("interface addresses unreadable: %v", err)
	}
	for _, ia := range addrs {
		n, ok := ia.(*net.IPNet)
		if !ok {
			continue
		}
		a, ok := netip.AddrFromSlice(n.IP)
		if !ok {
			continue
		}
		if a = a.Unmap(); a.Is4() && !a.IsLoopback() {
			if !isLocalAddr(a) {
				t.Fatalf("own interface address %s not recognized as local", a)
			}
			return
		}
	}
	t.Skip("no non-loopback IPv4 interface address to check against")
}
