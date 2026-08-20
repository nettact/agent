//go:build linux || darwin

package traceroute

// Live diagnostics for the Linux/macOS ICMP traceroute path. They need a raw
// ICMP socket (root / CAP_NET_RAW) and a real network, so they are skipped
// unless NETTACT_TRACE_LIVE=1 — `go test ./...` never runs them.

import (
	"context"
	"net/netip"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/nettact/agent/internal/netguard"
	"github.com/nettact/agent/probepolicy"
	pcfg "github.com/nettact/protocol/config"
	"github.com/nettact/protocol/permission"
	"github.com/nettact/protocol/telemetry"
)

// liveBudget is the per-probe budget these tests use, defaulting to the engine's
// own ceiling so a live run mirrors what a real sweep would do. Override with
// NETTACT_TRACE_BUDGET_MS to measure a different one.
func liveBudget(t *testing.T) time.Duration {
	t.Helper()
	v := os.Getenv("NETTACT_TRACE_BUDGET_MS")
	if v == "" {
		return maxPerAttempt
	}
	ms, err := strconv.Atoi(v)
	if err != nil || ms <= 0 {
		t.Fatalf("bad NETTACT_TRACE_BUDGET_MS %q", v)
	}
	return time.Duration(ms) * time.Millisecond
}

// TestLiveICMPSweep runs the real icmpProbe over increasing TTLs and logs each
// outcome, mirroring what the engine's walk would record.
func TestLiveICMPSweep(t *testing.T) {
	if os.Getenv("NETTACT_TRACE_LIVE") == "" {
		t.Skip("set NETTACT_TRACE_LIVE=1 (requires root/CAP_NET_RAW + network)")
	}
	dest := netip.MustParseAddr("1.1.1.1")
	if v := os.Getenv("NETTACT_TRACE_DEST"); v != "" {
		a, err := netip.ParseAddr(v)
		if err != nil {
			t.Fatalf("bad NETTACT_TRACE_DEST %q: %v", v, err)
		}
		dest = a
	}
	for ttl := 1; ttl <= 10; ttl++ {
		start := time.Now()
		out, err := icmpProbe(context.Background(), dest, 0, ttl, liveBudget(t))
		t.Logf("ttl=%d responder=%v reached=%v timeout=%v local=%v rtt=%.1fms err=%v elapsed=%v",
			ttl, out.responder, out.reached, out.timeout, out.localUnreachable, out.rttMs, err, time.Since(start))
		if err != nil || out.reached || out.localUnreachable {
			return
		}
	}
}

// TestLiveICMPLocalFailureIsNeverAHop is the regression check for the reason
// localUnreachable exists. When the next hop toward a destination cannot be
// resolved, Linux answers our own echo with an ICMP Destination Unreachable that
// it sources from a LOCAL address and loops back to us; taken at face value the
// sweep reports the agent's own address as a router, once per TTL, for packets
// that never reached the wire.
//
// Set NETTACT_TRACE_LOCALFAIL_DEST to an address this host cannot send to, and
// arrange that beforehand, e.g.:
//
//	ip link add nt-a type veth peer name nt-b   # nt-b stays down => no carrier
//	ip addr add 10.66.66.1/24 dev nt-a && ip link set nt-a up
//	ip route add 203.0.113.9/32 via 10.66.66.9 dev nt-a
//
// The assertion is "no probe ever names a hop, and at least one reports the
// local failure" rather than "every probe reports it", because the two are not
// the same: neighbour resolution takes seconds to give up and fails a whole
// batch of queued packets at once, so probes that started a fresh resolution
// cycle legitimately time out with nothing to show. Naming a hop is the defect;
// silence is not.
func TestLiveICMPLocalFailureIsNeverAHop(t *testing.T) {
	if os.Getenv("NETTACT_TRACE_LIVE") == "" {
		t.Skip("set NETTACT_TRACE_LIVE=1 (requires root/CAP_NET_RAW)")
	}
	v := os.Getenv("NETTACT_TRACE_LOCALFAIL_DEST")
	if v == "" {
		t.Skip("set NETTACT_TRACE_LOCALFAIL_DEST to a locally unroutable address")
	}
	dest, err := netip.ParseAddr(v)
	if err != nil {
		t.Fatalf("bad NETTACT_TRACE_LOCALFAIL_DEST %q: %v", v, err)
	}

	sawLocal := false
	budget := liveBudget(t)
	// Probes, not hops: the engine sends AttemptsPerHop of these per TTL, and what
	// is being checked here is the classification of each one. The count is
	// generous because neighbour resolution fails a batch every few seconds, so a
	// short budget can take several probes before one is in flight at that moment.
	for i := 1; i <= 12; i++ {
		start := time.Now()
		out, perr := icmpProbe(context.Background(), dest, 0, (i+2)/3, budget)
		t.Logf("probe=%d ttl=%d responder=%v timeout=%v local=%v rtt=%.1fms elapsed=%v",
			i, (i+2)/3, out.responder, out.timeout, out.localUnreachable, out.rttMs, time.Since(start))
		if perr != nil {
			t.Fatalf("probe=%d: %v", i, perr)
		}
		if out.responder.IsValid() {
			t.Fatalf("probe=%d named %v as a hop; nothing left this host", i, out.responder)
		}
		if out.reached {
			t.Fatalf("probe=%d reported the destination as reached", i)
		}
		if out.localUnreachable {
			sawLocal = true
			t.Logf("local failure classified after %d probe(s), %v of budget spent",
				i, time.Duration(i)*budget)
			break
		}
	}
	if !sawLocal {
		t.Fatal("no probe reported a local send failure; the destination may still be routable")
	}
}

// TestLiveSocketKindProducesRealHops is the check that matters for the macOS
// unprivileged path: it asserts the socket kind this process actually resolved
// can name routers, in BOTH modes, through the full engine.
//
// Run it as an ordinary user on macOS to exercise the datagram fallback, and
// under root to confirm the raw path did not regress; the log line reports
// which kind was in play so the two runs are distinguishable. A pass as uid!=0
// on Darwin is the evidence that observing intermediate Time-Exceeded there
// needs no privilege.
//
// The destination is a literal IP, never a hostname, so no round-robin can move
// the target between the two sub-runs.
func TestLiveSocketKindProducesRealHops(t *testing.T) {
	if os.Getenv("NETTACT_TRACE_LIVE") == "" {
		t.Skip("set NETTACT_TRACE_LIVE=1 (requires network; root only for the raw path)")
	}
	dest := "1.1.1.1"
	if v := os.Getenv("NETTACT_TRACE_DEST"); v != "" {
		if _, err := netip.ParseAddr(v); err != nil {
			t.Fatalf("NETTACT_TRACE_DEST %q must be a literal IP: %v", v, err)
		}
		dest = v
	}
	caps := detectCapabilities()
	t.Logf("uid=%d socketKind=%d caps=%+v dest=%s", os.Getuid(), resolveICMPSocket(), caps, dest)
	if !caps.ICMP && !caps.TCP {
		t.Skip("no ICMP socket available to this process")
	}

	all := permission.FromStrings([]string{
		string(permission.DiagnosticTracerouteICMP),
		string(permission.DiagnosticTracerouteTCP),
	})
	e := New(netguard.New(probepolicy.Policy{}, true), all, all, all, NewLimiter(2), nil)

	for _, mode := range []string{pcfg.TraceModeICMP, pcfg.TraceModeTCP} {
		t.Run(mode, func(t *testing.T) {
			res := e.Run(context.Background(), Request{
				ReportID: "live-" + mode, Mode: mode,
				DestKey: "ip:" + dest, DestHost: dest, Port: 443,
				SubjectKind:   telemetry.TraceSubjectTarget,
				TriggerReason: telemetry.TraceTriggerConsecutiveFailures,
				TriggerStreak: 3, FirstFailedAt: time.Now().Add(-time.Minute),
				MaxHops: 15, AttemptsPerHop: 3, TotalTimeoutMs: 30000,
			}, time.Now())
			named := 0
			for _, h := range res.Hops {
				for _, a := range h.Attempts {
					t.Logf("ttl=%d responder=%q rtt=%.1fms timeout=%v", h.TTL, a.ResponderAddr, a.RTTMs, a.Timeout)
					if a.ResponderAddr != "" {
						named++
					}
				}
			}
			if res.Status != telemetry.TraceStatusSucceeded {
				t.Fatalf("status=%s reason=%s", res.Status, res.Reason)
			}
			// The failure this guards is silent: a responder the code cannot read
			// off the socket normalizes into a timeout, so a broken path still
			// "succeeds" — as a column of stars.
			if named == 0 {
				t.Fatal("every attempt timed out; no responder was extracted from this socket kind")
			}
			if !res.Reached {
				t.Errorf("destination %s not reached", dest)
			}
		})
	}
}
