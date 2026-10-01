package tracetrigger

import (
	"testing"
	"time"

	pcfg "github.com/nettact/protocol/config"
	"github.com/nettact/protocol/permission"
	"github.com/nettact/protocol/telemetry"
)

// A lost session traces toward the server it was connected to — TCP on the
// port the session dialled — stamped with the disconnect trigger and the moment
// the session was lost.
func TestSessionLostTracesTowardServer(t *testing.T) {
	h := newHarness(t, nil)
	lost := time.Date(2026, 10, 1, 8, 0, 0, 0, time.FixedZone("CST", 8*3600))
	h.trk.SessionUp()
	h.trk.SessionLost("https://Nettact.Example.com:12450", lost)

	reqs := h.requests()
	if len(reqs) != 1 {
		t.Fatalf("requests = %d, want 1", len(reqs))
	}
	r := reqs[0]
	if r.Mode != pcfg.TraceModeTCP || r.DestHost != "nettact.example.com" || r.Port != 12450 ||
		r.DestKey != "host:nettact.example.com" {
		t.Fatalf("plan = %s %s:%d (%s)", r.Mode, r.DestHost, r.Port, r.DestKey)
	}
	if r.TriggerReason != telemetry.TraceTriggerServerDisconnect {
		t.Fatalf("trigger = %q", r.TriggerReason)
	}
	if !r.FirstFailedAt.Equal(lost) || r.FirstFailedAt.Location() != time.UTC {
		t.Fatalf("first failed at = %v, want %v in UTC", r.FirstFailedAt, lost)
	}
	if len(h.sunk()) != 1 {
		t.Fatal("the report was not filed")
	}
}

// One established session yields at most one trace: the retries that follow
// the first loss find the arm spent. The next session re-arms.
func TestSessionLostOncePerSession(t *testing.T) {
	h := newHarness(t, nil)
	h.trk.SessionUp()
	h.trk.SessionLost("http://10.0.0.5", time.Now())
	h.trk.SessionLost("http://10.0.0.5", time.Now())
	h.trk.SessionLost("http://10.0.0.5", time.Now())
	if n := len(h.requests()); n != 1 {
		t.Fatalf("requests = %d, want 1", n)
	}
	if r := h.requests()[0]; r.Port != 80 || r.DestKey != "ip:10.0.0.5" {
		t.Fatalf("plan = %s:%d", r.DestKey, r.Port)
	}
}

// An agent that starts while its server is already unreachable never gets a
// session; its first failed dial is the edge, and later ones are not.
func TestSessionLostProcessStartArm(t *testing.T) {
	h := newHarness(t, nil)
	h.trk.SessionLost("http://10.0.0.5:12450", time.Now())
	h.trk.SessionLost("http://10.0.0.5:12450", time.Now())
	if n := len(h.requests()); n != 1 {
		t.Fatalf("requests = %d, want 1", n)
	}
}

// Disarm spends the arm: an ending that is not a network fault leaves nothing
// for the next failed dial to trace.
func TestDisarmSpendsArm(t *testing.T) {
	h := newHarness(t, nil)
	h.trk.SessionUp()
	h.trk.Disarm()
	h.trk.SessionLost("http://10.0.0.5:12450", time.Now())
	if n := len(h.requests()); n != 0 {
		t.Fatalf("requests = %d, want 0", n)
	}
}

// Without any traceroute permission nothing runs and nothing is filed — not even
// a denial report.
func TestSessionLostWithoutPermission(t *testing.T) {
	h := newHarness(t, nil, permission.HostLoadRead)
	h.trk.SessionUp()
	h.trk.SessionLost("http://10.0.0.5:12450", time.Now())
	if n := len(h.requests()); n != 0 {
		t.Fatalf("requests = %d, want 0", n)
	}
	if n := len(h.sunk()); n != 0 {
		t.Fatalf("filed = %d, want 0", n)
	}
}

// ICMP-only grants still trace, downgraded and saying so.
func TestSessionLostFallsBackToICMP(t *testing.T) {
	h := newHarness(t, nil, permission.DiagnosticTracerouteICMP)
	h.trk.SessionUp()
	h.trk.SessionLost("http://10.0.0.5:12450", time.Now())
	reqs := h.requests()
	if len(reqs) != 1 || reqs[0].Mode != pcfg.TraceModeICMP || reqs[0].FallbackFrom != pcfg.TraceModeTCP {
		t.Fatalf("requests = %+v", reqs)
	}
}

// No trace for a server with no network path (loopback) or no address at all
// (an in-process server), and none when the pushed policy disables diagnostics.
func TestSessionLostSkips(t *testing.T) {
	for _, u := range []string{"", "http://127.0.0.1:12450", "http://localhost:12450", "http://[::1]:12450"} {
		h := newHarness(t, nil)
		h.trk.SessionUp()
		h.trk.SessionLost(u, time.Now())
		if n := len(h.requests()); n != 0 {
			t.Fatalf("%q: requests = %d, want 0", u, n)
		}
	}

	h := newHarness(t, nil)
	h.trk.ApplyDiagPolicy(&pcfg.DiagPolicy{Enabled: false})
	h.trk.SessionUp()
	h.trk.SessionLost("http://10.0.0.5:12450", time.Now())
	if n := len(h.requests()); n != 0 {
		t.Fatalf("disabled policy: requests = %d, want 0", n)
	}
}

// A probe-fault trace of the server's own address must not consume the
// disconnect trace's cooldown: the two diagnose different faults.
func TestServerCohortIndependentOfProbeCohort(t *testing.T) {
	h := newHarness(t, nil)
	p, _ := planServer("http://10.0.0.5:12450")
	h.trk.mu.Lock()
	h.trk.cooldown[p.cohortKey()] = time.Now()
	h.trk.mu.Unlock()
	h.trk.SessionUp()
	h.trk.SessionLost("http://10.0.0.5:12450", time.Now())
	if n := len(h.requests()); n != 1 {
		t.Fatalf("requests = %d, want 1", n)
	}
}
