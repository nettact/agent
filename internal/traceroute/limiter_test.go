package traceroute

import (
	"context"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nettact/agent/internal/netguard"
	"github.com/nettact/agent/probepolicy"
	"github.com/nettact/protocol/permission"
	"github.com/nettact/protocol/telemetry"
)

// However many scheduled traces want to run, they can hold at most the
// background share, and the slot left over is always there for a diagnosis.
func TestLimiterReservesASlotForDiagnosis(t *testing.T) {
	l := NewLimiter(DefaultConcurrency)
	if l.Cap() != DefaultConcurrency || l.BackgroundCap() != DefaultConcurrency-1 {
		t.Fatalf("cap/background = %d/%d, want %d/%d", l.Cap(), l.BackgroundCap(), DefaultConcurrency, DefaultConcurrency-1)
	}
	for i := 0; i < DefaultConcurrency-1; i++ {
		if !l.tryAcquireBackground() {
			t.Fatalf("scheduled acquire %d refused inside the background share", i)
		}
	}
	if l.tryAcquireBackground() {
		t.Fatal("a scheduled trace took the slot reserved for diagnosis")
	}
	select {
	case l.slots <- struct{}{}:
	default:
		t.Fatal("diagnosis found no slot while scheduled traces held their whole share")
	}
}

// A scheduled try that finds every slot held by diagnoses fails without
// keeping its background token, so the share is not leaked.
func TestLimiterBackgroundTryReturnsTokenWhenSlotsAreFull(t *testing.T) {
	l := NewLimiter(2)
	l.slots <- struct{}{}
	l.slots <- struct{}{}
	if l.tryAcquireBackground() {
		t.Fatal("scheduled trace admitted with every slot held")
	}
	if n := len(l.background); n != 0 {
		t.Fatalf("background tokens held after a failed try = %d, want 0", n)
	}
	<-l.slots
	if !l.tryAcquireBackground() {
		t.Fatal("scheduled trace refused once a slot freed")
	}
	l.releaseBackground()
	if len(l.slots) != 1 || len(l.background) != 0 {
		t.Fatalf("after release: slots=%d background=%d, want 1/0", len(l.slots), len(l.background))
	}
}

// A budget of one still admits route monitoring rather than disabling it.
func TestLimiterOfOneStillAdmitsScheduled(t *testing.T) {
	l := NewLimiter(1)
	if l.BackgroundCap() != 1 {
		t.Fatalf("background share at budget 1 = %d, want 1", l.BackgroundCap())
	}
	if !l.tryAcquireBackground() {
		t.Fatal("scheduled trace refused on an idle budget of one")
	}
}

// TryRun never waits: with the background share taken it reports "not
// admitted" without sending a probe, while a diagnosis on the same engine
// still runs in the reserved slot.
func TestTryRunDefersWhenBackgroundShareIsBusy(t *testing.T) {
	guard := netguard.New(probepolicy.Policy{}, true)
	granted := permission.FromStrings([]string{string(permission.DiagnosticTracerouteICMP)})
	var probes atomic.Int32
	resolver := func(context.Context, string, int) (EgressProbeFunc, error) {
		return func(_ context.Context, d netip.Addr, _ int, _ time.Duration) (EgressReply, error) {
			probes.Add(1)
			return EgressReply{Responder: d, Reached: true, RTTMs: 2}, nil
		}, nil
	}
	lim := NewLimiter(2) // background share 1
	e := New(guard, permission.Set{}, granted, permission.Set{}, lim, resolver)

	if !lim.tryAcquireBackground() { // another scheduled trace holds the share
		t.Fatal("setup: could not take the background share")
	}
	start := time.Now()
	if res, ok := e.TryRun(context.Background(), egressRequest(), time.Now()); ok {
		t.Fatalf("TryRun admitted past a full background share: %+v", res)
	}
	if time.Since(start) > time.Second {
		t.Fatal("TryRun waited for a slot")
	}
	if probes.Load() != 0 {
		t.Fatal("a deferred scheduled trace sent probes")
	}

	if res := e.Run(context.Background(), egressRequest(), time.Now()); res.Status != telemetry.TraceStatusSucceeded {
		t.Fatalf("diagnosis beside a busy background share = %s/%s, want succeeded", res.Status, res.Reason)
	}

	lim.releaseBackground()
	res, ok := e.TryRun(context.Background(), egressRequest(), time.Now())
	if !ok || res.Status != telemetry.TraceStatusSucceeded {
		t.Fatalf("TryRun on a free budget = ok %v %s/%s, want admitted and succeeded", ok, res.Status, res.Reason)
	}
	if len(lim.slots) != 0 || len(lim.background) != 0 {
		t.Fatalf("slots leaked: slots=%d background=%d", len(lim.slots), len(lim.background))
	}
}

// A refusal that sends no probe is final for TryRun too: it is reported, not
// deferred, since retrying cannot change it.
func TestTryRunReportsRefusalsAsFinal(t *testing.T) {
	e := New(nil, permission.Set{}, permission.Set{}, permission.Set{}, NewLimiter(1), nil)
	res, ok := e.TryRun(context.Background(), Request{ReportID: "r", Mode: "udp", DestHost: "192.0.2.1"}, time.Now())
	if !ok || res.Status != telemetry.TraceStatusFailed || res.Reason != reasonInvalidMode {
		t.Fatalf("TryRun invalid mode = ok %v %s/%s, want final failed/%s", ok, res.Status, res.Reason, reasonInvalidMode)
	}
}
