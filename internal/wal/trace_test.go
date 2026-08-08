//go:build !lite

package wal

import (
	"testing"
	"time"

	"github.com/nettact/protocol/telemetry"
)

// A traceroute report is in the outbox precisely because the fault it diagnoses
// is the likeliest reason the socket is unusable. So it has to survive the two
// things that happen during an outage: a spill to disk, and a restart.
func TestTraceResultSurvivesSpillAndRestart(t *testing.T) {
	s, dir := openTempFor(t, "alpha")
	res := telemetry.TraceResult{
		ReportID: "trace_1", Mode: "icmp", DestKey: "ip:1.1.1.1", DestHost: "1.1.1.1",
		SubjectKind: telemetry.TraceSubjectTarget, PathScope: telemetry.TracePathDirect,
		TriggerReason: telemetry.TraceTriggerConsecutiveFailures, TriggerStreak: 3,
		FirstFailedAt: time.Unix(1700000000, 0).UTC(),
		Status:        telemetry.TraceStatusPartial, MaxHops: 30, AttemptsPerHop: 3,
		Hops: []telemetry.TraceHop{
			{TTL: 1, Attempts: []telemetry.TraceAttempt{{ResponderAddr: "10.0.0.1", RTTMs: 1.5}}},
			{TTL: 2, Attempts: []telemetry.TraceAttempt{{Timeout: true}}},
		},
	}
	if _, err := s.Append(Records{TraceResults: []telemetry.TraceResult{res}}, "alpha"); err != nil {
		t.Fatalf("append: %v", err)
	}
	if err := s.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	reopened, err := Open(dir, []string{"alpha"})
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	t.Cleanup(func() { _ = reopened.Close() })

	b, ok, err := reopened.NextBatch("alpha", 100)
	if err != nil || !ok {
		t.Fatalf("NextBatch after restart: ok=%v err=%v", ok, err)
	}
	if len(b.TraceResults) != 1 {
		t.Fatalf("got %d trace results after restart, want 1", len(b.TraceResults))
	}
	got := b.TraceResults[0]
	if got.ReportID != res.ReportID || got.DestKey != res.DestKey || got.TriggerStreak != 3 {
		t.Fatalf("report lost its identity across the spill: %+v", got)
	}
	if len(got.Hops) != 2 || got.Hops[0].Attempts[0].ResponderAddr != "10.0.0.1" || !got.Hops[1].Attempts[0].Timeout {
		t.Fatalf("hops did not round-trip: %+v", got.Hops)
	}
}

// A trace belongs to the server whose pipeline planned it: it was derived from
// that server's targets, permissions and proxy generation, and means nothing to
// a second server that pushed none of them.
func TestTraceResultIsServedOnlyToItsOwner(t *testing.T) {
	s, _ := openTempFor(t, "alpha", "beta")
	if _, err := s.Append(Records{TraceResults: []telemetry.TraceResult{{ReportID: "trace_alpha"}}}, "alpha"); err != nil {
		t.Fatalf("append: %v", err)
	}
	b, ok, err := s.NextBatch("beta", 100)
	if err != nil {
		t.Fatalf("NextBatch(beta): %v", err)
	}
	if ok && len(b.TraceResults) > 0 {
		t.Fatalf("beta was served alpha's trace report: %+v", b.TraceResults)
	}
	b, ok, err = s.NextBatch("alpha", 100)
	if err != nil || !ok || len(b.TraceResults) != 1 {
		t.Fatalf("alpha did not get its own report: ok=%v err=%v batch=%+v", ok, err, b)
	}
}
