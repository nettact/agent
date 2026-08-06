//go:build !lite

package wal

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/nettact/protocol/telemetry"
)

// The multi-server contract: one log, one set of files, one sequence allocator —
// and N consumers that cannot see, delay, or lose each other's records.

// openTempFor opens a store in a fresh directory serving the named servers.
func openTempFor(t *testing.T, servers ...string) (*Store, string) {
	t.Helper()
	dir := filepath.Join(tempWALDir(t), "wal")
	s, err := Open(dir, servers)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, dir
}

// values pulls the metric values out of a batch, which is how these tests
// identify which records came back.
func values(b Batch) []float64 {
	out := make([]float64, 0, len(b.Metrics))
	for _, m := range b.Metrics {
		out = append(out, m.Value)
	}
	return out
}

func equalFloats(a, b []float64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// A server is only ever served its own records. This is the load-bearing rule:
// a probe result names a MonitorID minted by the server that pushed the target,
// so handing it to a second server would have it store a series under an
// identity that means something else there.
func TestEachServerSeesOnlyItsOwnRecords(t *testing.T) {
	s, _ := openTempFor(t, srvA, srvB)

	if _, err := s.Append(Records{Metrics: []telemetry.Metric{metric(1)}}, srvA); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Append(Records{Metrics: []telemetry.Metric{metric(2)}}, srvB); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Append(Records{Metrics: []telemetry.Metric{metric(3)}}, srvA); err != nil {
		t.Fatal(err)
	}

	a, ok, err := s.NextBatch(srvA, 500)
	if err != nil || !ok {
		t.Fatalf("NextBatch(%s): ok=%v err=%v", srvA, ok, err)
	}
	if got := values(a); !equalFloats(got, []float64{1, 3}) {
		t.Fatalf("%s got %v, want its own two records in order", srvA, got)
	}
	b, ok, err := s.NextBatch(srvB, 500)
	if err != nil || !ok {
		t.Fatalf("NextBatch(%s): ok=%v err=%v", srvB, ok, err)
	}
	if got := values(b); !equalFloats(got, []float64{2}) {
		t.Fatalf("%s got %v, want only its own record", srvB, got)
	}
	if a.Sequence == b.Sequence {
		t.Fatalf("two live packets share sequence %d; the allocator must not hand one out twice", a.Sequence)
	}
}

// Claims and acks are independent per server: one server holding an unacked
// packet — the whole of an outage — must not stop another from draining, and an
// ack from one must not release the other's claim.
func TestOneServerStallDoesNotBlockAnother(t *testing.T) {
	s, _ := openTempFor(t, srvA, srvB)

	for i := 1; i <= 3; i++ {
		if _, err := s.Append(Records{Metrics: []telemetry.Metric{metric(float64(i))}}, srvA); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Append(Records{Metrics: []telemetry.Metric{metric(float64(10 * i))}}, srvB); err != nil {
			t.Fatal(err)
		}
	}

	// B claims once and then goes silent, as an unreachable server does.
	stalled, ok, _ := s.NextBatch(srvB, 500)
	if !ok {
		t.Fatal("B was owed records and got none")
	}

	// A drains everything it is owed while B's claim sits there.
	drained, ok, err := s.NextBatch(srvA, 500)
	if err != nil || !ok {
		t.Fatalf("NextBatch(%s): ok=%v err=%v", srvA, ok, err)
	}
	if got := values(drained); !equalFloats(got, []float64{1, 2, 3}) {
		t.Fatalf("%s got %v while %s was stalled", srvA, got, srvB)
	}
	if err := s.Ack(srvA, drained.Sequence); err != nil {
		t.Fatal(err)
	}
	if p := s.Pending(srvA); p != 0 {
		t.Fatalf("%s still owed %d rows after acking everything", srvA, p)
	}

	// B's claim survived A's ack untouched, and re-serves under its own sequence.
	again, ok, err := s.NextBatch(srvB, 500)
	if err != nil || !ok {
		t.Fatalf("re-serve for %s: ok=%v err=%v", srvB, ok, err)
	}
	if again.Sequence != stalled.Sequence {
		t.Fatalf("%s re-served under sequence %d, want its original %d", srvB, again.Sequence, stalled.Sequence)
	}
	if got := values(again); !equalFloats(got, []float64{10, 20, 30}) {
		t.Fatalf("%s re-served %v, want its original records", srvB, got)
	}
}

// A segment's bytes may only be collected once every server that owed something
// in it has acked. A sweep that ran on one server's progress alone would delete
// the backlog of whichever server was offline — which is the one case this store
// exists for.
func TestSegmentSurvivesUntilEveryOwnerHasAcked(t *testing.T) {
	s, dir := openTempFor(t, srvA, srvB)

	if _, err := s.Append(Records{Metrics: []telemetry.Metric{metric(1)}}, srvA); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Append(Records{Metrics: []telemetry.Metric{metric(2)}}, srvB); err != nil {
		t.Fatal(err)
	}
	if err := s.Flush(); err != nil { // both groups are now in one segment
		t.Fatal(err)
	}
	if n := storedRows(t, s); n != 2 {
		t.Fatalf("expected both groups spilled, found %d rows on disk", n)
	}

	a, _, err := s.NextBatch(srvA, 500)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Ack(srvA, a.Sequence); err != nil {
		t.Fatal(err)
	}
	segs, err := listSegments(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(segs) == 0 {
		t.Fatalf("the segment was deleted while %s still owed its record", srvB)
	}
	if p := s.Pending(srvB); p != 1 {
		t.Fatalf("%s should still be owed 1 row, got %d", srvB, p)
	}

	b, _, err := s.NextBatch(srvB, 500)
	if err != nil {
		t.Fatal(err)
	}
	if got := values(b); !equalFloats(got, []float64{2}) {
		t.Fatalf("%s got %v after %s acked, want its own record intact", srvB, got, srvA)
	}
	if err := s.Ack(srvB, b.Sequence); err != nil {
		t.Fatal(err)
	}
	segs, err = listSegments(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(segs) != 0 {
		t.Fatalf("segments %v survived after every owner acked", segs)
	}
}

// The row cap is the backpressure policy for a server that has been unreachable
// for a long time: its own oldest groups are shed, and a healthy server sharing
// the store neither loses anything nor stops draining.
func TestCapShedsTheLaggardNotTheHealthyServer(t *testing.T) {
	s, _ := openTempFor(t, srvA, srvB)
	s.mu.Lock()
	s.maxRows = 20 // small enough to reach quickly; the behaviour is the point
	s.mu.Unlock()

	// B never claims. A drains after every spill.
	for i := 1; i <= 60; i++ {
		if _, err := s.Append(Records{Metrics: []telemetry.Metric{metric(float64(i))}}, srvB); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Append(Records{Metrics: []telemetry.Metric{metric(float64(i))}}, srvA); err != nil {
			t.Fatal(err)
		}
		if err := s.Flush(); err != nil {
			t.Fatal(err)
		}
		b, ok, err := s.NextBatch(srvA, 500)
		if err != nil {
			t.Fatal(err)
		}
		if ok {
			if err := s.Ack(srvA, b.Sequence); err != nil {
				t.Fatal(err)
			}
		}
	}

	if p := s.Pending(srvA); p != 0 {
		t.Fatalf("the healthy server lost track of %d rows it had acked", p)
	}
	pending := s.Pending(srvB)
	if pending == 0 {
		t.Fatal("the stalled server's whole backlog was dropped; the cap must shed the oldest, not everything")
	}
	if pending > s.maxRows {
		t.Fatalf("the stalled server holds %d rows past a cap of %d", pending, s.maxRows)
	}

	// What survived is the NEWEST of its records: the cap sheds from the front.
	b, ok, err := s.NextBatch(srvB, 500)
	if err != nil || !ok {
		t.Fatalf("NextBatch(%s): ok=%v err=%v", srvB, ok, err)
	}
	got := values(b)
	if len(got) == 0 {
		t.Fatal("nothing served to the stalled server")
	}
	if got[len(got)-1] != 60 {
		t.Fatalf("the newest record was shed instead of the oldest: last value %v", got[len(got)-1])
	}
	for i := 1; i < len(got); i++ {
		if got[i] <= got[i-1] {
			t.Fatalf("records came back out of order: %v", got)
		}
	}
}

// A packet claimed out of memory keeps its sequence when a spill lands under it
// AND when the process restarts — the two together are what stop the same group
// going out twice under different sequences, which the server cannot dedup.
func TestMemoryClaimKeepsItsSequenceAcrossRestart(t *testing.T) {
	dir := filepath.Join(tempWALDir(t), "wal")
	s, err := Open(dir, []string{srvA, srvB})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Append(Records{Metrics: []telemetry.Metric{metric(1), metric(2)}}, srvA); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Append(Records{Metrics: []telemetry.Metric{metric(9)}}, srvB); err != nil {
		t.Fatal(err)
	}
	sent, ok, err := s.NextBatch(srvA, 500) // claimed from memory: nothing on disk yet
	if err != nil || !ok {
		t.Fatalf("NextBatch: ok=%v err=%v", ok, err)
	}
	// Close spills the buffer, which is where the claim becomes durable.
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	again, err := Open(dir, []string{srvA, srvB})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = again.Close() })
	got, ok, err := again.NextBatch(srvA, 500)
	if err != nil || !ok {
		t.Fatalf("after restart: ok=%v err=%v", ok, err)
	}
	if got.Sequence != sent.Sequence {
		t.Fatalf("re-served under sequence %d, want the original %d", got.Sequence, sent.Sequence)
	}
	if v := values(got); !equalFloats(v, []float64{1, 2}) {
		t.Fatalf("re-served %v, want the original group whole", v)
	}
	if v := values(got); len(v) != 2 {
		t.Fatalf("the other server's record leaked into the re-served packet: %v", v)
	}
}

// Cursors are restored per server, so a restart in the middle of an outage
// resumes each server where it was rather than replaying what one of them had
// already acknowledged.
func TestCursorsAreRestoredPerServer(t *testing.T) {
	dir := filepath.Join(tempWALDir(t), "wal")
	s, err := Open(dir, []string{srvA, srvB})
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 2; i++ {
		if _, err := s.Append(Records{Metrics: []telemetry.Metric{metric(float64(i))}}, srvA); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Append(Records{Metrics: []telemetry.Metric{metric(float64(10 * i))}}, srvB); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Flush(); err != nil {
		t.Fatal(err)
	}
	a, _, err := s.NextBatch(srvA, 500)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Ack(srvA, a.Sequence); err != nil { // A is caught up, B has not started
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	again, err := Open(dir, []string{srvA, srvB})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = again.Close() })
	if _, ok, err := again.NextBatch(srvA, 500); err != nil || ok {
		t.Fatalf("%s was re-served records it had already acknowledged", srvA)
	}
	b, ok, err := again.NextBatch(srvB, 500)
	if err != nil || !ok {
		t.Fatalf("NextBatch(%s): ok=%v err=%v", srvB, ok, err)
	}
	if v := values(b); !equalFloats(v, []float64{10, 20}) {
		t.Fatalf("%s got %v, want the backlog it never acknowledged", srvB, v)
	}
}

// A server removed from the configuration stops owing anything. Without this its
// cursor would pin every group it never acked for the whole retention window —
// bytes nothing will ever deliver, on a machine whose owner has said that server
// is no longer theirs.
func TestUnconfiguredServerReleasesItsBacklog(t *testing.T) {
	dir := filepath.Join(tempWALDir(t), "wal")
	s, err := Open(dir, []string{srvA, srvB})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Append(Records{Metrics: []telemetry.Metric{metric(1)}}, srvA); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		if _, err := s.Append(Records{Metrics: []telemetry.Metric{metric(float64(100 + i))}}, srvB); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Flush(); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	// Reopen with B gone from the configuration.
	again, err := Open(dir, []string{srvA})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = again.Close() })
	if p := again.Pending(srvB); p != 0 {
		t.Fatalf("the removed server still holds %d rows", p)
	}
	b, ok, err := again.NextBatch(srvA, 500)
	if err != nil || !ok {
		t.Fatalf("NextBatch(%s): ok=%v err=%v", srvA, ok, err)
	}
	if v := values(b); !equalFloats(v, []float64{1}) {
		t.Fatalf("%s got %v; removing another server must not disturb it", srvA, v)
	}
	if err := again.Ack(srvA, b.Sequence); err != nil {
		t.Fatal(err)
	}
	// With nothing left owed to anyone, the segment goes.
	segs, err := listSegments(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(segs) != 0 {
		t.Fatalf("segments %v survived although nobody is owed anything", segs)
	}
}

// Appending for a server that is not configured is a wiring bug, not a silent
// drop: those bytes would be stored and never delivered or collected.
func TestAppendForUnknownServerIsRejected(t *testing.T) {
	s, _ := openTempFor(t, srvA)
	if _, err := s.Append(Records{Metrics: []telemetry.Metric{metric(1)}}, "nobody"); err == nil {
		t.Fatal("append for an unconfigured server was accepted")
	}
	if p := s.Pending(srvA); p != 0 {
		t.Fatalf("the rejected append reached the configured server anyway (%d rows)", p)
	}
}

// Retention is per store but its effect is per server: a claim whose groups all
// aged out is dropped rather than served as an empty packet under a sequence the
// server may already associate with content.
func TestExpiryDropsAStaleClaimWithoutDisturbingOthers(t *testing.T) {
	s, _ := openTempFor(t, srvA, srvB)

	if _, err := s.Append(Records{Metrics: []telemetry.Metric{metric(1)}}, srvA); err != nil {
		t.Fatal(err)
	}
	if err := s.Flush(); err != nil {
		t.Fatal(err)
	}
	stale, ok, err := s.NextBatch(srvA, 500)
	if err != nil || !ok {
		t.Fatalf("NextBatch(%s): ok=%v err=%v", srvA, ok, err)
	}

	// Age the whole durable backlog past the window.
	s.mu.Lock()
	for i := range s.disk {
		s.disk[i].at = time.Now().UTC().Add(-2 * s.retention)
	}
	s.mu.Unlock()

	if _, err := s.Append(Records{Metrics: []telemetry.Metric{metric(2)}}, srvB); err != nil {
		t.Fatal(err)
	}
	b, ok, err := s.NextBatch(srvB, 500)
	if err != nil || !ok {
		t.Fatalf("NextBatch(%s): ok=%v err=%v", srvB, ok, err)
	}
	if b.Sequence == stale.Sequence {
		t.Fatalf("%s was handed %s's burned sequence %d", srvB, srvA, b.Sequence)
	}
	if v := values(b); !equalFloats(v, []float64{2}) {
		t.Fatalf("%s got %v, want its own fresh record", srvB, v)
	}
	if _, ok, err := s.NextBatch(srvA, 500); err != nil || ok {
		t.Fatalf("the expired claim was served anyway: ok=%v err=%v", ok, err)
	}
}
