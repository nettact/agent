//go:build !lite

package wal

import (
	"path/filepath"
	"testing"

	"github.com/nettact/protocol/telemetry"
)

// The identity contract: a server's queue belongs to the enrollment that
// collected it. A revoked agent that re-enrolls comes back as a different
// agent_id, and the server files every packet under the identity it
// authenticated — so the old queue must never be served to the new identity, and
// discarding it must actually give the bytes back rather than pinning a segment
// nothing will ever drain.

const (
	idOld = "agent-old"
	idNew = "agent-new"
	idB   = "agent-beta"
)

// A re-enrollment discards that server's whole queue — buffered, spilled and
// in-flight alike — without touching a second server that shares the log, and the
// segment is collected as soon as that second server is caught up. A "tag the old
// groups and skip them" fix would pass every assertion above the last two and
// still leak the segment forever.
func TestReenrollmentDiscardsTheOldIdentitysQueue(t *testing.T) {
	s, dir := openTempFor(t, srvA, srvB)
	if _, err := s.BindIdentity(srvA, idOld); err != nil {
		t.Fatalf("BindIdentity(%s): %v", srvA, err)
	}
	if _, err := s.BindIdentity(srvB, idB); err != nil {
		t.Fatalf("BindIdentity(%s): %v", srvB, err)
	}

	for i := 1; i <= 3; i++ {
		if _, err := s.Append(Records{Metrics: []telemetry.Metric{metric(float64(i))}}, srvA); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.Append(Records{Metrics: []telemetry.Metric{metric(99)}}, srvB); err != nil {
		t.Fatal(err)
	}
	if err := s.Flush(); err != nil { // both servers' groups now share one segment
		t.Fatal(err)
	}
	if n := storedRows(t, s); n != 4 {
		t.Fatalf("expected all four groups spilled, found %d rows on disk", n)
	}

	// A packet is in flight under the old credential when the revocation lands.
	inflight, ok, err := s.NextBatch(srvA, 500)
	if err != nil || !ok {
		t.Fatalf("NextBatch(%s): ok=%v err=%v", srvA, ok, err)
	}

	dropped, err := s.BindIdentity(srvA, idNew)
	if err != nil {
		t.Fatalf("BindIdentity(%s, %s): %v", srvA, idNew, err)
	}
	if dropped != 3 {
		t.Fatalf("discarded %d rows, want the old identity's 3", dropped)
	}

	// Nothing the old agent collected is ever handed to the new one — not the
	// unclaimed groups and not the claim that was already on the wire.
	if b, ok, err := s.NextBatch(srvA, 500); err != nil || ok {
		t.Fatalf("the old identity's records were served to the new one: %v (ok=%v err=%v)", values(b), ok, err)
	}
	if p := s.Pending(srvA); p != 0 {
		t.Fatalf("%s still owes %d rows collected under a dead identity", srvA, p)
	}

	// The cursor advanced past them rather than the records merely being hidden:
	// fresh telemetry still flows, under a sequence the burned claim cannot
	// collide with.
	if _, err := s.Append(Records{Metrics: []telemetry.Metric{metric(7)}}, srvA); err != nil {
		t.Fatal(err)
	}
	fresh, ok, err := s.NextBatch(srvA, 500)
	if err != nil || !ok {
		t.Fatalf("NextBatch(%s) after re-enrollment: ok=%v err=%v", srvA, ok, err)
	}
	if v := values(fresh); !equalFloats(v, []float64{7}) {
		t.Fatalf("%s got %v, want only what the new identity collected", srvA, v)
	}
	if fresh.Sequence == inflight.Sequence {
		t.Fatalf("the discarded claim's sequence %d was handed out again", inflight.Sequence)
	}
	if err := s.Ack(srvA, fresh.Sequence); err != nil {
		t.Fatal(err)
	}

	// The other server never noticed: same records, same claim rules, and its
	// share of the shared segment is still there.
	if p := s.Pending(srvB); p != 1 {
		t.Fatalf("%s should still be owed its 1 row, got %d", srvB, p)
	}
	b, ok, err := s.NextBatch(srvB, 500)
	if err != nil || !ok {
		t.Fatalf("NextBatch(%s): ok=%v err=%v", srvB, ok, err)
	}
	if v := values(b); !equalFloats(v, []float64{99}) {
		t.Fatalf("%s got %v; another server's re-enrollment must not disturb it", srvB, v)
	}
	segs, err := listSegments(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(segs) == 0 {
		t.Fatalf("the segment was deleted while %s still owed its record", srvB)
	}
	if err := s.Ack(srvB, b.Sequence); err != nil {
		t.Fatal(err)
	}

	// Storage is genuinely reclaimed. This is what a discard buys over tagging
	// the stale groups and skipping them: a group that is never served pins its
	// segment for good, and disk then only grows.
	segs, err = listSegments(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(segs) != 0 {
		t.Fatalf("segments %v survived although the discard and the last ack left nothing owed", segs)
	}
	if n := storedRows(t, s); n != 0 {
		t.Fatalf("%d rows still on disk after everything was discarded or acked", n)
	}
}

// The identity travels with the backlog, so a re-enrollment is still detected
// when the process that performed it never got to reconnect — which is the
// ordinary case, since the credential is replaced on disk and the agent may be
// restarted (or crash) before its next session. Here the discard alone returns
// the segment: nothing else is owed anything in it.
func TestReenrollmentIsDetectedAfterARestart(t *testing.T) {
	dir := filepath.Join(tempWALDir(t), "wal")
	s, err := Open(dir, []string{srvA}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.BindIdentity(srvA, idOld); err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 2; i++ {
		if _, err := s.Append(Records{Metrics: []telemetry.Metric{metric(float64(i))}}, srvA); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Close(); err != nil { // spills, and records the identity beside it
		t.Fatal(err)
	}
	if segs, err := listSegments(dir); err != nil || len(segs) != 1 {
		t.Fatalf("listSegments = %v (err=%v), want the spilled backlog", segs, err)
	}

	again, err := Open(dir, []string{srvA}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = again.Close() })
	dropped, err := again.BindIdentity(srvA, idNew)
	if err != nil {
		t.Fatalf("BindIdentity after restart: %v", err)
	}
	if dropped != 2 {
		t.Fatalf("discarded %d rows after restarting as a new agent, want 2", dropped)
	}
	if p := again.Pending(srvA); p != 0 {
		t.Fatalf("%s still owes %d rows collected under the previous enrollment", srvA, p)
	}
	if b, ok, err := again.NextBatch(srvA, 500); err != nil || ok {
		t.Fatalf("a restarted agent served its predecessor's records: %v (ok=%v err=%v)", values(b), ok, err)
	}
	segs, err := listSegments(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(segs) != 0 {
		t.Fatalf("segments %v survived the discard; nothing is owed anything in them", segs)
	}
}

// The first identity a store is told about ADOPTS whatever is queued: there was
// no previous enrollment to attribute it to, which is the ordinary first-boot
// case (collectors run while the enrollment exchange is still in flight).
// Re-binding the same identity — every reconnect — must likewise change nothing.
func TestFirstIdentityAdoptsTheQueueAndRebindingIsANoOp(t *testing.T) {
	s, _ := openTempFor(t, srvA)
	for i := 1; i <= 2; i++ {
		if _, err := s.Append(Records{Metrics: []telemetry.Metric{metric(float64(i))}}, srvA); err != nil {
			t.Fatal(err)
		}
	}

	dropped, err := s.BindIdentity(srvA, idOld)
	if err != nil {
		t.Fatalf("BindIdentity: %v", err)
	}
	if dropped != 0 {
		t.Fatalf("the first enrollment discarded %d rows this install had already collected", dropped)
	}
	if dropped, err = s.BindIdentity(srvA, idOld); err != nil || dropped != 0 {
		t.Fatalf("reconnecting under the same identity discarded %d rows (err=%v)", dropped, err)
	}
	// An unenrolled caller states nothing, so it must not be read as a change.
	if dropped, err = s.BindIdentity(srvA, ""); err != nil || dropped != 0 {
		t.Fatalf("an empty identity discarded %d rows (err=%v)", dropped, err)
	}

	b, ok, err := s.NextBatch(srvA, 500)
	if err != nil || !ok {
		t.Fatalf("NextBatch: ok=%v err=%v", ok, err)
	}
	if v := values(b); !equalFloats(v, []float64{1, 2}) {
		t.Fatalf("got %v, want the queue intact", v)
	}

	// Binding an identity for a server this store does not serve is the same
	// wiring bug Append reports, not a silent no-op.
	if _, err := s.BindIdentity("nobody", idNew); err == nil {
		t.Fatal("BindIdentity accepted an unconfigured server")
	}
}
