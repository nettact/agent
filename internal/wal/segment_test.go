//go:build !lite

package wal

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/nettact/protocol/telemetry"
)

// The durable tier's own contract: what survives a restart, what a damaged file
// costs, and what the store does with things it did not put in its directory.

// A packet claimed from disk and not yet acked must come back after a restart
// under the SAME sequence and with the SAME content. The old row-level store got
// this from its per-row packet_seq tag; here it rests on the claim recorded in
// state.json, so it is worth pinning directly.
func TestDiskClaimSurvivesRestart(t *testing.T) {
	dir := filepath.Join(tempWALDir(t), "wal")
	s, err := Open(dir, []string{srvA})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Append(Records{Metrics: []telemetry.Metric{metric(11), metric(12)}}, srvA); err != nil {
		t.Fatal(err)
	}
	if err := s.Flush(); err != nil { // the agent is offline: this went durable
		t.Fatalf("Flush: %v", err)
	}
	sent, ok, err := s.NextBatch(srvA, 500)
	if err != nil || !ok {
		t.Fatalf("NextBatch: ok=%v err=%v", ok, err)
	}
	// The upload never completes: no Ack, and the process goes away.
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	again, err := Open(dir, []string{srvA})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = again.Close() })
	got, ok, err := again.NextBatch(srvA, 500)
	if err != nil || !ok {
		t.Fatalf("after restart: ok=%v err=%v", ok, err)
	}
	if got.Sequence != sent.Sequence {
		t.Fatalf("packet renumbered across the restart: %d -> %d; the server could not dedup it",
			sent.Sequence, got.Sequence)
	}
	if len(got.Metrics) != 2 || got.Metrics[0].Value != 11 || got.Metrics[1].Value != 12 {
		t.Fatalf("packet content changed across the restart: %+v", got.Metrics)
	}
	if err := again.Ack(srvA, got.Sequence); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := again.NextBatch(srvA, 500); ok {
		t.Fatal("acked packet was served again")
	}
	if n := storedRows(t, again); n != 0 {
		t.Fatalf("%d rows survived the ack; the segment should have been collected", n)
	}
}

// A power cut can leave a half-written line at the end of a segment. Everything
// before it is intact telemetry and must still be delivered — refusing to open,
// or discarding the whole segment, would turn a torn tail into a total loss.
func TestTornSegmentTailKeepsEarlierGroups(t *testing.T) {
	dir := filepath.Join(tempWALDir(t), "wal")
	s, err := Open(dir, []string{srvA})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if _, err := s.Append(Records{Metrics: []telemetry.Metric{metric(float64(i))}}, srvA); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	segs, err := listSegments(dir)
	if err != nil || len(segs) != 1 {
		t.Fatalf("listSegments = %v, %v; want exactly one segment", segs, err)
	}
	f, err := os.OpenFile(segPath(dir, segs[0]), os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(`{"at":"2026-01-0`); err != nil { // interrupted mid-line
		t.Fatal(err)
	}
	f.Close()

	again, err := Open(dir, []string{srvA})
	if err != nil {
		t.Fatalf("a torn tail must not stop the store opening: %v", err)
	}
	t.Cleanup(func() { _ = again.Close() })
	b, ok, err := again.NextBatch(srvA, 500)
	if err != nil || !ok {
		t.Fatalf("NextBatch: ok=%v err=%v", ok, err)
	}
	if len(b.Metrics) != 3 {
		t.Fatalf("recovered %d metrics, want the 3 complete groups written before the tear", len(b.Metrics))
	}
}

// The store owns a directory, not the whole data dir, and must not trip over
// anything else that ends up in it — including the wal.db an older build left
// behind, which is simply not its business.
func TestForeignFilesAreIgnored(t *testing.T) {
	dir := filepath.Join(tempWALDir(t), "wal")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"wal.db", "wal.db-shm", "notes.txt", "0000nonsense.seg"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("not a segment"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	s, err := Open(dir, []string{srvA})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if _, err := s.Append(Records{Metrics: []telemetry.Metric{metric(1)}}, srvA); err != nil {
		t.Fatal(err)
	}
	b, ok, err := s.NextBatch(srvA, 500)
	if err != nil || !ok || len(b.Metrics) != 1 {
		t.Fatalf("NextBatch = (%+v, %v, %v)", b.Metrics, ok, err)
	}
	if _, err := os.Stat(filepath.Join(dir, "wal.db")); err != nil {
		t.Fatalf("the store deleted a file it does not own: %v", err)
	}
}

// A leftover temp file is an interrupted write nothing references. It must be
// cleaned up rather than accumulating on a router's flash forever.
func TestStaleTempFilesAreRemovedOnOpen(t *testing.T) {
	dir := filepath.Join(tempWALDir(t), "wal")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	stale := filepath.Join(dir, "wal-123456.tmp")
	if err := os.WriteFile(stale, []byte("half a spill"), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := Open(dir, []string{srvA})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatalf("os.Stat(stale temp) = %v, want it removed", err)
	}
}

// A claim naming more groups than the store actually holds means the segment
// carrying them never landed. Serving a short packet under a sequence the server
// may already associate with different content is worse than dropping it, so the
// claim is discarded and the sequence burned.
func TestOversizedClaimIsDropped(t *testing.T) {
	dir := filepath.Join(tempWALDir(t), "wal")
	s, err := Open(dir, []string{srvA})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Append(Records{Metrics: []telemetry.Metric{metric(1)}}, srvA); err != nil {
		t.Fatal(err)
	}
	if err := s.Flush(); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	st, found, err := readState(dir)
	if err != nil || !found {
		t.Fatalf("readState = (%+v, %v, %v)", st, found, err)
	}
	st.Cursors[srvA] = cursorState{ClaimSeq: 42, ClaimFrom: 1, ClaimTo: 9, ClaimN: 9} // more groups than were ever written
	if err := writeState(dir, st); err != nil {
		t.Fatal(err)
	}

	again, err := Open(dir, []string{srvA})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = again.Close() })
	b, ok, err := again.NextBatch(srvA, 500)
	if err != nil || !ok {
		t.Fatalf("NextBatch: ok=%v err=%v", ok, err)
	}
	if b.Sequence == 42 {
		t.Fatal("the unbacked claim was served; its sequence must be burned instead")
	}
	if len(b.Metrics) != 1 {
		t.Fatalf("the surviving group was lost: %+v", b.Metrics)
	}
}

// A claim that is never acknowledged — an outage, which is precisely when this
// store is doing its job — must not let the backlog grow without limit. The
// claim pins the head in place, so a segment sweep that only looked at the head
// would keep every spill's file forever.
func TestUnackedClaimDoesNotLeakSegments(t *testing.T) {
	dir := filepath.Join(tempWALDir(t), "wal")
	s, err := Open(dir, []string{srvA})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })

	// A small cap keeps the test quick; the behaviour under test is the sweep,
	// not the number.
	s.mu.Lock()
	s.maxRows = 40
	s.mu.Unlock()

	// Claim a packet from disk and never ack it.
	if _, err := s.Append(Records{Metrics: []telemetry.Metric{metric(0)}}, srvA); err != nil {
		t.Fatal(err)
	}
	if err := s.Flush(); err != nil {
		t.Fatal(err)
	}
	claimed, ok, err := s.NextBatch(srvA, 10)
	if err != nil || !ok {
		t.Fatalf("NextBatch: ok=%v err=%v", ok, err)
	}

	// The outage continues: telemetry keeps arriving and keeps spilling.
	for round := 0; round < 30; round++ {
		for i := 0; i < 10; i++ {
			if _, err := s.Append(Records{Metrics: []telemetry.Metric{metric(float64(i))}}, srvA); err != nil {
				t.Fatal(err)
			}
		}
		if err := s.Flush(); err != nil {
			t.Fatalf("Flush round %d: %v", round, err)
		}
	}

	segs, err := listSegments(dir)
	if err != nil {
		t.Fatal(err)
	}
	// The claim's segment, plus however many hold the capped backlog. A handful
	// is expected; one per spill is the bug.
	if len(segs) > 8 {
		t.Fatalf("%d segment files after 30 spills behind one unacked claim; the cap is not being enforced on disk", len(segs))
	}
	if rows := storedRows(t, s); rows > 4*s.maxRows {
		t.Fatalf("%d rows on disk against a %d-row cap", rows, s.maxRows)
	}

	// And the claimed packet is still intact and still its own sequence.
	again, ok, err := s.NextBatch(srvA, 10)
	if err != nil || !ok {
		t.Fatalf("NextBatch after the spills: ok=%v err=%v", ok, err)
	}
	if again.Sequence != claimed.Sequence {
		t.Fatalf("claim was renumbered by the eviction: %d -> %d", claimed.Sequence, again.Sequence)
	}
	if len(again.Metrics) != 1 || again.Metrics[0].Value != 0 {
		t.Fatalf("claimed packet lost its content: %+v", again.Metrics)
	}
}

// Unreadable bookkeeping is not something to guess around: the backlog goes,
// because replaying it without the allocator position would re-send every group
// under sequences the server cannot recognise as duplicates.
func TestCorruptStateStartsOver(t *testing.T) {
	dir := filepath.Join(tempWALDir(t), "wal")
	s, err := Open(dir, []string{srvA})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Append(Records{Metrics: []telemetry.Metric{metric(1)}}, srvA); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, stateName), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}

	again, err := Open(dir, []string{srvA})
	if err != nil {
		t.Fatalf("a corrupt state file must not stop the store opening: %v", err)
	}
	t.Cleanup(func() { _ = again.Close() })
	if n := storedRows(t, again); n != 0 {
		t.Fatalf("%d rows survived an unreadable state file, want the backlog discarded", n)
	}
	if _, ok, err := again.NextBatch(srvA, 500); ok || err != nil {
		t.Fatalf("NextBatch = (%v, %v), want nothing to serve", ok, err)
	}
	// Still usable afterwards.
	if _, err := again.Append(Records{Metrics: []telemetry.Metric{metric(2)}}, srvA); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := again.NextBatch(srvA, 500); !ok || err != nil {
		t.Fatalf("post-recovery NextBatch = (%v, %v)", ok, err)
	}
}
