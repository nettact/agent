//go:build lite

package wal

import (
	"path/filepath"
	"testing"
	"time"
)

// The floor barrier is the ONE place the lite build makes the allocator's
// floor durable — the per-ack FastForward stays memory-only so erase cycles
// never ride the healthy path. A reboot must therefore resume above the floor
// from the persisted allocator position alone, which this pins by using a
// floor far above any wall-clock seed (initialSeq is the current time in
// nanoseconds, so the only source that can beat it is the state file
// ApplyFloor wrote).
func TestLiteApplyFloorSurvivesRestart(t *testing.T) {
	path := filepath.Join(tempWALDir(t), "wal")
	s := openPersist(t, path, []string{srvA}, nil)
	t.Cleanup(func() { _ = s.Close() })

	if _, err := s.SetEpoch(srvA, 3); err != nil {
		t.Fatalf("SetEpoch: %v", err)
	}
	const floor uint64 = 2_000_000_000_000_000_000
	if conflict, err := s.ApplyFloor(srvA, 3, floor); err != nil || conflict {
		t.Fatalf("ApplyFloor = %v, %v; want no conflict, nil", conflict, err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	s2 := openPersist(t, path, []string{srvA}, nil)
	t.Cleanup(func() { _ = s2.Close() })
	if _, err := s2.Append(one(1), srvA); err != nil {
		t.Fatalf("Append: %v", err)
	}
	// The epoch survived too: re-stating it is a no-op that leaves the pending
	// row untouched; a lost epoch would re-queue it.
	if n, err := s2.SetEpoch(srvA, 3); err != nil || n != 0 {
		t.Fatalf("SetEpoch after reopen = %d, %v; the cursor epoch did not survive", n, err)
	}
	b, ok, err := s2.NextBatch(srvA, 500)
	if err != nil || !ok {
		t.Fatalf("NextBatch: ok=%v err=%v", ok, err)
	}
	if b.Sequence <= floor {
		t.Fatalf("post-restart sequence %d is at or below the floor %d; the barrier did not survive", b.Sequence, floor)
	}
}

// The epoch move must not resurrect delivered groups in the lite build either:
// the acked watermark stays, so a restart's recover (which keeps gid > acked)
// cannot re-live acknowledged lines that physically survive in a segment the
// store still references.
func TestLiteSetEpochDoesNotResurrectDeliveredGroups(t *testing.T) {
	path := filepath.Join(tempWALDir(t), "wal")
	ck := newClock()
	s := openPersist(t, path, []string{srvA}, ck)
	t.Cleanup(func() { _ = s.Close() })

	if _, err := s.SetEpoch(srvA, 5); err != nil {
		t.Fatalf("SetEpoch: %v", err)
	}
	if _, err := s.Append(one(1), srvA); err != nil {
		t.Fatalf("Append 1: %v", err)
	}
	if _, err := s.Append(one(2), srvA); err != nil {
		t.Fatalf("Append 2: %v", err)
	}
	// Age the groups past the persist window, then end the "session" so the
	// spill puts both lines in one segment.
	ck.add(31 * time.Minute)
	s.SetServerOnline(srvA, false)

	b1, ok, err := s.NextBatch(srvA, 1) // claims group 1 only
	if err != nil || !ok {
		t.Fatalf("NextBatch: ok=%v err=%v", ok, err)
	}
	if err := s.Ack(srvA, b1.Sequence); err != nil {
		t.Fatalf("Ack: %v", err)
	}
	if _, err := s.Append(one(3), srvA); err != nil {
		t.Fatalf("Append 3: %v", err)
	}
	b2, ok, err := s.NextBatch(srvA, 500) // in-flight claim over the owed tail
	if err != nil || !ok {
		t.Fatalf("NextBatch 2: ok=%v err=%v", ok, err)
	}
	n, err := s.SetEpoch(srvA, 6)
	if err != nil {
		t.Fatalf("SetEpoch(6): %v", err)
	}
	if n != 2 {
		t.Fatalf("SetEpoch(6) re-queued %d rows, want 2 (owed tail only)", n)
	}
	// Age the tail group past the window so the shutdown spill persists it;
	// without that Close drops it (a healthy buffer is deliberately not
	// written) and the reopen assertion below would under-count.
	ck.add(31 * time.Minute)
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	s2 := openPersist(t, path, []string{srvA}, nil)
	t.Cleanup(func() { _ = s2.Close() })
	if n := s2.Pending(srvA); n != 2 {
		t.Fatalf("pending after reopen = %d, want 2 — the delivered group resurrected", n)
	}
	b3, ok, err := s2.NextBatch(srvA, 500)
	if err != nil || !ok {
		t.Fatalf("NextBatch after reopen: ok=%v err=%v", ok, err)
	}
	if len(b3.Metrics) != 2 || b3.Metrics[0].Value != 2 || b3.Metrics[1].Value != 3 {
		t.Fatalf("re-served batch = %+v; want only the owed records, delivered one excluded", b3.Metrics)
	}
	if b3.Sequence == b2.Sequence {
		t.Fatalf("re-served batch kept the abandoned claim's sequence %d", b2.Sequence)
	}
}
