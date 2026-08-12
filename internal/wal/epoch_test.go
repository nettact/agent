package wal

import (
	"path/filepath"
	"testing"

	"github.com/nettact/protocol/telemetry"
)

// Shared by both builds (memory-only assertions; persistence is pinned in the
// build-specific files).

// TestSetEpochIdempotent: re-stating the cursor's current epoch changes
// nothing — no re-queue, no claim reset, the backlog keeps its place — while a
// real epoch move re-queues exactly what the server is still owed.
func TestSetEpochIdempotent(t *testing.T) {
	s, err := Open(filepath.Join(tempWALDir(t), "wal"), []string{srvA}, Options{})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	if n, err := s.SetEpoch(srvA, 5); err != nil || n != 0 {
		t.Fatalf("first SetEpoch = %d, %v; want 0 rows, nil", n, err)
	}
	if _, err := s.Append(Records{Metrics: []telemetry.Metric{metric(1)}}, srvA); err != nil {
		t.Fatalf("Append: %v", err)
	}
	if n, err := s.SetEpoch(srvA, 5); err != nil || n != 0 {
		t.Fatalf("second SetEpoch = %d, %v; want a no-op", n, err)
	}
	if n := s.Pending(srvA); n != 1 {
		t.Fatalf("pending after the idempotent SetEpoch = %d, want 1", n)
	}
	if n, err := s.SetEpoch(srvA, 6); err != nil || n != 1 {
		t.Fatalf("SetEpoch(6) = %d, %v; want the 1 owed row re-queued", n, err)
	}
}

// TestApplyFloorConflictDetection: an in-flight claim at or below the floor is
// a conflict (its sequence must never be re-served), one above it is not, a
// floor for another epoch is refused, and once the claim is released the
// allocator hands out only sequences above the floor.
func TestApplyFloorConflictDetection(t *testing.T) {
	s, err := Open(filepath.Join(tempWALDir(t), "wal"), []string{srvA}, Options{})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	if _, err := s.SetEpoch(srvA, 3); err != nil {
		t.Fatalf("SetEpoch: %v", err)
	}
	if _, err := s.Append(Records{Metrics: []telemetry.Metric{metric(1)}}, srvA); err != nil {
		t.Fatalf("Append: %v", err)
	}
	b, ok, err := s.NextBatch(srvA, 500)
	if err != nil || !ok {
		t.Fatalf("NextBatch: ok=%v err=%v", ok, err)
	}

	if conflict, err := s.ApplyFloor(srvA, 3, b.Sequence); err != nil || !conflict {
		t.Fatalf("ApplyFloor at the claim's own sequence = %v, %v; want conflict, nil", conflict, err)
	}
	if conflict, err := s.ApplyFloor(srvA, 3, b.Sequence-1); err != nil || conflict {
		t.Fatalf("ApplyFloor below the claim = %v, %v; want no conflict, nil", conflict, err)
	}
	if _, err := s.ApplyFloor(srvA, 4, b.Sequence); err == nil {
		t.Fatal("ApplyFloor for a different epoch: want an error, got nil")
	}

	if err := s.Ack(srvA, b.Sequence); err != nil {
		t.Fatalf("Ack: %v", err)
	}
	if _, err := s.Append(Records{Metrics: []telemetry.Metric{metric(2)}}, srvA); err != nil {
		t.Fatalf("Append: %v", err)
	}
	b2, ok, err := s.NextBatch(srvA, 500)
	if err != nil || !ok {
		t.Fatalf("NextBatch: ok=%v err=%v", ok, err)
	}
	if b2.Sequence <= b.Sequence {
		t.Fatalf("post-floor sequence %d is not above the floor %d", b2.Sequence, b.Sequence)
	}
}
