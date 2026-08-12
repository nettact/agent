//go:build !lite

package wal

import (
	"testing"

	"github.com/nettact/protocol/telemetry"
)

// An epoch move re-opens the whole backlog without discarding the data: the
// in-flight claim is abandoned (its sequence belongs to the old epoch and is
// never renumbered in place), everything the server is still owed becomes
// pending again, and the next claim re-serves the SAME records under a FRESH
// sequence. The new epoch itself must survive a restart, so the server's floor
// for it can be validated by a later session.
func TestSetEpochRequuesBacklogUnderFreshSequences(t *testing.T) {
	s, dir := openTempFor(t, srvA)
	if _, err := s.SetEpoch(srvA, 5); err != nil {
		t.Fatalf("SetEpoch: %v", err)
	}
	if _, err := s.Append(Records{Metrics: []telemetry.Metric{metric(1)}}, srvA); err != nil {
		t.Fatalf("Append: %v", err)
	}
	b, ok, err := s.NextBatch(srvA, 500) // in-flight claim under epoch 5
	if err != nil || !ok {
		t.Fatalf("NextBatch: ok=%v err=%v", ok, err)
	}
	if _, err := s.Append(Records{Metrics: []telemetry.Metric{metric(2)}}, srvA); err != nil {
		t.Fatalf("Append: %v", err)
	}

	n, err := s.SetEpoch(srvA, 6)
	if err != nil {
		t.Fatalf("SetEpoch(6): %v", err)
	}
	if n != 2 {
		t.Fatalf("SetEpoch(6) re-queued %d rows, want 2 (claim + backlog)", n)
	}

	// The whole backlog is re-served — same records, fresh sequence. (The old
	// claim boundary is gone with the claim, so both groups now form one batch.)
	b2, ok, err := s.NextBatch(srvA, 500)
	if err != nil || !ok {
		t.Fatalf("NextBatch after SetEpoch: ok=%v err=%v", ok, err)
	}
	if b2.Sequence == b.Sequence {
		t.Fatalf("re-served batch kept the old epoch's sequence %d", b2.Sequence)
	}
	if len(b2.Metrics) != 2 || b2.Metrics[0].Value != 1 || b2.Metrics[1].Value != 2 {
		t.Fatalf("re-served batch = %+v; want both records, claim before backlog", b2.Metrics)
	}
	if err := s.Ack(srvA, b2.Sequence); err != nil {
		t.Fatalf("Ack: %v", err)
	}
	if n := s.Pending(srvA); n != 0 {
		t.Fatalf("pending after the ack = %d, want 0", n)
	}

	// One unacked row so the reopened store has visible backlog, then persist
	// everything and reopen.
	if _, err := s.Append(Records{Metrics: []telemetry.Metric{metric(3)}}, srvA); err != nil {
		t.Fatalf("Append: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	s2, err := Open(dir, []string{srvA}, Options{})
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	t.Cleanup(func() { _ = s2.Close() })
	// The epoch survived: re-stating it is a no-op that leaves the backlog
	// untouched. A lost epoch would re-queue the pending row instead.
	if n, err := s2.SetEpoch(srvA, 6); err != nil || n != 0 {
		t.Fatalf("SetEpoch(6) after reopen = %d, %v; the epoch did not survive", n, err)
	}
	if n := s2.Pending(srvA); n != 1 {
		t.Fatalf("pending after reopen = %d, want 1", n)
	}
}
