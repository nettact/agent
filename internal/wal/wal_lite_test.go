//go:build lite

package wal

import (
	"math"
	"os"
	"testing"
	"time"

	"github.com/nettact/protocol/telemetry"
)

// The memory-only store's contract: the same FIFO/indivisible-group/re-serve
// rules as the default build, minus durability, plus a bounded buffer that sheds
// its oldest whole groups rather than growing without limit.

func openLite(t *testing.T) *Store {
	t.Helper()
	// The path is ignored, but a real-looking one is passed to keep the call
	// identical to the production one in agentrt.
	s, err := Open(t.TempDir() + "/wal")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func metric(v float64) telemetry.Metric {
	return telemetry.Metric{TS: time.Now().UTC(), Kind: telemetry.ICMPRTTms, Target: "10.0.0.1", Value: v}
}

// Nothing is written to disk, ever — that is what makes this build usable on the
// mips routers whose SQLite port does not exist and whose flash should not be
// carrying a telemetry backlog.
func TestLiteStoreCreatesNoFile(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir + "/wal")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()
	for i := 0; i < 50; i++ {
		if _, err := s.Append(Records{Metrics: []telemetry.Metric{metric(float64(i))}}); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}
	if _, err := os.Stat(dir + "/wal"); !os.IsNotExist(err) {
		t.Fatalf("os.Stat(wal) = %v, want a not-exist error: the lite store must not touch disk", err)
	}
}

// Delivery is FIFO and each Records stays whole, which the server's fault
// detectors depend on.
func TestLiteFIFOAndWholeGroups(t *testing.T) {
	s := openLite(t)
	for i := 0; i < 3; i++ {
		if _, err := s.Append(Records{Metrics: []telemetry.Metric{metric(float64(i)), metric(float64(i) + 0.5)}}); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}
	// maxItems 3 cannot fit a second 2-row group, so exactly one group is claimed
	// — a group is never split to fill the packet.
	b, ok, err := s.NextBatch(3)
	if err != nil || !ok {
		t.Fatalf("NextBatch = (%v, %v)", ok, err)
	}
	if len(b.Metrics) != 2 {
		t.Fatalf("claimed %d metrics, want the 2 of one whole group", len(b.Metrics))
	}
	if b.Metrics[0].Value != 0 {
		t.Fatalf("first metric = %v, want the oldest (0)", b.Metrics[0].Value)
	}
	if err := s.Ack(b.Sequence); err != nil {
		t.Fatalf("Ack: %v", err)
	}
	next, ok, err := s.NextBatch(3)
	if err != nil || !ok {
		t.Fatalf("NextBatch after ack = (%v, %v)", ok, err)
	}
	if next.Metrics[0].Value != 1 {
		t.Fatalf("second batch starts at %v, want 1", next.Metrics[0].Value)
	}
	if next.Sequence == b.Sequence {
		t.Fatal("a new batch reused the acked sequence")
	}
}

// A single group larger than maxItems must still make progress rather than wedge
// the queue behind a packet that can never be assembled.
func TestLiteOversizedGroupStillProgresses(t *testing.T) {
	s := openLite(t)
	big := Records{}
	for i := 0; i < 10; i++ {
		big.Metrics = append(big.Metrics, metric(float64(i)))
	}
	if _, err := s.Append(big); err != nil {
		t.Fatalf("Append: %v", err)
	}
	b, ok, err := s.NextBatch(3)
	if err != nil || !ok {
		t.Fatalf("NextBatch = (%v, %v)", ok, err)
	}
	if len(b.Metrics) != 10 {
		t.Fatalf("claimed %d metrics, want the whole 10-row group", len(b.Metrics))
	}
}

// An unacked packet is re-served under its ORIGINAL sequence, so a dropped
// session re-sends it and the server dedups rather than the agent losing it.
func TestLiteUnackedBatchIsReserved(t *testing.T) {
	s := openLite(t)
	if _, err := s.Append(Records{Metrics: []telemetry.Metric{metric(1)}}); err != nil {
		t.Fatalf("Append: %v", err)
	}
	first, _, err := s.NextBatch(100)
	if err != nil {
		t.Fatalf("NextBatch: %v", err)
	}
	// New telemetry arriving mid-flight must not overtake the claimed packet.
	if _, err := s.Append(Records{Metrics: []telemetry.Metric{metric(2)}}); err != nil {
		t.Fatalf("Append: %v", err)
	}
	again, ok, err := s.NextBatch(100)
	if err != nil || !ok {
		t.Fatalf("NextBatch = (%v, %v)", ok, err)
	}
	if again.Sequence != first.Sequence {
		t.Fatalf("re-served sequence %d, want the original %d", again.Sequence, first.Sequence)
	}
	if len(again.Metrics) != 1 || again.Metrics[0].Value != 1 {
		t.Fatalf("re-served batch = %v, want the original single metric", again.Metrics)
	}
	// A stale ack for a sequence that is not in flight is ignored, not an error.
	if err := s.Ack(first.Sequence + 999); err != nil {
		t.Fatalf("stale Ack: %v", err)
	}
	if s.Pending() != 2 {
		t.Fatalf("Pending = %d, want 2 (in-flight + buffered)", s.Pending())
	}
}

// Over capacity, whole oldest groups are shed and the count is reported, so the
// caller can surface a real data gap instead of it passing unnoticed.
func TestLiteEvictsOldestWholeGroups(t *testing.T) {
	s := openLite(t)
	totalDropped := 0
	// Two rows per group; enough groups to run well past the cap.
	for i := 0; i < memOnlyMaxRows; i++ {
		d, err := s.Append(Records{Metrics: []telemetry.Metric{metric(float64(i)), metric(float64(i))}})
		if err != nil {
			t.Fatalf("Append: %v", err)
		}
		totalDropped += d
	}
	if totalDropped == 0 {
		t.Fatal("nothing was dropped despite appending far past the cap")
	}
	if got := s.Pending(); got > memOnlyMaxRows {
		t.Fatalf("Pending = %d, want it held at or below the %d-row cap", got, memOnlyMaxRows)
	}
	// Eviction is whole-group, so the buffer never holds half a Records: an odd
	// pending count would mean one was split.
	if s.Pending()%2 != 0 {
		t.Fatalf("Pending = %d is odd, so a 2-row group was split", s.Pending())
	}
	// The survivors are the NEWEST ones.
	b, ok, err := s.NextBatch(2)
	if err != nil || !ok {
		t.Fatalf("NextBatch = (%v, %v)", ok, err)
	}
	if b.Metrics[0].Value == 0 {
		t.Fatal("the oldest group survived eviction; it should have been the first shed")
	}
}

func TestLiteFastForwardOnlyRaises(t *testing.T) {
	s := openLite(t)
	start := s.seqNext

	// Below the current position: ignored, so an ordinary ack cannot renumber
	// sequences backwards.
	if err := s.FastForward(start - 10); err != nil {
		t.Fatalf("FastForward: %v", err)
	}
	if s.seqNext != start {
		t.Fatalf("seqNext = %d, want it left at %d", s.seqNext, start)
	}

	// Above it: raised past the server's watermark, which is the recovery path
	// for a boot whose clock was not yet set.
	if err := s.FastForward(start + 100); err != nil {
		t.Fatalf("FastForward: %v", err)
	}
	if s.seqNext != start+101 {
		t.Fatalf("seqNext = %d, want %d", s.seqNext, start+101)
	}

	// The uint64 max has no representable successor; erroring beats wrapping the
	// allocator back to zero.
	if err := s.FastForward(math.MaxUint64); err == nil {
		t.Fatal("expected an error for a watermark at the uint64 max")
	}
}

// The seed only ever moves forward with the clock, so a reboot does not re-issue
// sequences an earlier boot already sent. A clock that is unset must not wrap the
// allocator to the top of the range.
func TestLiteInitialSeq(t *testing.T) {
	early := initialSeq(time.Unix(1700000000, 0))
	later := initialSeq(time.Unix(1700000001, 0))
	if later <= early {
		t.Fatalf("initialSeq did not advance with the clock: %d then %d", early, later)
	}
	for _, tc := range []time.Time{time.Unix(0, 0), time.Unix(-100, 0), {}} {
		if got := initialSeq(tc); got != 1 {
			t.Fatalf("initialSeq(%v) = %d, want 1 rather than a wrapped uint64", tc, got)
		}
	}
}

func TestLiteFlushAndPendingAreCheap(t *testing.T) {
	s := openLite(t)
	if s.Pending() != 0 {
		t.Fatalf("Pending on a fresh store = %d, want 0", s.Pending())
	}
	if err := s.Flush(); err != nil {
		t.Fatalf("Flush on an empty store: %v", err)
	}
	if _, err := s.Append(Records{Metrics: []telemetry.Metric{metric(1), metric(2)}}); err != nil {
		t.Fatalf("Append: %v", err)
	}
	// Flush cannot make anything durable here, but it must not drop the buffer
	// either — the samples are still queued for the next upload.
	if err := s.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if s.Pending() != 2 {
		t.Fatalf("Pending after Flush = %d, want the 2 still-queued samples", s.Pending())
	}
}
