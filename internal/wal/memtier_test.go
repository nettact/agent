//go:build !lite

package wal

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nettact/protocol/telemetry"
)

// The memory tier's contract, in one place: a draining agent writes nothing to
// disk; a stalled one writes everything, in one transaction, still in order; and
// no packet is ever lost, duplicated, or reordered across the boundary between
// the two.

// srvA and srvB are configured server names. Most tests need only one — the
// tier's contract is per server and does not change with how many there are —
// so srvA is the default and srvB appears where two consumers is the point.
const (
	srvA = "alpha"
	srvB = "beta"
)

// tempWALDir returns a directory to hold a WAL, removed on a best-effort basis
// when the test ends.
//
// t.TempDir is the wrong owner for it on Windows: its cleanup fails the test if
// RemoveAll errors, and Windows can release a just-closed file slightly after
// Close returns — so a passing test intermittently reports a failure on the
// unlink rather than on anything it asserted. (server-core has the same helper,
// for the same reason.) Retry briefly and never fail: a leftover directory under
// the OS temp root is the operating system's to reap.
func tempWALDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "nettact-wal-")
	if err != nil {
		t.Fatalf("temp dir: %v", err)
	}
	t.Cleanup(func() {
		for i := 0; i < 20; i++ {
			if os.RemoveAll(dir) == nil {
				return
			}
			time.Sleep(25 * time.Millisecond)
		}
	})
	return dir
}

func openTemp(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(tempWALDir(t), "wal"), []string{srvA})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// metric builds one recognisable sample.
func metric(v float64) telemetry.Metric {
	return telemetry.Metric{TS: time.Now().UTC(), Kind: telemetry.ICMPRTTms, Target: "10.0.0.1", Value: v}
}

// storedRows is how many sample rows are physically present in the store's
// segment files. It counts bytes on disk rather than the in-memory index, which
// is what makes "a draining agent writes nothing" an honest assertion.
func storedRows(t *testing.T, s *Store) int {
	t.Helper()
	segs, err := listSegments(s.dir)
	if err != nil {
		t.Fatalf("list segments: %v", err)
	}
	n := 0
	for _, seg := range segs {
		groups, err := scanSegment(segPath(s.dir, seg), seg)
		if err != nil {
			t.Fatalf("scan segment %d: %v", seg, err)
		}
		for _, g := range groups {
			n += g.n
		}
	}
	return n
}

// TestDrainingAgentWritesNothingToDisk is the whole point of the tier: while the
// session is up and every packet is acked, telemetry goes memory -> socket and
// never touches durable storage.
func TestDrainingAgentWritesNothingToDisk(t *testing.T) {
	s := openTemp(t)
	for i := 0; i < 200; i++ {
		if _, err := s.Append(Records{Metrics: []telemetry.Metric{metric(float64(i))}}, srvA); err != nil {
			t.Fatalf("Append %d: %v", i, err)
		}
		b, ok, err := s.NextBatch(srvA, 500)
		if err != nil || !ok {
			t.Fatalf("NextBatch %d: ok=%v err=%v", i, ok, err)
		}
		if err := s.Ack(srvA, b.Sequence); err != nil {
			t.Fatalf("Ack %d: %v", i, err)
		}
	}
	if n := storedRows(t, s); n != 0 {
		t.Fatalf("a draining agent wrote %d rows to disk; the memory tier must absorb all of it", n)
	}
	if p := s.Pending(srvA); p != 0 {
		t.Fatalf("Pending = %d after every packet was acked, want 0", p)
	}
}

// TestUnackedMemoryBatchIsReservedUntilAcked: a dropped session must re-send the
// same packet under the same sequence, exactly as the disk tier always did.
func TestUnackedMemoryBatchIsReservedUntilAcked(t *testing.T) {
	s := openTemp(t)
	if _, err := s.Append(Records{Metrics: []telemetry.Metric{metric(1), metric(2)}}, srvA); err != nil {
		t.Fatal(err)
	}
	first, ok, err := s.NextBatch(srvA, 500)
	if err != nil || !ok {
		t.Fatalf("NextBatch: ok=%v err=%v", ok, err)
	}
	again, ok, err := s.NextBatch(srvA, 500)
	if err != nil || !ok {
		t.Fatalf("re-NextBatch: ok=%v err=%v", ok, err)
	}
	if again.Sequence != first.Sequence || len(again.Metrics) != 2 {
		t.Fatalf("unacked packet changed: first seq=%d n=%d, again seq=%d n=%d",
			first.Sequence, len(first.Metrics), again.Sequence, len(again.Metrics))
	}
	if err := s.Ack(srvA, first.Sequence); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := s.NextBatch(srvA, 500); ok {
		t.Fatal("acked packet was served again")
	}
}

// TestSpilledBacklogIsServedBeforeMemory pins the ordering invariant the server's
// fault detectors depend on. Rounds that reached disk are older than anything
// still buffered, so they must go first; the reverse would let a target's rounds
// arrive out of order and be folded twice.
func TestSpilledBacklogIsServedBeforeMemory(t *testing.T) {
	s := openTemp(t)
	if _, err := s.Append(Records{Metrics: []telemetry.Metric{metric(100)}}, srvA); err != nil {
		t.Fatal(err)
	}
	if err := s.Flush(); err != nil { // the agent was offline: this went durable
		t.Fatalf("Flush: %v", err)
	}
	if storedRows(t, s) != 1 {
		t.Fatal("Flush did not spill the buffer")
	}
	// Newer telemetry arrives after the spill and stays in memory.
	if _, err := s.Append(Records{Metrics: []telemetry.Metric{metric(200)}}, srvA); err != nil {
		t.Fatal(err)
	}

	b, ok, err := s.NextBatch(srvA, 500)
	if err != nil || !ok {
		t.Fatalf("NextBatch: ok=%v err=%v", ok, err)
	}
	if len(b.Metrics) != 1 || b.Metrics[0].Value != 100 {
		t.Fatalf("memory jumped the disk backlog: got %+v", b.Metrics)
	}
	if err := s.Ack(srvA, b.Sequence); err != nil {
		t.Fatal(err)
	}
	b2, ok, err := s.NextBatch(srvA, 500)
	if err != nil || !ok {
		t.Fatalf("second NextBatch: ok=%v err=%v", ok, err)
	}
	if len(b2.Metrics) != 1 || b2.Metrics[0].Value != 200 {
		t.Fatalf("second packet = %+v, want the buffered 200", b2.Metrics)
	}
	if b2.Sequence <= b.Sequence {
		t.Fatalf("sequences went backwards: %d then %d", b.Sequence, b2.Sequence)
	}
}

// TestSpillPreservesTheClaimedPacket: spilling while a memory packet is in flight
// must keep it claimed and first in line, so the uploader re-sends that exact
// sequence from disk rather than renumbering or reordering it.
func TestSpillPreservesTheClaimedPacket(t *testing.T) {
	s := openTemp(t)
	if _, err := s.Append(Records{Metrics: []telemetry.Metric{metric(1)}}, srvA); err != nil {
		t.Fatal(err)
	}
	inflight, ok, err := s.NextBatch(srvA, 500)
	if err != nil || !ok {
		t.Fatalf("NextBatch: ok=%v err=%v", ok, err)
	}
	// More telemetry arrives, then the whole tier goes durable (long outage).
	if _, err := s.Append(Records{Metrics: []telemetry.Metric{metric(2)}}, srvA); err != nil {
		t.Fatal(err)
	}
	if err := s.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	got, ok, err := s.NextBatch(srvA, 500)
	if err != nil || !ok {
		t.Fatalf("post-spill NextBatch: ok=%v err=%v", ok, err)
	}
	if got.Sequence != inflight.Sequence {
		t.Fatalf("in-flight packet was renumbered by the spill: %d -> %d", inflight.Sequence, got.Sequence)
	}
	if len(got.Metrics) != 1 || got.Metrics[0].Value != 1 {
		t.Fatalf("in-flight packet changed content: %+v", got.Metrics)
	}
	if err := s.Ack(srvA, got.Sequence); err != nil {
		t.Fatal(err)
	}
	next, ok, err := s.NextBatch(srvA, 500)
	if err != nil || !ok {
		t.Fatalf("NextBatch after ack: ok=%v err=%v", ok, err)
	}
	if len(next.Metrics) != 1 || next.Metrics[0].Value != 2 {
		t.Fatalf("buffered record lost or reordered by the spill: %+v", next.Metrics)
	}
}

// TestCloseFlushesSoRestartLosesNothing: an ordinary shutdown is not a crash.
func TestCloseFlushesSoRestartLosesNothing(t *testing.T) {
	dir := tempWALDir(t)
	path := filepath.Join(dir, "wal")
	s, err := Open(path, []string{srvA})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Append(Records{Metrics: []telemetry.Metric{metric(7)}}, srvA); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	again, err := Open(path, []string{srvA})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = again.Close() })
	b, ok, err := again.NextBatch(srvA, 500)
	if err != nil || !ok {
		t.Fatalf("after restart: ok=%v err=%v", ok, err)
	}
	if len(b.Metrics) != 1 || b.Metrics[0].Value != 7 {
		t.Fatalf("clean shutdown lost buffered telemetry: %+v", b.Metrics)
	}
}

// TestSequencesNeverRepeatAcrossRestarts guards the block allocator. A reused
// (agent_id, sequence) is silently deduped by the server — telemetry that looks
// sent and is never stored — so a restart must resume ABOVE every sequence the
// previous process could have handed out.
func TestSequencesNeverRepeatAcrossRestarts(t *testing.T) {
	dir := tempWALDir(t)
	path := filepath.Join(dir, "wal")
	seen := map[uint64]bool{}

	for restart := 0; restart < 3; restart++ {
		s, err := Open(path, []string{srvA})
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 5; i++ {
			if _, err := s.Append(Records{Metrics: []telemetry.Metric{metric(float64(i))}}, srvA); err != nil {
				t.Fatal(err)
			}
			b, ok, err := s.NextBatch(srvA, 500)
			if err != nil || !ok {
				t.Fatalf("NextBatch: ok=%v err=%v", ok, err)
			}
			if seen[b.Sequence] {
				t.Fatalf("sequence %d reused after restart %d — the server would dedup it away", b.Sequence, restart)
			}
			seen[b.Sequence] = true
			if err := s.Ack(srvA, b.Sequence); err != nil {
				t.Fatal(err)
			}
		}
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

// TestBufferSpillsOnceItAges bounds what a crash can lose while the server is
// unreachable: past memBufferAge the buffer goes durable on its own, with no
// upload and no shutdown to trigger it.
func TestBufferSpillsOnceItAges(t *testing.T) {
	s := openTemp(t)
	// Backdate the first group past the age limit, simulating an outage without
	// making the test wait one out.
	if _, err := s.Append(Records{Metrics: []telemetry.Metric{metric(1)}}, srvA); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	s.mem[0].at = time.Now().UTC().Add(-memBufferAge - time.Second)
	s.mu.Unlock()
	if n := storedRows(t, s); n != 0 {
		t.Fatalf("nothing should be durable yet, got %d rows", n)
	}

	if _, err := s.Append(Records{Metrics: []telemetry.Metric{metric(2)}}, srvA); err != nil {
		t.Fatal(err)
	}
	if n := storedRows(t, s); n != 2 {
		t.Fatalf("an aged buffer must spill in full: %d rows on disk, want 2", n)
	}
}

// TestFastForwardRecoversWhenTheWatermarkIsInsideAReservedBlock is the case
// FastForward exists for, made reachable again by the block allocator.
//
// Reserving a block pushes the DURABLE position a whole block past what is
// actually being issued, so a recreated WAL (allocator back near 1) against a
// server that still retains a high watermark looks, by the durable value alone,
// as though it were already ahead. It is not: every sequence from the block's
// cursor up to the watermark has already been stored by the server and would be
// silently deduped — telemetry that reads as sent and is never kept.
func TestFastForwardRecoversWhenTheWatermarkIsInsideAReservedBlock(t *testing.T) {
	s := openTemp(t)

	// A fresh WAL issues sequence 1 and reserves the block behind it.
	if _, err := s.Append(Records{Metrics: []telemetry.Metric{metric(1)}}, srvA); err != nil {
		t.Fatal(err)
	}
	first, ok, err := s.NextBatch(srvA, 500)
	if err != nil || !ok {
		t.Fatalf("NextBatch: ok=%v err=%v", ok, err)
	}
	if first.Sequence != 1 {
		t.Fatalf("first sequence = %d, want 1", first.Sequence)
	}
	if err := s.Ack(srvA, first.Sequence); err != nil {
		t.Fatal(err)
	}

	// The server reports a far higher watermark: this agent's enrollment survived
	// a WAL that did not, and sequences up to 500 are already stored there.
	const watermark = 500
	if err := s.FastForward(watermark); err != nil {
		t.Fatalf("FastForward: %v", err)
	}

	if _, err := s.Append(Records{Metrics: []telemetry.Metric{metric(2)}}, srvA); err != nil {
		t.Fatal(err)
	}
	next, ok, err := s.NextBatch(srvA, 500)
	if err != nil || !ok {
		t.Fatalf("post-FastForward NextBatch: ok=%v err=%v", ok, err)
	}
	if next.Sequence <= watermark {
		t.Fatalf("issued sequence %d at or below the server watermark %d; the server would dedup it away",
			next.Sequence, watermark)
	}
}

// TestSpillFailureDoesNotRejectTheAppend: the buffer has taken the records, so
// reporting a rejection would make agentrt's game drain re-queue them and upload
// two copies once the disk recovers.
func TestSpillFailureDoesNotRejectTheAppend(t *testing.T) {
	s := openTemp(t)
	// Break the durable tier underneath the buffer: a path that is a regular
	// file, so every attempt to create a segment inside it fails.
	blocked := filepath.Join(tempWALDir(t), "not-a-dir")
	if err := os.WriteFile(blocked, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	s.dir = blocked
	s.mu.Unlock()

	// Force the age trigger so this append must try to spill.
	if _, err := s.Append(Records{Metrics: []telemetry.Metric{metric(1)}}, srvA); err != nil {
		t.Fatalf("first append: %v", err)
	}
	s.mu.Lock()
	s.mem[0].at = time.Now().UTC().Add(-memBufferAge - time.Second)
	s.mu.Unlock()

	if _, err := s.Append(Records{Metrics: []telemetry.Metric{metric(2)}}, srvA); err != nil {
		t.Fatalf("a failed spill must not reject records the buffer already holds: %v", err)
	}
	s.mu.Lock()
	held := s.memRows
	s.mu.Unlock()
	if held != 2 {
		t.Fatalf("buffer holds %d rows after a failed spill, want both retained", held)
	}
}

// TestExpiredBacklogIsNotServedAfterTheWindow: server-core prunes its dedup rows
// assuming the agent never replays anything older than the retention window, so
// an aged backlog must be expired before it can be claimed — not merely whenever
// a spill happens to run.
func TestExpiredBacklogIsNotServedAfterTheWindow(t *testing.T) {
	s := openTemp(t)
	if _, err := s.Append(Records{Metrics: []telemetry.Metric{metric(1)}}, srvA); err != nil {
		t.Fatal(err)
	}
	if err := s.Flush(); err != nil {
		t.Fatal(err)
	}
	// Age the spilled groups past the retention window.
	old := time.Now().UTC().Add(-s.retention - time.Hour)
	s.mu.Lock()
	for i := range s.disk {
		s.disk[i].at = old
	}
	s.mu.Unlock()

	if _, ok, err := s.NextBatch(srvA, 500); err != nil || ok {
		t.Fatalf("expired backlog was served: ok=%v err=%v", ok, err)
	}
	if n := storedRows(t, s); n != 0 {
		t.Fatalf("%d expired rows survived the claim path", n)
	}
}
