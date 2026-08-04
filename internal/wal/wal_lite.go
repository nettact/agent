//go:build lite

package wal

import (
	"fmt"
	"log"
	"math"
	"sync"
	"time"
)

const (
	// memOnlyMaxRows caps the buffer. Past it the oldest whole groups are shed —
	// the same contract the default build's over-capacity eviction has, and the
	// only one available here: without a spill, an agent that cannot upload has
	// nowhere else to put samples, and growing until the kernel kills the process
	// would lose the whole buffer instead of its oldest tail.
	//
	// Sized for a router rather than a workstation: a few MB worst case on a
	// device that typically has 64-256 MB of RAM, and well over an hour of
	// backlog at the rate a home network's probes actually produce.
	memOnlyMaxRows = 5000
)

// Store is the agent's outbox in lite (OpenWrt router) builds: memory only, with
// no durable tier behind it.
//
// The default build spills to segment files when uploads stop. On a router that
// would mean writing a telemetry backlog to the flash the device boots from,
// spending erase cycles on data whose whole purpose is to be uploaded and
// discarded — and in ram mode the binary itself runs from a tmpfs a reboot
// clears anyway, so the backlog would outlive very little.
//
// So the durability trade is explicit and worse than the default build's: a
// crash, a reboot, or a power cut loses whatever is buffered, bounded by
// memOnlyMaxRows. What it does NOT lose is the agent's identity — agent.key and
// agent.json live in the data directory on flash, so a router comes back as the
// same agent and never re-enrolls. Delivery order and the indivisible-group and
// re-serve-until-acked rules are identical to the default build; only the spill
// is missing.
type Store struct {
	mu sync.Mutex

	mem      []memGroup // buffered, not yet claimed
	memRows  int
	inflight *memBatch // claimed, awaiting ack; nil when none

	seqNext uint64
}

// Open returns a memory-only store. The path is accepted and ignored so callers
// need no build-specific branch; nothing is created on disk.
func Open(_ string) (*Store, error) {
	return &Store{seqNext: initialSeq(time.Now())}, nil
}

// initialSeq picks the first packet sequence. With no durable allocator, the
// counter has to restart on every boot, and restarting it at 1 would re-issue
// sequences the server already stored — which it dedups on (agent_id, sequence),
// silently suppressing telemetry until the counter climbed past its watermark.
//
// Seeding from the wall clock avoids that: nanoseconds since the epoch only ever
// move forward, so a later boot practically always starts above every sequence
// an earlier one issued. The server never requires sequences to be contiguous —
// it takes MAX for its watermark — so jumping is free.
//
// A router without an RTC can still boot with a 1970 clock and pick a low seed.
// That case is not silent data loss: conn calls FastForward with the server's
// watermark on the first ack, which lifts the allocator above it, so at most one
// deduped batch is lost. (The init script also waits for a plausible clock
// before starting the agent, since TLS would fail at 1970 anyway.)
func initialSeq(now time.Time) uint64 {
	ns := now.UTC().UnixNano()
	if ns < 1 {
		// Pre-epoch or an unset clock. Converting a negative to uint64 would land
		// near MaxUint64 and leave almost no sequence space, so start at 1 and let
		// FastForward do the recovering.
		return 1
	}
	return uint64(ns)
}

// Close reports what the shutdown drops. There is nothing durable to flush to,
// so unlike the default build an ordinary shutdown is NOT lossless; saying so is
// the difference between a known gap and an invisible one.
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if n := s.pendingLocked(); n > 0 {
		log.Printf("wal: %d buffered samples lost at shutdown (memory-only build has no spill)", n)
	}
	s.mem, s.memRows, s.inflight = nil, 0, nil
	return nil
}

// Flush is a no-op: there is no durable tier to flush to. It returns nil rather
// than an error because callers use it as a best-effort durability point, and
// failing here would turn a normal session end into a reported fault.
func (s *Store) Flush() error { return nil }

// Append queues one batch of records for upload. It returns the number of
// samples dropped for over-capacity (>0 means a data gap the caller should
// surface).
func (s *Store) Append(r Records) (dropped int, err error) {
	n := rowsOf(r)
	if n == 0 {
		return 0, nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.mem = append(s.mem, memGroup{at: time.Now().UTC(), rec: r, n: n})
	s.memRows += n
	if s.memRows > memOnlyMaxRows {
		dropped = s.evictOldestLocked(s.memRows - memOnlyMaxRows)
	}
	return dropped, nil
}

// evictOldestLocked drops whole buffered groups, oldest first, until at least n
// rows are gone, and returns how many it actually dropped. Whole groups only:
// splitting one would strip a metric from a Result while leaving its snapshot,
// which is the invariant grouping exists to protect. The in-flight batch is
// never evicted — it has been handed to the uploader and may still need
// re-sending. Caller holds mu.
func (s *Store) evictOldestLocked(n int) int {
	dropped := 0
	for dropped < n && len(s.mem) > 0 {
		dropped += s.mem[0].n
		s.memRows -= s.mem[0].n
		s.mem = s.mem[1:]
	}
	// Re-slice onto a fresh array so the evicted groups become unreachable; the
	// old backing array would otherwise pin their payloads for as long as the
	// buffer lives.
	s.mem = append([]memGroup(nil), s.mem...)
	return dropped
}

// NextBatch returns the next packet to send, or ok=false when there is nothing.
//
// Order is FIFO, which the server's fault detectors rely on (a target's rounds
// arriving out of order would be folded twice):
//
//  1. a batch already claimed and not yet acked — re-served under the SAME
//     sequence, so a dropped session re-sends rather than loses it;
//  2. otherwise the buffer, oldest groups first.
func (s *Store) NextBatch(maxItems int) (Batch, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.inflight != nil {
		return s.inflight.batch(), true, nil
	}
	if len(s.mem) == 0 {
		return Batch{}, false, nil
	}

	// Whole groups, up to maxItems rows — but always at least one, so a single
	// oversized group still makes progress instead of wedging the queue.
	take, rows := 0, 0
	for take < len(s.mem) && (take == 0 || rows+s.mem[take].n <= maxItems) {
		rows += s.mem[take].n
		take++
	}

	mb := &memBatch{seq: s.seqNext, groups: append([]memGroup(nil), s.mem[:take]...)}
	s.seqNext++
	s.mem = append([]memGroup(nil), s.mem[take:]...)
	s.memRows -= rows
	s.inflight = mb
	return mb.batch(), true, nil
}

// Ack releases the samples of an acknowledged packet. A stale ack — for a
// sequence that is not the one in flight — is ignored rather than treated as an
// error: it means a duplicate or late reply, and there is nothing to release.
func (s *Store) Ack(seq uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.inflight != nil && s.inflight.seq == seq {
		s.inflight = nil
	}
	return nil
}

// FastForward raises the next-sequence allocator to at least watermark+1 so the
// WAL stops re-emitting sequences the server has already consumed. Here that is
// the recovery path for a reboot whose clock had not yet been set (see
// initialSeq), where the fresh allocator can start below the server's watermark.
//
// The allocator is never lowered: an ordinary ack whose watermark equals the
// just-sent sequence leaves it untouched. Overflow is explicit — a watermark at
// the uint64 max has no representable successor, so it errors rather than
// wrapping back to zero.
func (s *Store) FastForward(watermark uint64) error {
	if watermark == math.MaxUint64 {
		return fmt.Errorf("wal: watermark %d at uint64 max; no successor sequence", watermark)
	}
	target := watermark + 1

	s.mu.Lock()
	defer s.mu.Unlock()
	if target > s.seqNext {
		s.seqNext = target
	}
	return nil
}

// Pending returns the number of samples not yet acknowledged: buffered plus
// claimed-but-unacked. It backs the agent.wal_pending metric.
func (s *Store) Pending() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pendingLocked()
}

// pendingLocked is Pending without the lock. Caller holds mu.
func (s *Store) pendingLocked() int {
	n := s.memRows
	if s.inflight != nil {
		for _, g := range s.inflight.groups {
			n += g.n
		}
	}
	return n
}
