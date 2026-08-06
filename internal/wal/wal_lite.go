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
	//
	// It is a store-wide cap, not per server. A router reporting to two servers
	// with one of them offline sheds that one's backlog first simply because its
	// groups are the oldest ones present — the same backpressure the default
	// build's row cap applies, without needing to know whose they are.
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
// same agent and never re-enrolls. Delivery order, per-server ownership, and the
// indivisible-group and re-serve-until-acked rules are identical to the default
// build; only the spill is missing.
type Store struct {
	mu sync.Mutex

	mem     []memGroup // buffered, gid-ascending; includes groups under a claim
	memRows int

	cursors map[string]*cursor
	nextGid uint64
	seqNext uint64
}

// Open returns a memory-only store serving the named servers. The path is
// accepted and ignored so callers need no build-specific branch; nothing is
// created on disk.
func Open(_ string, servers []string) (*Store, error) {
	if len(servers) == 0 {
		return nil, fmt.Errorf("wal: Open needs at least one server name")
	}
	s := &Store{
		cursors: make(map[string]*cursor, len(servers)),
		nextGid: 1,
		seqNext: initialSeq(time.Now()),
	}
	for _, name := range servers {
		s.cursors[name] = &cursor{}
	}
	return s, nil
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
	if n := s.memRows; n > 0 {
		log.Printf("wal: %d buffered samples lost at shutdown (memory-only build has no spill)", n)
	}
	s.mem, s.memRows = nil, 0
	for _, c := range s.cursors {
		c.claim = nil
	}
	return nil
}

// Flush is a no-op: there is no durable tier to flush to. It returns nil rather
// than an error because callers use it as a best-effort durability point, and
// failing here would turn a normal session end into a reported fault.
func (s *Store) Flush() error { return nil }

// Append queues one batch of records for delivery to one server. It returns the
// number of samples dropped for over-capacity (>0 means a data gap the caller
// should surface). An unknown server name is an error: appending for a server
// with no cursor would store bytes nothing will ever deliver.
func (s *Store) Append(r Records, server string) (dropped int, err error) {
	n := rowsOf(r)
	if n == 0 {
		return 0, nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.cursors[server]; !ok {
		return 0, fmt.Errorf("wal: append for unknown server %q", server)
	}
	s.mem = append(s.mem, memGroup{gid: s.nextGid, owner: server, at: time.Now().UTC(), rec: r, n: n})
	s.nextGid++
	s.memRows += n
	if s.memRows > memOnlyMaxRows {
		dropped = s.evictOldestLocked(s.memRows - memOnlyMaxRows)
	}
	return dropped, nil
}

// evictOldestLocked drops whole buffered groups, oldest first, until at least n
// rows are gone, and returns how many it actually dropped. Whole groups only:
// splitting one would strip a metric from a Result while leaving its snapshot,
// which is the invariant grouping exists to protect. A claimed group is never
// evicted — it has been handed to a session and may still need re-sending.
// Caller holds mu.
func (s *Store) evictOldestLocked(n int) int {
	dropped := 0
	// Re-slice onto a fresh array so the evicted groups become unreachable; the
	// old backing array would otherwise pin their payloads for as long as the
	// buffer lives.
	out := make([]memGroup, 0, len(s.mem))
	for _, g := range s.mem {
		if dropped < n && !s.claimedLocked(g.owner, g.gid) {
			dropped += g.n
			s.memRows -= g.n
			continue
		}
		out = append(out, g)
	}
	s.mem = out
	return dropped
}

// claimedLocked reports whether a group is inside its owner's in-flight claim.
// Caller holds mu.
func (s *Store) claimedLocked(owner string, gid uint64) bool {
	c, ok := s.cursors[owner]
	return ok && c.claim.covers(gid)
}

// NextBatch returns the next packet to send to one server, or ok=false when that
// server is owed nothing.
//
// Order is FIFO within the server's own groups, which the server's fault
// detectors rely on (a target's rounds arriving out of order would be folded
// twice):
//
//  1. a batch already claimed and not yet acked — re-served under the SAME
//     sequence, so a dropped session re-sends rather than loses it;
//  2. otherwise the buffer, oldest groups first.
func (s *Store) NextBatch(server string, maxItems int) (Batch, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	c, ok := s.cursors[server]
	if !ok {
		return Batch{}, false, fmt.Errorf("wal: unknown server %q", server)
	}
	if c.claim != nil {
		return s.loadClaimLocked(server, c.claim), true, nil
	}

	// Whole groups, up to maxItems rows — but always at least one, so a single
	// oversized group still makes progress instead of wedging the queue.
	rows := 0
	var first, last uint64
	recs := make([]Records, 0, 8)
	for _, g := range s.mem {
		if g.owner != server || g.gid <= c.acked {
			continue
		}
		if len(recs) > 0 && rows+g.n > maxItems {
			break
		}
		if len(recs) == 0 {
			first = g.gid
		}
		last = g.gid
		rows += g.n
		recs = append(recs, g.rec)
	}
	if len(recs) == 0 {
		return Batch{}, false, nil
	}

	seq := s.seqNext
	s.seqNext++
	c.claim = &claim{seq: seq, from: first, to: last, n: len(recs)}
	return flatten(seq, recs), true, nil
}

// loadClaimLocked re-serves a claim's groups under their original sequence.
// Caller holds mu.
func (s *Store) loadClaimLocked(server string, cl *claim) Batch {
	recs := make([]Records, 0, cl.n)
	for _, g := range s.mem {
		if g.owner == server && cl.covers(g.gid) {
			recs = append(recs, g.rec)
		}
	}
	return flatten(cl.seq, recs)
}

// Ack releases one server's acknowledged packet. A stale ack — for a sequence
// that is not the one in flight, or for a server that is not configured — is
// ignored rather than treated as an error: it means a duplicate or late reply,
// and there is nothing to release.
func (s *Store) Ack(server string, seq uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	c, ok := s.cursors[server]
	if !ok || c.claim == nil || c.claim.seq != seq {
		return nil
	}
	cl := c.claim
	c.acked = cl.to
	c.claim = nil

	out := make([]memGroup, 0, len(s.mem))
	for _, g := range s.mem {
		if g.owner == server && cl.covers(g.gid) {
			s.memRows -= g.n
			continue
		}
		out = append(out, g)
	}
	s.mem = out
	return nil
}

// FastForward raises the next-sequence allocator to at least watermark+1 so the
// WAL stops re-emitting sequences the server has already consumed. Here that is
// the recovery path for a reboot whose clock had not yet been set (see
// initialSeq), where the fresh allocator can start below a server's watermark.
//
// The allocator is shared by every server, so a watermark from one raises it for
// all of them. Skipping ahead only leaves gaps, which every server tolerates.
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

// Pending returns the number of samples one server has not yet acknowledged:
// buffered plus claimed-but-unacked. It backs that server's agent.wal_pending
// metric.
func (s *Store) Pending(server string) int {
	s.mu.Lock()
	defer s.mu.Unlock()

	c, ok := s.cursors[server]
	if !ok {
		return 0
	}
	n := 0
	for _, g := range s.mem {
		if g.owner == server && g.gid > c.acked {
			n += g.n
		}
	}
	return n
}
