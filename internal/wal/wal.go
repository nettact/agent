//go:build !lite

package wal

import (
	"fmt"
	"log"
	"math"
	"os"
	"sync"
	"time"
)

const (
	// memBufferRows caps the in-memory tier. It is only reached when uploads are
	// not keeping up; the buffer then spills to one segment file, which is what
	// makes a disconnected agent cheap to store rather than expensive.
	memBufferRows = 20000

	// memBufferAge is how long a record may sit in memory before it is spilled
	// regardless of depth. It bounds what a crash can lose while the server is
	// unreachable. A healthy agent uploads every DefaultUploadInterval (30s) and
	// so drains well inside this, never spilling at all.
	memBufferAge = 90 * time.Second

	// seqBlock is how many packet sequences one durable reservation covers. The
	// allocator has to survive restarts (a reused sequence is silently deduped by
	// the server, i.e. lost telemetry), but writing it per packet would put back
	// the per-upload write this tier exists to remove. Reserving in blocks costs
	// one small write per seqBlock packets; the unused tail of a block is skipped
	// after a restart, which is harmless because the server dedups on the exact
	// (agent_id, sequence) pair and takes MAX for its watermark — it never
	// requires sequences to be contiguous.
	seqBlock = 1000

	// memBufferHardCap is how far past memBufferRows the buffer may grow while
	// spills are failing before it starts shedding the oldest groups.
	memBufferHardCap = 2 * memBufferRows
)

// Store is the agent's outbox: an in-memory queue in front of a segment-file
// spill.
//
// Telemetry is appended to memory and, when the session is up, handed straight
// to the uploader and dropped on ack — so a healthy agent writes NOTHING to
// disk beyond one small state file per seqBlock packets. Disk is what the buffer
// falls back on: when the buffer fills, ages past memBufferAge, or the process
// shuts down, the whole buffer is written as one new segment.
//
// The cost is bounded and deliberate: a crash loses whatever is still in
// memory. While connected that is at most one upload interval's worth. While
// disconnected it is BOUNDED, not zero: the session's end flushes the buffer
// immediately (conn.run), and after that each unspilled stretch is capped by
// memBufferAge — the age check rides on Append, which the 30s status heartbeat
// guarantees keeps arriving. Callers needing a hard point can Flush.
//
// Delivery order is FIFO across both tiers, which the fault detectors depend on:
// NextBatch serves the disk backlog before any memory group, and a spill appends
// a segment after the ones already there, so a target's rounds can never reach
// the server out of order.
//
// See segment.go for the on-disk format and its durability guarantees.
type Store struct {
	dir       string
	mu        sync.Mutex
	maxRows   int
	retention time.Duration

	mem      []memGroup // buffered, not yet claimed
	memRows  int
	inflight *memBatch // claimed from memory, awaiting ack; nil when none

	// disk indexes the live spilled groups in FIFO order. It is the authority on
	// what is still owed; the files may additionally hold groups this index has
	// dropped (see the cap eviction in spillLocked).
	disk    []diskGroup
	claim   *diskClaim // the head groups already issued as a packet; nil when none
	head    diskPos    // durable consumed prefix
	nextSeg uint64     // counter the next spill will use

	seqNext, seqCeil uint64 // reserved sequence block [seqNext, seqCeil)
	durableSeq       uint64 // persisted allocator position, mirrored in memory
}

// Open creates/opens the WAL in directory dir.
func Open(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	removeStaleTemps(dir)

	s := &Store{dir: dir, maxRows: 50000, retention: 72 * time.Hour, durableSeq: 1, nextSeg: 1}

	st, found, err := readState(dir)
	if err != nil {
		// state.json is published by rename, so a torn write is impossible; this
		// is hand-editing or real corruption. Starting over loses the backlog,
		// which beats replaying it: without the allocator position, every group
		// would be re-sent under sequences the server cannot recognise as
		// duplicates. FastForward lifts the allocator on the first ack — this is
		// precisely the recreated-WAL case it exists for.
		log.Printf("wal: unreadable %s (%v); discarding the durable backlog and starting fresh", stateName, err)
		if err := s.discardSegments(); err != nil {
			return nil, err
		}
		return s, nil
	}
	if found {
		if st.NextSeq > 0 {
			s.durableSeq = st.NextSeq
		}
		s.head = diskPos{seg: st.HeadSeg, grp: st.HeadGrp}
	}

	segs, err := listSegments(dir)
	if err != nil {
		return nil, err
	}
	for _, n := range segs {
		if n < s.head.seg {
			os.Remove(segPath(dir, n)) // fully consumed before the last shutdown
			continue
		}
		groups, err := scanSegment(segPath(dir, n), n)
		if err != nil {
			return nil, err
		}
		if n == s.head.seg && s.head.grp > 0 {
			if s.head.grp >= len(groups) {
				// The whole segment was consumed; its deletion just did not happen
				// before the process went away.
				os.Remove(segPath(dir, n))
				groups = nil
			} else {
				groups = groups[s.head.grp:]
			}
		}
		s.disk = append(s.disk, groups...)
		if n >= s.nextSeg {
			s.nextSeg = n + 1
		}
	}
	if s.head.seg >= s.nextSeg {
		s.nextSeg = s.head.seg + 1
	}

	if st.ClaimN > 0 {
		if st.ClaimN <= len(s.disk) {
			s.claim = &diskClaim{seq: st.ClaimSeq, n: st.ClaimN}
		} else {
			// The state naming this claim was written, but the segment carrying
			// its groups never got renamed into place. Serving a short packet
			// under a sequence the server may already associate with different
			// content would be worse than dropping it: the sequence is simply
			// burned, which the server tolerates (it takes MAX, never requires
			// contiguity).
			log.Printf("wal: claim %d covers %d groups but only %d survived; dropping the claim",
				st.ClaimSeq, st.ClaimN, len(s.disk))
		}
	}
	s.refreshHeadLocked()
	return s, nil
}

// discardSegments deletes every segment, used when the bookkeeping that
// describes them cannot be trusted.
func (s *Store) discardSegments() error {
	segs, err := listSegments(s.dir)
	if err != nil {
		return err
	}
	for _, n := range segs {
		os.Remove(segPath(s.dir, n))
	}
	s.disk, s.claim, s.head, s.nextSeg = nil, nil, diskPos{seg: 1}, 1
	return nil
}

// Close flushes the memory tier to disk. Flushing here is what makes an ordinary
// shutdown lossless: the caller already stops every producer and joins them
// before closing, so nothing is still being appended.
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	dropped, err := s.spillLocked(time.Now().UTC())
	if dropped > 0 {
		// Nobody is left to inspect a return value at shutdown, and an offline
		// agent closing with a full backlog can shed thousands of samples here.
		// Reporting success while silently dropping them would make a real data
		// gap invisible.
		log.Printf("WAL over capacity at shutdown: dropped %d oldest samples (data gap)", dropped)
	}
	return err
}

// Flush spills everything buffered in memory to durable storage. Callers that
// want a hard durability point (a session ending, suspend) can use it; ordinary
// operation relies on Close.
func (s *Store) Flush() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	dropped, err := s.spillLocked(time.Now().UTC())
	if dropped > 0 {
		// Same reason Close logs it: the signature returns only an error, so a
		// caller cannot see this, and a spill into a backlog already at capacity
		// sheds whole groups. An unreported eviction is an invisible data gap.
		log.Printf("WAL over capacity while flushing: dropped %d oldest samples (data gap)", dropped)
	}
	return err
}

// Append queues one batch of records for upload. It returns the number of
// samples dropped for over-capacity (>0 means a data gap the caller should
// surface).
//
// The records go to memory. They reach disk only if the buffer fills, ages past
// memBufferAge, or the store is closed — so while the session is up and draining
// this costs no disk write at all. See Store for the durability trade.
//
// An error means the records were NOT accepted and the caller still owns them.
// A failed spill is deliberately not one: the records are in the buffer and the
// next trigger retries writing them, so reporting a rejection would be both
// untrue and harmful — agentrt's game drain re-queues on error, which would put
// a second copy of the same records in the buffer and upload both once the disk
// recovers. Spill failures are logged here instead.
func (s *Store) Append(r Records) (dropped int, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	n := rowsOf(r)
	if n == 0 {
		return 0, nil
	}
	now := time.Now().UTC()
	s.mem = append(s.mem, memGroup{at: now, rec: r, n: n})
	s.memRows += n

	if s.memRows < memBufferRows && now.Sub(s.oldestLocked()) < memBufferAge {
		return 0, nil
	}
	dropped, spillErr := s.spillLocked(now)
	if spillErr != nil {
		log.Printf("wal: spill failed, %d rows still buffered: %v", s.memRows, spillErr)
		if s.memRows > memBufferHardCap {
			// Spilling is the buffer's only exit when nothing is being uploaded, so a
			// disk that refuses writes (full, read-only, gone) would otherwise let
			// memory grow until the agent is killed — trading a bounded data gap for
			// losing the process, and with it every unspilled sample anyway. Drop the
			// oldest whole groups instead, which is the same contract the durable
			// tier's own over-capacity eviction has always had.
			dropped += s.evictOldestLocked(s.memRows - memBufferRows)
		}
	}
	return dropped, nil
}

// evictOldestLocked drops whole buffered groups, oldest first, until at least n
// rows are gone, and returns how many it actually dropped. Whole groups only:
// splitting one would strip a metric from a Result while leaving its snapshot,
// which is the invariant grouping exists to protect. Caller holds mu.
func (s *Store) evictOldestLocked(n int) int {
	dropped := 0
	for dropped < n && len(s.mem) > 0 {
		dropped += s.mem[0].n
		s.memRows -= s.mem[0].n
		s.mem = s.mem[1:]
	}
	s.mem = append([]memGroup(nil), s.mem...)
	return dropped
}

// oldestLocked is the arrival time of the oldest record still held in memory,
// counting the in-flight batch (which is older than anything in mem). Zero when
// memory is empty, which never triggers a spill because time.Since(zero) is
// compared only when there is something to spill.
func (s *Store) oldestLocked() time.Time {
	if s.inflight != nil && len(s.inflight.groups) > 0 {
		return s.inflight.groups[0].at
	}
	if len(s.mem) > 0 {
		return s.mem[0].at
	}
	return time.Now().UTC()
}

// spillLocked writes the whole memory tier to one new segment and enforces the
// store's caps. The in-flight batch is written first and keeps its sequence via
// the claim, so it stays both the oldest group and a claimed one — the uploader
// then re-sends it under the same sequence from disk, exactly as it would have
// from memory.
//
// Nothing in the Store is mutated until the segment is safely renamed into
// place, so a failure anywhere leaves the buffer intact for the next attempt —
// which is what lets Append tolerate a broken disk. Caller holds mu.
func (s *Store) spillLocked(now time.Time) (dropped int, err error) {
	if s.inflight == nil && len(s.mem) == 0 {
		return 0, nil
	}

	groups := make([]memGroup, 0, len(s.mem)+1)
	if s.inflight != nil {
		groups = append(groups, s.inflight.groups...)
	}
	groups = append(groups, s.mem...)

	seg := s.nextSeg
	tmp, lines, err := writeSegmentTemp(s.dir, groups)
	if err != nil {
		return 0, err
	}
	published := false
	defer func() {
		if !published {
			os.Remove(tmp)
		}
	}()
	for i := range lines {
		lines[i].seg = seg
	}

	// Build the post-spill index without touching s yet.
	index := make([]diskGroup, 0, len(s.disk)+len(lines))
	index = append(index, s.disk...)
	claim := s.claim
	if s.inflight != nil && len(index) == 0 && claim == nil {
		// A memory in-flight batch can only exist when the disk backlog was empty
		// (NextBatch serves disk before memory), so the spilled in-flight lands at
		// the head — exactly where a claim addresses it. The guard keeps that
		// reasoning enforced rather than assumed.
		claim = &diskClaim{seq: s.inflight.seq, n: len(s.inflight.groups)}
	}
	index = append(index, lines...)

	index, claim = expirePrefix(index, claim, now.Add(-s.retention))
	index, dropped = capOldestUnclaimed(index, claim, s.maxRows)

	nextSeg := seg + 1
	head := headOf(index, nextSeg)
	prev := s.stateLocked()
	next := walState{V: stateFormat, NextSeq: s.durableSeq, HeadSeg: head.seg, HeadGrp: head.grp}
	if claim != nil {
		next.ClaimSeq, next.ClaimN = claim.seq, claim.n
	}

	// State first, segment second. A crash in between leaves a claim describing
	// groups that never became visible, which Open clamps away — bounded loss.
	// The reverse order would leave the in-flight groups on disk with no claim,
	// so they would be re-issued under a NEW sequence and the server, unable to
	// recognise them as the packet it may already hold, would ingest them twice.
	if err = writeState(s.dir, next); err != nil {
		return 0, err
	}
	if err = os.Rename(tmp, segPath(s.dir, seg)); err != nil {
		// Put the bookkeeping back so this process keeps describing what is
		// actually on disk. If even that fails, Open's clamp is the backstop.
		if rbErr := writeState(s.dir, prev); rbErr != nil {
			log.Printf("wal: could not roll back %s after a failed spill: %v", stateName, rbErr)
		}
		return 0, err
	}
	published = true

	s.disk, s.claim, s.head, s.nextSeg = index, claim, head, nextSeg
	s.inflight, s.mem, s.memRows = nil, nil, 0
	s.gcLocked()
	return dropped, nil
}

// expirePrefix drops leading groups that arrived before cutoff and shrinks a
// claim that covered any of them. Expiry is always a prefix because arrival
// times are non-decreasing across the index: spills happen in time order and
// preserve arrival order within themselves.
//
// A claim losing groups mirrors what the old store's unconditional retention
// delete did to already-tagged rows: past the window, server-core has pruned the
// dedup entry, so replaying the packet would be re-ingested as new.
func expirePrefix(index []diskGroup, claim *diskClaim, cutoff time.Time) ([]diskGroup, *diskClaim) {
	drop := 0
	for drop < len(index) && index[drop].at.Before(cutoff) {
		drop++
	}
	if drop == 0 {
		return index, claim
	}
	if claim != nil {
		if claim.n <= drop {
			claim = nil
		} else {
			claim = &diskClaim{seq: claim.seq, n: claim.n - drop}
		}
	}
	return append([]diskGroup(nil), index[drop:]...), claim
}

// capOldestUnclaimed enforces the row cap by dropping the oldest UNCLAIMED whole
// groups, and reports how many rows went. Whole-group eviction preserves the
// indivisible-Result invariant, so this may drop slightly more than the exact
// overflow; the actual count is what gets returned and logged.
//
// The claimed head is never evicted: it has been handed to the uploader and may
// still need re-sending under its sequence. Evicting from behind it leaves the
// index describing less than the files hold; gcLocked then deletes every
// segment the index no longer references, which is what keeps the cap real even
// while a claim pins the head in place.
//
// What can survive is the evicted tail of a segment that still holds live
// groups — at most the two segments the evicted run starts and ends in, since
// the run is contiguous. A restart rescans those and brings those groups back:
// they are unclaimed, unsent, in their original position and within retention,
// so the next spill evicts them again.
func capOldestUnclaimed(index []diskGroup, claim *diskClaim, maxRows int) ([]diskGroup, int) {
	total := 0
	for _, g := range index {
		total += g.n
	}
	if total <= maxRows {
		return index, 0
	}
	keep := 0
	if claim != nil {
		keep = claim.n
	}
	cut, dropped := keep, 0
	for total > maxRows && cut < len(index) {
		dropped += index[cut].n
		total -= index[cut].n
		cut++
	}
	if cut == keep {
		return index, 0
	}
	out := make([]diskGroup, 0, len(index)-(cut-keep))
	out = append(out, index[:keep]...)
	out = append(out, index[cut:]...)
	return out, dropped
}

// headOf is the consumed-prefix pointer implied by a live index. With nothing
// live it points past every existing segment, which is what makes them all
// collectable.
func headOf(index []diskGroup, nextSeg uint64) diskPos {
	if len(index) == 0 {
		return diskPos{seg: nextSeg}
	}
	return diskPos{seg: index[0].seg, grp: index[0].line}
}

func (s *Store) refreshHeadLocked() {
	s.head = headOf(s.disk, s.nextSeg)
}

// stateLocked renders the current bookkeeping. Caller holds mu.
func (s *Store) stateLocked() walState {
	st := walState{V: stateFormat, NextSeq: s.durableSeq, HeadSeg: s.head.seg, HeadGrp: s.head.grp}
	if s.claim != nil {
		st.ClaimSeq, st.ClaimN = s.claim.seq, s.claim.n
	}
	return st
}

func (s *Store) saveStateLocked() error {
	return writeState(s.dir, s.stateLocked())
}

// gcLocked deletes every segment the live index no longer references. Caller
// holds mu.
//
// Liveness rather than "before the head" is what makes the row cap real. While
// a claim sits unacknowledged — which is the whole of a long outage, since the
// claim is only released by an ack — the head cannot move past it, so a
// head-based sweep would keep every segment behind it forever while each spill
// added another. Disk then grew without limit on exactly the path this store
// exists for. A segment nothing in the index points at owes nothing and can go
// regardless of where the head is.
func (s *Store) gcLocked() {
	segs, err := listSegments(s.dir)
	if err != nil {
		return
	}
	live := make(map[uint64]struct{}, 4)
	for _, g := range s.disk {
		live[g.seg] = struct{}{}
	}
	for _, n := range segs {
		if _, ok := live[n]; ok {
			continue
		}
		os.Remove(segPath(s.dir, n))
	}
}

// NextBatch returns the next packet to send, or ok=false when there is nothing.
//
// Order is FIFO across both tiers, which is what the server's fault detectors
// rely on (a target's rounds arriving out of order would be folded twice):
//
//  1. a memory batch already claimed and not yet acked — re-served under the
//     SAME sequence, so a dropped session re-sends rather than loses it;
//  2. the disk backlog, the claimed head first, then unclaimed groups —
//     everything on disk is older than anything in memory, because memory only
//     spills in arrival order and only ever appends a segment;
//  3. finally the memory buffer.
//
// Step 3 is the case a healthy agent is always in, and it touches no disk.
func (s *Store) NextBatch(maxItems int) (Batch, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.inflight != nil {
		return s.inflight.batch(), true, nil
	}
	b, ok, err := s.nextDiskBatchLocked(maxItems)
	if err != nil || ok {
		return b, ok, err
	}
	return s.nextMemBatchLocked(maxItems)
}

// nextMemBatchLocked claims whole groups from the memory buffer, up to maxItems
// rows (always at least one group, so a single oversized group still makes
// progress). The claimed groups move into s.inflight rather than being dropped:
// until the ack lands they may still have to be re-sent or spilled. Caller holds
// mu.
func (s *Store) nextMemBatchLocked(maxItems int) (Batch, bool, error) {
	if len(s.mem) == 0 {
		return Batch{}, false, nil
	}
	take, rows := 0, 0
	for take < len(s.mem) && (take == 0 || rows+s.mem[take].n <= maxItems) {
		rows += s.mem[take].n
		take++
	}
	seq, err := s.allocSeqLocked()
	if err != nil {
		return Batch{}, false, err
	}
	mb := &memBatch{seq: seq, groups: append([]memGroup(nil), s.mem[:take]...)}
	s.mem = append([]memGroup(nil), s.mem[take:]...)
	s.memRows -= rows
	s.inflight = mb
	return mb.batch(), true, nil
}

// nextDiskBatchLocked serves the spilled backlog: the already-claimed head first
// so a failed/crashed upload re-sends the same sequence, otherwise up to
// maxItems rows of unclaimed groups under a new sequence. Caller holds mu.
func (s *Store) nextDiskBatchLocked(maxItems int) (Batch, bool, error) {
	// Expire stale groups before any of them can be claimed. This used to ride on
	// every Append, but appends now usually stop at memory, so without it a
	// backlog spilled during a long outage could be uploaded after sitting past
	// the retention window — and server-core prunes its (agent_id, sequence)
	// dedup rows on exactly the assumption that the agent never replays anything
	// older than this, so those packets would be re-ingested as if new. Nothing
	// expired means no write at all, so the common case is free.
	if err := s.expireLocked(time.Now().UTC()); err != nil {
		return Batch{}, false, err
	}

	if s.claim != nil {
		b, err := s.loadClaimLocked()
		if err != nil {
			return Batch{}, false, err
		}
		return b, true, nil
	}
	if len(s.disk) == 0 {
		return Batch{}, false, nil
	}

	// Claim whole result-groups: take up to maxItems rows, never splitting a
	// group, so one Append (one collector Result) never rides two sequences — its
	// metrics, events, inventory and interface snapshot always travel together
	// even when the backlog exceeds maxItems. A single group larger than maxItems
	// is sent whole, so progress is always made.
	take, rows := 0, 0
	for take < len(s.disk) && (take == 0 || rows+s.disk[take].n <= maxItems) {
		rows += s.disk[take].n
		take++
	}

	seq, err := s.allocSeqLocked()
	if err != nil {
		return Batch{}, false, err
	}
	s.claim = &diskClaim{seq: seq, n: take}
	if err := s.saveStateLocked(); err != nil {
		// The claim never became durable, so nothing may be sent under it: a
		// crash would leave those groups unclaimed and they would go out again
		// under a different sequence, which the server cannot dedup.
		s.claim = nil
		return Batch{}, false, err
	}
	b, err := s.loadClaimLocked()
	if err != nil {
		return Batch{}, false, err
	}
	return b, true, nil
}

// expireLocked drops backlog past the retention window and makes the removal
// durable. Caller holds mu.
func (s *Store) expireLocked(now time.Time) error {
	index, claim := expirePrefix(s.disk, s.claim, now.Add(-s.retention))
	if len(index) == len(s.disk) {
		return nil
	}
	s.disk, s.claim = index, claim
	s.refreshHeadLocked()
	if err := s.saveStateLocked(); err != nil {
		return err
	}
	s.gcLocked()
	return nil
}

// loadClaimLocked reads the claimed head groups back into a packet. Caller holds
// mu and has verified s.claim is set.
func (s *Store) loadClaimLocked() (Batch, error) {
	n := s.claim.n
	if n > len(s.disk) {
		n = len(s.disk)
	}
	recs, err := readGroups(s.dir, s.disk[:n])
	if err != nil {
		return Batch{}, err
	}
	b := Batch{Sequence: s.claim.seq}
	for _, r := range recs {
		b.Metrics = append(b.Metrics, r.Metrics...)
		b.Events = append(b.Events, r.Events...)
		b.Inventory = append(b.Inventory, r.Inventory...)
		b.Snapshots = append(b.Snapshots, r.Snapshots...)
		b.GameRuns = append(b.GameRuns, r.GameRuns...)
		b.GameBuckets = append(b.GameBuckets, r.GameBuckets...)
		b.GameGaps = append(b.GameGaps, r.GameGaps...)
		b.GameHostSeconds = append(b.GameHostSeconds, r.GameHostSeconds...)
	}
	return b, nil
}

// allocSeqLocked hands out the next packet sequence, reserving a fresh block
// when the current one is exhausted. Caller holds mu.
func (s *Store) allocSeqLocked() (uint64, error) {
	if s.seqNext < s.seqCeil {
		seq := s.seqNext
		s.seqNext++
		return seq, nil
	}
	cur := s.durableSeq
	if cur < 1 {
		cur = 1
	}
	if cur > math.MaxUint64-seqBlock {
		return 0, fmt.Errorf("wal: next_seq %d cannot reserve a block of %d", cur, seqBlock)
	}
	if err := s.setDurableSeqLocked(cur + seqBlock); err != nil {
		return 0, err
	}
	s.seqNext, s.seqCeil = cur+1, cur+seqBlock
	return cur, nil
}

// setDurableSeqLocked persists a new allocator position, leaving the in-memory
// mirror untouched if the write fails. Caller holds mu.
func (s *Store) setDurableSeqLocked(v uint64) error {
	prev := s.durableSeq
	s.durableSeq = v
	if err := s.saveStateLocked(); err != nil {
		s.durableSeq = prev
		return err
	}
	return nil
}

// Ack releases the samples of an acknowledged packet. A memory-served packet is
// simply forgotten — the whole point of the tier is that it never reached disk
// to be deleted from. An ack for anything else (a duplicate, a late reply for a
// packet already released) is a no-op rather than an error.
func (s *Store) Ack(seq uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.inflight != nil && s.inflight.seq == seq {
		s.inflight = nil
		return nil
	}
	if s.claim == nil || s.claim.seq != seq {
		return nil
	}
	n := s.claim.n
	if n > len(s.disk) {
		n = len(s.disk)
	}
	s.disk = append([]diskGroup(nil), s.disk[n:]...)
	s.claim = nil
	s.refreshHeadLocked()
	if err := s.saveStateLocked(); err != nil {
		return err
	}
	s.gcLocked()
	return nil
}

// FastForward durably raises the next-sequence allocator to at least
// watermark+1 so the WAL stops re-emitting sequences the server has already
// consumed. It exists to recover the one case where the local allocator falls
// behind the server: the WAL was recreated/reset (next_seq back near 1) while
// the agent kept its enrollment and the server still retains far higher packet
// sequences. Without this, every fresh batch reuses an already-stored
// (agent_id, sequence) and the server silently dedups it — telemetry is
// suppressed for as long as the counter takes to climb past the watermark.
//
// The allocator is never lowered: a normal ack whose watermark equals the
// just-sent sequence leaves next_seq untouched (target <= current), so ordinary
// operation is unchanged and no in-flight sequence is renumbered. Overflow is
// explicit — a watermark at the uint64 max has no representable successor, so it
// errors rather than wrapping next_seq back to zero.
func (s *Store) FastForward(watermark uint64) error {
	if watermark == math.MaxUint64 {
		return fmt.Errorf("wal: watermark %d at uint64 max; no successor sequence", watermark)
	}
	target := watermark + 1

	s.mu.Lock()
	defer s.mu.Unlock()

	// The live reservation has to be checked FIRST, and separately from the
	// durable position. Reserving a block pushes the durable value a whole block
	// ahead of what is actually being issued, so on a recreated WAL the durable
	// value alone says "already past the watermark" while seqNext is still down at
	// the bottom of the block — and every sequence from there up to the watermark
	// is one the server has already stored and will silently dedup. That is the
	// exact recovery this function exists for, so comparing only against the
	// durable value would disable it precisely when it is needed.
	if s.seqCeil > 0 && target > s.seqNext {
		if target < s.seqCeil {
			s.seqNext = target // skip the consumed prefix; the rest of the block is still ours
		} else {
			s.seqNext, s.seqCeil = 0, 0 // the whole block is consumed; take a fresh one
		}
	}

	if target <= s.durableSeq {
		return nil // allocator already at/above the watermark; never lower it
	}
	if err := s.setDurableSeqLocked(target); err != nil {
		return err
	}
	// A durable jump invalidates any reservation made below it.
	s.seqNext, s.seqCeil = 0, 0
	return nil
}

// Pending returns the number of samples not yet acknowledged, across both tiers
// — buffered, claimed-but-unacked, and spilled. It backs the agent.wal_pending
// metric, which is a backlog signal rather than a disk-usage one, so counting
// only the durable groups would read as "nothing queued" on an agent whose
// uploads are failing but whose buffer has not yet aged into a spill.
func (s *Store) Pending() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := s.memRows
	if s.inflight != nil {
		for _, g := range s.inflight.groups {
			n += g.n
		}
	}
	for _, g := range s.disk {
		n += g.n
	}
	return n
}
