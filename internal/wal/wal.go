//go:build !lite

package wal

import (
	"errors"
	"fmt"
	"log"
	"math"
	"os"
	"sync"
	"time"
)

const (
	// memBufferRows is the depth that forces a spill. Sized so a healthy agent —
	// one whose session is up and draining every 30s — never reaches it, while an
	// agent that has just lost its server spills within a few minutes rather than
	// holding an unbounded backlog only in memory.
	memBufferRows = 20000

	// memBufferAge is the other spill trigger: a slow trickle of samples would
	// otherwise sit in memory indefinitely, so a crash on an idle-ish agent would
	// lose more than a busy one. Checked on Append, so it is a floor on how stale
	// the buffer can be at the moment anything is added.
	memBufferAge = 90 * time.Second

	// seqBlock is how many packet sequences one durable reservation covers. The
	// allocator persists its ceiling, not each handout, so a crash burns at most
	// this many sequences — which costs nothing, since the server takes MAX for
	// its watermark and never requires contiguity — in exchange for one small
	// write per thousand packets instead of one per packet.
	seqBlock = 1000

	// memBufferHardCap is where a buffer that cannot spill starts shedding. See
	// Append for why a failed spill is not an error.
	memBufferHardCap = 2 * memBufferRows
)

// Store is the agent's outbox: a memory buffer in front of a durable tier of
// segment files, shared by every server session this agent runs (see the package
// doc for the ownership model).
//
// The whole store is behind one mutex. Sessions are independent goroutines that
// claim and ack concurrently, but their cursors are disjoint — two servers never
// contend for the same group — so the lock is only ever held for the length of
// one index walk.
//
// See segment.go for the on-disk format and its durability guarantees.
type Store struct {
	dir       string
	mu        sync.Mutex
	maxRows   int
	retention time.Duration

	// clock supplies the correction for telemetry stamped while this machine's
	// wall clock was wrong. Nil disables correction; see ClockSource.
	clock ClockSource

	mem     []memGroup // buffered, gid-ascending; includes groups under a claim
	memRows int

	// disk indexes the live spilled groups in gid order. Every disk gid is below
	// every mem gid, because a spill writes the whole buffer and empties it, so
	// "disk then mem" is already delivery order.
	disk    []diskGroup
	nextSeg uint64 // counter the next spill will use

	// cursors is one entry per configured server, created at Open. A group whose
	// owner has no cursor is dead — that is how a server dropped from the config
	// stops pinning bytes forever.
	cursors map[string]*cursor

	nextGid uint64 // group id the next Append will take

	seqNext, seqCeil uint64 // reserved sequence block [seqNext, seqCeil)
	durableSeq       uint64 // persisted allocator position, mirrored in memory
}

// Open creates/opens the WAL in directory dir, serving the named servers.
//
// The names are the store's whole notion of who its consumers are: a cursor
// persisted for a name not listed here is discarded along with everything it
// owed, which is what stops a server the user removed from the config from
// pinning its backlog until the retention window expires. Renaming a server
// entry therefore discards its backlog, the same as removing it.
//
// Options.Persist and Options.PersistWindow are accepted and ignored: both tune
// the lite build's conditional durable tier, and this store's tier is
// unconditional — it always spills, so "persist while disconnected" is already
// what it does and a window bounding flash wear has nothing to bound. Taking the
// argument anyway keeps one call site in agentrt for both builds. Options.Clock
// IS honoured here, because a workstation's clock can be wrong for the same
// reasons a router's can and the correction is not a flash-wear question.
func Open(dir string, servers []string, opt Options) (*Store, error) {
	if len(servers) == 0 {
		return nil, errors.New("wal: Open needs at least one server name")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	removeStaleTemps(dir)

	s := &Store{
		dir:        dir,
		maxRows:    50000,
		retention:  72 * time.Hour,
		durableSeq: 1,
		nextSeg:    1,
		nextGid:    1,
		clock:      opt.Clock,
		cursors:    make(map[string]*cursor, len(servers)),
	}
	for _, name := range servers {
		s.cursors[name] = &cursor{}
	}

	st, found, err := readState(dir)
	if err == nil && found && st.V != stateFormat {
		err = fmt.Errorf("state format %d, want %d", st.V, stateFormat)
	}
	if err != nil {
		// state.json is published by rename, so a torn write is impossible; this
		// is hand-editing, real corruption, or a store written by a build whose
		// format this one cannot read. Starting over loses the backlog, which
		// beats replaying it: without the allocator position, every group would be
		// re-sent under sequences the server cannot recognise as duplicates.
		// FastForward lifts the allocator on the first ack — this is precisely the
		// recreated-WAL case it exists for.
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
		if st.NextGid > s.nextGid {
			s.nextGid = st.NextGid
		}
		for name, cs := range st.Cursors {
			c, ok := s.cursors[name]
			if !ok {
				log.Printf("wal: server %q is no longer configured; discarding what it had not acknowledged", name)
				continue
			}
			c.acked = cs.Acked
			c.identity = cs.Identity
			if cs.ClaimN > 0 {
				c.claim = &claim{seq: cs.ClaimSeq, from: cs.ClaimFrom, to: cs.ClaimTo, n: cs.ClaimN}
			}
			if cs.Acked >= s.nextGid {
				s.nextGid = cs.Acked + 1
			}
		}
	}

	segs, err := listSegments(dir)
	if err != nil {
		return nil, err
	}
	for _, n := range segs {
		groups, err := scanSegment(segPath(dir, n), n)
		if err != nil {
			return nil, err
		}
		live := 0
		for _, g := range groups {
			if g.gid >= s.nextGid {
				s.nextGid = g.gid + 1
			}
			if s.liveLocked(g.gid, g.owner) {
				s.disk = append(s.disk, g)
				live++
			}
		}
		if live == 0 {
			// Everything in it was acknowledged (or belonged to a server that is
			// gone) before the last shutdown; its deletion just did not happen.
			os.Remove(segPath(dir, n))
		}
		if n >= s.nextSeg {
			s.nextSeg = n + 1
		}
	}

	// A claim that does not resolve to the number of groups it was taken over
	// means the state naming it was written but the segment carrying them never
	// got renamed into place. Serving a short packet under a sequence the server
	// may already associate with different content would be worse than dropping
	// it: the sequence is simply burned, which the server tolerates (it takes
	// MAX, never requires contiguity).
	for name, c := range s.cursors {
		if c.claim == nil {
			continue
		}
		if got := countClaimed(name, c.claim, s.disk, nil); got != c.claim.n {
			log.Printf("wal: claim %d for %q covers %d groups but %d survived; dropping the claim",
				c.claim.seq, name, c.claim.n, got)
			c.claim = nil
		}
	}
	return s, nil
}

// liveLocked reports whether a stored group is still owed to anyone. Caller
// holds mu (or is Open, before the store is shared).
func (s *Store) liveLocked(gid uint64, owner string) bool {
	c, ok := s.cursors[owner]
	return ok && gid > c.acked
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
	s.disk, s.nextSeg = nil, 1
	for _, c := range s.cursors {
		c.acked, c.claim = 0, nil
	}
	return nil
}

// SetServerOnline is a no-op here, and exists so the session runner can report
// the same connection edges to either build without a build-tagged call site.
//
// Nothing in this store's policy depends on whether a server is reachable: it
// spills on buffer depth and age alone, so a link that just dropped changes
// nothing about when the backlog reaches disk. The lite build is where the
// answer matters, because there the edge is the only thing that turns writing on
// at all.
func (s *Store) SetServerOnline(string, bool) {}

// Close flushes the memory tier to disk. Flushing here is what makes an ordinary
// shutdown lossless: the caller already stops every producer and every session
// and joins them before closing, so nothing is still being appended or claimed.
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
// operation relies on Close. It is safe to call from any session goroutine: a
// spill covers the whole buffer regardless of which server prompted it.
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

// Append queues one batch of records for delivery to one server. It returns the
// number of samples dropped for over-capacity (>0 means a data gap the caller
// should surface).
//
// The records go to memory. They reach disk only if the buffer fills, ages past
// memBufferAge, or the store is closed — so while the sessions are up and
// draining this costs no disk write at all. See Store for the durability trade.
//
// An error means the records were NOT accepted and the caller still owns them.
// An unknown server name is one: appending for a server with no cursor would
// store bytes nothing will ever deliver or collect, so it is reported as the
// wiring bug it is rather than silently swallowed. A failed spill is NOT an
// error: the records are in the buffer and the next trigger retries writing
// them, so reporting a rejection would be both untrue and harmful — agentrt's
// game drain re-queues on error, which would put a second copy of the same
// records in the buffer and upload both once the disk recovers. Spill failures
// are logged here instead.
func (s *Store) Append(r Records, server string) (dropped int, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	n := rowsOf(r)
	if n == 0 {
		return 0, nil
	}
	if _, ok := s.cursors[server]; !ok {
		return 0, fmt.Errorf("wal: append for unknown server %q", server)
	}
	now := time.Now().UTC()
	epoch, mono := clockTag(s.clock)
	s.mem = append(s.mem, memGroup{gid: s.nextGid, owner: server, at: now, rec: r, n: n, epoch: epoch, mono: mono})
	s.nextGid++
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
// which is the invariant grouping exists to protect. Groups under a claim are
// skipped — they have been handed to a session and may still need re-sending
// under their sequence. Caller holds mu.
func (s *Store) evictOldestLocked(n int) int {
	dropped := 0
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

// oldestLocked is the arrival time of the oldest record still held in memory.
// Now when memory is empty, which never triggers a spill because the comparison
// is only reached when there is something to spill.
func (s *Store) oldestLocked() time.Time {
	if len(s.mem) > 0 {
		return s.mem[0].at
	}
	return time.Now().UTC()
}

// spillLocked writes the whole memory tier to one new segment and enforces the
// store's caps. Claimed groups are written along with everything else and keep
// their group ids, so the claims addressing them stay valid — a session then
// re-sends its packet under the same sequence from disk, exactly as it would
// have from memory.
//
// Nothing in the Store is mutated until the segment is safely renamed into
// place, so a failure anywhere leaves the buffer intact for the next attempt —
// which is what lets Append tolerate a broken disk. Caller holds mu.
func (s *Store) spillLocked(now time.Time) (dropped int, err error) {
	if len(s.mem) == 0 {
		return 0, nil
	}

	seg := s.nextSeg
	tmp, lines, err := writeSegmentTemp(s.dir, s.mem)
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

	// Build the post-spill index and claim set without touching s yet.
	index := make([]diskGroup, 0, len(s.disk)+len(lines))
	index = append(index, s.disk...)
	index = append(index, lines...)

	claims := s.copyClaimsLocked()
	index = expireIndex(index, now, s.retention, s.clock)
	// Everything live now lives in index (the buffer is being emptied into it),
	// so counting against index alone is the whole picture.
	reconcileClaims(claims, index, nil)
	index, dropped = capOldest(index, claims, s.maxRows)

	nextSeg := seg + 1
	prev := s.stateLocked()
	next := s.stateWithLocked(claims)

	// State first, segment second. A crash in between leaves a claim describing
	// groups that never became visible, which Open clamps away — bounded loss.
	// The reverse order would leave the claimed groups on disk with no claim, so
	// they would be re-issued under a NEW sequence and the server, unable to
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

	s.disk, s.nextSeg = index, nextSeg
	s.applyClaimsLocked(claims)
	s.mem, s.memRows = nil, 0
	s.gcLocked()
	return dropped, nil
}

// copyClaimsLocked snapshots the in-flight claims by value, so expiry and the
// cap can adjust them while a spill is still able to fail and leave the store
// untouched. Caller holds mu.
func (s *Store) copyClaimsLocked() map[string]*claim {
	out := make(map[string]*claim, len(s.cursors))
	for name, c := range s.cursors {
		if c.claim != nil {
			cp := *c.claim
			out[name] = &cp
		}
	}
	return out
}

// applyClaimsLocked commits a snapshot back onto the cursors: a name missing
// from it lost its claim. Caller holds mu.
func (s *Store) applyClaimsLocked(claims map[string]*claim) {
	for name, c := range s.cursors {
		c.claim = claims[name]
	}
}

// expireIndex drops leading groups that arrived before cutoff. Expiry is always
// a prefix because arrival times are non-decreasing across the index: spills
// happen in time order and preserve arrival order within themselves.
//
// Only the durable tier expires. The memory tier cannot: memBufferAge forces a
// spill long before the retention window, so nothing buffered is ever old
// enough.
func expireIndex(index []diskGroup, now time.Time, retention time.Duration, clock ClockSource) []diskGroup {
	drop := 0
	for drop < len(index) && expiredAt(clock, index[drop].at, index[drop].epoch, index[drop].mono, now, retention) {
		drop++
	}
	if drop == 0 {
		return index
	}
	return append([]diskGroup(nil), index[drop:]...)
}

// reconcileClaims re-counts every claim against the groups that survive, and
// drops one that lost all of them.
//
// A claim losing groups mirrors what the old store's unconditional retention
// delete did to already-tagged rows: past the window, server-core has pruned the
// dedup entry, so replaying the packet would be re-ingested as new. Shrinking it
// keeps the sequence honest about what it now carries; losing everything leaves
// nothing to send under it, so the sequence is burned.
func reconcileClaims(claims map[string]*claim, disk []diskGroup, mem []memGroup) {
	for name, cl := range claims {
		got := countClaimed(name, cl, disk, mem)
		if got == 0 {
			delete(claims, name)
			continue
		}
		cl.n = got
	}
}

// capOldest enforces the row cap by dropping the oldest UNCLAIMED whole groups,
// and reports how many rows went. Whole-group eviction preserves the
// indivisible-Result invariant, so this may drop slightly more than the exact
// overflow; the actual count is what gets returned and logged.
//
// This is also the multi-server backpressure policy. The index is in arrival
// order, so the oldest groups are by construction those of whichever server has
// been unable to receive for longest: a server offline for a week sheds its own
// backlog while a healthy one, whose groups are acked and removed within
// seconds, never accumulates enough to be a candidate. No cursor is explicitly
// forced forward — the groups simply stop existing, and a cursor only ever
// addresses what the index still holds.
//
// Claimed groups are never evicted: they have been handed to a session and may
// still need re-sending under their sequence. Evicting from behind one leaves
// the index describing less than the files hold; gcLocked then deletes every
// segment the index no longer references, which is what keeps the cap real even
// while a claim pins an old group in place.
//
// What can survive is the evicted tail of a segment that still holds live
// groups. A restart rescans those and brings those groups back: they are
// unclaimed, unsent, in their original position and within retention, so the
// next spill evicts them again.
func capOldest(index []diskGroup, claims map[string]*claim, maxRows int) ([]diskGroup, int) {
	total := 0
	for _, g := range index {
		total += g.n
	}
	if total <= maxRows {
		return index, 0
	}
	out := make([]diskGroup, 0, len(index))
	dropped := 0
	for _, g := range index {
		if total > maxRows && !claims[g.owner].covers(g.gid) {
			total -= g.n
			dropped += g.n
			continue
		}
		out = append(out, g)
	}
	return out, dropped
}

// stateLocked renders the current bookkeeping. Caller holds mu.
func (s *Store) stateLocked() walState {
	return s.stateWithLocked(s.claimsLocked())
}

// claimsLocked is the live claim set by reference, for rendering state without
// copying. Caller holds mu.
func (s *Store) claimsLocked() map[string]*claim {
	out := make(map[string]*claim, len(s.cursors))
	for name, c := range s.cursors {
		if c.claim != nil {
			out[name] = c.claim
		}
	}
	return out
}

// stateWithLocked renders the bookkeeping with a given claim set, which a spill
// uses to persist the claims it is about to commit. Caller holds mu.
func (s *Store) stateWithLocked(claims map[string]*claim) walState {
	st := walState{
		V:       stateFormat,
		NextSeq: s.durableSeq,
		NextGid: s.nextGid,
		Cursors: make(map[string]cursorState, len(s.cursors)),
	}
	for name, c := range s.cursors {
		cs := cursorState{Acked: c.acked, Identity: c.identity}
		if cl := claims[name]; cl != nil {
			cs.ClaimSeq, cs.ClaimFrom, cs.ClaimTo, cs.ClaimN = cl.seq, cl.from, cl.to, cl.n
		}
		st.Cursors[name] = cs
	}
	return st
}

func (s *Store) saveStateLocked() error {
	return writeState(s.dir, s.stateLocked())
}

// gcLocked deletes every segment the live index no longer references. Caller
// holds mu.
//
// Liveness rather than a consumed-prefix sweep is what makes the row cap real.
// While a claim sits unacknowledged — which is the whole of a long outage, since
// the claim is only released by an ack — a prefix could not move past it, so
// every segment behind it would be kept forever while each spill added another.
// Disk then grew without limit on exactly the path this store exists for. It is
// also what makes N consumers cheap: a segment is collectable as soon as the
// last server owing anything in it has acked, with no per-segment refcounting.
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

// NextBatch returns the next packet to send to one server, or ok=false when that
// server is owed nothing.
//
// Order is FIFO within the server's own groups, which the server's fault
// detectors rely on (a target's rounds arriving out of order would be folded
// twice):
//
//  1. a batch already claimed and not yet acked — re-served under the SAME
//     sequence, so a dropped session re-sends rather than loses it;
//  2. otherwise the durable backlog, oldest first — everything on disk is older
//     than anything in memory, because memory only spills in arrival order and
//     only ever appends a segment;
//  3. finally the memory buffer.
//
// Step 3 is the case a healthy agent is always in, and it touches no disk.
//
// A batch never mixes the two tiers. A claim over durable groups must itself be
// durable before the packet goes out (a crash otherwise re-issues them under a
// different sequence, which the server cannot dedup), while a claim over
// buffered groups needs no write at all because a crash loses those groups
// anyway. Stopping at the boundary keeps each batch in exactly one of those
// regimes instead of paying the write for every packet a healthy agent sends.
func (s *Store) NextBatch(server string, maxItems int) (Batch, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	c, ok := s.cursors[server]
	if !ok {
		return Batch{}, false, fmt.Errorf("wal: unknown server %q", server)
	}

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

	if c.claim != nil {
		b, err := s.loadClaimLocked(server, c.claim)
		if err != nil {
			return Batch{}, false, err
		}
		return b, true, nil
	}
	if b, ok, err := s.nextDiskBatchLocked(server, c, maxItems); err != nil || ok {
		return b, ok, err
	}
	return s.nextMemBatchLocked(server, c, maxItems)
}

// nextDiskBatchLocked claims whole groups from the durable backlog. Caller holds
// mu and has established the server has no claim outstanding.
func (s *Store) nextDiskBatchLocked(server string, c *cursor, maxItems int) (Batch, bool, error) {
	take, rows := 0, 0
	var first, last uint64
	for _, g := range s.disk {
		if g.owner != server || g.gid <= c.acked {
			continue
		}
		// Claim whole result-groups: take up to maxItems rows, never splitting a
		// group, so one Append (one collector Result) never rides two sequences —
		// its metrics, events, inventory and interface snapshot always travel
		// together even when the backlog exceeds maxItems. A single group larger
		// than maxItems is sent whole, so progress is always made.
		if take > 0 && rows+g.n > maxItems {
			break
		}
		if take == 0 {
			first = g.gid
		}
		last = g.gid
		rows += g.n
		take++
	}
	if take == 0 {
		return Batch{}, false, nil
	}

	seq, err := s.allocSeqLocked()
	if err != nil {
		return Batch{}, false, err
	}
	c.claim = &claim{seq: seq, from: first, to: last, n: take, clockRev: clockRevOf(s.clock)}
	if err := s.saveStateLocked(); err != nil {
		// The claim never became durable, so nothing may be sent under it: a
		// crash would leave those groups unclaimed and they would go out again
		// under a different sequence, which the server cannot dedup.
		c.claim = nil
		return Batch{}, false, err
	}
	b, err := s.loadClaimLocked(server, c.claim)
	if err != nil {
		return Batch{}, false, err
	}
	return b, true, nil
}

// nextMemBatchLocked claims whole groups from the memory buffer. The groups stay
// in the buffer rather than moving to a side list: until the ack lands they may
// still have to be re-served or spilled, and leaving them in place is what lets
// a spill carry them across with their group ids — and therefore the claim —
// intact. Caller holds mu.
func (s *Store) nextMemBatchLocked(server string, c *cursor, maxItems int) (Batch, bool, error) {
	rows := 0
	var first, last uint64
	recs := make([]Records, 0, 8)
	offs := make([]time.Duration, 0, 8)
	rev := clockRevOf(s.clock)
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
		offs = append(offs, clockOffset(s.clock, g.epoch, g.mono, rev))
	}
	if len(recs) == 0 {
		return Batch{}, false, nil
	}
	seq, err := s.allocSeqLocked()
	if err != nil {
		return Batch{}, false, err
	}
	c.claim = &claim{seq: seq, from: first, to: last, n: len(recs), clockRev: rev}
	return flatten(seq, recs, offs), true, nil
}

// expireLocked drops backlog past the retention window and makes the removal
// durable. Caller holds mu.
func (s *Store) expireLocked(now time.Time) error {
	index := expireIndex(s.disk, now, s.retention, s.clock)
	if len(index) == len(s.disk) {
		return nil
	}
	s.disk = index
	claims := s.claimsLocked()
	reconcileClaims(claims, s.disk, s.mem)
	s.applyClaimsLocked(claims)
	if err := s.saveStateLocked(); err != nil {
		return err
	}
	s.gcLocked()
	return nil
}

// loadClaimLocked reads a claim's groups back into the packet to send. It spans
// both tiers because a claim taken from memory migrates to disk wholesale when a
// spill happens under it; disk before memory is already group-id order. Caller
// holds mu.
func (s *Store) loadClaimLocked(server string, cl *claim) (Batch, error) {
	var dg []diskGroup
	for _, g := range s.disk {
		if g.owner == server && cl.covers(g.gid) {
			dg = append(dg, g)
		}
	}
	recs := make([]Records, 0, cl.n)
	offs := make([]time.Duration, 0, cl.n)
	if len(dg) > 0 {
		loaded, err := readGroups(s.dir, dg)
		if err != nil {
			return Batch{}, err
		}
		recs = append(recs, loaded...)
		for _, g := range dg {
			offs = append(offs, clockOffset(s.clock, g.epoch, g.mono, cl.clockRev))
		}
	}
	for _, g := range s.mem {
		if g.owner == server && cl.covers(g.gid) {
			recs = append(recs, g.rec)
			offs = append(offs, clockOffset(s.clock, g.epoch, g.mono, cl.clockRev))
		}
	}
	return flatten(cl.seq, recs, offs), nil
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

// Ack releases one server's acknowledged packet: its cursor moves past the
// claimed groups and they stop being owed to it. An ack for anything else (a
// duplicate, a late reply for a packet already released, an unknown server) is a
// no-op rather than an error.
//
// Only a packet that had durable groups costs a write. A memory-served packet is
// simply forgotten — the whole point of that tier is that it never reached disk
// to be deleted from, and a watermark that is not persisted only ever
// under-reports what was delivered, which after a restart addresses groups that
// no longer exist.
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

	touchedDisk := s.dropClaimedLocked(server, cl)
	if !touchedDisk {
		return nil
	}
	if err := s.saveStateLocked(); err != nil {
		return err
	}
	s.gcLocked()
	return nil
}

// dropClaimedLocked removes a claim's groups from both tiers and reports whether
// any of them were durable. Caller holds mu.
func (s *Store) dropClaimedLocked(server string, cl *claim) bool {
	touchedDisk := false
	out := make([]diskGroup, 0, len(s.disk))
	for _, g := range s.disk {
		if g.owner == server && cl.covers(g.gid) {
			touchedDisk = true
			continue
		}
		out = append(out, g)
	}
	if touchedDisk {
		s.disk = out
	}

	if len(s.mem) > 0 {
		kept := make([]memGroup, 0, len(s.mem))
		for _, g := range s.mem {
			if g.owner == server && cl.covers(g.gid) {
				s.memRows -= g.n
				continue
			}
			kept = append(kept, g)
		}
		s.mem = kept
	}
	return touchedDisk
}

// BindIdentity states the enrolled identity (the server-assigned agent_id) one
// server's session is about to run under, and returns how many queued samples
// were discarded because they belong to a different one (>0 is a data gap the
// caller should surface).
//
// # Why the queue has to be discarded at all
//
// A revoked agent deletes its credential and re-enrolls, and without a
// console-issued reinstall token the server mints a BRAND-NEW agent_id. The
// backlog is grouped by server name, which survives that exchange, so without
// this the first packet of the new session would upload records collected by the
// old agent — and the server files every packet under the identity it
// authenticated, so metrics, events, inventory deltas, traceroutes and incident
// scenes collected by agent X would land on agent Y's timeline. Scene reports
// make the contradiction visible: their payload still names the id they were
// collected under, which would then disagree with the row storing them.
//
// # Why discard rather than carry the old id along
//
// The alternative is to persist the collecting agent_id per group and hand those
// groups over under it. That needs the SERVER to accept telemetry attributed to
// an identity the connection did not authenticate, which is a new authenticated
// handover path (prove old and new are the same machine) rather than a WAL
// change — and until that exists, an agent asserting "store this as someone
// else" is exactly the thing an authenticated ingest must refuse. Losing the
// records collected before a revocation is a bounded, explainable gap; filing
// them under the wrong machine is silent corruption of the evidence the product
// exists to produce.
//
// # Why the discard must be explicit
//
// Tagging the stale groups and merely skipping them in NextBatch would leak
// disk forever: a segment's bytes are only collectable once every server owing
// something in it has acked, so a group that will never be served pins its
// segment for good and each spill adds another. The discard therefore does the
// full ack-shaped thing — drop the groups from both tiers, release the in-flight
// claim, advance the cursor past everything appended so far, persist, and run the
// segment sweep — so the storage is actually reclaimed. The cursor is advanced to
// the last gid handed out rather than to the newest group still indexed, so
// groups that only exist in a segment tail (evicted from the index but rescanned
// by a restart) cannot come back from the dead.
//
// The in-flight claim goes with them: its packet was built from the old agent's
// records and its sequence is simply burned, which the server tolerates since it
// takes MAX for its watermark and never requires contiguity.
//
// # Ownership and ordering
//
// It is called by the session runner on the session goroutine, before that
// session's first NextBatch — the same goroutine that owns this server's cursor
// for everything else. Only this server's groups are touched: another server's
// cursor, claim and view of a shared segment are untouched, because their
// identities are independent and one server revoking says nothing about the rest.
//
// An empty agentID states nothing and is a no-op, so a caller that has not
// enrolled needs no branch. An unknown server name is a wiring bug and is
// reported. A failed state write leaves the in-memory discard standing and is
// self-correcting: the stale state resurrects those groups at the next Open,
// where the identity recorded beside them still disagrees and they are discarded
// again.
func (s *Store) BindIdentity(server, agentID string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	c, ok := s.cursors[server]
	if !ok {
		return 0, fmt.Errorf("wal: bind identity for unknown server %q", server)
	}
	if agentID == "" || c.identity == agentID {
		return 0, nil
	}
	prev := c.identity
	c.identity = agentID
	if prev == "" {
		// Nothing was ever collected under a different identity, so the backlog
		// is this identity's own: a first enrollment, or a server just added to
		// the configuration. Only record it.
		return 0, s.saveStateLocked()
	}

	dropped := s.discardServerLocked(server, c)
	log.Printf("wal: %q re-enrolled as %s (was %s); discarded %d queued samples collected under the old identity (data gap)",
		server, agentID, prev, dropped)
	if err := s.saveStateLocked(); err != nil {
		return dropped, err
	}
	s.gcLocked()
	return dropped, nil
}

// discardServerLocked drops everything one server owns from both tiers, releases
// its claim and moves its cursor past every group handed out so far, returning
// the number of sample rows discarded. Caller holds mu.
func (s *Store) discardServerLocked(server string, c *cursor) int {
	dropped := 0
	kept := make([]diskGroup, 0, len(s.disk))
	for _, g := range s.disk {
		if g.owner == server {
			dropped += g.n
			continue
		}
		kept = append(kept, g)
	}
	s.disk = kept

	buf := make([]memGroup, 0, len(s.mem))
	for _, g := range s.mem {
		if g.owner == server {
			dropped += g.n
			s.memRows -= g.n
			continue
		}
		buf = append(buf, g)
	}
	s.mem = buf

	c.claim = nil
	c.acked = s.nextGid - 1
	return dropped
}

// FastForward durably raises the next-sequence allocator to at least
// watermark+1 so the WAL stops re-emitting sequences the server has already
// consumed. It exists to recover the one case where the local allocator falls
// behind a server: the WAL was recreated/reset (next_seq back near 1) while the
// agent kept its enrollment and the server still retains far higher packet
// sequences. Without this, every fresh batch reuses an already-stored
// (agent_id, sequence) and the server silently dedups it — telemetry is
// suppressed for as long as the counter takes to climb past the watermark.
//
// The allocator is shared by every server and so is this: a watermark from one
// server raises the counter for all of them. That is harmless because a
// sequence only has to be unique per (agent, server) pair — skipping ahead
// leaves gaps, which every server tolerates (it takes MAX, never requires
// contiguity) — and it is what keeps the recovery working when the server that
// remembers the high watermark is not the one that reconnects first.
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

// Pending returns the number of samples one server has not yet acknowledged,
// across both tiers — buffered, claimed-but-unacked, and spilled. It backs that
// server's agent.wal_pending metric, which is a backlog signal rather than a
// disk-usage one, so counting only the durable groups would read as "nothing
// queued" on an agent whose uploads are failing but whose buffer has not yet
// aged into a spill. Per server rather than store-wide for the same reason: one
// server being unreachable says nothing about the health of another's link.
func (s *Store) Pending(server string) int {
	s.mu.Lock()
	defer s.mu.Unlock()

	c, ok := s.cursors[server]
	if !ok {
		return 0
	}
	n := 0
	for _, g := range s.disk {
		if g.owner == server && g.gid > c.acked {
			n += g.n
		}
	}
	for _, g := range s.mem {
		if g.owner == server && g.gid > c.acked {
			n += g.n
		}
	}
	return n
}
