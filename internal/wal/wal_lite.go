//go:build lite

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
	// memMaxRows caps the memory buffer. Past it the oldest whole groups are
	// shed — the same contract the default build's over-capacity eviction has.
	//
	// Sized for a router rather than a workstation: a few MB worst case on a
	// device that typically has 64-256 MB of RAM, and well over an hour of
	// backlog at the rate a home network's probes actually produce.
	//
	// It is a store-wide cap, not per server. A router reporting to two servers
	// with one of them offline sheds that one's backlog first simply because its
	// groups are the oldest ones present — the same backpressure the default
	// build's row cap applies, without needing to know whose they are.
	memMaxRows = 5000

	// defaultPersistWindow is how long after a disconnect the durable tier keeps
	// accepting that server's backlog. See Store for why the window exists and
	// why it is anchored at the disconnect.
	defaultPersistWindow = 30 * time.Minute

	// persistInterval is the floor between two spills for one server, so a long
	// outage costs a bounded number of erase cycles rather than one per upload
	// attempt. Five minutes against a 30-minute window is at most seven writes
	// per outage, and it bounds how much a power cut can cost: whatever arrived
	// since the last spill, never more than five minutes of samples.
	//
	// It is NOT reset when a server reconnects. A flapping link — up for twenty
	// seconds, down again — would otherwise spill on every drop, which is the
	// one access pattern that could wear flash faster than the default build's
	// unconditional spilling this whole design exists to avoid.
	persistInterval = 5 * time.Minute

	// persistMaxRows bounds how much ONE server may hold on flash, as the
	// backstop for a window that never closes because the clock jumped, or a
	// device that produces far more telemetry than a router usually does. It is
	// deliberately the same order as memMaxRows: the durable tier exists to
	// preserve roughly what the memory tier was already holding, not to become a
	// bigger queue in its own right.
	//
	// Per server rather than store-wide because the two are independent outages:
	// one server being unreachable for an hour must not decide how much of a
	// second server's outage survives a reboot. A router reports to one or two
	// servers, so the worst case is bounded by construction.
	persistMaxRows = 5000

	// persistRetention drops backlog nothing can usefully deliver any more. It
	// matches the default build's window because it answers to the same fact on
	// the other side: server-core prunes its (agent_id, sequence) dedup rows on
	// the assumption that an agent never replays anything older, so a packet
	// uploaded past it would be re-ingested as if new rather than recognised as
	// the duplicate it is.
	persistRetention = 72 * time.Hour
)

// Store is the agent's outbox in lite (OpenWrt router) builds: a memory buffer
// with a durable tier that is written ONLY while a server is disconnected, and
// only for a bounded window after it dropped.
//
// # Why not simply spill like the default build
//
// The only honestly writable storage on a router is the flash it boots from, and
// erase cycles are the part of that hardware which wears out. The default build
// spills whenever its buffer fills or ages, which on a healthy agent would mean
// writing telemetry to flash every couple of minutes for the sole purpose of
// deleting it again thirty seconds later, forever. So while a server's session
// is up, this store writes nothing at all — not a segment, not a state file, not
// even the directory.
//
// # Why not stay memory-only either
//
// That was the previous behaviour, and it loses precisely the data that matters
// most. The agent is disconnected because the internet is down; the near-certain
// next event is the owner power-cycling the router to fix it. Everything the
// agent observed about the failure — the moment the uplink stopped answering,
// what the LAN still looked like, which probes died first — was buffered in RAM
// and is gone, and the server's incident starts at "agent went quiet".
//
// So the trigger is the connection edge, not a buffer level: the samples worth
// an erase cycle are exactly the ones with nowhere to go.
//
// # Why a window, and why it starts at the disconnect
//
// A disconnect that lasts a week would otherwise keep writing for a week. The
// window bounds that to the first PersistWindow (30 minutes by default) after
// the link dropped — the interval that contains the fault's onset, which is what
// diagnosis needs and what a reboot would destroy. Past it the store keeps
// buffering in memory exactly as before, and a very long outage degrades to the
// old behaviour rather than to unbounded flash wear. Reconnecting resets it, so
// each outage gets its own window.
//
// The alternatives were worse. A size cap alone cannot distinguish a minute-long
// blip from a week and would spend the same writes on both. A cap on total
// writes per boot silently stops protecting a router that stays up for months.
// Anchoring at the disconnect says what the feature is for in one sentence, and
// persistMaxRows is kept only as a backstop for a broken clock.
//
// # Sequence numbers across a reboot
//
// A packet's sequence must never be reused: the server dedups on (agent_id,
// sequence), so a re-issued one is silently swallowed. Memory-only, that was
// handled by seeding the allocator from the wall clock (see initialSeq). Now
// that a backlog can outlive the process, the seed alone is not enough on a
// router whose clock resets to 1970, so every state write also carries the
// allocator position and Open takes the maximum of the two. The allocator is
// persisted only when something else is already being written — a spill, or a
// claim over durable groups — so a healthy agent still pays nothing for it, and
// FastForward remains memory-only for the same reason: it runs on EVERY ack, and
// a write there would undo the whole zero-cost-while-healthy property. The
// first-ack FastForward stays as the backstop it always was.
//
// # What is still lost
//
// A crash or power cut loses whatever is in memory and not yet spilled: at most
// persistInterval of samples during a covered outage, and everything for a
// server that is connected — which is the trade the first section describes and
// not an accident. Delivery order, per-server ownership, and the
// indivisible-group and re-serve-until-acked rules are identical to the default
// build.
type Store struct {
	mu sync.Mutex

	// dir is where the durable tier lives. It is not created until there is
	// something to write into it, so a store that has never been disconnected
	// leaves no trace on the flash at all. persist false means it is never
	// touched even then.
	dir     string
	persist bool
	window  time.Duration

	// clock supplies the correction for telemetry stamped while this machine's
	// wall clock was wrong. On this build that is not a corner case: a router
	// with no RTC comes back from a power cut with sysfixtime's guess, and the
	// samples this store is spilling are exactly the ones taken under it.
	clock ClockSource

	// now is the clock. A field rather than a direct time.Now call so the window
	// and the spill interval are testable without sleeping through them.
	now func() time.Time

	mem     []memGroup // buffered, gid-ascending; includes groups under a claim
	memRows int

	// disk indexes the live spilled groups. Unlike the default build this is not
	// globally gid-ordered — server A's outage can be spilled while server B's
	// older groups are still buffered — but it IS gid-ordered per owner, which is
	// the only order anything reads it in: a spill always takes a prefix of that
	// owner's buffered groups and never resumes after skipping one.
	disk    []diskGroup
	nextSeg uint64 // counter the next spill will use

	// cursors is one entry per configured server, created at Open. A group whose
	// owner has no cursor is dead — that is how a server dropped from the config
	// stops pinning bytes forever.
	cursors map[string]*cursor

	// links is what the store knows about each server's session, which is the
	// whole input to the spill decision. See SetServerOnline.
	links map[string]*link

	nextGid uint64 // group id the next Append will take
	seqNext uint64 // sequence the next packet will go out under
}

// link is one server's connection state as the store sees it.
//
// down is when the session was last observed to end; the window is measured from
// it. lastSpill is when this server last cost an erase cycle, and it deliberately
// survives reconnects — it is a rate limit on the flash, not on the outage.
type link struct {
	up        bool
	down      time.Time
	lastSpill time.Time
}

// spillReason says which of the three spill triggers is asking, and therefore
// which limits still apply. Making it explicit beats a pair of booleans because
// the interesting part is exactly that the three answers differ.
type spillReason int

const (
	// spillDue is the ordinary periodic spill of a disconnected server, from
	// Flush or the disconnect edge. Honours both the window and the interval.
	spillDue spillReason = iota

	// spillPressure is the buffer about to shed groups it was going to persist.
	// Honours the window but not the interval: the alternative is dropping the
	// samples outright, which no rate limit is worth.
	spillPressure

	// spillFinal is shutdown. Honours neither, because the window bounds
	// RECURRING wear over a long outage and a shutdown writes once — and because
	// a reboot during an outage is the exact scenario this store exists for, so
	// refusing to write on the way out would fail the case it was built for.
	// persistMaxRows still applies, which is what keeps even this bounded.
	spillFinal
)

// Open returns the lite store serving the named servers, recovering any durable
// backlog left in dir by a previous run.
//
// Every server starts DISCONNECTED rather than optimistically connected. A store
// that opened during an outage — a router rebooted while the uplink is still
// down, which is the second half of the exact scenario this tier exists for —
// would otherwise persist nothing until it had managed one session first, and
// the second reboot would lose everything again. The window therefore runs from
// Open until the first session comes up, and a healthy start still costs no
// write: the first spill only happens when a session actually fails.
//
// With opt.Persist false the directory is never read or created and the store is
// exactly the memory-only one this build used to be.
func Open(dir string, servers []string, opt Options) (*Store, error) {
	if len(servers) == 0 {
		return nil, fmt.Errorf("wal: Open needs at least one server name")
	}
	now := time.Now().UTC()
	s := &Store{
		dir:     dir,
		persist: opt.Persist,
		window:  opt.PersistWindow,
		clock:   opt.Clock,
		now:     func() time.Time { return time.Now().UTC() },
		cursors: make(map[string]*cursor, len(servers)),
		links:   make(map[string]*link, len(servers)),
		nextGid: 1,
		nextSeg: 1,
		seqNext: initialSeq(now),
	}
	if s.window <= 0 {
		s.window = defaultPersistWindow
	}
	for _, name := range servers {
		s.cursors[name] = &cursor{}
		s.links[name] = &link{down: now}
	}
	if !s.persist {
		return s, nil
	}
	if err := s.recover(now); err != nil {
		return nil, err
	}
	return s, nil
}

// recover rebuilds the durable tier from dir. Called only from Open, before the
// store is shared, so it takes no lock.
//
// Unreadable bookkeeping discards the backlog rather than replaying it: without
// the allocator position every group would go out under a sequence the server
// cannot recognise as a duplicate, and re-ingesting an outage twice is worse
// than losing it once. FastForward lifts the allocator on the first ack, which
// is precisely the recreated-store case it exists for.
func (s *Store) recover(now time.Time) error {
	removeStaleTemps(s.dir)

	st, found, err := readState(s.dir)
	if err == nil && found && st.V != stateFormat {
		err = fmt.Errorf("state format %d, want %d", st.V, stateFormat)
	}
	if err != nil {
		log.Printf("wal: unreadable %s (%v); discarding the durable backlog and starting fresh", stateName, err)
		return s.discardSegments()
	}
	if found {
		// The persisted allocator position is a floor, not the truth: a router
		// with a working clock seeds far above it, and taking the maximum keeps
		// that case unchanged while covering the one without an RTC.
		if st.NextSeq > s.seqNext {
			s.seqNext = st.NextSeq
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
			if cs.ClaimSeq >= s.seqNext {
				s.seqNext = cs.ClaimSeq + 1
			}
		}
	}

	segs, err := listSegments(s.dir)
	if err != nil {
		return err
	}
	for _, n := range segs {
		groups, err := scanSegment(segPath(s.dir, n), n)
		if err != nil {
			return err
		}
		live := 0
		for _, g := range groups {
			if g.gid >= s.nextGid {
				s.nextGid = g.gid + 1
			}
			if !s.liveLocked(g.gid, g.owner) || expiredAt(s.clock, g.at, g.epoch, g.mono, now, persistRetention) {
				continue
			}
			s.disk = append(s.disk, g)
			live++
		}
		if live == 0 {
			// Everything in it was acknowledged, expired, or belonged to a server
			// that is gone; its deletion just did not happen.
			os.Remove(segPath(s.dir, n))
		}
		if n >= s.nextSeg {
			s.nextSeg = n + 1
		}
	}

	// A claim that no longer resolves to the number of groups it was taken over
	// lost some of them: the spill that was supposed to make them durable never
	// landed, a segment's tail was torn by the power cut, or part of it fell past
	// the retention cutoff while the agent was off.
	//
	// The survivors stay under the ORIGINAL sequence, exactly as expireLocked
	// treats the same loss at runtime, and are re-served by NextBatch as that
	// packet. Freeing them into the ordinary pool instead — which is what dropping
	// the claim outright would do — would send them under a NEW sequence, and that
	// is unsafe in the case this store exists for: if the original packet reached
	// the server and only its ack was lost to the crash, a fresh sequence carries
	// the same samples past (agent_id, sequence) dedup and they are ingested twice.
	// Replaying under the original sequence is correct either way — the server
	// swallows it as a duplicate if the packet landed, and ingests the short
	// version if it did not. Only a claim that lost EVERYTHING is dropped: there is
	// nothing left to send under it, so the sequence is simply burned, which the
	// server tolerates since it takes MAX and never requires contiguity.
	for name, c := range s.cursors {
		if c.claim == nil {
			continue
		}
		got := countClaimed(name, c.claim, s.disk, nil)
		if got == c.claim.n {
			continue
		}
		if got == 0 {
			log.Printf("wal: claim %d for %q covers %d groups but none survived; burning the sequence",
				c.claim.seq, name, c.claim.n)
			c.claim = nil
			continue
		}
		log.Printf("wal: claim %d for %q covers %d groups but %d survived; re-sending those under the same sequence",
			c.claim.seq, name, c.claim.n, got)
		c.claim.n = got
	}
	return nil
}

// liveLocked reports whether a stored group is still owed to anyone. Caller
// holds mu (or is recover, before the store is shared).
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

// initialSeq picks the first packet sequence when there is no persisted
// allocator position to start from.
//
// Restarting the counter at 1 would re-issue sequences the server already
// stored — which it dedups on (agent_id, sequence), silently suppressing
// telemetry until the counter climbed past its watermark.
//
// Seeding from the wall clock avoids that: nanoseconds since the epoch only ever
// move forward, so a later boot practically always starts above every sequence
// an earlier one issued. The server never requires sequences to be contiguous —
// it takes MAX for its watermark — so jumping is free.
//
// A router without an RTC can still boot with a 1970 clock and pick a low seed.
// That case has two backstops: Open takes the maximum of this and the position
// last written to state.json, and conn calls FastForward with the server's
// watermark on the first ack, so at most one deduped batch is lost. (The init
// script also waits for a plausible clock before starting the agent, since TLS
// would fail at 1970 anyway.)
func initialSeq(now time.Time) uint64 {
	ns := now.UTC().UnixNano()
	if ns < 1 {
		// Pre-epoch or an unset clock. Converting a negative to uint64 would land
		// near MaxUint64 and leave almost no sequence space, so start at 1 and let
		// the state file and FastForward do the recovering.
		return 1
	}
	return uint64(ns)
}

// SetServerOnline records one server's session edge, which is the entire input
// to the spill decision (see Store).
//
// The down edge spills immediately rather than waiting for the next periodic
// attempt, because it is the one instant where the buffer is known to hold the
// samples describing the failure and nothing is going to drain them. The up edge
// only closes the window: the backlog already on flash stays there until it is
// acked, since a session coming up is not the same as it having delivered
// anything.
//
// Repeated calls with the same state do nothing, so a caller may report the edge
// it saw without tracking whether it was a change.
func (s *Store) SetServerOnline(server string, online bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	l, ok := s.links[server]
	if !ok || l.up == online {
		return
	}
	l.up = online
	if online {
		l.down = time.Time{}
		return
	}
	l.down = s.now()
	if err := s.spillLocked(l.down, spillDue); err != nil {
		log.Printf("wal: could not persist %q's backlog when its session ended: %v", server, err)
	}
}

// Close persists what the disconnected servers are still holding and reports
// what the shutdown drops anyway.
//
// A connected server's buffer is NOT written: it is the case the zero-write
// promise is about, and its samples were seconds from being uploaded. Saying how
// many were lost is the difference between a known gap and an invisible one.
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	err := s.spillLocked(s.now(), spillFinal)
	if err != nil {
		log.Printf("wal: could not persist the disconnected servers' backlog at shutdown: %v", err)
	}
	if n := s.memRows; n > 0 {
		log.Printf("wal: %d buffered samples lost at shutdown (connected servers are never spilled, and a disconnected one only within its persist window)", n)
	}
	s.mem, s.memRows = nil, 0
	for _, c := range s.cursors {
		c.claim = nil
	}
	return err
}

// Flush persists every disconnected server's unspilled backlog, subject to the
// window and the per-server interval.
//
// It is called by the session runner each time a session ends, which during an
// outage is every reconnect attempt — a few tens of seconds apart. That is what
// drives the periodic spill without this package owning a timer goroutine: the
// cadence is enforced here (persistInterval), so calling it more often costs
// nothing, and a build where nothing ever disconnects never reaches a write.
//
// A connected server's buffer is never written, so one server's outage cannot
// make another's healthy telemetry touch the flash.
func (s *Store) Flush() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.spillLocked(s.now(), spillDue)
}

// Append queues one batch of records for delivery to one server. It returns the
// number of samples dropped for over-capacity (>0 means a data gap the caller
// should surface). An unknown server name is an error: appending for a server
// with no cursor would store bytes nothing will ever deliver.
//
// A full buffer tries to persist before it sheds. Without that, a busy agent
// could evict an offline server's samples minutes before the next scheduled
// spill would have written them — losing exactly the data the durable tier was
// asked to keep, to save an erase cycle the window had already approved. A
// failed spill is not an error here for the same reason it is not in the default
// build: the records are buffered and the caller must not re-queue them.
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
	now := s.now()
	epoch, mono := clockTag(s.clock)
	s.mem = append(s.mem, memGroup{gid: s.nextGid, owner: server, at: now, rec: r, n: n, epoch: epoch, mono: mono})
	s.nextGid++
	s.memRows += n
	if s.memRows <= memMaxRows {
		return 0, nil
	}
	if err := s.spillLocked(now, spillPressure); err != nil {
		log.Printf("wal: spill under buffer pressure failed, %d rows still buffered: %v", s.memRows, err)
	}
	if s.memRows > memMaxRows {
		dropped = s.evictOldestLocked(s.memRows - memMaxRows)
	}
	return dropped, nil
}

// spillLocked writes the eligible servers' buffered groups to one new segment
// and moves them to the durable tier. Nothing is written when no server is
// eligible or none of them has anything buffered, which is the healthy agent's
// path through every caller. Caller holds mu.
//
// Ordering: the state file is published BEFORE the segment is renamed into
// place, so a crash in between leaves a claim describing groups that never
// became visible — which recover shrinks to the survivors (or burns outright if
// none are left), a bounded loss. The reverse order would leave claimed groups
// on disk with no claim, so they would be re-issued under a NEW sequence and the
// server, unable to recognise them as the packet it may already hold, would
// ingest them twice.
//
// No rollback is needed if the rename fails, unlike the default build's spill:
// nothing here adjusts a cursor or a claim, so the state just written stays
// exactly as true as it was before.
func (s *Store) spillLocked(now time.Time, why spillReason) error {
	if !s.persist {
		return nil
	}
	take, kept := s.selectSpillLocked(now, why)
	if len(take) == 0 {
		return nil
	}
	// Whether it succeeds or fails, this server has just had its turn: a disk
	// that refuses writes must not be retried on every reconnect attempt for the
	// rest of the outage.
	defer func() {
		for _, g := range take {
			if l, ok := s.links[g.owner]; ok {
				l.lastSpill = now
			}
		}
	}()

	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return err
	}
	seg := s.nextSeg
	tmp, lines, err := writeSegmentTemp(s.dir, take)
	if err != nil {
		return err
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

	if err := writeState(s.dir, s.stateLocked()); err != nil {
		return err
	}
	if err := os.Rename(tmp, segPath(s.dir, seg)); err != nil {
		return err
	}
	published = true

	index := make([]diskGroup, 0, len(s.disk)+len(lines))
	index = append(index, s.disk...)
	index = append(index, lines...)
	s.disk, s.nextSeg = index, seg+1

	rows := 0
	for _, g := range take {
		rows += g.n
	}
	s.mem, s.memRows = kept, s.memRows-rows
	return nil
}

// selectSpillLocked splits the buffer into the groups this spill writes and the
// groups that stay, or returns nothing when there is nothing to do.
//
// Per owner it takes a PREFIX and stops at the first group that does not fit the
// remaining flash budget. Taking a later group after skipping an earlier one
// would break the invariant every read path relies on — that a server's durable
// groups are all older than its buffered ones — and would deliver its telemetry
// out of order, which the server's fault detectors fold incorrectly. Caller
// holds mu.
func (s *Store) selectSpillLocked(now time.Time, why spillReason) (take, kept []memGroup) {
	budget := make(map[string]int, len(s.links))
	for name, l := range s.links {
		if !dueForSpill(l, now, s.window, why) {
			continue
		}
		if room := persistMaxRows - s.durableRowsLocked(name); room > 0 {
			budget[name] = room
		}
	}
	if len(budget) == 0 || len(s.mem) == 0 {
		return nil, nil
	}

	kept = make([]memGroup, 0, len(s.mem))
	for _, g := range s.mem {
		room, ok := budget[g.owner]
		if !ok || g.n > room {
			if ok {
				budget[g.owner] = 0 // this owner is done for this spill
			}
			kept = append(kept, g)
			continue
		}
		budget[g.owner] = room - g.n
		take = append(take, g)
	}
	if len(take) == 0 {
		return nil, nil
	}
	return take, kept
}

// dueForSpill decides whether one server's backlog may reach flash now. A
// connected server never may, whatever the reason: that is the promise the whole
// design rests on, and the only one with no exception.
func dueForSpill(l *link, now time.Time, window time.Duration, why spillReason) bool {
	if l.up {
		return false
	}
	if why == spillFinal {
		return true
	}
	if now.Sub(l.down) > window {
		return false
	}
	if why == spillPressure {
		return true
	}
	return l.lastSpill.IsZero() || now.Sub(l.lastSpill) >= persistInterval
}

// durableRowsLocked counts what one server already holds on flash. Caller holds mu.
func (s *Store) durableRowsLocked(owner string) int {
	n := 0
	for _, g := range s.disk {
		if g.owner == owner {
			n += g.n
		}
	}
	return n
}

// stateLocked renders the bookkeeping file. NextSeq is the live allocator rather
// than a reserved block: this build hands out sequences from memory and only
// persists the position when something else is already being written, so there
// is nothing to reserve ahead. Caller holds mu.
func (s *Store) stateLocked() walState {
	st := walState{
		V:       stateFormat,
		NextSeq: s.seqNext,
		NextGid: s.nextGid,
		Cursors: make(map[string]cursorState, len(s.cursors)),
	}
	for name, c := range s.cursors {
		cs := cursorState{Acked: c.acked, Identity: c.identity}
		if cl := c.claim; cl != nil {
			cs.ClaimSeq, cs.ClaimFrom, cs.ClaimTo, cs.ClaimN = cl.seq, cl.from, cl.to, cl.n
		}
		st.Cursors[name] = cs
	}
	return st
}

func (s *Store) saveStateLocked() error {
	return writeState(s.dir, s.stateLocked())
}

// gcLocked deletes every segment the live index no longer references: a segment
// is collectable as soon as the last server owing anything in it has acked, with
// no per-segment refcounting. On a router that matters more than elsewhere —
// this is what returns the flash after an outage drains, so a store that has
// caught up occupies nothing again. Caller holds mu.
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
//  2. otherwise the durable backlog, oldest first — everything this server has
//     on flash is older than anything of its own still buffered, because a spill
//     only ever takes a prefix;
//  3. finally the memory buffer.
//
// Step 3 is the case a healthy agent is always in, and it touches no disk. Step 2
// is the reconnect drain, and it does write: a claim over durable groups is
// persisted before the packet goes out, because a crash would otherwise re-issue
// those groups under a different sequence the server cannot dedup. Those writes
// are the cost of having kept the data at all, and they stop as soon as the
// backlog is acked and gcLocked removes its segments.
func (s *Store) NextBatch(server string, maxItems int) (Batch, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	c, ok := s.cursors[server]
	if !ok {
		return Batch{}, false, fmt.Errorf("wal: unknown server %q", server)
	}
	if len(s.disk) > 0 {
		if err := s.expireLocked(s.now()); err != nil {
			return Batch{}, false, err
		}
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

// expireLocked drops durable backlog past the retention window and makes the
// removal durable.
//
// It filters rather than trimming a prefix, which is the one place this build
// cannot borrow the default's shortcut: arrival times are not monotonic across
// this index, because a server that disconnects later spills groups older than
// ones another server's earlier outage already wrote. Nothing expired means no
// write at all, so the common case is free. Caller holds mu.
func (s *Store) expireLocked(now time.Time) error {
	kept := make([]diskGroup, 0, len(s.disk))
	for _, g := range s.disk {
		if expiredAt(s.clock, g.at, g.epoch, g.mono, now, persistRetention) {
			continue
		}
		kept = append(kept, g)
	}
	if len(kept) == len(s.disk) {
		return nil
	}
	s.disk = kept

	// A claim that lost groups is shrunk to what it still carries, so the
	// sequence stays honest about its content; one that lost everything leaves
	// nothing to send, so the sequence is burned.
	for name, c := range s.cursors {
		if c.claim == nil {
			continue
		}
		if got := countClaimed(name, c.claim, s.disk, s.mem); got == 0 {
			c.claim = nil
		} else {
			c.claim.n = got
		}
	}
	if err := s.saveStateLocked(); err != nil {
		return err
	}
	s.gcLocked()
	return nil
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
		// Whole groups, up to maxItems rows — but always at least one, so a single
		// oversized group still makes progress instead of wedging the queue.
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

	seq := s.seqNext
	s.seqNext++
	c.claim = &claim{seq: seq, from: first, to: last, n: take, clockRev: clockRevOf(s.clock)}
	if err := s.saveStateLocked(); err != nil {
		// The claim never became durable, so nothing may be sent under it: a crash
		// would leave those groups unclaimed and they would go out again under a
		// different sequence, which the server cannot dedup. The sequence is burned.
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
// intact. No write: a crash loses those groups anyway, so persisting a claim
// over them would buy nothing. Caller holds mu.
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
	seq := s.seqNext
	s.seqNext++
	c.claim = &claim{seq: seq, from: first, to: last, n: len(recs), clockRev: rev}
	return flatten(seq, recs, offs), true, nil
}

// loadClaimLocked re-serves a claim's groups under their original sequence. It
// spans both tiers because a claim taken from memory keeps its group ids when a
// spill moves them to flash underneath it; disk before memory is already
// group-id order for one owner. Caller holds mu.
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

// Ack releases one server's acknowledged packet. A stale ack — for a sequence
// that is not the one in flight, or for a server that is not configured — is
// ignored rather than treated as an error: it means a duplicate or late reply,
// and there is nothing to release.
//
// Only a packet that had durable groups costs a write. A memory-served packet is
// simply forgotten — that tier never reached flash to be deleted from, and a
// watermark that is not persisted only ever under-reports what was delivered.
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

	if !s.dropClaimedLocked(server, cl) {
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
// Same contract and the same reasoning as the default build's BindIdentity —
// read that one for why a re-enrollment must discard the backlog, why the
// records cannot simply be handed over under the old id, and why a "tag and
// skip" would pin segments forever. Only the writing differs, and in the
// direction this build always differs: the identity is kept in memory and rides
// out with the next state file the store was going to write anyway (every spill
// and every durable claim renders it), so binding an identity on a router that
// has never been disconnected still costs no erase cycle. A discard that
// actually removed durable groups DOES write, because it has just invalidated
// what is on the flash and the sweep behind it is what gives those bytes back.
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
		// the configuration.
		return 0, nil
	}

	dropped, touchedDisk := s.discardServerLocked(server, c)
	log.Printf("wal: %q re-enrolled as %s (was %s); discarded %d queued samples collected under the old identity (data gap)",
		server, agentID, prev, dropped)
	if !touchedDisk {
		return dropped, nil
	}
	if err := s.saveStateLocked(); err != nil {
		return dropped, err
	}
	s.gcLocked()
	return dropped, nil
}

// discardServerLocked drops everything one server owns from both tiers, releases
// its claim and moves its cursor past every group handed out so far. It returns
// the number of sample rows discarded and whether any of them were durable — the
// latter being what decides whether the flash has to be written. Caller holds mu.
func (s *Store) discardServerLocked(server string, c *cursor) (int, bool) {
	dropped, touchedDisk := 0, false
	kept := make([]diskGroup, 0, len(s.disk))
	for _, g := range s.disk {
		if g.owner == server {
			dropped += g.n
			touchedDisk = true
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
	return dropped, touchedDisk
}

// FastForward raises the next-sequence allocator to at least watermark+1 so the
// WAL stops re-emitting sequences the server has already consumed. It recovers
// the case where the local allocator falls behind a server: a store recreated or
// discarded while the agent kept its enrollment, or a boot whose clock had not
// yet been set (see initialSeq).
//
// It is deliberately memory-only, unlike the default build's, which persists the
// new position immediately. conn calls this on EVERY ack, so a write here would
// put an erase cycle on the healthy path — the one thing this build is built not
// to do. The position reaches flash at the next spill or durable claim instead,
// which are the only moments a persisted backlog exists to be confused by it.
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

// Pending returns the number of samples one server has not yet acknowledged,
// across both tiers — buffered, claimed-but-unacked, and spilled. It backs that
// server's agent.wal_pending metric.
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
