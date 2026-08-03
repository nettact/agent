// Package wal is the agent's outbox (architecture §3.3): collectors append
// samples locally so monitoring never stops when the server is unreachable, and
// batches carry a sequence so a crash mid-upload re-sends the SAME sequence and
// the server dedups on (agent_id, sequence).
//
// It is two tiers, not one. Appends land in memory and are handed straight to
// the uploader, so an agent whose session is up writes nothing to disk; SQLite
// is the spill the buffer falls back on when uploads stop, when the buffer ages
// or fills, and at shutdown. Storing every collector Result durably as it
// arrived cost ~18 KB of disk writes for ~500 bytes of telemetry — SQLite's
// minimum write is a page, so the fix had to be fewer transactions rather than
// cheaper ones. See Store for the durability trade and the ordering rules that
// hold across the two tiers.
package wal

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"

	"github.com/nettact/protocol/gamesense"
	"github.com/nettact/protocol/telemetry"
)

const (
	kindMetric     = "m"
	kindEvent      = "e"
	kindInventory  = "i"
	kindSnapshot   = "n" // telemetry.InterfaceSnapshot (authoritative interface set)
	kindGameRun    = "g" // gamesense.Run
	kindGameBucket = "b" // gamesense.Bucket
	kindGameGap    = "p" // gamesense.Gap ("pause")
	kindGameHost   = "h" // gamesense.HostSecond
)

const (
	// memBufferRows caps the in-memory tier. It is only reached when uploads are
	// not keeping up; the buffer then spills to SQLite in ONE transaction, which
	// is what makes a disconnected agent cheap to store rather than expensive.
	memBufferRows = 20000

	// memBufferAge is how long a record may sit in memory before it is spilled
	// regardless of depth. It bounds what a crash can lose while the server is
	// unreachable. A healthy agent uploads every DefaultUploadInterval (30s) and
	// so drains well inside this, never spilling at all.
	memBufferAge = 90 * time.Second

	// seqBlock is how many packet sequences one durable reservation covers. The
	// allocator has to survive restarts (a reused sequence is silently deduped by
	// the server, i.e. lost telemetry), but writing it per packet would put back
	// the per-upload page write this tier exists to remove. Reserving in blocks
	// costs one small write per seqBlock packets; the unused tail of a block is
	// skipped after a restart, which is harmless because the server dedups on the
	// exact (agent_id, sequence) pair and takes MAX for its watermark — it never
	// requires sequences to be contiguous.
	seqBlock = 1000
)

// memGroup is one Append held in memory: an indivisible Records plus the wall
// clock it arrived at (its created_at if it is ever spilled) and its row count.
type memGroup struct {
	at  time.Time
	rec Records
	n   int
}

// memBatch is the one memory-served packet handed to the uploader and awaiting
// its ack. It keeps the groups rather than a flattened Batch so a spill can
// write them back out with their own created_at and grouping intact.
type memBatch struct {
	seq    uint64
	groups []memGroup
}

// Store is the agent's outbox: an in-memory queue in front of a SQLite spill.
//
// Telemetry is appended to memory and, when the session is up, handed straight
// to the uploader and dropped on ack — so a healthy agent writes NOTHING to
// disk. SQLite is what the buffer falls back on: when the buffer fills, ages
// past memBufferAge, or the process shuts down, the whole buffer is written in
// one transaction. That is the point of the split — SQLite's minimum write is a
// page, so per-Append transactions cost ~18 KB for ~500 bytes of telemetry, and
// the fix is fewer transactions rather than cheaper ones.
//
// The cost is bounded and deliberate: a crash loses whatever is still in memory,
// at most one upload interval's worth while connected. Durability when it
// actually matters — the server being unreachable — is unchanged, because that
// is exactly the case that spills.
//
// Delivery order is FIFO across both tiers, which the fault detectors depend on:
// NextBatch serves the disk backlog before any memory group, and a spill appends
// after the rows already there, so a target's rounds can never reach the server
// out of order.
type Store struct {
	db        *sql.DB
	mu        sync.Mutex
	maxRows   int
	retention time.Duration

	mem      []memGroup // buffered, not yet claimed
	memRows  int
	inflight *memBatch // claimed from memory, awaiting ack; nil when none

	seqNext, seqCeil uint64 // reserved sequence block [seqNext, seqCeil)
	grpNext          int64  // group ids, unique among the rows currently stored
}

// Open creates/opens the WAL at path.
func Open(path string) (*Store, error) {
	dsn := path + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=synchronous(NORMAL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, err
	}
	if _, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS sample(
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			created_at TIMESTAMP NOT NULL,
			kind TEXT NOT NULL,
			data TEXT NOT NULL,
			grp INTEGER NOT NULL,
			packet_seq INTEGER
		);
		CREATE INDEX IF NOT EXISTS idx_sample_seq ON sample(packet_seq, id);
		CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT NOT NULL);`); err != nil {
		db.Close()
		return nil, err
	}
	s := &Store{db: db, maxRows: 50000, retention: 72 * time.Hour}
	// Group ids only have to be unique among the rows CURRENTLY stored, so
	// seeding past the highest surviving one is enough and costs no meta row —
	// the counter then lives in memory, removing a whole B-tree from every spill
	// transaction (measured: ~4 KB of WAL per transaction).
	if err := db.QueryRow(`SELECT COALESCE(MAX(grp),0)+1 FROM sample`).Scan(&s.grpNext); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// Close flushes the memory tier to disk and closes the database. Flushing here
// is what makes an ordinary shutdown lossless: the caller already stops every
// producer and joins them before closing, so nothing is still being appended.
func (s *Store) Close() error {
	s.mu.Lock()
	dropped, ferr := s.spillLocked(time.Now().UTC())
	if dropped > 0 {
		// Nobody is left to inspect a return value at shutdown, and an offline
		// agent closing with a full backlog can shed thousands of samples here.
		// Reporting success while silently dropping them would make a real data
		// gap invisible.
		log.Printf("WAL over capacity at shutdown: dropped %d oldest samples (data gap)", dropped)
	}
	s.mu.Unlock()
	cerr := s.db.Close()
	if ferr != nil {
		return ferr
	}
	return cerr
}

// Flush spills everything buffered in memory to durable storage. Callers that
// want a hard durability point (shutdown, suspend) can use it; ordinary
// operation relies on Close.
func (s *Store) Flush() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.spillLocked(time.Now().UTC())
	return err
}

// Records is one Append's worth of telemetry. A struct rather than a parameter
// per payload kind because the kinds are added to over time and every caller
// fills two or three of them: naming the ones it has beats counting nils.
//
// Everything in one Records is stored as one indivisible group, so a caller that
// puts related records together — a run and the buckets that hang from it — is
// guaranteed they reach the server in the same packet.
type Records struct {
	Metrics         []telemetry.Metric
	Events          []telemetry.Event
	Inventory       []telemetry.InventoryItem
	Snapshots       []telemetry.InterfaceSnapshot
	GameRuns        []gamesense.Run
	GameBuckets     []gamesense.Bucket
	GameGaps        []gamesense.Gap
	GameHostSeconds []gamesense.HostSecond
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
// a second copy of the same records in the buffer and upload both once SQLite
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
			// disk that refuses writes (full, read-only, corrupt) would otherwise let
			// memory grow until the agent is killed — trading a bounded data gap for
			// losing the process, and with it every unspilled sample anyway. Drop the
			// oldest whole groups instead, which is the same contract the durable
			// tier's own over-capacity eviction has always had.
			dropped += s.evictOldestLocked(s.memRows - memBufferRows)
		}
	}
	return dropped, nil
}

// memBufferHardCap is how far past memBufferRows the buffer may grow while
// spills are failing before it starts shedding the oldest groups.
const memBufferHardCap = 2 * memBufferRows

// retentionDeleteSQL expires un-acked rows past the retention window. Shared by
// the spill (which runs it inside its own transaction) and the disk claim, so
// the two can never disagree about what "expired" means.
const retentionDeleteSQL = `DELETE FROM sample WHERE created_at < ?`

// evictOldestLocked drops whole buffered groups, oldest first, until at least n
// rows are gone, and returns how many it actually dropped. Whole groups only:
// splitting one would strip a metric from a Result while leaving its snapshot,
// which is the invariant the group id exists to protect. Caller holds mu.
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

// rowsOf counts the sample rows one Records would occupy.
func rowsOf(r Records) int {
	return len(r.Metrics) + len(r.Events) + len(r.Inventory) + len(r.Snapshots) +
		len(r.GameRuns) + len(r.GameBuckets) + len(r.GameGaps) + len(r.GameHostSeconds)
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

// spillLocked writes the whole memory tier to SQLite in ONE transaction and
// enforces the store's caps. The in-flight batch is written first and keeps its
// packet_seq, so it stays both the oldest row and a claimed one — the uploader
// then re-sends it under the same sequence from disk, exactly as it would have
// from memory. Caller holds mu.
func (s *Store) spillLocked(now time.Time) (dropped int, err error) {
	if s.inflight == nil && len(s.mem) == 0 {
		return 0, nil
	}

	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	// One prepared statement reused for every row of every group — a spill can
	// carry thousands of rows and per-row re-parsing adds up.
	stmt, err := tx.Prepare(`INSERT INTO sample(created_at, kind, data, grp, packet_seq) VALUES(?,?,?,?,?)`)
	if err != nil {
		return 0, err
	}
	defer stmt.Close()

	if s.inflight != nil {
		seq := sql.NullInt64{Int64: int64(s.inflight.seq), Valid: true}
		for _, g := range s.inflight.groups {
			if err = s.insertGroup(stmt, g, seq); err != nil {
				return 0, err
			}
		}
	}
	for _, g := range s.mem {
		if err = s.insertGroup(stmt, g, sql.NullInt64{}); err != nil {
			return 0, err
		}
	}

	// Time-based eviction of stale un-acked samples. All rows of one group share
	// its created_at, so this removes whole groups — never a partial Result.
	if _, err = tx.Exec(retentionDeleteSQL, now.Add(-s.retention)); err != nil {
		return 0, err
	}

	// Count-based cap: drop the oldest UNTAGGED groups (whole Appends) until the
	// store is at or below maxRows, or no untagged group remains. Whole-group
	// deletion preserves the indivisible-Result invariant — a row-level delete of
	// just the exact overflow could strip one metric from an old group while
	// leaving its remaining metrics/snapshot. This may drop slightly more rows
	// than the exact overflow; the actual count is returned/logged.
	var total int
	if err = tx.QueryRow(`SELECT COUNT(*) FROM sample`).Scan(&total); err != nil {
		return 0, err
	}
	for total > s.maxRows {
		var g sql.NullInt64
		if err = tx.QueryRow(`SELECT MIN(grp) FROM sample WHERE packet_seq IS NULL`).Scan(&g); err != nil {
			return 0, err
		}
		if !g.Valid {
			break // nothing untagged left to evict (the backlog is all in-flight)
		}
		res, e := tx.Exec(`DELETE FROM sample WHERE packet_seq IS NULL AND grp=?`, g.Int64)
		if e != nil {
			err = e
			return 0, err
		}
		n, _ := res.RowsAffected()
		if n == 0 {
			break // defensive: no progress possible
		}
		dropped += int(n)
		total -= int(n)
	}

	if err = tx.Commit(); err != nil {
		return 0, err
	}
	// Durable now: memory hands ownership to the database. The in-flight batch
	// goes with it — its rows carry the same packet_seq, so NextBatch will serve
	// it from disk before anything else and the uploader never sees a gap.
	s.inflight = nil
	s.mem = nil
	s.memRows = 0
	return dropped, nil
}

// insertGroup writes one group's rows, all sharing its created_at and a fresh
// group id so NextBatch can claim the whole collector Result as an indivisible
// unit — its metrics/events/inventory/snapshot never split across packet
// sequences (WIFI-001). seq is set only when the group is being spilled as part
// of an already-claimed packet. Caller holds mu.
func (s *Store) insertGroup(stmt *sql.Stmt, g memGroup, seq sql.NullInt64) error {
	grp := s.grpNext
	s.grpNext++
	ins := func(kind string, v any) error {
		b, _ := json.Marshal(v)
		_, e := stmt.Exec(g.at, kind, string(b), grp, seq)
		return e
	}
	for i := range g.rec.Metrics {
		if err := ins(kindMetric, g.rec.Metrics[i]); err != nil {
			return err
		}
	}
	for i := range g.rec.Events {
		if err := ins(kindEvent, g.rec.Events[i]); err != nil {
			return err
		}
	}
	for i := range g.rec.Inventory {
		if err := ins(kindInventory, g.rec.Inventory[i]); err != nil {
			return err
		}
	}
	for i := range g.rec.Snapshots {
		if err := ins(kindSnapshot, g.rec.Snapshots[i]); err != nil {
			return err
		}
	}
	for i := range g.rec.GameRuns {
		if err := ins(kindGameRun, g.rec.GameRuns[i]); err != nil {
			return err
		}
	}
	for i := range g.rec.GameBuckets {
		if err := ins(kindGameBucket, g.rec.GameBuckets[i]); err != nil {
			return err
		}
	}
	for i := range g.rec.GameGaps {
		if err := ins(kindGameGap, g.rec.GameGaps[i]); err != nil {
			return err
		}
	}
	for i := range g.rec.GameHostSeconds {
		if err := ins(kindGameHost, g.rec.GameHostSeconds[i]); err != nil {
			return err
		}
	}
	return nil
}

// Batch is a packet to upload.
type Batch struct {
	Sequence        uint64
	Metrics         []telemetry.Metric
	Events          []telemetry.Event
	Inventory       []telemetry.InventoryItem
	Snapshots       []telemetry.InterfaceSnapshot
	GameRuns        []gamesense.Run
	GameBuckets     []gamesense.Bucket
	GameGaps        []gamesense.Gap
	GameHostSeconds []gamesense.HostSecond
}

// NextBatch returns the next packet to send, or ok=false when there is nothing.
//
// Order is FIFO across both tiers, which is what the server's fault detectors
// rely on (a target's rounds arriving out of order would be folded twice):
//
//  1. a memory batch already claimed and not yet acked — re-served under the
//     SAME sequence, so a dropped session re-sends rather than loses it;
//  2. the disk backlog, tagged packets first, then untagged rows — everything
//     on disk is older than anything in memory, because memory only spills in
//     arrival order and only ever appends;
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

// batch flattens the claimed groups into the packet to send, preserving arrival
// order across groups and payload order within each.
func (m *memBatch) batch() Batch {
	b := Batch{Sequence: m.seq}
	for _, g := range m.groups {
		b.Metrics = append(b.Metrics, g.rec.Metrics...)
		b.Events = append(b.Events, g.rec.Events...)
		b.Inventory = append(b.Inventory, g.rec.Inventory...)
		b.Snapshots = append(b.Snapshots, g.rec.Snapshots...)
		b.GameRuns = append(b.GameRuns, g.rec.GameRuns...)
		b.GameBuckets = append(b.GameBuckets, g.rec.GameBuckets...)
		b.GameGaps = append(b.GameGaps, g.rec.GameGaps...)
		b.GameHostSeconds = append(b.GameHostSeconds, g.rec.GameHostSeconds...)
	}
	return b
}

// nextDiskBatchLocked serves the SQLite backlog: a pending (previously-tagged)
// packet first so a failed/crashed upload re-sends the same sequence, otherwise
// up to maxItems untagged samples claimed under a new sequence. Caller holds mu.
func (s *Store) nextDiskBatchLocked(maxItems int) (Batch, bool, error) {
	// Expire stale rows before any of them can be claimed. This used to ride on
	// every Append, but appends now usually stop at memory, so without it a
	// backlog spilled during a long outage could be uploaded after sitting past
	// the retention window — and server-core prunes its (agent_id, sequence)
	// dedup rows on exactly the assumption that the agent never replays anything
	// older than this, so those packets would be re-ingested as if new. A delete
	// that matches nothing dirties no page, so the common case costs no write.
	if _, err := s.db.Exec(retentionDeleteSQL, time.Now().UTC().Add(-s.retention)); err != nil {
		return Batch{}, false, err
	}

	var pending sql.NullInt64
	if err := s.db.QueryRow(`SELECT MIN(packet_seq) FROM sample WHERE packet_seq IS NOT NULL`).Scan(&pending); err != nil {
		return Batch{}, false, err
	}
	if pending.Valid {
		return s.loadBatch(uint64(pending.Int64))
	}

	// Select the rows to claim BEFORE opening the write transaction and before
	// allocating a sequence. Both matter: the pool is capped at one connection, so
	// a block reservation issued inside an open transaction would wait forever for
	// a second one, and finding nothing here must not burn a sequence — NextBatch
	// is called on every drain tick, most of which have no disk backlog at all.
	// Reads need no transaction of their own: mu makes this the only writer.
	//
	// Claim whole result-groups. Take up to maxItems rows in id order, then
	// extend to the end of the group the window cut through, so one Append (one
	// collector Result) is never split across sequences — its metrics, events,
	// inventory and interface snapshot always ride the same packet even when the
	// backlog exceeds maxItems. A single group larger than maxItems is sent whole
	// (progress is always made). Groups are contiguous in id order (one Append =
	// consecutive ids + one grp), so only the last group in the window can be
	// partial, and the tail query completes exactly that one.
	rows, err := s.db.Query(`SELECT id, grp FROM sample WHERE packet_seq IS NULL ORDER BY id LIMIT ?`, maxItems)
	if err != nil {
		return Batch{}, false, err
	}
	var ids []int64
	var lastGrp, lastID int64
	for rows.Next() {
		var id, grp int64
		if err := rows.Scan(&id, &grp); err != nil {
			rows.Close()
			return Batch{}, false, err
		}
		ids = append(ids, id)
		lastGrp, lastID = grp, id
	}
	rows.Close()
	if len(ids) == 0 {
		return Batch{}, false, nil
	}
	tail, err := s.db.Query(`SELECT id FROM sample WHERE packet_seq IS NULL AND grp=? AND id>? ORDER BY id`, lastGrp, lastID)
	if err != nil {
		return Batch{}, false, err
	}
	for tail.Next() {
		var id int64
		if err := tail.Scan(&id); err != nil {
			tail.Close()
			return Batch{}, false, err
		}
		ids = append(ids, id)
	}
	tail.Close()

	seq, err := s.allocSeqLocked()
	if err != nil {
		return Batch{}, false, err
	}
	placeholders := make([]string, len(ids))
	args := make([]any, 0, len(ids)+1)
	args = append(args, int64(seq))
	for i, id := range ids {
		placeholders[i] = "?"
		args = append(args, id)
	}
	// A single statement is its own transaction, so the claim is still atomic —
	// either every selected row carries the sequence or none does.
	if _, err := s.db.Exec(`UPDATE sample SET packet_seq=? WHERE id IN (`+strings.Join(placeholders, ",")+`)`, args...); err != nil {
		return Batch{}, false, err
	}
	return s.loadBatch(seq)
}

// allocSeqLocked hands out the next packet sequence, reserving a fresh block
// from SQLite when the current one is exhausted. Caller holds mu, and must not
// hold an open transaction: the reservation writes on the same single pooled
// connection.
func (s *Store) allocSeqLocked() (uint64, error) {
	if s.seqNext < s.seqCeil {
		seq := s.seqNext
		s.seqNext++
		return seq, nil
	}
	cur, err := s.durableSeqLocked()
	if err != nil {
		return 0, err
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

// durableSeqLocked reads the persisted allocator position (1 when unset).
func (s *Store) durableSeqLocked() (uint64, error) {
	var v string
	err := s.db.QueryRow(`SELECT v FROM meta WHERE k='next_seq'`).Scan(&v)
	switch {
	case err == nil:
		n, e := strconv.ParseUint(v, 10, 64)
		if e != nil {
			return 0, fmt.Errorf("corrupt next_seq: %w", e)
		}
		return n, nil
	case err == sql.ErrNoRows:
		return 1, nil
	default:
		return 0, err
	}
}

func (s *Store) setDurableSeqLocked(v uint64) error {
	_, err := s.db.Exec(`INSERT INTO meta(k,v) VALUES('next_seq',?)
		ON CONFLICT(k) DO UPDATE SET v=excluded.v`, strconv.FormatUint(v, 10))
	return err
}

// Ack releases the samples of an acknowledged packet. A memory-served packet is
// simply forgotten — the whole point of the tier is that it never reached disk
// to be deleted from.
func (s *Store) Ack(seq uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.inflight != nil && s.inflight.seq == seq {
		s.inflight = nil
		return nil
	}
	_, err := s.db.Exec(`DELETE FROM sample WHERE packet_seq=?`, int64(seq))
	return err
}

// FastForward durably raises the next-sequence allocator to at least
// watermark+1 so the WAL stops re-emitting sequences the server has already
// consumed. It exists to recover the one case where the local allocator falls
// behind the server: the WAL db was recreated/reset (next_seq back near 1)
// while the agent kept its enrollment and the server still retains far higher
// packet sequences. Without this, every fresh batch reuses an already-stored
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

	cur, err := s.durableSeqLocked()
	if err != nil {
		return err
	}
	if target <= cur {
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
// only the durable rows would read as "nothing queued" on an agent whose uploads
// are failing but whose buffer has not yet aged into a spill.
func (s *Store) Pending() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := s.memRows
	if s.inflight != nil {
		for _, g := range s.inflight.groups {
			n += g.n
		}
	}
	var stored int
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM sample`).Scan(&stored)
	return n + stored
}

// loadBatch reads all samples tagged with seq into a Batch (caller holds mu).
func (s *Store) loadBatch(seq uint64) (Batch, bool, error) {
	rows, err := s.db.Query(`SELECT kind, data FROM sample WHERE packet_seq=? ORDER BY id`, int64(seq))
	if err != nil {
		return Batch{}, false, err
	}
	defer rows.Close()
	b := Batch{Sequence: seq}
	for rows.Next() {
		var kind, data string
		if err := rows.Scan(&kind, &data); err != nil {
			return Batch{}, false, err
		}
		switch kind {
		case kindMetric:
			var m telemetry.Metric
			if json.Unmarshal([]byte(data), &m) == nil {
				b.Metrics = append(b.Metrics, m)
			}
		case kindEvent:
			var e telemetry.Event
			if json.Unmarshal([]byte(data), &e) == nil {
				b.Events = append(b.Events, e)
			}
		case kindInventory:
			var it telemetry.InventoryItem
			if json.Unmarshal([]byte(data), &it) == nil {
				b.Inventory = append(b.Inventory, it)
			}
		case kindSnapshot:
			var s telemetry.InterfaceSnapshot
			if json.Unmarshal([]byte(data), &s) == nil {
				b.Snapshots = append(b.Snapshots, s)
			}
		case kindGameRun:
			var r gamesense.Run
			if json.Unmarshal([]byte(data), &r) == nil {
				b.GameRuns = append(b.GameRuns, r)
			}
		case kindGameBucket:
			var bk gamesense.Bucket
			if json.Unmarshal([]byte(data), &bk) == nil {
				b.GameBuckets = append(b.GameBuckets, bk)
			}
		case kindGameGap:
			var g gamesense.Gap
			if json.Unmarshal([]byte(data), &g) == nil {
				b.GameGaps = append(b.GameGaps, g)
			}
		case kindGameHost:
			var h gamesense.HostSecond
			if json.Unmarshal([]byte(data), &h) == nil {
				b.GameHostSeconds = append(b.GameHostSeconds, h)
			}
		}
	}
	return b, true, rows.Err()
}
