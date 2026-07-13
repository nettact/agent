// Package wal is the agent's durable outbox (architecture §3.3): collectors
// append samples locally so monitoring never stops when the server is
// unreachable, and batches carry a persistent sequence so a crash mid-upload
// re-sends the SAME sequence and the server dedups on (agent_id, sequence).
package wal

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"

	"github.com/nettact/protocol/telemetry"
)

const (
	kindMetric    = "m"
	kindEvent     = "e"
	kindInventory = "i"
	kindSnapshot  = "n" // telemetry.InterfaceSnapshot (authoritative interface set)
)

// Store is the SQLite-backed outbox.
type Store struct {
	db        *sql.DB
	mu        sync.Mutex
	maxRows   int
	retention time.Duration
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
	return &Store{db: db, maxRows: 50000, retention: 72 * time.Hour}, nil
}

func (s *Store) Close() error { return s.db.Close() }

// Append durably stores one collect result's items and enforces caps. It
// returns the number of untagged samples dropped for over-capacity (>0 means a
// data gap the caller should surface).
func (s *Store) Append(metrics []telemetry.Metric, events []telemetry.Event, inv []telemetry.InventoryItem, snaps []telemetry.InterfaceSnapshot) (dropped int, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	// Every row of this Append shares one group id, so NextBatch can claim the
	// whole collector Result as an indivisible unit — its metrics/events/
	// inventory/snapshot never split across packet sequences (WIFI-001).
	grp, err := nextGrpTx(tx)
	if err != nil {
		return 0, err
	}

	// One prepared statement reused for every row in the batch — at 1s probe
	// intervals a batch carries dozens of rows and per-row re-parsing adds up.
	stmt, err := tx.Prepare(`INSERT INTO sample(created_at, kind, data, grp, packet_seq) VALUES(?,?,?,?,NULL)`)
	if err != nil {
		return 0, err
	}
	defer stmt.Close()
	ins := func(kind string, v any) error {
		b, _ := json.Marshal(v)
		_, e := stmt.Exec(now, kind, string(b), grp)
		return e
	}
	for i := range metrics {
		if err = ins(kindMetric, metrics[i]); err != nil {
			return 0, err
		}
	}
	for i := range events {
		if err = ins(kindEvent, events[i]); err != nil {
			return 0, err
		}
	}
	for i := range inv {
		if err = ins(kindInventory, inv[i]); err != nil {
			return 0, err
		}
	}
	for i := range snaps {
		if err = ins(kindSnapshot, snaps[i]); err != nil {
			return 0, err
		}
	}

	// Time-based eviction of stale un-acked samples. All rows of one Append share
	// the same created_at (computed once above), so this removes whole groups —
	// never a partial Result.
	if _, err = tx.Exec(`DELETE FROM sample WHERE created_at < ?`, now.Add(-s.retention)); err != nil {
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
	return dropped, nil
}

// Batch is a packet to upload.
type Batch struct {
	Sequence  uint64
	Metrics   []telemetry.Metric
	Events    []telemetry.Event
	Inventory []telemetry.InventoryItem
	Snapshots []telemetry.InterfaceSnapshot
}

// NextBatch returns the next packet to send. A pending (previously-tagged)
// packet is returned first so a failed/crashed upload re-sends the same
// sequence. Otherwise up to maxItems untagged samples are claimed under a new
// sequence. ok=false means nothing to send.
func (s *Store) NextBatch(maxItems int) (Batch, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var pending sql.NullInt64
	if err := s.db.QueryRow(`SELECT MIN(packet_seq) FROM sample WHERE packet_seq IS NOT NULL`).Scan(&pending); err != nil {
		return Batch{}, false, err
	}
	if pending.Valid {
		return s.loadBatch(uint64(pending.Int64))
	}

	// Claim untagged rows under a fresh sequence, atomically.
	tx, err := s.db.Begin()
	if err != nil {
		return Batch{}, false, err
	}
	rollback := true
	defer func() {
		if rollback {
			_ = tx.Rollback()
		}
	}()

	// Claim whole result-groups. Take up to maxItems rows in id order, then
	// extend to the end of the group the window cut through, so one Append (one
	// collector Result) is never split across sequences — its metrics, events,
	// inventory and interface snapshot always ride the same packet even when the
	// backlog exceeds maxItems. A single group larger than maxItems is sent whole
	// (progress is always made). Groups are contiguous in id order (one Append =
	// consecutive ids + one grp), so only the last group in the window can be
	// partial, and the tail query completes exactly that one.
	rows, err := tx.Query(`SELECT id, grp FROM sample WHERE packet_seq IS NULL ORDER BY id LIMIT ?`, maxItems)
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
	tail, err := tx.Query(`SELECT id FROM sample WHERE packet_seq IS NULL AND grp=? AND id>? ORDER BY id`, lastGrp, lastID)
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

	seq, err := nextSeqTx(tx)
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
	if _, err := tx.Exec(`UPDATE sample SET packet_seq=? WHERE id IN (`+strings.Join(placeholders, ",")+`)`, args...); err != nil {
		return Batch{}, false, err
	}
	if err := tx.Commit(); err != nil {
		return Batch{}, false, err
	}
	rollback = false
	return s.loadBatch(seq)
}

// Ack removes the samples of an acknowledged packet.
func (s *Store) Ack(seq uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
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

	var v string
	err := s.db.QueryRow(`SELECT v FROM meta WHERE k='next_seq'`).Scan(&v)
	cur := uint64(1)
	switch {
	case err == nil:
		n, e := strconv.ParseUint(v, 10, 64)
		if e != nil {
			return fmt.Errorf("corrupt next_seq: %w", e)
		}
		cur = n
	case err != sql.ErrNoRows:
		return err
	}
	if target <= cur {
		return nil // allocator already at/above the watermark; never lower it
	}
	_, err = s.db.Exec(`INSERT INTO meta(k,v) VALUES('next_seq',?)
		ON CONFLICT(k) DO UPDATE SET v=excluded.v`, strconv.FormatUint(target, 10))
	return err
}

// Pending returns the number of samples not yet acknowledged.
func (s *Store) Pending() int {
	var n int
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM sample`).Scan(&n)
	return n
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
		}
	}
	return b, true, rows.Err()
}

func nextSeqTx(tx *sql.Tx) (uint64, error) {
	var v string
	err := tx.QueryRow(`SELECT v FROM meta WHERE k='next_seq'`).Scan(&v)
	seq := uint64(1)
	if err == nil {
		n, e := strconv.ParseUint(v, 10, 64)
		if e != nil {
			return 0, fmt.Errorf("corrupt next_seq: %w", e)
		}
		seq = n
	} else if err != sql.ErrNoRows {
		return 0, err
	}
	if _, err := tx.Exec(`INSERT INTO meta(k,v) VALUES('next_seq',?)
		ON CONFLICT(k) DO UPDATE SET v=excluded.v`, strconv.FormatUint(seq+1, 10)); err != nil {
		return 0, err
	}
	return seq, nil
}

// nextGrpTx allocates the next monotonic group id (persisted in meta so ids stay
// unique across restarts, keeping any leftover un-acked rows correctly grouped).
func nextGrpTx(tx *sql.Tx) (int64, error) {
	var v string
	err := tx.QueryRow(`SELECT v FROM meta WHERE k='next_grp'`).Scan(&v)
	grp := int64(1)
	if err == nil {
		n, e := strconv.ParseInt(v, 10, 64)
		if e != nil {
			return 0, fmt.Errorf("corrupt next_grp: %w", e)
		}
		grp = n
	} else if err != sql.ErrNoRows {
		return 0, err
	}
	if _, err := tx.Exec(`INSERT INTO meta(k,v) VALUES('next_grp',?)
		ON CONFLICT(k) DO UPDATE SET v=excluded.v`, strconv.FormatInt(grp+1, 10)); err != nil {
		return 0, err
	}
	return grp, nil
}
