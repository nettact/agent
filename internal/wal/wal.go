// Package wal is the agent's durable outbox (architecture §3.3): collectors
// append samples locally so monitoring never stops when the server is
// unreachable, and batches carry a persistent sequence so a crash mid-upload
// re-sends the SAME sequence and the server dedups on (agent_id, sequence).
package wal

import (
	"database/sql"
	"encoding/json"
	"fmt"
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
func (s *Store) Append(metrics []telemetry.Metric, events []telemetry.Event, inv []telemetry.InventoryItem) (dropped int, err error) {
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

	// One prepared statement reused for every row in the batch — at 1s probe
	// intervals a batch carries dozens of rows and per-row re-parsing adds up.
	stmt, err := tx.Prepare(`INSERT INTO sample(created_at, kind, data, packet_seq) VALUES(?,?,?,NULL)`)
	if err != nil {
		return 0, err
	}
	defer stmt.Close()
	ins := func(kind string, v any) error {
		b, _ := json.Marshal(v)
		_, e := stmt.Exec(now, kind, string(b))
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

	// Time-based eviction of stale un-acked samples.
	if _, err = tx.Exec(`DELETE FROM sample WHERE created_at < ?`, now.Add(-s.retention)); err != nil {
		return 0, err
	}

	// Count-based cap: drop oldest UNTAGGED samples beyond maxRows.
	var total int
	if err = tx.QueryRow(`SELECT COUNT(*) FROM sample`).Scan(&total); err != nil {
		return 0, err
	}
	if total > s.maxRows {
		over := total - s.maxRows
		res, e := tx.Exec(`DELETE FROM sample WHERE packet_seq IS NULL AND id IN
			(SELECT id FROM sample WHERE packet_seq IS NULL ORDER BY id LIMIT ?)`, over)
		if e != nil {
			err = e
			return 0, err
		}
		n, _ := res.RowsAffected()
		dropped = int(n)
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

	rows, err := tx.Query(`SELECT id FROM sample WHERE packet_seq IS NULL ORDER BY id LIMIT ?`, maxItems)
	if err != nil {
		return Batch{}, false, err
	}
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return Batch{}, false, err
		}
		ids = append(ids, id)
	}
	rows.Close()
	if len(ids) == 0 {
		return Batch{}, false, nil
	}

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
