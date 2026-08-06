//go:build !lite

package wal

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// On-disk mechanics for the durable tier. The store is a directory of
// append-never segment files plus one small state file:
//
//	000000000000000001.seg   one spill's worth of groups, one JSON line each
//	000000000000000002.seg
//	state.json               allocator positions and one cursor per server
//
// A spill writes a WHOLE new segment — it is never appended to — because a spill
// already is the old store's "one transaction": composing it in a temp file and
// publishing it with a rename makes it atomically all-or-nothing, so no reader
// can ever observe half a spill. Consuming moves a server's cursor forward in
// state.json, and a segment is deleted once no server still owes anything in it.
//
// Every line carries the group id and the owning server, so the files are
// self-describing: a scan can rebuild the live set from the cursors alone, which
// is what lets a restart tell "server A already acked this" from "server B has
// not reached it yet" for two groups sitting side by side.
//
// Durability: both segment and state files are fsynced before their rename, but
// the containing directory is never fsynced (there is no portable way to on
// Windows, where the agent also runs). A process crash therefore loses nothing
// that was written; a power cut can lose the most recent rename — the last spill
// or the last state update — and can never leave the store unreadable. That is
// the same trade the SQLite tier made with synchronous=NORMAL.
//
// Every read path is deliberately tolerant: a truncated or garbled line ends
// that segment's scan rather than failing the store. Losing the tail of a
// backlog is recoverable; refusing to open is not.

const (
	segSuffix   = ".seg"
	tmpPattern  = "wal-*.tmp"
	stateName   = "state.json"
	stateFormat = 2
)

// segLine is one group as stored: the group id, the server it belongs to, the
// arrival time that drives retention, and the Records themselves. One line is
// one indivisible group — the invariant the old row-level store needed an
// explicit group id to protect is structural here.
type segLine struct {
	At    time.Time `json:"at"`
	Gid   uint64    `json:"gid"`
	Owner string    `json:"owner"`
	R     Records   `json:"r"`
}

// diskGroup locates one live group without holding its payload: the segment it
// is in, the byte range of its line, plus the facts the store reasons about
// constantly (group id and owner for cursor arithmetic, arrival time for
// retention, row count for caps and Pending). Keeping offsets means serving a
// claim reads only the claimed lines rather than re-scanning a segment that may
// hold thousands of groups.
type diskGroup struct {
	gid   uint64
	owner string
	seg   uint64
	line  int // 0-based position within the segment
	off   int64
	size  int
	at    time.Time
	n     int
}

// cursorState is one server's persisted position. The claim fields are omitted
// when there is none in flight, so a store whose servers are all idle renders a
// state file barely longer than the allocator positions.
type cursorState struct {
	Acked     uint64 `json:"acked"`
	ClaimSeq  uint64 `json:"claim_seq,omitempty"`
	ClaimFrom uint64 `json:"claim_from,omitempty"`
	ClaimTo   uint64 `json:"claim_to,omitempty"`
	ClaimN    int    `json:"claim_n,omitempty"`
}

// walState is state.json. Small and rewritten whole; there is no partial update.
//
// NextGid rides along with every write for one reason: a cursor's Acked is a gid,
// so a restart that handed out gids below a persisted watermark would declare
// fresh groups already-delivered. Both are written together, so Acked < NextGid
// holds in every state file that was ever published, and Open only has to take
// the maximum of what it finds.
type walState struct {
	V       int                    `json:"v"`
	NextSeq uint64                 `json:"next_seq"`
	NextGid uint64                 `json:"next_gid"`
	Cursors map[string]cursorState `json:"cursors,omitempty"`
}

// segPath renders a segment's path. The counter is zero-padded so a lexical
// directory listing is already in numeric order.
func segPath(dir string, n uint64) string {
	return filepath.Join(dir, fmt.Sprintf("%018d%s", n, segSuffix))
}

// parseSegName returns the counter encoded in a segment file name.
func parseSegName(name string) (uint64, bool) {
	if !strings.HasSuffix(name, segSuffix) {
		return 0, false
	}
	n, err := strconv.ParseUint(strings.TrimSuffix(name, segSuffix), 10, 64)
	if err != nil {
		return 0, false
	}
	return n, true
}

// atomicWrite publishes data at path via a temp file in the SAME directory, so
// the rename is within one filesystem and therefore atomic. The temp file is
// fsynced before the rename: a rename that survives a power cut must not expose
// a file whose contents did not.
func atomicWrite(path string, data []byte) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, tmpPattern)
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() {
		if tmp != "" {
			f.Close()
			os.Remove(tmp)
		}
	}()

	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		// Windows refuses a rename onto a path another handle still has open.
		// Nothing here keeps one, so this is a genuine I/O failure.
		return err
	}
	tmp = "" // published; the deferred cleanup must not delete it
	return nil
}

// writeSegmentTemp composes a segment in a temp file and returns its path plus
// the index of what it contains. The caller renames it into place once the state
// naming it has been persisted, so the file becomes visible only after the
// bookkeeping that describes it — a crash in between loses the spill rather than
// resurrecting its groups as unclaimed ones the uploader would send twice.
//
// The returned index entries carry no segment number yet; the caller stamps it.
func writeSegmentTemp(dir string, groups []memGroup) (tmpPath string, index []diskGroup, err error) {
	f, err := os.CreateTemp(dir, tmpPattern)
	if err != nil {
		return "", nil, err
	}
	tmp := f.Name()
	defer func() {
		if err != nil {
			f.Close()
			os.Remove(tmp)
		}
	}()

	w := bufio.NewWriter(f)
	index = make([]diskGroup, 0, len(groups))
	var off int64
	for _, g := range groups {
		var line []byte
		line, err = json.Marshal(segLine{At: g.at, Gid: g.gid, Owner: g.owner, R: g.rec})
		if err != nil {
			return "", nil, err
		}
		line = append(line, '\n')
		if _, err = w.Write(line); err != nil {
			return "", nil, err
		}
		index = append(index, diskGroup{
			gid: g.gid, owner: g.owner, line: len(index), off: off, size: len(line), at: g.at, n: g.n,
		})
		off += int64(len(line))
	}
	if err = w.Flush(); err != nil {
		return "", nil, err
	}
	if err = f.Sync(); err != nil {
		return "", nil, err
	}
	if err = f.Close(); err != nil {
		return "", nil, err
	}
	return tmp, index, nil
}

// scanSegment indexes one segment file. A line that will not decode ends the
// scan: a torn tail is exactly what an interrupted write leaves behind, and
// everything before it is still perfectly good telemetry.
func scanSegment(path string, seg uint64) ([]diskGroup, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var (
		out []diskGroup
		off int64
	)
	r := bufio.NewReader(f)
	for {
		line, err := r.ReadBytes('\n')
		if len(line) > 0 {
			// A line without a trailing newline is a torn write, not a record.
			if line[len(line)-1] != '\n' {
				break
			}
			var sl segLine
			if json.Unmarshal(line[:len(line)-1], &sl) != nil {
				break
			}
			out = append(out, diskGroup{
				gid: sl.Gid, owner: sl.Owner, seg: seg, line: len(out),
				off: off, size: len(line), at: sl.At, n: rowsOf(sl.R),
			})
			off += int64(len(line))
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return out, err
		}
	}
	return out, nil
}

// readGroups loads the records for an ordered run of live groups. Segments are
// opened once each and the lines read by offset, so serving a 500-row packet out
// of a 20 000-group backlog costs 500 short reads rather than a full re-scan.
//
// A group whose bytes cannot be read or decoded is skipped with a log rather
// than failing the batch: the alternative is an outbox that refuses to drain
// because of one damaged record.
func readGroups(dir string, groups []diskGroup) ([]Records, error) {
	out := make([]Records, 0, len(groups))
	var (
		cur  *os.File
		curN uint64
	)
	defer func() {
		if cur != nil {
			cur.Close()
		}
	}()

	for _, g := range groups {
		if cur == nil || curN != g.seg {
			if cur != nil {
				cur.Close()
				cur = nil
			}
			f, err := os.Open(segPath(dir, g.seg))
			if err != nil {
				return nil, err
			}
			cur, curN = f, g.seg
		}
		buf := make([]byte, g.size)
		if _, err := cur.ReadAt(buf, g.off); err != nil {
			return nil, err
		}
		var sl segLine
		if err := json.Unmarshal(dropNewline(buf), &sl); err != nil {
			return nil, err
		}
		out = append(out, sl.R)
	}
	return out, nil
}

func dropNewline(b []byte) []byte {
	if len(b) > 0 && b[len(b)-1] == '\n' {
		return b[:len(b)-1]
	}
	return b
}

// writeState publishes the bookkeeping file.
func writeState(dir string, st walState) error {
	b, err := json.Marshal(st)
	if err != nil {
		return err
	}
	return atomicWrite(filepath.Join(dir, stateName), b)
}

// readState loads state.json. A missing file is a fresh store, not an error. An
// unreadable one is reported so the caller can decide (it starts over).
func readState(dir string) (walState, bool, error) {
	b, err := os.ReadFile(filepath.Join(dir, stateName))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return walState{}, false, nil
		}
		return walState{}, false, err
	}
	var st walState
	if err := json.Unmarshal(b, &st); err != nil {
		return walState{}, false, err
	}
	return st, true, nil
}

// listSegments returns the segment counters present in dir, ascending. Files
// that are not segments — a leftover database from an older build, anything a
// user dropped in — are ignored rather than tripping the store.
func listSegments(dir string) ([]uint64, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []uint64
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if n, ok := parseSegName(e.Name()); ok {
			out = append(out, n)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out, nil
}

// removeStaleTemps clears temp files an interrupted write left behind. They are
// never referenced by state.json, so they are pure garbage.
func removeStaleTemps(dir string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if !e.IsDir() && strings.HasPrefix(e.Name(), "wal-") && strings.HasSuffix(e.Name(), ".tmp") {
			os.Remove(filepath.Join(dir, e.Name()))
		}
	}
}
