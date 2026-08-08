//go:build lite

package wal

import (
	"math"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nettact/protocol/telemetry"
)

// The lite store's contract: the same FIFO/indivisible-group/re-serve rules as
// the default build, a bounded buffer that sheds its oldest whole groups, and a
// durable tier that is written ONLY for a disconnected server and only inside
// its window — so a healthy router never touches its flash and a rebooted one
// still has the outage it was buffering.

// srvA and srvB are configured server names, mirroring the default build's
// helpers so the two suites read the same.
const (
	srvA = "alpha"
	srvB = "beta"
)

// openLite is the memory-only store: persistence off, exactly what this build
// used to be unconditionally.
func openLite(t *testing.T) *Store {
	t.Helper()
	s, err := Open(tempWALDir(t)+"/wal", []string{srvA}, Options{})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// clock is a manually advanced test clock. The window and the spill interval are
// minutes long, so every timing test drives them from here rather than sleeping.
//
// It starts at the real wall clock rather than a fixed date because Open reads
// time.Now directly — it has to, since it runs before a test can install
// anything — and the retention cutoff it computes there would otherwise declare
// every group written under a fixed test date long expired.
type clock struct{ t time.Time }

func newClock() *clock { return &clock{t: time.Now().UTC()} }

func (c *clock) now() time.Time          { return c.t }
func (c *clock) add(d time.Duration)     { c.t = c.t.Add(d) }
func (c *clock) install(s *Store) *clock { s.now = c.now; return c }

// openPersist is the store as an OpenWrt router runs it, on a fixed clock.
func openPersist(t *testing.T, dir string, servers []string, ck *clock) *Store {
	t.Helper()
	s, err := Open(dir, servers, Options{Persist: true})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if ck != nil {
		ck.install(s)
	}
	return s
}

func metric(v float64) telemetry.Metric {
	return telemetry.Metric{TS: time.Now().UTC(), Kind: telemetry.ICMPRTTms, Target: "10.0.0.1", Value: v}
}

func one(v float64) Records {
	return Records{Metrics: []telemetry.Metric{metric(v)}}
}

// segmentCount reports how many segment files the store has published.
func segmentCount(t *testing.T, dir string) int {
	t.Helper()
	segs, err := listSegments(dir)
	if err != nil {
		t.Fatalf("listSegments: %v", err)
	}
	return len(segs)
}

// dirIsUntouched asserts nothing has been created at path at all — not a
// segment, not a state file, not even the directory.
func dirIsUntouched(t *testing.T, path, why string) {
	t.Helper()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("os.Stat(%s) = %v, want a not-exist error: %s", path, err, why)
	}
}

// With persistence off the store never touches disk, whatever the connection is
// doing. That is the setting for an owner who would rather lose an outage's
// telemetry than spend erase cycles on it.
func TestLitePersistDisabledNeverTouchesDisk(t *testing.T) {
	dir := tempWALDir(t)
	path := filepath.Join(dir, "wal")
	s, err := Open(path, []string{srvA}, Options{})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	ck := newClock().install(s)

	s.SetServerOnline(srvA, true)
	s.SetServerOnline(srvA, false)
	for i := 0; i < 50; i++ {
		if _, err := s.Append(one(float64(i)), srvA); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}
	ck.add(10 * time.Minute)
	if err := s.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	dirIsUntouched(t, path, "persistence is off, so nothing may reach the flash")
}

// A server whose session is up costs no write, ever. This is the promise the
// whole design rests on: on a router, spilling a backlog that is thirty seconds
// from being uploaded would spend erase cycles for nothing.
func TestLiteOnlineServerNeverSpills(t *testing.T) {
	dir := tempWALDir(t)
	path := filepath.Join(dir, "wal")
	s := openPersist(t, path, []string{srvA}, nil)
	ck := newClock().install(s)
	defer s.Close()

	s.SetServerOnline(srvA, true)
	for i := 0; i < 200; i++ {
		if _, err := s.Append(one(float64(i)), srvA); err != nil {
			t.Fatalf("Append: %v", err)
		}
		ck.add(time.Second)
		if err := s.Flush(); err != nil {
			t.Fatalf("Flush: %v", err)
		}
	}
	dirIsUntouched(t, path, "a connected server's backlog must never reach the flash")

	// Draining over the socket is likewise write-free: the claim covers memory
	// groups, which a crash would lose anyway, so persisting it would buy nothing.
	b, ok, err := s.NextBatch(srvA, 1000)
	if err != nil || !ok {
		t.Fatalf("NextBatch = (%v, %v)", ok, err)
	}
	if err := s.Ack(srvA, b.Sequence); err != nil {
		t.Fatalf("Ack: %v", err)
	}
	dirIsUntouched(t, path, "a memory-served packet must not persist anything")
}

// Losing the session is the trigger. The edge spill happens immediately rather
// than at the next periodic attempt, because that instant is when the buffer is
// known to hold the samples describing the failure.
func TestLiteDisconnectEdgeSpillsImmediately(t *testing.T) {
	dir := tempWALDir(t)
	path := filepath.Join(dir, "wal")
	s := openPersist(t, path, []string{srvA}, nil)
	newClock().install(s)
	defer s.Close()

	s.SetServerOnline(srvA, true)
	for i := 0; i < 5; i++ {
		if _, err := s.Append(one(float64(i)), srvA); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}
	dirIsUntouched(t, path, "still connected")

	s.SetServerOnline(srvA, false)
	if got := segmentCount(t, path); got != 1 {
		t.Fatalf("segments after the disconnect edge = %d, want 1", got)
	}
	if len(s.mem) != 0 {
		t.Fatalf("%d groups left buffered, want them all moved to the durable tier", len(s.mem))
	}
	if s.Pending(srvA) != 5 {
		t.Fatalf("Pending = %d, want the 5 spilled samples still owed", s.Pending(srvA))
	}
}

// While disconnected the store keeps writing, but no faster than
// persistInterval: a long outage costs a bounded number of erase cycles rather
// than one per reconnect attempt.
func TestLitePeriodicSpillIsRateLimited(t *testing.T) {
	dir := tempWALDir(t)
	path := filepath.Join(dir, "wal")
	s := openPersist(t, path, []string{srvA}, nil)
	ck := newClock().install(s)
	defer s.Close()

	s.SetServerOnline(srvA, true)
	s.SetServerOnline(srvA, false) // edge spill, but nothing buffered yet
	if got := segmentCount(t, path); got != 0 {
		t.Fatalf("segments = %d, want 0: an empty buffer must not write a segment", got)
	}

	// The session runner calls Flush on every reconnect attempt — a few tens of
	// seconds apart. Only one in every persistInterval may write.
	for i := 0; i < 20; i++ {
		if _, err := s.Append(one(float64(i)), srvA); err != nil {
			t.Fatalf("Append: %v", err)
		}
		ck.add(30 * time.Second)
		if err := s.Flush(); err != nil {
			t.Fatalf("Flush: %v", err)
		}
	}
	// 10 minutes of attempts at 30s each: the first spills immediately (nothing
	// has been written yet), the next only once 5 minutes have passed.
	if got := segmentCount(t, path); got != 2 {
		t.Fatalf("segments after 10 minutes of attempts = %d, want 2 (t=0:30 and t=5:30)", got)
	}
	// Another interval, another write — the rate limit delays, it does not stop.
	ck.add(persistInterval)
	if _, err := s.Append(one(99), srvA); err != nil {
		t.Fatalf("Append: %v", err)
	}
	if err := s.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if got := segmentCount(t, path); got != 3 {
		t.Fatalf("segments after a further interval = %d, want 3", got)
	}
	if s.Pending(srvA) != 21 {
		t.Fatalf("Pending = %d, want all 21 samples still owed", s.Pending(srvA))
	}
}

// The window is measured from the disconnect. Past it the store stops writing
// and degrades to the old memory-only behaviour rather than to unbounded wear;
// reconnecting resets it, so each outage gets its own window.
func TestLitePersistWindowStopsAndResets(t *testing.T) {
	dir := tempWALDir(t)
	path := filepath.Join(dir, "wal")
	s, err := Open(path, []string{srvA}, Options{Persist: true, PersistWindow: 30 * time.Minute})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	ck := newClock().install(s)
	defer s.Close()

	s.SetServerOnline(srvA, true)
	s.SetServerOnline(srvA, false)

	// Inside the window: writes.
	if _, err := s.Append(one(1), srvA); err != nil {
		t.Fatalf("Append: %v", err)
	}
	if err := s.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	inWindow := segmentCount(t, path)
	if inWindow == 0 {
		t.Fatal("nothing was written inside the window")
	}

	// Past it: the buffer keeps filling but the flash is left alone.
	ck.add(31 * time.Minute)
	for i := 0; i < 10; i++ {
		if _, err := s.Append(one(float64(i)), srvA); err != nil {
			t.Fatalf("Append: %v", err)
		}
		ck.add(6 * time.Minute)
		if err := s.Flush(); err != nil {
			t.Fatalf("Flush: %v", err)
		}
	}
	if got := segmentCount(t, path); got != inWindow {
		t.Fatalf("segments = %d, want it held at %d: the window has closed", got, inWindow)
	}
	if len(s.mem) != 10 {
		t.Fatalf("%d groups buffered, want the 10 that arrived past the window", len(s.mem))
	}

	// Reconnect, then drop again: a fresh outage gets a fresh window.
	s.SetServerOnline(srvA, true)
	ck.add(time.Minute)
	s.SetServerOnline(srvA, false)
	if got := segmentCount(t, path); got <= inWindow {
		t.Fatalf("segments = %d, want more than %d: the window resets on reconnect", got, inWindow)
	}
}

// Two servers are two independent outages. One being unreachable must never put
// the other's healthy telemetry on the flash.
func TestLitePerServerIndependence(t *testing.T) {
	dir := tempWALDir(t)
	path := filepath.Join(dir, "wal")
	s := openPersist(t, path, []string{srvA, srvB}, nil)
	newClock().install(s)
	defer s.Close()

	s.SetServerOnline(srvA, true)
	s.SetServerOnline(srvB, true)
	for i := 0; i < 4; i++ {
		if _, err := s.Append(one(float64(i)), srvA); err != nil {
			t.Fatalf("Append A: %v", err)
		}
		if _, err := s.Append(one(float64(i)), srvB); err != nil {
			t.Fatalf("Append B: %v", err)
		}
	}

	s.SetServerOnline(srvA, false)
	for _, g := range s.disk {
		if g.owner != srvA {
			t.Fatalf("durable tier holds a group owned by %q; only the disconnected server may be written", g.owner)
		}
	}
	if len(s.disk) != 4 {
		t.Fatalf("durable groups = %d, want alpha's 4", len(s.disk))
	}
	for _, g := range s.mem {
		if g.owner != srvB {
			t.Fatalf("buffer still holds a group owned by %q, want only beta's", g.owner)
		}
	}
	if s.Pending(srvA) != 4 || s.Pending(srvB) != 4 {
		t.Fatalf("Pending = (%d, %d), want (4, 4): moving tiers changes nothing that is owed",
			s.Pending(srvA), s.Pending(srvB))
	}
}

// The per-server flash budget is the backstop for a window that never closes.
// Past it the buffer keeps running and sheds as it always did.
func TestLitePersistRowCap(t *testing.T) {
	dir := tempWALDir(t)
	path := filepath.Join(dir, "wal")
	// A window long enough that only the row cap can stop this.
	s, err := Open(path, []string{srvA}, Options{Persist: true, PersistWindow: 24 * time.Hour})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	ck := newClock().install(s)
	defer s.Close()

	s.SetServerOnline(srvA, true)
	s.SetServerOnline(srvA, false)

	// Append well past the cap, spilling whenever the interval allows.
	for i := 0; i < persistMaxRows+2000; i++ {
		if _, err := s.Append(one(float64(i)), srvA); err != nil {
			t.Fatalf("Append: %v", err)
		}
		if i%500 == 0 {
			ck.add(persistInterval)
			if err := s.Flush(); err != nil {
				t.Fatalf("Flush: %v", err)
			}
		}
	}
	ck.add(persistInterval)
	if err := s.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	rows := 0
	for _, g := range s.disk {
		rows += g.n
	}
	if rows > persistMaxRows {
		t.Fatalf("durable rows = %d, want them held at or below the %d cap", rows, persistMaxRows)
	}
	if rows == 0 {
		t.Fatal("nothing was persisted at all")
	}
}

// A full buffer persists before it sheds. Without this a busy agent would evict
// an offline server's samples minutes before the next scheduled spill — losing
// exactly the data the durable tier was asked to keep, to save an erase cycle
// the window had already approved.
func TestLiteBufferPressureSpillsBeforeShedding(t *testing.T) {
	dir := tempWALDir(t)
	path := filepath.Join(dir, "wal")
	s := openPersist(t, path, []string{srvA}, nil)
	newClock().install(s) // frozen: the interval alone would forbid a second spill
	defer s.Close()

	s.SetServerOnline(srvA, true)
	s.SetServerOnline(srvA, false)

	dropped := 0
	for i := 0; i < memMaxRows+100; i++ {
		d, err := s.Append(one(float64(i)), srvA)
		if err != nil {
			t.Fatalf("Append: %v", err)
		}
		dropped += d
	}
	if dropped != 0 {
		t.Fatalf("dropped %d samples, want none: the buffer should have spilled instead of shedding", dropped)
	}
	if s.Pending(srvA) != memMaxRows+100 {
		t.Fatalf("Pending = %d, want all %d samples still owed", s.Pending(srvA), memMaxRows+100)
	}
	if len(s.disk) == 0 {
		t.Fatal("nothing reached the durable tier despite the buffer filling")
	}
}

// Shutdown persists what a disconnected server is still holding — the reboot
// this whole tier exists for. A connected server's buffer is dropped, which is
// the zero-write promise and not an accident.
func TestLiteCloseSpillsDisconnectedOnly(t *testing.T) {
	dir := tempWALDir(t)
	path := filepath.Join(dir, "wal")
	s := openPersist(t, path, []string{srvA, srvB}, nil)
	ck := newClock().install(s)

	s.SetServerOnline(srvA, true)
	s.SetServerOnline(srvB, true)
	s.SetServerOnline(srvA, false)
	// Well past the window: a shutdown writes once, so it is not bounded by the
	// limit that exists to bound recurring wear.
	ck.add(2 * time.Hour)
	for i := 0; i < 3; i++ {
		if _, err := s.Append(one(float64(i)), srvA); err != nil {
			t.Fatalf("Append A: %v", err)
		}
		if _, err := s.Append(one(float64(i)), srvB); err != nil {
			t.Fatalf("Append B: %v", err)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	again := openPersist(t, path, []string{srvA, srvB}, nil)
	defer again.Close()
	if got := again.Pending(srvA); got != 3 {
		t.Fatalf("alpha Pending after restart = %d, want its 3 samples persisted at shutdown", got)
	}
	if got := again.Pending(srvB); got != 0 {
		t.Fatalf("beta Pending after restart = %d, want 0: a connected server is never spilled", got)
	}
}

// The reboot scenario end to end: an outage is buffered and persisted, the power
// goes, and the router comes back and uploads it — under sequences the earlier
// boot had not used, so nothing is deduped away.
func TestLiteBacklogSurvivesRestartAndUploads(t *testing.T) {
	dir := tempWALDir(t)
	path := filepath.Join(dir, "wal")
	s := openPersist(t, path, []string{srvA}, nil)
	ck := newClock().install(s)

	s.SetServerOnline(srvA, true)
	s.SetServerOnline(srvA, false)
	for i := 0; i < 6; i++ {
		if _, err := s.Append(one(float64(i)), srvA); err != nil {
			t.Fatalf("Append: %v", err)
		}
		ck.add(persistInterval)
		if err := s.Flush(); err != nil {
			t.Fatalf("Flush: %v", err)
		}
	}
	// One packet goes out and is never acked: it must come back under the SAME
	// sequence, because the server may already hold it.
	inflight, ok, err := s.NextBatch(srvA, 2)
	if err != nil || !ok {
		t.Fatalf("NextBatch = (%v, %v)", ok, err)
	}
	beforeSeq := s.seqNext
	// No Close: this is a power cut, not a shutdown.

	again := openPersist(t, path, []string{srvA}, nil)
	defer again.Close()
	if again.seqNext < beforeSeq {
		t.Fatalf("seqNext after restart = %d, want at least the %d the last boot had reached",
			again.seqNext, beforeSeq)
	}
	if got := again.Pending(srvA); got != 6 {
		t.Fatalf("Pending after restart = %d, want all 6 persisted samples", got)
	}

	resumed, ok, err := again.NextBatch(srvA, 2)
	if err != nil || !ok {
		t.Fatalf("NextBatch after restart = (%v, %v)", ok, err)
	}
	if resumed.Sequence != inflight.Sequence {
		t.Fatalf("re-served sequence %d, want the original %d", resumed.Sequence, inflight.Sequence)
	}
	if len(resumed.Metrics) != len(inflight.Metrics) || resumed.Metrics[0].Value != inflight.Metrics[0].Value {
		t.Fatalf("re-served batch = %v, want the original %v", resumed.Metrics, inflight.Metrics)
	}

	// Drain the rest in order and confirm every sample arrives exactly once.
	seen := []float64{}
	for {
		b, ok, err := again.NextBatch(srvA, 2)
		if err != nil {
			t.Fatalf("NextBatch: %v", err)
		}
		if !ok {
			break
		}
		for _, m := range b.Metrics {
			seen = append(seen, m.Value)
		}
		if err := again.Ack(srvA, b.Sequence); err != nil {
			t.Fatalf("Ack: %v", err)
		}
	}
	if len(seen) != 6 {
		t.Fatalf("drained %d samples (%v), want 6", len(seen), seen)
	}
	for i, v := range seen {
		if v != float64(i) {
			t.Fatalf("drained out of order: %v", seen)
		}
	}
}

// Once the backlog is acked the segments go, so a router that has caught up
// occupies no flash again. Liveness rather than a consumed prefix is what makes
// that true even while a claim sits unacknowledged.
func TestLiteDrainedBacklogReturnsTheFlash(t *testing.T) {
	dir := tempWALDir(t)
	path := filepath.Join(dir, "wal")
	s := openPersist(t, path, []string{srvA}, nil)
	ck := newClock().install(s)
	defer s.Close()

	s.SetServerOnline(srvA, true)
	s.SetServerOnline(srvA, false)
	for i := 0; i < 4; i++ {
		if _, err := s.Append(one(float64(i)), srvA); err != nil {
			t.Fatalf("Append: %v", err)
		}
		ck.add(persistInterval)
		if err := s.Flush(); err != nil {
			t.Fatalf("Flush: %v", err)
		}
	}
	if segmentCount(t, path) < 2 {
		t.Fatalf("segments = %d, want several to have accumulated", segmentCount(t, path))
	}

	s.SetServerOnline(srvA, true)
	for {
		b, ok, err := s.NextBatch(srvA, 100)
		if err != nil {
			t.Fatalf("NextBatch: %v", err)
		}
		if !ok {
			break
		}
		if err := s.Ack(srvA, b.Sequence); err != nil {
			t.Fatalf("Ack: %v", err)
		}
	}
	if got := segmentCount(t, path); got != 0 {
		t.Fatalf("segments after the drain = %d, want 0", got)
	}
	if s.Pending(srvA) != 0 {
		t.Fatalf("Pending = %d, want 0", s.Pending(srvA))
	}
}

// Delivery is FIFO and each Records stays whole, which the server's fault
// detectors depend on.
func TestLiteFIFOAndWholeGroups(t *testing.T) {
	s := openLite(t)
	for i := 0; i < 3; i++ {
		if _, err := s.Append(Records{Metrics: []telemetry.Metric{metric(float64(i)), metric(float64(i) + 0.5)}}, srvA); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}
	// maxItems 3 cannot fit a second 2-row group, so exactly one group is claimed
	// — a group is never split to fill the packet.
	b, ok, err := s.NextBatch(srvA, 3)
	if err != nil || !ok {
		t.Fatalf("NextBatch = (%v, %v)", ok, err)
	}
	if len(b.Metrics) != 2 {
		t.Fatalf("claimed %d metrics, want the 2 of one whole group", len(b.Metrics))
	}
	if b.Metrics[0].Value != 0 {
		t.Fatalf("first metric = %v, want the oldest (0)", b.Metrics[0].Value)
	}
	if err := s.Ack(srvA, b.Sequence); err != nil {
		t.Fatalf("Ack: %v", err)
	}
	next, ok, err := s.NextBatch(srvA, 3)
	if err != nil || !ok {
		t.Fatalf("NextBatch after ack = (%v, %v)", ok, err)
	}
	if next.Metrics[0].Value != 1 {
		t.Fatalf("second batch starts at %v, want 1", next.Metrics[0].Value)
	}
	if next.Sequence == b.Sequence {
		t.Fatal("a new batch reused the acked sequence")
	}
}

// A single group larger than maxItems must still make progress rather than wedge
// the queue behind a packet that can never be assembled.
func TestLiteOversizedGroupStillProgresses(t *testing.T) {
	s := openLite(t)
	big := Records{}
	for i := 0; i < 10; i++ {
		big.Metrics = append(big.Metrics, metric(float64(i)))
	}
	if _, err := s.Append(big, srvA); err != nil {
		t.Fatalf("Append: %v", err)
	}
	b, ok, err := s.NextBatch(srvA, 3)
	if err != nil || !ok {
		t.Fatalf("NextBatch = (%v, %v)", ok, err)
	}
	if len(b.Metrics) != 10 {
		t.Fatalf("claimed %d metrics, want the whole 10-row group", len(b.Metrics))
	}
}

// An unacked packet is re-served under its ORIGINAL sequence, so a dropped
// session re-sends it and the server dedups rather than the agent losing it.
func TestLiteUnackedBatchIsReserved(t *testing.T) {
	s := openLite(t)
	if _, err := s.Append(one(1), srvA); err != nil {
		t.Fatalf("Append: %v", err)
	}
	first, _, err := s.NextBatch(srvA, 100)
	if err != nil {
		t.Fatalf("NextBatch: %v", err)
	}
	// New telemetry arriving mid-flight must not overtake the claimed packet.
	if _, err := s.Append(one(2), srvA); err != nil {
		t.Fatalf("Append: %v", err)
	}
	again, ok, err := s.NextBatch(srvA, 100)
	if err != nil || !ok {
		t.Fatalf("NextBatch = (%v, %v)", ok, err)
	}
	if again.Sequence != first.Sequence {
		t.Fatalf("re-served sequence %d, want the original %d", again.Sequence, first.Sequence)
	}
	if len(again.Metrics) != 1 || again.Metrics[0].Value != 1 {
		t.Fatalf("re-served batch = %v, want the original single metric", again.Metrics)
	}
	// A stale ack for a sequence that is not in flight is ignored, not an error.
	if err := s.Ack(srvA, first.Sequence+999); err != nil {
		t.Fatalf("stale Ack: %v", err)
	}
	if s.Pending(srvA) != 2 {
		t.Fatalf("Pending = %d, want 2 (in-flight + buffered)", s.Pending(srvA))
	}
}

// Over capacity, whole oldest groups are shed and the count is reported, so the
// caller can surface a real data gap instead of it passing unnoticed.
func TestLiteEvictsOldestWholeGroups(t *testing.T) {
	s := openLite(t)
	totalDropped := 0
	// Two rows per group; enough groups to run well past the cap.
	for i := 0; i < memMaxRows; i++ {
		d, err := s.Append(Records{Metrics: []telemetry.Metric{metric(float64(i)), metric(float64(i))}}, srvA)
		if err != nil {
			t.Fatalf("Append: %v", err)
		}
		totalDropped += d
	}
	if totalDropped == 0 {
		t.Fatal("nothing was dropped despite appending far past the cap")
	}
	if got := s.Pending(srvA); got > memMaxRows {
		t.Fatalf("Pending = %d, want it held at or below the %d-row cap", got, memMaxRows)
	}
	// Eviction is whole-group, so the buffer never holds half a Records: an odd
	// pending count would mean one was split.
	if s.Pending(srvA)%2 != 0 {
		t.Fatalf("Pending = %d is odd, so a 2-row group was split", s.Pending(srvA))
	}
	// The survivors are the NEWEST ones.
	b, ok, err := s.NextBatch(srvA, 2)
	if err != nil || !ok {
		t.Fatalf("NextBatch = (%v, %v)", ok, err)
	}
	if b.Metrics[0].Value == 0 {
		t.Fatal("the oldest group survived eviction; it should have been the first shed")
	}
}

func TestLiteFastForwardOnlyRaises(t *testing.T) {
	s := openLite(t)
	start := s.seqNext

	// Below the current position: ignored, so an ordinary ack cannot renumber
	// sequences backwards.
	if err := s.FastForward(start - 10); err != nil {
		t.Fatalf("FastForward: %v", err)
	}
	if s.seqNext != start {
		t.Fatalf("seqNext = %d, want it left at %d", s.seqNext, start)
	}

	// Above it: raised past the server's watermark, which is the recovery path
	// for a boot whose clock was not yet set.
	if err := s.FastForward(start + 100); err != nil {
		t.Fatalf("FastForward: %v", err)
	}
	if s.seqNext != start+101 {
		t.Fatalf("seqNext = %d, want %d", s.seqNext, start+101)
	}

	// The uint64 max has no representable successor; erroring beats wrapping the
	// allocator back to zero.
	if err := s.FastForward(math.MaxUint64); err == nil {
		t.Fatal("expected an error for a watermark at the uint64 max")
	}
}

// FastForward runs on every ack, so it must not write — the persisted position
// catches up at the next spill instead.
func TestLiteFastForwardCostsNoWrite(t *testing.T) {
	dir := tempWALDir(t)
	path := filepath.Join(dir, "wal")
	s := openPersist(t, path, []string{srvA}, nil)
	newClock().install(s)
	defer s.Close()

	s.SetServerOnline(srvA, true)
	for i := 0; i < 100; i++ {
		if err := s.FastForward(s.seqNext + 10); err != nil {
			t.Fatalf("FastForward: %v", err)
		}
	}
	dirIsUntouched(t, path, "FastForward runs on every ack and must never write")
}

// The persisted allocator position is what keeps a router whose clock resets to
// 1970 from re-issuing sequences the server already stored.
func TestLitePersistedSequenceSurvivesADeadClock(t *testing.T) {
	dir := tempWALDir(t)
	path := filepath.Join(dir, "wal")
	s := openPersist(t, path, []string{srvA}, nil)
	newClock().install(s)

	s.SetServerOnline(srvA, true)
	s.SetServerOnline(srvA, false)
	if _, err := s.Append(one(1), srvA); err != nil {
		t.Fatalf("Append: %v", err)
	}
	if err := s.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	// Consume a stretch of the sequence space, then persist the position by
	// serving the durable backlog (which persists its claim).
	if err := s.FastForward(9_000_000); err != nil {
		t.Fatalf("FastForward: %v", err)
	}
	if _, _, err := s.NextBatch(srvA, 100); err != nil {
		t.Fatalf("NextBatch: %v", err)
	}
	want := s.seqNext

	again, err := Open(path, []string{srvA}, Options{Persist: true})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer again.Close()
	// Simulate the dead clock: the seed a 1970 boot would have produced is 1, so
	// only the persisted position can be holding the allocator up here.
	if again.seqNext < want {
		t.Fatalf("seqNext after restart = %d, want at least the persisted %d", again.seqNext, want)
	}
	if got := initialSeq(time.Unix(0, 0)); got >= want {
		t.Fatalf("the test is not exercising the persisted position: a dead-clock seed is %d", got)
	}
}

// The seed only ever moves forward with the clock, so a reboot does not re-issue
// sequences an earlier boot already sent. A clock that is unset must not wrap the
// allocator to the top of the range.
func TestLiteInitialSeq(t *testing.T) {
	early := initialSeq(time.Unix(1700000000, 0))
	later := initialSeq(time.Unix(1700000001, 0))
	if later <= early {
		t.Fatalf("initialSeq did not advance with the clock: %d then %d", early, later)
	}
	for _, tc := range []time.Time{time.Unix(0, 0), time.Unix(-100, 0), {}} {
		if got := initialSeq(tc); got != 1 {
			t.Fatalf("initialSeq(%v) = %d, want 1 rather than a wrapped uint64", tc, got)
		}
	}
}

func TestLiteFlushAndPendingAreCheap(t *testing.T) {
	s := openLite(t)
	if s.Pending(srvA) != 0 {
		t.Fatalf("Pending on a fresh store = %d, want 0", s.Pending(srvA))
	}
	if err := s.Flush(); err != nil {
		t.Fatalf("Flush on an empty store: %v", err)
	}
	if _, err := s.Append(Records{Metrics: []telemetry.Metric{metric(1), metric(2)}}, srvA); err != nil {
		t.Fatalf("Append: %v", err)
	}
	// Flush cannot make anything durable with persistence off, but it must not
	// drop the buffer either — the samples are still queued for the next upload.
	if err := s.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if s.Pending(srvA) != 2 {
		t.Fatalf("Pending after Flush = %d, want the 2 still-queued samples", s.Pending(srvA))
	}
}

// A backlog nothing can usefully deliver any more is dropped rather than
// uploaded: server-core prunes its dedup rows on the assumption that an agent
// never replays anything older, so a packet past the window would be re-ingested
// as if new.
func TestLiteRetentionDropsAncientBacklog(t *testing.T) {
	dir := tempWALDir(t)
	path := filepath.Join(dir, "wal")
	s := openPersist(t, path, []string{srvA}, nil)
	ck := newClock().install(s)
	defer s.Close()

	s.SetServerOnline(srvA, true)
	s.SetServerOnline(srvA, false)
	if _, err := s.Append(one(1), srvA); err != nil {
		t.Fatalf("Append: %v", err)
	}
	if err := s.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if len(s.disk) != 1 {
		t.Fatalf("durable groups = %d, want 1", len(s.disk))
	}

	ck.add(persistRetention + time.Hour)
	if _, ok, err := s.NextBatch(srvA, 100); err != nil || ok {
		t.Fatalf("NextBatch = (%v, %v), want nothing left to send", ok, err)
	}
	if got := segmentCount(t, path); got != 0 {
		t.Fatalf("segments = %d, want the expired one collected", got)
	}
}
