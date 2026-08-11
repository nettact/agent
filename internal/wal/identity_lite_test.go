//go:build lite

package wal

import (
	"path/filepath"
	"testing"
)

// The identity contract on a router: exactly the default build's — a server's
// queue belongs to the enrollment that collected it, and a re-enrollment
// discards it rather than uploading it under the new agent_id the server just
// minted. What is specific here is the flash: the discard has to give the erase
// cycles back, and binding an identity must not spend one.

const (
	idOld = "agent-old"
	idNew = "agent-new"
	idB   = "agent-beta"
)

// A re-enrollment discards that server's spilled backlog and its in-flight
// claim, leaves a second server's share of the same segment alone, and the flash
// is returned as soon as that second server is caught up. Tagging the stale
// groups and merely skipping them would leave the segment pinned by a group
// nothing would ever drain — on the device where that matters most.
func TestLiteReenrollmentDiscardsTheOldIdentitysQueue(t *testing.T) {
	path := filepath.Join(tempWALDir(t), "wal")
	s := openPersist(t, path, []string{srvA, srvB}, nil)
	newClock().install(s)
	t.Cleanup(func() { _ = s.Close() })

	if _, err := s.BindIdentity(srvA, idOld); err != nil {
		t.Fatalf("BindIdentity(%s): %v", srvA, err)
	}
	if _, err := s.BindIdentity(srvB, idB); err != nil {
		t.Fatalf("BindIdentity(%s): %v", srvB, err)
	}
	// Every server starts disconnected, so this first Flush writes both.
	for i := 1; i <= 2; i++ {
		if _, err := s.Append(one(float64(i)), srvA); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}
	if _, err := s.Append(one(99), srvB); err != nil {
		t.Fatalf("Append: %v", err)
	}
	if err := s.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if got := segmentCount(t, path); got != 1 {
		t.Fatalf("segments = %d, want the one holding both servers' groups", got)
	}

	// A packet is in flight under the old credential when the revocation lands.
	inflight, ok, err := s.NextBatch(srvA, 100)
	if err != nil || !ok {
		t.Fatalf("NextBatch(%s) = (%v, %v)", srvA, ok, err)
	}

	dropped, err := s.BindIdentity(srvA, idNew)
	if err != nil {
		t.Fatalf("BindIdentity(%s, %s): %v", srvA, idNew, err)
	}
	if dropped != 2 {
		t.Fatalf("discarded %d rows, want the old identity's 2", dropped)
	}
	if _, ok, err := s.NextBatch(srvA, 100); err != nil || ok {
		t.Fatalf("the old identity's records were served to the new one: ok=%v err=%v", ok, err)
	}
	if p := s.Pending(srvA); p != 0 {
		t.Fatalf("%s still owes %d rows collected under a dead identity", srvA, p)
	}

	// The cursor advanced rather than the records merely being hidden, and the
	// discarded claim's sequence is burned rather than re-used.
	if _, err := s.Append(one(7), srvA); err != nil {
		t.Fatalf("Append: %v", err)
	}
	fresh, ok, err := s.NextBatch(srvA, 100)
	if err != nil || !ok {
		t.Fatalf("NextBatch(%s) after re-enrollment = (%v, %v)", srvA, ok, err)
	}
	if len(fresh.Metrics) != 1 || fresh.Metrics[0].Value != 7 {
		t.Fatalf("served %+v, want only what the new identity collected", fresh.Metrics)
	}
	if fresh.Sequence == inflight.Sequence {
		t.Fatalf("the discarded claim's sequence %d was handed out again", inflight.Sequence)
	}
	if err := s.Ack(srvA, fresh.Sequence); err != nil {
		t.Fatalf("Ack: %v", err)
	}

	// The other server is untouched, and its record still pins the shared segment.
	if got := segmentCount(t, path); got != 1 {
		t.Fatalf("segments = %d while %s still owed its record", got, srvB)
	}
	b, ok, err := s.NextBatch(srvB, 100)
	if err != nil || !ok {
		t.Fatalf("NextBatch(%s) = (%v, %v)", srvB, ok, err)
	}
	if len(b.Metrics) != 1 || b.Metrics[0].Value != 99 {
		t.Fatalf("%s served %+v; another server's re-enrollment must not disturb it", srvB, b.Metrics)
	}
	if err := s.Ack(srvB, b.Sequence); err != nil {
		t.Fatalf("Ack: %v", err)
	}
	if got := segmentCount(t, path); got != 0 {
		t.Fatalf("segments = %d after the discard and the last ack; the flash was never returned", got)
	}
}

// The identity is written beside the backlog, so a router that re-enrolled and
// was power-cycled before it could reconnect still discards on the way back up —
// which on this build is the likely order of events, since the reboot is what the
// owner does about the outage. The discard alone returns the flash here.
func TestLiteReenrollmentIsDetectedAfterAReboot(t *testing.T) {
	path := filepath.Join(tempWALDir(t), "wal")
	s := openPersist(t, path, []string{srvA}, nil)
	newClock().install(s)

	if _, err := s.BindIdentity(srvA, idOld); err != nil {
		t.Fatalf("BindIdentity: %v", err)
	}
	for i := 1; i <= 2; i++ {
		if _, err := s.Append(one(float64(i)), srvA); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}
	if err := s.Close(); err != nil { // spills, and records the identity beside it
		t.Fatalf("Close: %v", err)
	}
	if got := segmentCount(t, path); got != 1 {
		t.Fatalf("segments = %d, want the backlog the shutdown persisted", got)
	}

	again := openPersist(t, path, []string{srvA}, nil)
	newClock().install(again)
	t.Cleanup(func() { _ = again.Close() })

	dropped, err := again.BindIdentity(srvA, idNew)
	if err != nil {
		t.Fatalf("BindIdentity after reboot: %v", err)
	}
	if dropped != 2 {
		t.Fatalf("discarded %d rows after rebooting as a new agent, want 2", dropped)
	}
	if p := again.Pending(srvA); p != 0 {
		t.Fatalf("%s still owes %d rows collected under the previous enrollment", srvA, p)
	}
	if _, ok, err := again.NextBatch(srvA, 100); err != nil || ok {
		t.Fatalf("a rebooted agent served its predecessor's records: ok=%v err=%v", ok, err)
	}
	if got := segmentCount(t, path); got != 0 {
		t.Fatalf("segments = %d after the discard; nothing is owed anything in them", got)
	}
}

// Binding an identity costs no erase cycle on a store that has never spilled —
// including the bind that discards, when everything it discards was in memory.
// The zero-write-while-healthy promise has no exception for this.
func TestLiteIdentityBindTouchesNoFlashWithNothingSpilled(t *testing.T) {
	path := filepath.Join(tempWALDir(t), "wal")
	s, err := Open(path, []string{srvA}, Options{Persist: true})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	newClock().install(s)
	s.SetServerOnline(srvA, true) // connected: nothing may reach the flash

	if _, err := s.BindIdentity(srvA, idOld); err != nil {
		t.Fatalf("BindIdentity: %v", err)
	}
	for i := 1; i <= 3; i++ {
		if _, err := s.Append(one(float64(i)), srvA); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}
	dropped, err := s.BindIdentity(srvA, idNew)
	if err != nil {
		t.Fatalf("BindIdentity: %v", err)
	}
	if dropped != 3 {
		t.Fatalf("discarded %d rows, want the buffered 3", dropped)
	}
	if p := s.Pending(srvA); p != 0 {
		t.Fatalf("Pending = %d after the discard", p)
	}
	if _, ok, err := s.NextBatch(srvA, 100); err != nil || ok {
		t.Fatalf("the old identity's buffered records were served: ok=%v err=%v", ok, err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	dirIsUntouched(t, path, "a connected server's identity change must not spend an erase cycle")
}
