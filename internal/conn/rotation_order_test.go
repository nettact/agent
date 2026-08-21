package conn

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/nettact/agent/internal/wal"
	"github.com/nettact/protocol/telemetry"
	"github.com/nettact/protocol/wire"
)

// A credential rotation moves three things — the credential on disk, the
// outbox's epoch, and the identity this process is using — and this file pins
// the ORDER, one power cut per boundary.
//
// The order is the only part of a rotation a crash can get wrong in a way the
// agent cannot recover from. The tests below inject a failure (or a restart) at
// each boundary and assert the one property that has to survive it: the durable
// state is always a credential the agent can still authenticate with, and the
// outbox's epoch never leads the credential that names it.

// credStore is the durable half of a rotation, as a test double: the file the
// PersistRotation hook writes and a restart would read back.
type credStore struct {
	mu     sync.Mutex
	token  string
	epoch  uint64
	writes int
	// failUntil makes the first n writes fail, standing in for a disk that is
	// full, locked or simply gone at the instant the rotation lands. A write
	// that fails leaves the stored credential untouched — which is exactly what
	// a crash before the write does.
	failUntil int
}

func (c *credStore) persist(epoch uint64, token string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writes++
	if c.writes <= c.failUntil {
		return errors.New("credential store unavailable")
	}
	c.token, c.epoch = token, epoch
	return nil
}

func (c *credStore) read() (uint64, string, int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.epoch, c.token, c.writes
}

// walEpoch reports whether the outbox cursor is still on the given epoch,
// without moving it: the store refuses a floor whose epoch does not match the
// cursor's, and refuses it before touching anything.
func walEpochIs(outbox *wal.Store, epoch uint64) bool {
	_, err := outbox.ApplyFloor(testServer, epoch, 0)
	return err == nil
}

// startBearerServer is startTokenServer plus a record of which bearer token
// each accepted connection presented — the only way to see whether a session
// that failed to persist a rotation came back on the old credential or on one
// that exists nowhere but in memory.
func startBearerServer(t *testing.T, tokens []string, seen *[]string, mu *sync.Mutex,
	script func(ctx context.Context, c *websocket.Conn)) *httptest.Server {
	t.Helper()
	valid := make(map[string]bool, len(tokens))
	for _, tk := range tokens {
		valid["Bearer "+tk] = true
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if !valid[auth] {
			t.Errorf("upgrade Authorization = %q, want one of the known bearer tokens", auth)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		mu.Lock()
		*seen = append(*seen, strings.TrimPrefix(auth, "Bearer "))
		mu.Unlock()
		c, err := websocket.Accept(w, r, &websocket.AcceptOptions{
			Subprotocols: []string{wire.SubprotocolProtobuf, wire.SubprotocolJSON},
		})
		if err != nil {
			t.Logf("accept: %v", err)
			return
		}
		defer c.CloseNow() //nolint:errcheck
		script(r.Context(), c)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// driveRotation runs the server side of one rotation on an open connection:
// floor, applied reply, challenge, request, result. It returns after the result
// is written.
func driveRotation(t *testing.T, ctx context.Context, c *websocket.Conn, epoch uint64, res wire.EpochRotationResult) bool {
	t.Helper()
	if err := srvWrite(ctx, c, wire.Frame{SequenceFloor: &wire.SequenceFloor{EnrollmentEpoch: epoch, SequenceFloor: 0}}); err != nil {
		t.Errorf("write floor: %v", err)
		return false
	}
	if f, err := srvRead(ctx, c); err != nil || f.SequenceFloorApplied == nil {
		t.Errorf("applied reply: %+v err=%v", f, err)
		return false
	}
	if err := srvWrite(ctx, c, wire.Frame{EpochRotationChallenge: &wire.EpochRotationChallenge{
		Challenge: "chal", Reason: "sequence_conflict", ExpiresAt: time.Now().Add(time.Minute),
	}}); err != nil {
		t.Errorf("write challenge: %v", err)
		return false
	}
	if f, err := srvRead(ctx, c); err != nil || f.EpochRotationRequest == nil {
		t.Errorf("rotation request: %+v err=%v", f, err)
		return false
	}
	if err := srvWrite(ctx, c, wire.Frame{EpochRotationResult: &res}); err != nil {
		t.Errorf("write rotation result: %v", err)
		return false
	}
	return true
}

// TestRotationLostBeforeCredentialWriteKeepsOldIdentity is the first power cut:
// the server's verdict has arrived and the credential write does not land.
//
// Nothing about the rotation may take effect. The stored credential is still
// the old one, the outbox is still on the old epoch, and — the property that
// makes it recoverable — the process reconnects on the OLD bearer token, which
// the server is still honouring because the new one has never been used. The
// server then re-issues the same verdict idempotently and the retry converges.
func TestRotationLostBeforeCredentialWriteKeepsOldIdentity(t *testing.T) {
	deps, outbox, _, _ := newTestDeps(t)
	store := &credStore{token: "test-token", epoch: 5, failUntil: 1}
	deps.SignChallenge = func(challenge []byte) []byte { return append([]byte("sig:"), challenge...) }
	deps.PersistRotation = store.persist

	if _, err := outbox.SetEpoch(testServer, 5); err != nil {
		t.Fatalf("SetEpoch: %v", err)
	}

	var mu sync.Mutex
	var bearers []string
	var conns int32
	result := wire.EpochRotationResult{Status: wire.RotationOK, NewEpoch: 7, AgentToken: "rotated-token"}
	srv := startBearerServer(t, []string{"test-token", "rotated-token"}, &bearers, &mu,
		func(ctx context.Context, c *websocket.Conn) {
			n := atomic.AddInt32(&conns, 1)
			hello, err := srvRead(ctx, c)
			if err != nil || hello.Hello == nil {
				t.Errorf("hello: %+v err=%v", hello, err)
				return
			}
			switch {
			case n <= 2:
				// Sessions 1 and 2 both drive the rotation: the first write fails,
				// so the server sees the old epoch again and re-issues the same
				// verdict for the same old credential.
				if hello.Hello.EnrollmentEpoch != 5 {
					t.Errorf("session %d Hello epoch = %d, want 5 (the rotation never landed)", n, hello.Hello.EnrollmentEpoch)
					return
				}
				if !driveRotation(t, ctx, c, 5, result) {
					return
				}
			default:
				if hello.Hello.EnrollmentEpoch != 7 {
					t.Errorf("session %d Hello epoch = %d, want 7 (the retry landed)", n, hello.Hello.EnrollmentEpoch)
				}
			}
			_, _ = srvRead(ctx, c) // hold until the agent ends the session
		})

	runAgent(t, epochOptions(srv.URL, wire.SubprotocolJSON, 5), deps)

	// The failed write must leave nothing moved. Sampled while the agent is
	// between the two rotation attempts, which is where a crash would land.
	waitFor(t, "the first credential write to be attempted", func() bool {
		_, _, writes := store.read()
		return writes >= 1
	})
	if epoch, token, _ := store.read(); epoch != 5 || token != "test-token" {
		t.Fatalf("stored credential after a failed write = (%d, %q); want the old (5, test-token) untouched", epoch, token)
	}
	if !walEpochIs(outbox, 5) {
		t.Fatal("the outbox epoch moved even though the credential write failed — the outbox must never lead the credential that names it")
	}

	// The retry converges: the same verdict, written this time, and the next
	// session presents the rotated identity.
	waitFor(t, "the rotated credential to be stored", func() bool {
		epoch, token, _ := store.read()
		return epoch == 7 && token == "rotated-token"
	})
	waitFor(t, "a session under the rotated identity", func() bool { return atomic.LoadInt32(&conns) >= 3 })

	// Every session before the successful write used the old bearer. A session
	// on a token that exists nowhere durable is the unrecoverable state this
	// ordering exists to prevent.
	mu.Lock()
	defer mu.Unlock()
	if len(bearers) < 3 {
		t.Fatalf("bearers seen = %v, want at least three sessions", bearers)
	}
	for i := 0; i < 2; i++ {
		if bearers[i] != "test-token" {
			t.Fatalf("session %d presented %q; want the old bearer, which is the only credential written down at that point", i+1, bearers[i])
		}
	}
	if bearers[2] != "rotated-token" {
		t.Fatalf("the session after the successful write presented %q, want rotated-token", bearers[2])
	}
}

// TestRotationPersistFailurePersistsNothing is the same boundary held open: the
// credential store never recovers.
//
// Every session must reconnect on the old credential, the outbox must stay on
// the old epoch, and the agent must not answer a rotation more than once per
// session — a rotation it cannot persist is a rotation that did not happen, not
// a reason to hammer the server.
func TestRotationPersistFailurePersistsNothing(t *testing.T) {
	deps, outbox, _, _ := newTestDeps(t)
	store := &credStore{token: "test-token", epoch: 5, failUntil: 1 << 30}
	deps.SignChallenge = func(challenge []byte) []byte { return []byte("sig") }
	deps.PersistRotation = store.persist

	if _, err := outbox.SetEpoch(testServer, 5); err != nil {
		t.Fatalf("SetEpoch: %v", err)
	}

	var mu sync.Mutex
	var bearers []string
	var requests, conns int32
	// Only "test-token" is accepted: a session on the never-written rotated
	// token fails the upgrade and the harness reports it.
	srv := startBearerServer(t, []string{"test-token"}, &bearers, &mu,
		func(ctx context.Context, c *websocket.Conn) {
			if atomic.LoadInt32(&conns) >= 4 {
				return // the test has what it needs; later connections are teardown noise
			}
			atomic.AddInt32(&conns, 1)
			hello, err := srvRead(ctx, c)
			if err != nil || hello.Hello == nil {
				t.Errorf("hello: %+v err=%v", hello, err)
				return
			}
			if hello.Hello.EnrollmentEpoch != 5 {
				t.Errorf("Hello epoch = %d, want 5 — an unpersistable rotation must not move the identity", hello.Hello.EnrollmentEpoch)
				return
			}
			if err := srvWrite(ctx, c, wire.Frame{SequenceFloor: &wire.SequenceFloor{EnrollmentEpoch: 5, SequenceFloor: 0}}); err != nil {
				return
			}
			if f, err := srvRead(ctx, c); err != nil || f.SequenceFloorApplied == nil {
				t.Errorf("applied reply: %+v err=%v", f, err)
				return
			}
			if err := srvWrite(ctx, c, wire.Frame{EpochRotationChallenge: &wire.EpochRotationChallenge{
				Challenge: "chal", Reason: "sequence_conflict", ExpiresAt: time.Now().Add(time.Minute),
			}}); err != nil {
				return
			}
			f, err := srvRead(ctx, c)
			if err != nil || f.EpochRotationRequest == nil {
				t.Errorf("rotation request: %+v err=%v", f, err)
				return
			}
			atomic.AddInt32(&requests, 1)
			if err := srvWrite(ctx, c, wire.Frame{EpochRotationResult: &wire.EpochRotationResult{
				Status: wire.RotationOK, NewEpoch: 9, AgentToken: "never-written",
			}}); err != nil {
				return
			}
			// The agent must end the session here rather than send a second
			// request; a further frame on this connection is the storm.
			if extra, err := srvRead(ctx, c); err == nil && extra.EpochRotationRequest != nil {
				t.Errorf("the agent re-requested a rotation inside one session: %+v", extra.EpochRotationRequest)
			}
		})

	runAgent(t, epochOptions(srv.URL, wire.SubprotocolJSON, 5), deps)

	waitFor(t, "three rotation attempts across three sessions", func() bool { return atomic.LoadInt32(&requests) >= 3 })
	if epoch, token, _ := store.read(); epoch != 5 || token != "test-token" {
		t.Fatalf("stored credential = (%d, %q); want the old (5, test-token) — nothing may be written when the write itself is what fails", epoch, token)
	}
	if !walEpochIs(outbox, 5) {
		t.Fatal("the outbox epoch moved for a rotation that was never written down")
	}
	mu.Lock()
	defer mu.Unlock()
	for i, b := range bearers {
		if b != "test-token" {
			t.Fatalf("session %d presented %q; every session must fall back to the credential that is actually on disk", i+1, b)
		}
	}
}

// TestOutboxFollowsCredentialOnStart is the second power cut: the credential
// write landed and the outbox's epoch move did not.
//
// The durable state is then a credential ahead of the outbox, and the session
// start reconciles the outbox up to it — the one direction that converges,
// because the credential is the truth the server also holds. The reconcile must
// not resurrect anything already acknowledged.
func TestOutboxFollowsCredentialOnStart(t *testing.T) {
	deps, outbox, _, _ := newTestDeps(t)
	// The crashed state: the outbox still on 5, the credential already on 7.
	if _, err := outbox.SetEpoch(testServer, 5); err != nil {
		t.Fatalf("SetEpoch: %v", err)
	}
	if _, err := outbox.Append(wal.Records{Metrics: []telemetry.Metric{{
		TS: time.Now().UTC(), Kind: telemetry.AgentUptime, Target: "agent", Value: 1,
	}}}, testServer); err != nil {
		t.Fatalf("wal append: %v", err)
	}

	pktCh := make(chan telemetry.Packet, 1)
	srv := startServer(t, func(ctx context.Context, c *websocket.Conn) {
		hello, err := srvRead(ctx, c)
		if err != nil || hello.Hello == nil {
			t.Errorf("hello: %+v err=%v", hello, err)
			return
		}
		if hello.Hello.EnrollmentEpoch != 7 {
			t.Errorf("Hello epoch = %d, want 7 — the credential is what the session runs under", hello.Hello.EnrollmentEpoch)
			return
		}
		// A floor for the credential's epoch is only accepted if the outbox has
		// been reconciled to it; an unreconciled cursor answers with a mismatch
		// error and the session dies before any packet.
		if err := srvWrite(ctx, c, wire.Frame{SequenceFloor: &wire.SequenceFloor{EnrollmentEpoch: 7, SequenceFloor: 0}}); err != nil {
			t.Errorf("write floor: %v", err)
			return
		}
		if f, err := srvRead(ctx, c); err != nil || f.SequenceFloorApplied == nil {
			t.Errorf("applied reply for the credential's epoch: %+v err=%v (an unreconciled outbox rejects this floor)", f, err)
			return
		}
		pkt, err := srvRead(ctx, c)
		if err != nil || pkt.Packet == nil {
			t.Errorf("packet: %+v err=%v", pkt, err)
			return
		}
		if err := srvWrite(ctx, c, wire.Frame{Ack: &wire.Ack{
			HighestSequence: pkt.Packet.Sequence, ServerTime: time.Now().UTC(),
		}}); err != nil {
			t.Errorf("write ack: %v", err)
			return
		}
		pktCh <- *pkt.Packet
		_, _ = srvRead(ctx, c)
	})

	runAgent(t, epochOptions(srv.URL, wire.SubprotocolJSON, 7), deps)

	select {
	case pkt := <-pktCh:
		if len(pkt.Metrics) != 1 {
			t.Fatalf("packet = %+v; want the one queued record, re-served under the credential's epoch", pkt.Metrics)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the backlog never went out — the outbox was not reconciled to the credential's epoch")
	}
	waitFor(t, "WAL cleared after the ack", func() bool { return outbox.Pending(testServer) == 0 })
	// The ack stands: a reconcile re-queues what was never acknowledged, and
	// must not resurrect what was.
	if outbox.Pending(testServer) != 0 {
		t.Fatal("the reconcile resurrected acknowledged records")
	}
}
