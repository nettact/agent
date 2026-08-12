package conn

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/nettact/agent/internal/wal"
	"github.com/nettact/protocol/telemetry"
	"github.com/nettact/protocol/wire"
)

// startTokenServer is startServer with a caller-chosen set of bearer tokens:
// the rotation tests need the agent to reconnect under the rotated token,
// which the shared harness (fixed "test-token") would reject.
func startTokenServer(t *testing.T, tokens []string, script func(ctx context.Context, c *websocket.Conn)) *httptest.Server {
	t.Helper()
	valid := make(map[string]bool, len(tokens))
	for _, tk := range tokens {
		valid["Bearer "+tk] = true
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !valid[r.Header.Get("Authorization")] {
			t.Errorf("upgrade Authorization = %q, want one of the known bearer tokens", r.Header.Get("Authorization"))
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
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

// epochOptions is testOptions plus a schema-8 enrollment epoch, which is what
// switches the floor barrier on for a session.
func epochOptions(serverURL, format string, epoch uint64) Options {
	opts := testOptions(serverURL, format)
	opts.EnrollmentEpoch = epoch
	opts.Hello.EnrollmentEpoch = epoch
	return opts
}

// TestFloorBarrierGatesFirstPacket: a session under a schema-8 epoch sends
// nothing until the server pushes a SequenceFloor and the agent has applied
// it — the first agent frame after Hello must be SequenceFloorApplied, never a
// packet — and the drain opens right after.
func TestFloorBarrierGatesFirstPacket(t *testing.T) {
	for name, format := range map[string]string{
		"protobuf": wire.SubprotocolProtobuf,
		"json":     wire.SubprotocolJSON,
	} {
		t.Run(name, func(t *testing.T) {
			deps, outbox, _, _ := newTestDeps(t)
			if _, err := outbox.Append(wal.Records{Metrics: []telemetry.Metric{{
				TS: time.Now().UTC(), Kind: telemetry.AgentUptime, Target: "agent", Value: 1,
			}}}, testServer); err != nil {
				t.Fatalf("wal append: %v", err)
			}

			type got struct {
				applied *wire.SequenceFloorApplied
				pkt     telemetry.Packet
			}
			gotCh := make(chan got, 1)
			srv := startServer(t, func(ctx context.Context, c *websocket.Conn) {
				first, err := srvRead(ctx, c)
				if err != nil || first.Hello == nil {
					t.Errorf("first frame: %+v err=%v; want Hello", first, err)
					return
				}
				if first.Hello.EnrollmentEpoch != 5 {
					t.Errorf("Hello epoch = %d, want 5", first.Hello.EnrollmentEpoch)
					return
				}
				if err := srvWrite(ctx, c, wire.Frame{SequenceFloor: &wire.SequenceFloor{
					EnrollmentEpoch: 5, SequenceFloor: 0, SessionID: "sess-1",
				}}); err != nil {
					t.Errorf("write floor: %v", err)
					return
				}
				f, err := srvRead(ctx, c)
				if err != nil || f.SequenceFloorApplied == nil {
					// A Packet here means the barrier let the drain claim and send
					// before the floor was applied.
					t.Errorf("first frame after the floor: %+v err=%v; want SequenceFloorApplied (a packet means the barrier is open)", f, err)
					return
				}
				pkt, err := srvRead(ctx, c)
				if err != nil || pkt.Packet == nil {
					t.Errorf("frame after the applied reply: %+v err=%v; want Packet", pkt, err)
					return
				}
				if err := srvWrite(ctx, c, wire.Frame{Ack: &wire.Ack{
					HighestSequence: pkt.Packet.Sequence, ServerTime: time.Now().UTC(),
				}}); err != nil {
					t.Errorf("write ack: %v", err)
					return
				}
				gotCh <- got{f.SequenceFloorApplied, *pkt.Packet}
				_, _ = srvRead(ctx, c) // hold the connection open until the client leaves
			})

			runAgent(t, epochOptions(srv.URL, format, 5), deps)

			select {
			case g := <-gotCh:
				if g.applied.EnrollmentEpoch != 5 || g.applied.SequenceFloor != 0 {
					t.Errorf("applied reply = %+v; want epoch 5, floor 0", g.applied)
				}
				if g.pkt.AgentID != "agent-1" || len(g.pkt.Metrics) != 1 {
					t.Errorf("packet = %+v; want agent-1 with 1 metric", g.pkt)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("server never received the applied reply and a packet")
			}
			waitFor(t, "WAL cleared after ack", func() bool { return outbox.Pending(testServer) == 0 })
		})
	}
}

// TestLowWaterAckDoesNotDeleteClaim: an ack whose watermark is below the
// in-flight claim's sequence must not release the claim — the agent keeps
// waiting, the session ends on the ack timeout, and the reconnect re-serves
// the SAME sequence. Only an ack at or above it releases the claim.
func TestLowWaterAckDoesNotDeleteClaim(t *testing.T) {
	for name, format := range map[string]string{
		"protobuf": wire.SubprotocolProtobuf,
		"json":     wire.SubprotocolJSON,
	} {
		t.Run(name, func(t *testing.T) {
			deps, outbox, _, _ := newTestDeps(t)
			if _, err := outbox.Append(wal.Records{Metrics: []telemetry.Metric{{
				TS: time.Now().UTC(), Kind: telemetry.AgentUptime, Target: "agent", Value: 1,
			}}}, testServer); err != nil {
				t.Fatalf("wal append: %v", err)
			}

			firstCh := make(chan uint64, 1)
			secondCh := make(chan uint64, 1)
			var conns int32
			srv := startServer(t, func(ctx context.Context, c *websocket.Conn) {
				n := atomic.AddInt32(&conns, 1)
				if f, err := srvRead(ctx, c); err != nil || f.Hello == nil {
					t.Errorf("hello: %+v err=%v", f, err)
					return
				}
				if err := srvWrite(ctx, c, wire.Frame{SequenceFloor: &wire.SequenceFloor{EnrollmentEpoch: 5, SequenceFloor: 0}}); err != nil {
					t.Errorf("write floor: %v", err)
					return
				}
				if f, err := srvRead(ctx, c); err != nil || f.SequenceFloorApplied == nil {
					t.Errorf("applied: %+v err=%v", f, err)
					return
				}
				pkt, err := srvRead(ctx, c)
				if err != nil || pkt.Packet == nil {
					t.Errorf("packet: %+v err=%v", pkt, err)
					return
				}
				if n == 1 {
					// A lower-water ack. The agent must reject it and keep the
					// claim; with no valid ack coming, its ack timeout ends the
					// session and the claim is re-served on the reconnect.
					firstCh <- pkt.Packet.Sequence
					if err := srvWrite(ctx, c, wire.Frame{Ack: &wire.Ack{
						HighestSequence: pkt.Packet.Sequence - 1, ServerTime: time.Now().UTC(),
					}}); err != nil {
						t.Errorf("write low ack: %v", err)
						return
					}
					_, _ = srvRead(ctx, c) // hold until the agent gives up on the ack
					return
				}
				secondCh <- pkt.Packet.Sequence
				if err := srvWrite(ctx, c, wire.Frame{Ack: &wire.Ack{
					HighestSequence: pkt.Packet.Sequence, ServerTime: time.Now().UTC(),
				}}); err != nil {
					t.Errorf("write ack: %v", err)
					return
				}
				_, _ = srvRead(ctx, c) // hold the connection open until the client leaves
			})

			opts := epochOptions(srv.URL, format, 5)
			opts.ackTimeout = 300 * time.Millisecond // the low ack must time out, not hang the test
			runAgent(t, opts, deps)

			var first, second uint64
			select {
			case first = <-firstCh:
			case <-time.After(5 * time.Second):
				t.Fatal("server never received the first packet")
			}
			select {
			case second = <-secondCh:
			case <-time.After(5 * time.Second):
				t.Fatal("the claim was never re-served")
			}
			if second != first {
				t.Fatalf("claim re-served as sequence %d after first going out as %d; the low-water ack deleted it", second, first)
			}
			waitFor(t, "WAL cleared after the valid ack", func() bool { return outbox.Pending(testServer) == 0 })
		})
	}
}

// TestUnsolicitedAckDoesNotDeleteClaim: an ack that arrives while nothing is
// in flight sits in the ack channel and must be rejected by the next awaitAck
// as below-watermark. The claim the drain takes afterwards is served intact
// under its own sequence — the stale ack neither deletes it nor fast-forwards
// the allocator past it.
func TestUnsolicitedAckDoesNotDeleteClaim(t *testing.T) {
	deps, outbox, _, _ := newTestDeps(t)
	if _, err := outbox.Append(wal.Records{Metrics: []telemetry.Metric{{
		TS: time.Now().UTC(), Kind: telemetry.AgentUptime, Target: "agent", Value: 1,
	}}}, testServer); err != nil {
		t.Fatalf("wal append: %v", err)
	}

	firstCh := make(chan uint64, 1)
	secondCh := make(chan uint64, 1)
	var conns int32
	srv := startServer(t, func(ctx context.Context, c *websocket.Conn) {
		n := atomic.AddInt32(&conns, 1)
		if f, err := srvRead(ctx, c); err != nil || f.Hello == nil {
			t.Errorf("hello: %+v err=%v", f, err)
			return
		}
		if err := srvWrite(ctx, c, wire.Frame{SequenceFloor: &wire.SequenceFloor{EnrollmentEpoch: 5, SequenceFloor: 0}}); err != nil {
			t.Errorf("write floor: %v", err)
			return
		}
		if f, err := srvRead(ctx, c); err != nil || f.SequenceFloorApplied == nil {
			t.Errorf("applied: %+v err=%v", f, err)
			return
		}
		if n == 1 {
			// An ack naming nothing in flight (watermark 0 — below any sequence
			// the drain can claim). It must not release or fast-forward the
			// claim the drain is about to take.
			if err := srvWrite(ctx, c, wire.Frame{Ack: &wire.Ack{HighestSequence: 0, ServerTime: time.Now().UTC()}}); err != nil {
				t.Errorf("write unsolicited ack: %v", err)
				return
			}
			pkt, err := srvRead(ctx, c)
			if err != nil || pkt.Packet == nil {
				t.Errorf("packet after the unsolicited ack: %+v err=%v; the stale ack ate the claim", pkt, err)
				return
			}
			firstCh <- pkt.Packet.Sequence
			_, _ = srvRead(ctx, c) // no valid ack; the agent times out and reconnects
			return
		}
		pkt, err := srvRead(ctx, c)
		if err != nil || pkt.Packet == nil {
			t.Errorf("re-served packet: %+v err=%v", pkt, err)
			return
		}
		secondCh <- pkt.Packet.Sequence
		if err := srvWrite(ctx, c, wire.Frame{Ack: &wire.Ack{
			HighestSequence: pkt.Packet.Sequence, ServerTime: time.Now().UTC(),
		}}); err != nil {
			t.Errorf("write ack: %v", err)
			return
		}
		_, _ = srvRead(ctx, c) // hold the connection open until the client leaves
	})

	opts := epochOptions(srv.URL, wire.SubprotocolJSON, 5)
	opts.ackTimeout = 300 * time.Millisecond // the dangling wait must time out, not hang the test
	runAgent(t, opts, deps)

	var first, second uint64
	select {
	case first = <-firstCh:
	case <-time.After(5 * time.Second):
		t.Fatal("server never received the first packet")
	}
	select {
	case second = <-secondCh:
	case <-time.After(5 * time.Second):
		t.Fatal("the claim was never re-served")
	}
	if second != first {
		t.Fatalf("claim re-served as sequence %d after first going out as %d; the unsolicited ack disturbed it", second, first)
	}
	waitFor(t, "WAL cleared after the valid ack", func() bool { return outbox.Pending(testServer) == 0 })
}

// TestClaimBelowFloorRotatesEpoch: the server pushes a floor above the agent's
// in-flight claim sequence. The agent must not serve that claim — instead it
// asks for an epoch rotation, completes the challenge/request/result flow,
// persists the rotated credential, and reconnects: the next Hello carries the
// new epoch and the same backlog goes out under fresh sequences above the old
// floor.
func TestClaimBelowFloorRotatesEpoch(t *testing.T) {
	deps, outbox, _, _ := newTestDeps(t)
	type rotated struct {
		epoch uint64
		token string
	}
	rotCh := make(chan rotated, 1)
	deps.SignChallenge = func(challenge []byte) []byte { return append([]byte("sig:"), challenge...) }
	deps.PersistRotation = func(epoch uint64, token string) error {
		rotCh <- rotated{epoch, token}
		return nil
	}

	// The state a rotation finds: an epoch-5 cursor with a claim in flight.
	if _, err := outbox.SetEpoch(testServer, 5); err != nil {
		t.Fatalf("SetEpoch: %v", err)
	}
	if _, err := outbox.Append(wal.Records{Metrics: []telemetry.Metric{{
		TS: time.Now().UTC(), Kind: telemetry.AgentUptime, Target: "agent", Value: 42,
	}}}, testServer); err != nil {
		t.Fatalf("wal append: %v", err)
	}
	claim, ok, err := outbox.NextBatch(testServer, batchItems)
	if err != nil || !ok {
		t.Fatalf("NextBatch: ok=%v err=%v", ok, err)
	}
	floor := claim.Sequence + 10

	pktCh := make(chan telemetry.Packet, 1)
	var conns int32
	srv := startTokenServer(t, []string{"test-token", "rotated-token"}, func(ctx context.Context, c *websocket.Conn) {
		n := atomic.AddInt32(&conns, 1)
		hello, err := srvRead(ctx, c)
		if err != nil || hello.Hello == nil {
			t.Errorf("hello: %+v err=%v", hello, err)
			return
		}
		if n == 1 {
			if hello.Hello.EnrollmentEpoch != 5 {
				t.Errorf("first Hello epoch = %d, want 5", hello.Hello.EnrollmentEpoch)
				return
			}
			if err := srvWrite(ctx, c, wire.Frame{SequenceFloor: &wire.SequenceFloor{
				EnrollmentEpoch: 5, SequenceFloor: floor, SessionID: "sess-1",
			}}); err != nil {
				t.Errorf("write floor: %v", err)
				return
			}
			f, err := srvRead(ctx, c)
			if err != nil || f.EpochRotationChallengeRequest == nil {
				t.Errorf("frame after the conflicting floor: %+v err=%v; want EpochRotationChallengeRequest", f, err)
				return
			}
			if f.EpochRotationChallengeRequest.Reason != "claim_below_floor" {
				t.Errorf("challenge request reason = %q, want claim_below_floor", f.EpochRotationChallengeRequest.Reason)
			}
			if err := srvWrite(ctx, c, wire.Frame{EpochRotationChallenge: &wire.EpochRotationChallenge{
				Challenge: "chal-1", Reason: "sequence_conflict", ExpiresAt: time.Now().Add(time.Minute),
			}}); err != nil {
				t.Errorf("write challenge: %v", err)
				return
			}
			req, err := srvRead(ctx, c)
			if err != nil || req.EpochRotationRequest == nil {
				t.Errorf("frame after the challenge: %+v err=%v; want EpochRotationRequest", req, err)
				return
			}
			if req.EpochRotationRequest.Challenge != "chal-1" || req.EpochRotationRequest.OldEpoch != 5 {
				t.Errorf("rotation request = %+v; want challenge chal-1 from epoch 5", req.EpochRotationRequest)
				return
			}
			if want := "sig:chal-1"; string(req.EpochRotationRequest.Signature) != want {
				t.Errorf("rotation request signature = %q, want %q", req.EpochRotationRequest.Signature, want)
				return
			}
			if err := srvWrite(ctx, c, wire.Frame{EpochRotationResult: &wire.EpochRotationResult{
				Status: wire.RotationOK, NewEpoch: 7, AgentToken: "rotated-token",
			}}); err != nil {
				t.Errorf("write rotation result: %v", err)
				return
			}
			_, _ = srvRead(ctx, c) // hold until the agent ends the session
			return
		}
		// Second session: the rotated credential, presenting the new epoch.
		if hello.Hello.EnrollmentEpoch != 7 {
			t.Errorf("second Hello epoch = %d, want 7 (the rotated epoch)", hello.Hello.EnrollmentEpoch)
			return
		}
		if err := srvWrite(ctx, c, wire.Frame{SequenceFloor: &wire.SequenceFloor{
			EnrollmentEpoch: 7, SequenceFloor: 0, SessionID: "sess-2",
		}}); err != nil {
			t.Errorf("write floor for the new epoch: %v", err)
			return
		}
		if f, err := srvRead(ctx, c); err != nil || f.SequenceFloorApplied == nil {
			t.Errorf("applied reply for the new epoch: %+v err=%v", f, err)
			return
		}
		pkt, err := srvRead(ctx, c)
		if err != nil || pkt.Packet == nil {
			t.Errorf("re-served packet: %+v err=%v", pkt, err)
			return
		}
		if pkt.Packet.Sequence <= floor {
			t.Errorf("re-served packet sequence %d is not above the old epoch's floor %d", pkt.Packet.Sequence, floor)
		}
		if err := srvWrite(ctx, c, wire.Frame{Ack: &wire.Ack{
			HighestSequence: pkt.Packet.Sequence, ServerTime: time.Now().UTC(),
		}}); err != nil {
			t.Errorf("write ack: %v", err)
			return
		}
		pktCh <- *pkt.Packet
		_, _ = srvRead(ctx, c) // hold the connection open until the client leaves
	})

	runAgent(t, epochOptions(srv.URL, wire.SubprotocolJSON, 5), deps)

	select {
	case got := <-rotCh:
		if got.epoch != 7 || got.token != "rotated-token" {
			t.Fatalf("PersistRotation(%d, %q), want (7, rotated-token)", got.epoch, got.token)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("PersistRotation never called")
	}
	select {
	case pkt := <-pktCh:
		if len(pkt.Metrics) != 1 || pkt.Metrics[0].Value != 42 {
			t.Fatalf("re-served packet = %+v; want the same record under the new epoch", pkt.Metrics)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the re-queued backlog was never served under the new epoch")
	}
	waitFor(t, "WAL cleared after the rotated session's ack", func() bool { return outbox.Pending(testServer) == 0 })
}

// TestRotationDeniedKeepsCredential: a denied rotation leaves the credential
// alone — PersistRotation is never called — and the session keeps retrying, so
// the server can re-drive a fresh challenge whenever its policy changes.
func TestRotationDeniedKeepsCredential(t *testing.T) {
	deps, _, _, _ := newTestDeps(t)
	type rotated struct {
		epoch uint64
		token string
	}
	rotCh := make(chan rotated, 4)
	deps.SignChallenge = func(challenge []byte) []byte { return []byte("sig") }
	deps.PersistRotation = func(epoch uint64, token string) error {
		rotCh <- rotated{epoch, token}
		return nil
	}

	var reqs int32
	srv := startServer(t, func(ctx context.Context, c *websocket.Conn) {
		if f, err := srvRead(ctx, c); err != nil || f.Hello == nil {
			t.Errorf("hello: %+v err=%v", f, err)
			return
		}
		if err := srvWrite(ctx, c, wire.Frame{SequenceFloor: &wire.SequenceFloor{EnrollmentEpoch: 5, SequenceFloor: 0}}); err != nil {
			t.Errorf("write floor: %v", err)
			return
		}
		if f, err := srvRead(ctx, c); err != nil || f.SequenceFloorApplied == nil {
			t.Errorf("applied: %+v err=%v", f, err)
			return
		}
		if err := srvWrite(ctx, c, wire.Frame{EpochRotationChallenge: &wire.EpochRotationChallenge{
			Challenge: "chal-denied", Reason: "epoch_mismatch", ExpiresAt: time.Now().Add(time.Minute),
		}}); err != nil {
			t.Errorf("write challenge: %v", err)
			return
		}
		if f, err := srvRead(ctx, c); err != nil || f.EpochRotationRequest == nil {
			t.Errorf("rotation request: %+v err=%v", f, err)
			return
		}
		atomic.AddInt32(&reqs, 1)
		if err := srvWrite(ctx, c, wire.Frame{EpochRotationResult: &wire.EpochRotationResult{
			Status: wire.RotationDenied, Reason: "policy_refused",
		}}); err != nil {
			t.Errorf("write denial: %v", err)
			return
		}
		_, _ = srvRead(ctx, c) // hold until the agent leaves; it reconnects and the script repeats
	})

	runAgent(t, epochOptions(srv.URL, wire.SubprotocolJSON, 5), deps)

	// The denial ends the session and the server re-challenges on every
	// reconnect, so the agent must reach the request again — the flow is
	// retryable rather than wedged.
	waitFor(t, "two rotation requests", func() bool { return atomic.LoadInt32(&reqs) >= 2 })
	select {
	case got := <-rotCh:
		t.Fatalf("PersistRotation(%d, %q) called after a denied rotation", got.epoch, got.token)
	case <-time.After(500 * time.Millisecond):
	}
}

// TestRotationPersistRetriedUntilSuccess: a transient failure of the durable
// credential write must not lose the accepted rotation. The agent keeps the
// in-memory identity and reconnects under the rotated token, and the write is
// retried at the top of the next session attempt until it lands — so a later
// restart finds the rotated credential on disk instead of the dying old one.
func TestRotationPersistRetriedUntilSuccess(t *testing.T) {
	deps, _, _, _ := newTestDeps(t)
	type rotated struct {
		epoch uint64
		token string
	}
	rotCh := make(chan rotated, 4)
	var attempts int32
	deps.SignChallenge = func(challenge []byte) []byte { return append([]byte("sig:"), challenge...) }
	deps.PersistRotation = func(epoch uint64, token string) error {
		n := atomic.AddInt32(&attempts, 1)
		rotCh <- rotated{epoch, token}
		if n == 1 {
			return errors.New("disk write failed (transient)")
		}
		return nil
	}

	var conns int32
	srv := startTokenServer(t, []string{"test-token", "rotated-token"}, func(ctx context.Context, c *websocket.Conn) {
		n := atomic.AddInt32(&conns, 1)
		hello, err := srvRead(ctx, c)
		if err != nil || hello.Hello == nil {
			t.Errorf("hello: %+v err=%v", hello, err)
			return
		}
		if n == 1 {
			if hello.Hello.EnrollmentEpoch != 5 {
				t.Errorf("first Hello epoch = %d, want 5", hello.Hello.EnrollmentEpoch)
				return
			}
			if err := srvWrite(ctx, c, wire.Frame{SequenceFloor: &wire.SequenceFloor{
				EnrollmentEpoch: 5, SequenceFloor: 0,
			}}); err != nil {
				t.Errorf("write floor: %v", err)
				return
			}
			if f, err := srvRead(ctx, c); err != nil || f.SequenceFloorApplied == nil {
				t.Errorf("applied reply: %+v err=%v", f, err)
				return
			}
			// No conflict here — the server initiates the rotation on its own.
			if err := srvWrite(ctx, c, wire.Frame{EpochRotationChallenge: &wire.EpochRotationChallenge{
				Challenge: "chal-1", Reason: "sequence_conflict", ExpiresAt: time.Now().Add(time.Minute),
			}}); err != nil {
				t.Errorf("write challenge: %v", err)
				return
			}
			req, err := srvRead(ctx, c)
			if err != nil || req.EpochRotationRequest == nil {
				t.Errorf("rotation request: %+v err=%v", req, err)
				return
			}
			if err := srvWrite(ctx, c, wire.Frame{EpochRotationResult: &wire.EpochRotationResult{
				Status: wire.RotationOK, NewEpoch: 6, AgentToken: "rotated-token",
			}}); err != nil {
				t.Errorf("write rotation result: %v", err)
				return
			}
			_, _ = srvRead(ctx, c) // hold until the agent ends the session
			return
		}
		// Second session: the rotated credential, despite the failed disk write.
		if hello.Hello.EnrollmentEpoch != 6 {
			t.Errorf("second Hello epoch = %d, want 6 (the rotated epoch, held in memory)", hello.Hello.EnrollmentEpoch)
			return
		}
		_, _ = srvRead(ctx, c) // hold the connection open until the client leaves
	})

	cancel := runAgent(t, epochOptions(srv.URL, wire.SubprotocolJSON, 5), deps)
	defer cancel()

	// Two calls: the failed first write inside the rotation, then the retry at
	// the top of the next session attempt.
	for want := 1; want <= 2; want++ {
		select {
		case got := <-rotCh:
			if got.epoch != 6 || got.token != "rotated-token" {
				t.Fatalf("PersistRotation call %d = (%d, %q), want (6, rotated-token)", want, got.epoch, got.token)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("PersistRotation call %d never arrived", want)
		}
	}
	waitFor(t, "the rotated session connected", func() bool { return atomic.LoadInt32(&conns) >= 2 })
}
