package conn

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/nettact/agent/internal/wal"
	"github.com/nettact/protocol"
	pcfg "github.com/nettact/protocol/config"
	"github.com/nettact/protocol/permission"
	"github.com/nettact/protocol/telemetry"
	"github.com/nettact/protocol/wire"
)

// This file pins the behaviour of a runner meeting a server that does not speak
// its wire schema: the two-schema search, what a downgraded session may and may
// not put on the wire, and how the conclusion is remembered.
//
// The fixture the older server is modelled on is a real one. A release before
// the current schema boundary refuses an unknown schema at the handshake, with
// the 4001 close code and nothing else — no error frame, no explanation — which
// is exactly why the retry has to be blind rather than informed.

// closeSchema closes the connection the way a server that does not know this
// agent's schema does.
func closeSchema(c *websocket.Conn) {
	_ = c.Close(websocket.StatusCode(wire.CloseUnsupportedSchema), "unsupported schema")
}

// schemaRecorder collects the schemas a runner reported as established.
type schemaRecorder struct {
	mu  sync.Mutex
	got []int
	err error
}

func (s *schemaRecorder) record(schema int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.got = append(s.got, schema)
	return s.err
}

func (s *schemaRecorder) all() []int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]int(nil), s.got...)
}

func (s *schemaRecorder) last() (int, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.got) == 0 {
		return 0, false
	}
	return s.got[len(s.got)-1], true
}

// pushConfig sends a DesiredState — the frame a server sends unconditionally on
// connect, and therefore the signal the agent takes as "the Hello was accepted".
func pushConfig(ctx context.Context, c *websocket.Conn, version int) error {
	return srvWrite(ctx, c, wire.Frame{DesiredState: &pcfg.DesiredState{
		ConfigVersion: version,
		Intervals:     pcfg.Intervals{BaseSeconds: 10, RegularSeconds: 60},
	}})
}

// TestRefusedSchemaRetriesWithThePreviousOne is the core of the search: a
// refusal is not a verdict on the pairing, only on one of the two schemas this
// build can speak, so the other one is tried at once — no backoff, because
// there is nothing to wait for — and the result is written down so the next
// start opens where this one finished.
func TestRefusedSchemaRetriesWithThePreviousOne(t *testing.T) {
	deps, outbox, _, _ := newTestDeps(t)
	rec := &schemaRecorder{}
	deps.PersistNegotiated = rec.record

	if _, err := outbox.Append(wal.Records{Metrics: []telemetry.Metric{{
		TS: time.Now().UTC(), Kind: telemetry.AgentUptime, Target: "agent", Value: 1,
	}}}, testServer); err != nil {
		t.Fatalf("wal append: %v", err)
	}

	type seen struct {
		hello wire.Hello
		pkt   telemetry.Packet
	}
	gotCh := make(chan seen, 1)
	var dials atomic.Int32
	srv := startServer(t, func(ctx context.Context, c *websocket.Conn) {
		n := dials.Add(1)
		f, err := srvRead(ctx, c)
		if err != nil || f.Hello == nil {
			t.Errorf("first frame: %+v err=%v; want Hello", f, err)
			return
		}
		if n == 1 {
			if f.Hello.SchemaVersion != protocol.SchemaVersion {
				t.Errorf("first Hello schema = %d, want the build's native %d", f.Hello.SchemaVersion, protocol.SchemaVersion)
			}
			closeSchema(c)
			return
		}
		if err := pushConfig(ctx, c, 1); err != nil {
			t.Errorf("push config: %v", err)
			return
		}
		pkt, err := srvRead(ctx, c)
		if err != nil || pkt.Packet == nil {
			t.Errorf("frame after the push: %+v err=%v; want Packet", pkt, err)
			return
		}
		if err := srvWrite(ctx, c, wire.Frame{Ack: &wire.Ack{
			HighestSequence: pkt.Packet.Sequence, ServerTime: time.Now().UTC(),
		}}); err != nil {
			t.Errorf("write ack: %v", err)
			return
		}
		select {
		case gotCh <- seen{*f.Hello, *pkt.Packet}:
		default:
		}
		_, _ = srvRead(ctx, c) // hold the connection open
	})

	opts := epochOptions(srv.URL, wire.SubprotocolJSON, 3)
	opts.Hello.Capabilities = []string{wire.CapSequenceFloorV1}
	runAgent(t, opts, deps)

	var got seen
	select {
	case got = <-gotCh:
	case <-time.After(5 * time.Second):
		t.Fatal("the retry in the previous schema never established a session")
	}

	// The Hello of a downgraded session declares only what that schema defines.
	// The options deliberately carry BOTH a capability list and a non-zero
	// epoch, so "declares nothing extra" is a claim with something to strip
	// rather than one an empty Hello satisfies for free.
	if got.hello.SchemaVersion != previousSchema {
		t.Errorf("retry Hello schema = %d, want %d", got.hello.SchemaVersion, previousSchema)
	}
	if len(got.hello.Capabilities) != 0 {
		t.Errorf("retry Hello declares capabilities %v; a session that will not run those state machines must not promise them", got.hello.Capabilities)
	}
	if got.hello.EnrollmentEpoch != 0 {
		t.Errorf("retry Hello carries epoch %d; it names a barrier this session does not run", got.hello.EnrollmentEpoch)
	}
	// The packet's schema follows the session, not the build. Stamping the
	// native version here is refused by the receiving side at the first packet,
	// on a link that otherwise looks perfectly healthy.
	if got.pkt.SchemaVersion != previousSchema {
		t.Errorf("packet schema = %d, want %d — the packet must follow the session it rides", got.pkt.SchemaVersion, previousSchema)
	}
	// Exactly two dials to get there: refused once, established once.
	if n := dials.Load(); n != 2 {
		t.Errorf("dials = %d, want 2 (one refusal, one retry)", n)
	}
	waitFor(t, "the negotiated schema to be recorded", func() bool {
		s, ok := rec.last()
		return ok && s == previousSchema
	})
	if all := rec.all(); len(all) != 1 {
		t.Errorf("negotiated schema recorded %v; want exactly one entry per established session", all)
	}
}

// TestRememberedSchemaIsUsedOnTheFirstDial is the other half of remembering:
// a runner told the server speaks the previous schema opens there, so the
// refusal is paid once ever rather than once per start.
func TestRememberedSchemaIsUsedOnTheFirstDial(t *testing.T) {
	deps, _, _, _ := newTestDeps(t)
	rec := &schemaRecorder{}
	deps.PersistNegotiated = rec.record

	helloCh := make(chan wire.Hello, 1)
	var dials atomic.Int32
	srv := startServer(t, func(ctx context.Context, c *websocket.Conn) {
		dials.Add(1)
		f, err := srvRead(ctx, c)
		if err != nil || f.Hello == nil {
			t.Errorf("first frame: %+v err=%v; want Hello", f, err)
			return
		}
		select {
		case helloCh <- *f.Hello:
		default:
		}
		if err := pushConfig(ctx, c, 1); err != nil {
			return
		}
		_, _ = srvRead(ctx, c)
	})

	opts := testOptions(srv.URL, wire.SubprotocolJSON)
	opts.WireSchema = previousSchema
	// Probed a moment ago, so the elapsed-time re-probe must not fire here.
	opts.SchemaProbedAt = time.Now()
	runAgent(t, opts, deps)

	select {
	case hello := <-helloCh:
		if hello.SchemaVersion != previousSchema {
			t.Fatalf("first Hello schema = %d, want the remembered %d — the record buys nothing if the first dial ignores it",
				hello.SchemaVersion, previousSchema)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no session")
	}
	if n := dials.Load(); n != 1 {
		t.Errorf("dials = %d, want 1 (the remembered schema was accepted first time)", n)
	}
}

// TestStaleProbeOffersTheNativeSchemaAgain is the escape from a downgrade that
// has outlived its reason. A server that was a release behind gets upgraded and
// nothing tells the agent — the downgraded session keeps working — so the agent
// re-offers its native schema once the last attempt is old enough.
func TestStaleProbeOffersTheNativeSchemaAgain(t *testing.T) {
	deps, _, _, _ := newTestDeps(t)
	rec := &schemaRecorder{}
	deps.PersistNegotiated = rec.record

	helloCh := make(chan wire.Hello, 1)
	srv := startServer(t, func(ctx context.Context, c *websocket.Conn) {
		f, err := srvRead(ctx, c)
		if err != nil || f.Hello == nil {
			t.Errorf("first frame: %+v err=%v; want Hello", f, err)
			return
		}
		select {
		case helloCh <- *f.Hello:
		default:
		}
		if err := pushConfig(ctx, c, 1); err != nil {
			return
		}
		_, _ = srvRead(ctx, c)
	})

	opts := testOptions(srv.URL, wire.SubprotocolJSON)
	opts.WireSchema = previousSchema
	// Last offered the native schema long enough ago that the cadence fires.
	opts.SchemaProbedAt = time.Now().Add(-30 * 24 * time.Hour)
	runAgent(t, opts, deps)

	select {
	case hello := <-helloCh:
		if hello.SchemaVersion != protocol.SchemaVersion {
			t.Fatalf("first Hello schema = %d, want the native %d — a stale downgrade must be re-probed", hello.SchemaVersion, protocol.SchemaVersion)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no session")
	}
	waitFor(t, "the successful probe to be recorded", func() bool {
		s, ok := rec.last()
		return ok && s == protocol.SchemaVersion
	})
}

// TestFailedProbeFallsBackWithoutLosingTheRecord: the re-probe finds the server
// still a release behind. It must fall straight back and record the previous
// schema again — the record's timestamp is what schedules the next probe, so a
// failed one still has to be written down or the agent probes on every single
// reconnect.
func TestFailedProbeFallsBackWithoutLosingTheRecord(t *testing.T) {
	deps, _, _, _ := newTestDeps(t)
	rec := &schemaRecorder{}
	deps.PersistNegotiated = rec.record

	var schemas []int
	var mu sync.Mutex
	srv := startServer(t, func(ctx context.Context, c *websocket.Conn) {
		f, err := srvRead(ctx, c)
		if err != nil || f.Hello == nil {
			t.Errorf("first frame: %+v err=%v; want Hello", f, err)
			return
		}
		mu.Lock()
		schemas = append(schemas, f.Hello.SchemaVersion)
		mu.Unlock()
		if f.Hello.SchemaVersion != previousSchema {
			closeSchema(c)
			return
		}
		if err := pushConfig(ctx, c, 1); err != nil {
			return
		}
		_, _ = srvRead(ctx, c)
	})

	opts := testOptions(srv.URL, wire.SubprotocolJSON)
	opts.WireSchema = previousSchema
	opts.SchemaProbedAt = time.Now().Add(-30 * 24 * time.Hour)
	runAgent(t, opts, deps)

	waitFor(t, "the fallback to be recorded", func() bool {
		s, ok := rec.last()
		return ok && s == previousSchema
	})
	mu.Lock()
	defer mu.Unlock()
	if len(schemas) < 2 || schemas[0] != protocol.SchemaVersion || schemas[1] != previousSchema {
		t.Fatalf("schemas offered = %v; want the native probe first, then the immediate fall back to %d", schemas, previousSchema)
	}
}

// TestBothSchemasRefusedIsTerminal is the other end of the search. Once both
// schemas this build can speak have been refused there is nothing left to try,
// and the pairing is terminal: reconnecting could only repeat the same two
// refusals forever, and monitoring stops because the server has said, twice,
// that it does not accept this agent.
func TestBothSchemasRefusedIsTerminal(t *testing.T) {
	deps, _, fc, _ := newTestDeps(t)
	rec := &schemaRecorder{}
	deps.PersistNegotiated = rec.record

	var mu sync.Mutex
	var schemas []int
	srv := startServer(t, func(ctx context.Context, c *websocket.Conn) {
		f, err := srvRead(ctx, c)
		if err != nil || f.Hello == nil {
			t.Errorf("first frame: %+v err=%v; want Hello", f, err)
			return
		}
		mu.Lock()
		schemas = append(schemas, f.Hello.SchemaVersion)
		mu.Unlock()
		closeSchema(c)
	})

	errCh := make(chan error, 1)
	go func() { errCh <- Run(context.Background(), testOptions(srv.URL, wire.SubprotocolJSON), deps) }()
	select {
	case err := <-errCh:
		if !errors.Is(err, ErrUnsupportedSchema) {
			t.Fatalf("Run returned %v; want ErrUnsupportedSchema", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run kept reconnecting after both schemas were refused")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(schemas) != 2 {
		t.Fatalf("schemas offered = %v; want exactly two attempts — one per schema this build speaks", schemas)
	}
	if schemas[0] == schemas[1] {
		t.Fatalf("schemas offered = %v; the retry must be the OTHER schema, not the same one again", schemas)
	}
	if got := rec.all(); len(got) != 0 {
		t.Errorf("a schema was recorded as negotiated %v; nothing was ever established", got)
	}
	// A terminal refusal stops this server's monitoring, like every other
	// identity verdict does.
	if ts := fc.lastTargets(); len(ts) != 0 {
		t.Errorf("targets still installed after a terminal refusal: %v", ts)
	}
}

// TestDowngradedSessionDrainsWithoutAFloor is the rollback case, and it is the
// one the obvious implementation gets wrong.
//
// The agent holds a credential whose epoch was rotated while the server still
// spoke the newer schema; the server has since been rolled back and no longer
// sends floors at all. Gating the drain on the epoch alone would leave this
// agent connected, healthy and permanently silent, waiting for a frame that is
// never coming. The gate is on the SCHEMA.
func TestDowngradedSessionDrainsWithoutAFloor(t *testing.T) {
	deps, outbox, _, _ := newTestDeps(t)
	if _, err := outbox.SetEpoch(testServer, 11); err != nil {
		t.Fatalf("SetEpoch: %v", err)
	}
	if _, err := outbox.Append(wal.Records{Metrics: []telemetry.Metric{{
		TS: time.Now().UTC(), Kind: telemetry.AgentUptime, Target: "agent", Value: 5,
	}}}, testServer); err != nil {
		t.Fatalf("wal append: %v", err)
	}

	pktCh := make(chan telemetry.Packet, 1)
	srv := startServer(t, func(ctx context.Context, c *websocket.Conn) {
		f, err := srvRead(ctx, c)
		if err != nil || f.Hello == nil {
			t.Errorf("first frame: %+v err=%v; want Hello", f, err)
			return
		}
		if f.Hello.EnrollmentEpoch != 0 {
			t.Errorf("downgraded Hello carries epoch %d, want 0", f.Hello.EnrollmentEpoch)
		}
		// No floor is sent — this server does not know how to send one.
		pkt, err := srvRead(ctx, c)
		if err != nil || pkt.Packet == nil {
			t.Errorf("frame after Hello: %+v err=%v; want Packet (a wait here is the barrier deadlock)", pkt, err)
			return
		}
		if err := srvWrite(ctx, c, wire.Frame{Ack: &wire.Ack{
			HighestSequence: pkt.Packet.Sequence, ServerTime: time.Now().UTC(),
		}}); err != nil {
			t.Errorf("write ack: %v", err)
			return
		}
		select {
		case pktCh <- *pkt.Packet:
		default:
		}
		_, _ = srvRead(ctx, c)
	})

	opts := epochOptions(srv.URL, wire.SubprotocolJSON, 11)
	opts.WireSchema = previousSchema
	opts.SchemaProbedAt = time.Now()
	runAgent(t, opts, deps)

	select {
	case pkt := <-pktCh:
		if len(pkt.Metrics) != 1 || pkt.Metrics[0].Value != 5 {
			t.Fatalf("packet = %+v; want the queued record", pkt.Metrics)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a credential with a non-zero epoch never drained on a downgraded session — the barrier is gating on the epoch instead of the schema")
	}
	waitFor(t, "WAL cleared after ack", func() bool { return outbox.Pending(testServer) == 0 })
}

// TestDowngradedSessionRefusesControlFrames: a session that declared no
// capabilities has told the server it will not run those state machines. A
// server that sends one anyway is not merely ignored — half-running a barrier
// or a rotation is worse than not having one — so the session ends and the
// agent reconnects. It does not answer, and it does not invent a close code of
// its own to say so.
func TestDowngradedSessionRefusesControlFrames(t *testing.T) {
	deps, _, _, _ := newTestDeps(t)

	var dials atomic.Int32
	replyCh := make(chan wire.Frame, 1)
	srv := startServer(t, func(ctx context.Context, c *websocket.Conn) {
		dials.Add(1)
		f, err := srvRead(ctx, c)
		if err != nil || f.Hello == nil {
			t.Errorf("first frame: %+v err=%v; want Hello", f, err)
			return
		}
		if err := srvWrite(ctx, c, wire.Frame{SequenceFloor: &wire.SequenceFloor{
			EnrollmentEpoch: 0, SequenceFloor: 0, SessionID: "sess-out-of-band",
		}}); err != nil {
			return
		}
		// Anything the agent writes back is a state machine it promised not to
		// run. A read error is the pass: the session ended instead.
		if reply, err := srvRead(ctx, c); err == nil {
			select {
			case replyCh <- reply:
			default:
			}
		}
	})

	opts := testOptions(srv.URL, wire.SubprotocolJSON)
	opts.WireSchema = previousSchema
	opts.SchemaProbedAt = time.Now()
	runAgent(t, opts, deps)

	// The session must end and be retried, rather than answering.
	waitFor(t, "the session to end and be redialed", func() bool { return dials.Load() >= 2 })
	select {
	case f := <-replyCh:
		t.Fatalf("the agent answered a control frame on a session that declared no capabilities: %+v", f)
	default:
	}
}

// TestNegotiationIsPerServer: two runners in one process, one downgraded and
// one not. Neither may disturb the other's session or its record — the whole
// point of remembering per server is that one server being behind says nothing
// about the rest.
func TestNegotiationIsPerServer(t *testing.T) {
	const (
		serverA = "alpha"
		serverB = "beta"
	)
	dataDir, err := os.MkdirTemp("", "nettact-conn-multi-")
	if err != nil {
		t.Fatalf("temp dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dataDir) })
	outbox, err := wal.Open(filepath.Join(dataDir, "wal"), []string{serverA, serverB}, wal.Options{})
	if err != nil {
		t.Fatalf("open wal: %v", err)
	}
	t.Cleanup(func() { _ = outbox.Close() })

	newDeps := func(rec *schemaRecorder) Deps {
		return Deps{
			Outbox:            outbox,
			Configurables:     []Configurable{&fakeConfigurable{}},
			Scheduler:         &fakeScheduler{},
			DrainInterval:     50 * time.Millisecond,
			PersistNegotiated: rec.record,
			CollectSnapshot: func(_ context.Context, requestID string, _ permission.Set) telemetry.HostSnapshot {
				return telemetry.HostSnapshot{TS: time.Now().UTC(), RequestID: requestID}
			},
		}
	}

	// alpha speaks the native schema; beta refuses it.
	var alphaSchemas, betaSchemas []int
	var mu sync.Mutex
	srvA := startServer(t, func(ctx context.Context, c *websocket.Conn) {
		f, err := srvRead(ctx, c)
		if err != nil || f.Hello == nil {
			return
		}
		mu.Lock()
		alphaSchemas = append(alphaSchemas, f.Hello.SchemaVersion)
		mu.Unlock()
		if err := pushConfig(ctx, c, 1); err != nil {
			return
		}
		_, _ = srvRead(ctx, c)
	})
	srvB := startServer(t, func(ctx context.Context, c *websocket.Conn) {
		f, err := srvRead(ctx, c)
		if err != nil || f.Hello == nil {
			return
		}
		mu.Lock()
		betaSchemas = append(betaSchemas, f.Hello.SchemaVersion)
		mu.Unlock()
		if f.Hello.SchemaVersion == protocol.SchemaVersion {
			closeSchema(c)
			return
		}
		if err := pushConfig(ctx, c, 1); err != nil {
			return
		}
		_, _ = srvRead(ctx, c)
	})

	recA, recB := &schemaRecorder{}, &schemaRecorder{}
	optsA := testOptions(srvA.URL, wire.SubprotocolJSON)
	optsA.ServerName = serverA
	optsB := testOptions(srvB.URL, wire.SubprotocolJSON)
	optsB.ServerName = serverB
	runAgent(t, optsA, newDeps(recA))
	runAgent(t, optsB, newDeps(recB))

	waitFor(t, "alpha to record the native schema", func() bool {
		s, ok := recA.last()
		return ok && s == protocol.SchemaVersion
	})
	waitFor(t, "beta to record the downgrade", func() bool {
		s, ok := recB.last()
		return ok && s == previousSchema
	})
	for _, s := range recA.all() {
		if s != protocol.SchemaVersion {
			t.Fatalf("alpha recorded %v; beta's downgrade must not reach it", recA.all())
		}
	}
	mu.Lock()
	defer mu.Unlock()
	for _, s := range alphaSchemas {
		if s != protocol.SchemaVersion {
			t.Fatalf("alpha was offered %v; it was never refused and must never be downgraded", alphaSchemas)
		}
	}
	if len(betaSchemas) < 2 {
		t.Fatalf("beta was offered %v; want a refusal followed by the retry", betaSchemas)
	}
}

// TestPipeSessionStaysNative guards the in-process assembly, where both halves
// are the same build by construction: the search must be invisible there — one
// session, native schema, capabilities and epoch intact, and the previous
// schema never recorded.
func TestPipeSessionStaysNative(t *testing.T) {
	deps, _, _, _ := newTestDeps(t)
	rec := &schemaRecorder{}
	deps.PersistNegotiated = rec.record

	helloCh := make(chan wire.Hello, 1)
	dialer := pipeDialer(t, make(chan string, 1), func(ctx context.Context, c wire.Conn) {
		f, err := c.ReadFrame(ctx)
		if err != nil || f.Hello == nil {
			t.Errorf("first frame: %+v err=%v; want Hello", f, err)
			return
		}
		select {
		case helloCh <- *f.Hello:
		default:
		}
		if err := c.WriteFrame(ctx, wire.Frame{DesiredState: &pcfg.DesiredState{
			ConfigVersion: 1, Intervals: pcfg.Intervals{BaseSeconds: 10, RegularSeconds: 60},
		}}); err != nil {
			return
		}
		<-ctx.Done()
	})

	opts := epochOptions("", wire.SubprotocolJSON, 4)
	opts.Dialer = dialer
	opts.Hello.Capabilities = []string{wire.CapSequenceFloorV1}
	runAgent(t, opts, deps)

	select {
	case hello := <-helloCh:
		if hello.SchemaVersion != protocol.SchemaVersion {
			t.Fatalf("in-process Hello schema = %d, want the native %d", hello.SchemaVersion, protocol.SchemaVersion)
		}
		if !wire.HasCapability(hello.Capabilities, wire.CapSequenceFloorV1) {
			t.Fatalf("in-process Hello dropped its capabilities: %+v", hello)
		}
		if hello.EnrollmentEpoch != 4 {
			t.Fatalf("in-process Hello epoch = %d, want 4", hello.EnrollmentEpoch)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no in-process session")
	}
	waitFor(t, "the native schema to be recorded", func() bool {
		s, ok := rec.last()
		return ok && s == protocol.SchemaVersion
	})
	for _, s := range rec.all() {
		if s != protocol.SchemaVersion {
			t.Fatalf("the in-process assembly recorded %v; both halves are the same build and can never disagree", rec.all())
		}
	}
}

// TestRetryableCloseCodesKeepTheClaimAndAreNamed: a close that says the pairing
// or one side's implementation is wrong — an unusable wire format, a frame the
// server would not allow — is not a verdict on this agent's identity. The
// credential is fine and the backlog is fine, so the session backs off and
// redials with its claim intact.
//
// What it must not stay is anonymous. Left as a generic session failure these
// read on a status page as an unreliable network, which sends whoever is
// looking to check cables for a problem that is a setting or a version.
func TestRetryableCloseCodesKeepTheClaimAndAreNamed(t *testing.T) {
	for name, tc := range map[string]struct {
		code wire.CloseCode
		want Reason
	}{
		"unusable wire format": {wire.CloseUnsupportedSubprotocol, ReasonUnsupportedSubprotocol},
		"refused frame":        {wire.CloseProtocolError, ReasonProtocolError},
		// An unknown code has to stay retryable too: a newer server must be able
		// to close for a reason this build has never heard of without stranding
		// the agent.
		"a code this build does not know": {wire.CloseCode(4099), ReasonNetwork},
	} {
		t.Run(name, func(t *testing.T) {
			deps, outbox, _, _ := newTestDeps(t)
			if _, err := outbox.Append(wal.Records{Metrics: []telemetry.Metric{{
				TS: time.Now().UTC(), Kind: telemetry.AgentUptime, Target: "agent", Value: 1,
			}}}, testServer); err != nil {
				t.Fatalf("wal append: %v", err)
			}

			var dials atomic.Int32
			srv := startServer(t, func(ctx context.Context, c *websocket.Conn) {
				dials.Add(1)
				if f, err := srvRead(ctx, c); err != nil || f.Hello == nil {
					return
				}
				_ = c.Close(websocket.StatusCode(tc.code), "closed")
			})

			reasons := make(chan Reason, 4)
			opts := testOptions(srv.URL, wire.SubprotocolJSON)
			opts.OnRetry = func(err error, _ time.Duration) {
				select {
				case reasons <- Classify(err):
				default:
				}
			}
			runAgent(t, opts, deps)

			// Retryable: the runner comes back rather than returning.
			waitFor(t, "a redial after the close", func() bool { return dials.Load() >= 2 })
			select {
			case got := <-reasons:
				if got != tc.want {
					t.Fatalf("reason = %q, want %q", got, tc.want)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("no retry was reported")
			}
			// The claim is untouched: nothing here said the server stored anything.
			if outbox.Pending(testServer) == 0 {
				t.Fatal("the queued record was dropped on a retryable close")
			}
		})
	}
}
