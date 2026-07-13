// Package conn maintains the agent's persistent WebSocket session to the
// server (architecture §5.1, WS transport). It replaces the old HTTP POST
// uploader: instead of polling uploads that piggybacked config on acks, one
// long-lived connection carries everything as wire.Frame messages — telemetry
// packets up, acks/DesiredState/SnapshotRequest down. The always-open socket
// is what makes config pushes and live-snapshot requests instant, and the
// close frame sent on shutdown is what lets the server mark the agent offline
// in seconds instead of waiting out a probe/heartbeat timeout.
//
// All traffic remains agent-initiated outbound; the agent still never listens.
package conn

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/nettact/agent/internal/hostsnapshot"
	"github.com/nettact/agent/internal/wal"
	"github.com/nettact/protocol"
	pcfg "github.com/nettact/protocol/config"
	"github.com/nettact/protocol/telemetry"
	"github.com/nettact/protocol/wire"
)

// Terminal session sentinels. Run returns one of these (wrapped) when the server
// closes with an application code that makes reconnecting pointless or harmful,
// so a supervisor (agentrt) can classify the outcome without re-parsing close
// codes. They live here — not in agentrt — because agentrt imports conn, and the
// reverse would be an import cycle. The close codes themselves are wire.Close*
// (wire.CloseSuperseded/UnsupportedSchema/Revoked), classified via
// wire.CloseStatus regardless of whether the link is a WebSocket or a pipe.
var (
	// ErrSuperseded: another process connected with this credential and the
	// server kicked us; redialing would kick that one back in a loop.
	ErrSuperseded = errors.New("agent instance superseded")
	// ErrUnsupportedSchema: the server rejected our schema version; nothing
	// changes until one side is upgraded.
	ErrUnsupportedSchema = errors.New("server rejected schema version")
	// ErrRevoked: the agent row was deleted server-side; the credential is dead
	// and the process must re-enroll to come back.
	ErrRevoked = errors.New("agent revoked on server")
)

const (
	writeTimeout = 10 * time.Second
	pingInterval = 15 * time.Second
	pingTimeout  = 5 * time.Second

	// stableSession is how long a session must survive before a later failure
	// resets the reconnect backoff — a connection that lasted this long proves
	// the server was genuinely reachable, not flapping.
	stableSession = 30 * time.Second

	// Drain bounds, carried over from the old uploader loop: cap work per tick
	// so a deep backfill spans ticks instead of monopolizing the session.
	maxBatchesPerDrain = 100
	batchItems         = 500

	defaultDialTimeout = 10 * time.Second
	defaultAckTimeout  = 30 * time.Second
	defaultBackoffBase = time.Second
	defaultBackoffCap  = 30 * time.Second
)

// Options configure the connection itself: where to dial, how to authenticate,
// and the static identity the server sees.
type Options struct {
	ServerURL string // e.g. http://localhost:8080; scheme maps http→ws, https→wss
	Token     string // bearer token presented on the upgrade request
	Insecure  bool   // skip TLS verification (LAN self-signed dev)
	Format    string // wire.SubprotocolProtobuf or wire.SubprotocolJSON

	// Dialer establishes the session link. Nil selects the default WebSocket
	// dialer built from ServerURL/Insecure/Format. The desktop injects the
	// embedded Lite server's in-process pipe dialer here, so no loopback socket
	// is used and ServerURL/Format are then irrelevant.
	Dialer wire.Dialer

	// AgentID/SiteID stamp every telemetry packet (from the enrollment credential).
	AgentID string
	SiteID  string

	// Hello carries the static identity fields sent as the first frame of every
	// (re)connect. ReportedConfigVersion is overwritten per connect with the
	// version applied in this process — the caller's value is ignored.
	Hello wire.Hello

	// OnSession, if non-nil, is called with up=true right after the Hello frame
	// is written (the session is live) and up=false when that session ends. It
	// lets a supervisor surface connected/disconnected without treating a
	// transient reconnect as an error. Must be fast and non-blocking: it runs on
	// the session goroutine.
	OnSession func(up bool)

	// Test knobs. Zero values select the production defaults above; only tests
	// (same package) can set them, so the production surface stays minimal.
	dialTimeout time.Duration
	ackTimeout  time.Duration
	backoffBase time.Duration
	backoffCap  time.Duration
}

// Configurable is a collector whose probe targets are pushed from the server
// (mirrors the interface main wires the collectors through).
type Configurable interface {
	SetTargets([]pcfg.ProbeTarget)
}

// IntervalSetter receives tier-interval updates from DesiredState pushes.
type IntervalSetter interface {
	SetIntervals(base, regular time.Duration)
}

// Deps are the agent-side components the session drives.
type Deps struct {
	Outbox        *wal.Store
	Configurables []Configurable
	Scheduler     IntervalSetter
	DrainInterval time.Duration // how often to drain the WAL over the socket

	// Host-monitoring opt-in flags, re-checked on every SnapshotRequest
	// (defense in depth: the server should never ask for a cap the agent didn't
	// advertise, but the launch flags stay the sole authority regardless).
	ReportProcs bool
	ReportConns bool

	// CollectSnapshot produces a live host snapshot for a SnapshotRequest.
	// Nil selects hostsnapshot.Collect; tests inject a stub to avoid the
	// ~300ms CPU sample window.
	CollectSnapshot func(ctx context.Context, requestID string, wantProcs, wantConns bool) telemetry.HostSnapshot
}

// Run dials the server and keeps a session alive until ctx is cancelled,
// reconnecting with jittered exponential backoff on any failure. It blocks for
// the life of the agent and returns nil on shutdown; a non-nil error means the
// configuration is unusable (bad URL) and retrying would never help.
func Run(ctx context.Context, opts Options, deps Deps) error {
	if opts.Dialer == nil {
		// Standalone path: build the WebSocket dialer. A bad ServerURL surfaces
		// here as the "config unusable, retrying won't help" early error.
		d, err := wsDialer(opts)
		if err != nil {
			return err
		}
		opts.Dialer = d
	}
	if opts.dialTimeout == 0 {
		opts.dialTimeout = defaultDialTimeout
	}
	if opts.ackTimeout == 0 {
		opts.ackTimeout = defaultAckTimeout
	}
	if opts.backoffBase == 0 {
		opts.backoffBase = defaultBackoffBase
	}
	if opts.backoffCap == 0 {
		opts.backoffCap = defaultBackoffCap
	}
	if deps.CollectSnapshot == nil {
		deps.CollectSnapshot = hostsnapshot.Collect
	}

	r := &runner{
		opts:   opts,
		deps:   deps,
		dialer: opts.Dialer,
		// Start behind any real version so the server's unconditional
		// on-connect DesiredState push is always applied, even after an agent
		// restart where the server thinks we are current.
		appliedConfigVersion: -1,
	}

	bo := &backoff{base: opts.backoffBase, cap: opts.backoffCap}
	for {
		start := time.Now()
		err := r.session(ctx)
		if ctx.Err() != nil {
			return nil // shutdown: the session already sent the close frame
		}
		// Application close codes that make reconnecting pointless (or actively
		// harmful — a superseded session redialing would kick its replacement in
		// an endless loop). CloseStatus sees through the %w wrapping and works
		// for both the WebSocket adapter and the in-memory pipe.
		switch wire.CloseStatus(err) {
		case wire.CloseSuperseded:
			return fmt.Errorf("another agent instance connected with this credential: %w", ErrSuperseded)
		case wire.CloseUnsupportedSchema:
			return fmt.Errorf("server rejected schema version %d; upgrade the agent or server: %w", protocol.SchemaVersion, ErrUnsupportedSchema)
		case wire.CloseRevoked:
			return fmt.Errorf("agent was deleted on the server; re-enroll to continue: %w", ErrRevoked)
		}
		if time.Since(start) > stableSession {
			bo.reset()
		}
		delay := bo.next()
		// One line per attempt; backoff caps this at ~2 lines/min steady-state,
		// so an unreachable server doesn't flood the log.
		log.Printf("session ended: %v; reconnecting in %s", err, delay.Round(time.Millisecond))
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(delay):
		}
	}
}

// runner holds the state that survives across sessions. appliedConfigVersion
// is in-memory only and touched exclusively by the session goroutine.
type runner struct {
	opts   Options
	deps   Deps
	dialer wire.Dialer

	appliedConfigVersion int
}

// session runs one connection lifecycle: dial, Hello, then the frame loop
// until the connection dies or ctx is cancelled. It always returns with the
// connection closed.
func (r *runner) session(ctx context.Context) error {
	dialCtx, cancel := context.WithTimeout(ctx, r.opts.dialTimeout)
	c, err := r.dialer(dialCtx, r.opts.Token)
	cancel()
	if err != nil {
		return err
	}

	// sessionCtx is deliberately detached from the parent ctx: the WebSocket
	// adapter tears the whole connection down (no close frame) when a Read/Write
	// context dies, so in-session I/O must not abort on shutdown before the
	// clean close below has gone out. (Harmless for the in-memory pipe, which
	// has no such handshake.)
	sessionCtx, endSession := context.WithCancel(context.Background())
	defer endSession()

	// Shutdown watcher: on parent cancel, perform the close handshake. This
	// close frame is the whole point of the redesign's shutdown path — the
	// server sees a normal closure and flips the agent offline immediately
	// (Ctrl+C → offline in seconds). Close takes no context (it uses an
	// internal timeout), so the dead parent ctx cannot wedge it, and it also
	// unblocks any in-flight Read/Write on this connection.
	closeDone := make(chan struct{})
	go func() {
		defer close(closeDone)
		select {
		case <-ctx.Done():
			_ = c.Close(wire.CloseNormalClosure, "shutdown")
		case <-sessionCtx.Done():
		}
	}()
	// Teardown (runs before endSession, so the watcher is still live here): on
	// shutdown, WAIT for the watcher's clean close instead of racing it with an
	// error-status close of our own; on session failure, close abnormally so
	// the server knows this was not a graceful exit.
	defer func() {
		if ctx.Err() != nil {
			<-closeDone
		} else {
			_ = c.Close(wire.CloseInternalError, "session error")
		}
	}()

	// Hello MUST be the first frame: it replaces the old per-request X-Agent-*
	// headers and reports the config version applied in this process so the
	// server knows its on-connect DesiredState push will land on fresh state.
	hello := r.opts.Hello
	hello.ReportedConfigVersion = r.appliedConfigVersion
	if err := r.writeFrame(sessionCtx, c, wire.Frame{Hello: &hello}); err != nil {
		return fmt.Errorf("send hello: %w", err)
	}
	// The session is live once Hello is on the wire. Fire OnSession(true) here and
	// pair it with a deferred (false) — placed after the write so the false only
	// fires when the true did (a dial/Hello failure reports no session at all).
	if r.opts.OnSession != nil {
		r.opts.OnSession(true)
		defer r.opts.OnSession(false)
	}

	// One reader goroutine feeds these; the session goroutine is the ONLY
	// writer and the only place config/WAL state is touched, so no locking is
	// needed anywhere in the session.
	errCh := make(chan error, 2) // reader + pinger, at most one send each
	ackCh := make(chan wire.Ack, 1)
	pushCh := make(chan wire.Frame, 4)

	go r.readLoop(sessionCtx, c, ackCh, pushCh, errCh)
	go r.pingLoop(sessionCtx, c, errCh)

	return r.sessionLoop(ctx, sessionCtx, c, ackCh, pushCh, errCh)
}

// readLoop is the session's sole reader: it decodes each frame and routes it
// to the session goroutine. Any read/decode failure ends the session (via
// errCh) — after a transport error the frame stream cannot be trusted.
func (r *runner) readLoop(sessionCtx context.Context, c wire.Conn, ackCh chan<- wire.Ack, pushCh chan<- wire.Frame, errCh chan<- error) {
	for {
		f, err := c.ReadFrame(sessionCtx)
		if err != nil {
			errCh <- err
			return
		}
		switch {
		case f.Ack != nil:
			select {
			case ackCh <- *f.Ack:
			case <-sessionCtx.Done():
				return
			}
		case f.DesiredState != nil, f.SnapshotRequest != nil:
			select {
			case pushCh <- f:
			case <-sessionCtx.Done():
				return
			}
		default:
			// Hello/Packet/HostSnapshot flow agent→server only; a server that
			// echoes them is broken and the session should not limp along.
			errCh <- fmt.Errorf("server sent an agent-bound-invalid frame")
			return
		}
	}
}

// pingLoop keeps liveness honest: TCP alone can sit half-open for minutes
// after e.g. a suspend or NAT idle-out, silently stalling telemetry. A failed
// ping ends the session so Run can redial. Over the in-memory pipe a Ping
// always succeeds while the link is open, so this loop harmlessly no-ops.
func (r *runner) pingLoop(sessionCtx context.Context, c wire.Conn, errCh chan<- error) {
	t := time.NewTicker(pingInterval)
	defer t.Stop()
	for {
		select {
		case <-sessionCtx.Done():
			return
		case <-t.C:
			pctx, cancel := context.WithTimeout(sessionCtx, pingTimeout)
			err := c.Ping(pctx)
			cancel()
			if err != nil {
				errCh <- fmt.Errorf("ping: %w", err)
				return
			}
		}
	}
}

// sessionLoop is the session goroutine's main loop: drain the WAL on a ticker
// (plus once immediately) and apply server pushes as they arrive.
func (r *runner) sessionLoop(ctx, sessionCtx context.Context, c wire.Conn, ackCh <-chan wire.Ack, pushCh <-chan wire.Frame, errCh <-chan error) error {
	// Immediate first drain: a freshly-(re)connected session should flush
	// whatever accumulated while offline without waiting a full tick —
	// preserves the old loop's fast-startup behavior.
	if err := r.drain(ctx, sessionCtx, c, ackCh, pushCh, errCh); err != nil {
		return err
	}
	ticker := time.NewTicker(r.deps.DrainInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err() // Run maps shutdown to a clean nil return
		case err := <-errCh:
			return err
		case f := <-pushCh:
			if err := r.applyPush(ctx, sessionCtx, c, f); err != nil {
				return err
			}
		case <-ticker.C:
			if err := r.drain(ctx, sessionCtx, c, ackCh, pushCh, errCh); err != nil {
				return err
			}
		}
	}
}

// drain uploads pending WAL batches over the socket, one ack-confirmed packet
// at a time (semantics carried over from the old uploader loop: bounded per
// tick, same-sequence retry on failure, server dedups on agent_id+sequence).
// All WAL access happens here, on the session goroutine — the store rides a
// single SQLite connection.
func (r *runner) drain(ctx, sessionCtx context.Context, c wire.Conn, ackCh <-chan wire.Ack, pushCh <-chan wire.Frame, errCh <-chan error) error {
	for i := 0; i < maxBatchesPerDrain; i++ {
		batch, ok, err := r.deps.Outbox.NextBatch(batchItems)
		if err != nil {
			// A WAL read error is local and usually transient (busy timeout);
			// keep the session alive and retry next tick, as the old loop did.
			log.Printf("wal next batch: %v", err)
			return nil
		}
		if !ok {
			return nil
		}
		pkt := telemetry.Packet{
			SchemaVersion:         protocol.SchemaVersion,
			AgentID:               r.opts.AgentID,
			SiteID:                r.opts.SiteID,
			Sequence:              batch.Sequence,
			SentAt:                time.Now().UTC(),
			Metrics:               batch.Metrics,
			Events:                batch.Events,
			InventoryDelta:        batch.Inventory,
			InterfaceSnapshots:    batch.Snapshots,
			ReportedConfigVersion: r.appliedConfigVersion,
		}
		if err := r.writeFrame(sessionCtx, c, wire.Frame{Packet: &pkt}); err != nil {
			return fmt.Errorf("write packet seq=%d: %w", batch.Sequence, err)
		}
		ack, err := r.awaitAck(ctx, sessionCtx, c, ackCh, pushCh, errCh, batch.Sequence)
		if err != nil {
			// The batch stays tagged in the WAL and is re-sent under the SAME
			// sequence by the next session, so nothing is lost or double-counted.
			return err
		}
		// Reconcile the local sequence allocator to the server's watermark BEFORE
		// deleting the acked batch. If this WAL's next_seq was reset below the
		// server's retained watermark (e.g. the WAL db was recreated while the
		// agent kept its enrollment), every fresh batch would otherwise reuse an
		// already-stored (agent_id, sequence) and be silently deduped, suppressing
		// all telemetry until the counter climbed back past the watermark.
		// FastForward raises next_seq to HighestSequence+1 (never lowering it), so
		// the next claimed batch lands above the watermark and is accepted. On
		// persistence failure we do NOT delete the batch and yield the drain: the
		// same sequence is retried on the next tick, not in a tight loop.
		if err := r.deps.Outbox.FastForward(ack.HighestSequence); err != nil {
			log.Printf("wal fast-forward to watermark=%d: %v", ack.HighestSequence, err)
			return nil
		}
		if err := r.deps.Outbox.Ack(batch.Sequence); err != nil {
			log.Printf("wal ack seq=%d: %v", batch.Sequence, err)
		}
		log.Printf("sent seq=%d metrics=%d events=%d inv=%d (watermark=%d, pending=%d)",
			batch.Sequence, len(pkt.Metrics), len(pkt.Events), len(pkt.InventoryDelta),
			ack.HighestSequence, r.deps.Outbox.Pending())
	}
	return nil
}

// awaitAck blocks until the in-flight packet is acknowledged. It keeps
// consuming pushCh while it waits — the deadlock guard: if pushes queued up
// unconsumed, the reader would block sending to pushCh and the ack could never
// be read off the wire.
func (r *runner) awaitAck(ctx, sessionCtx context.Context, c wire.Conn, ackCh <-chan wire.Ack, pushCh <-chan wire.Frame, errCh <-chan error, seq uint64) (wire.Ack, error) {
	timer := time.NewTimer(r.opts.ackTimeout)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return wire.Ack{}, ctx.Err()
		case err := <-errCh:
			return wire.Ack{}, err
		case f := <-pushCh:
			if err := r.applyPush(ctx, sessionCtx, c, f); err != nil {
				return wire.Ack{}, err
			}
		case ack := <-ackCh:
			return ack, nil
		case <-timer.C:
			// A connection that swallows packets without acking is as dead as a
			// broken one — end the session and redial.
			return wire.Ack{}, fmt.Errorf("ack timeout for seq=%d", seq)
		}
	}
}

// applyPush handles one server push. Runs only on the session goroutine, so
// config application and appliedConfigVersion stay race-free.
func (r *runner) applyPush(ctx, sessionCtx context.Context, c wire.Conn, f wire.Frame) error {
	switch {
	case f.DesiredState != nil:
		ds := f.DesiredState
		// Guard against out-of-order delivery: the server's fan-out builds
		// DesiredState on independent goroutines, so a push carrying version N
		// can arrive after N+1 was already applied. Applying it would silently
		// regress targets/intervals; equal versions re-apply harmlessly (the
		// content is identical and SetTargets is idempotent).
		if ds.ConfigVersion < r.appliedConfigVersion {
			log.Printf("ignoring stale config v%d (v%d already applied)", ds.ConfigVersion, r.appliedConfigVersion)
			return nil
		}
		for _, cfg := range r.deps.Configurables {
			cfg.SetTargets(ds.ProbeTargets)
		}
		r.deps.Scheduler.SetIntervals(
			time.Duration(ds.Intervals.BaseSeconds)*time.Second,
			time.Duration(ds.Intervals.RegularSeconds)*time.Second,
		)
		r.appliedConfigVersion = ds.ConfigVersion
		log.Printf("applied config v%d: %d probe targets", ds.ConfigVersion, len(ds.ProbeTargets))

	case f.SnapshotRequest != nil:
		req := f.SnapshotRequest
		// Re-check the launch flags (defense in depth): a request for a cap the
		// agent wasn't started with must never trigger collection. If nothing
		// permitted remains, drop the request outright.
		wantProcs := req.WantProcesses && r.deps.ReportProcs
		wantConns := req.WantConnections && r.deps.ReportConns
		if !wantProcs && !wantConns {
			log.Printf("dropping snapshot request %s: no permitted data requested", req.RequestID)
			return nil
		}
		// ~300ms CPU sample window; running it here just slips a drain tick
		// slightly, which is acceptable for an on-demand diagnostic.
		snap := r.deps.CollectSnapshot(ctx, req.RequestID, wantProcs, wantConns)
		// Fire and forget: snapshots live outside the sequence/ack path.
		if err := r.writeFrame(sessionCtx, c, wire.Frame{HostSnapshot: &snap}); err != nil {
			return fmt.Errorf("write snapshot req=%s: %w", req.RequestID, err)
		}
		log.Printf("sent host snapshot req=%s procs=%d conns=%d total=%d",
			req.RequestID, len(snap.Processes), len(snap.Connections), snap.ProcessTotal)
	}
	return nil
}

// writeFrame sends one frame with a bounded write deadline. The codec now lives
// in the transport adapter, so this only enforces the timeout that keeps a
// stuck writer from wedging the session.
func (r *runner) writeFrame(sessionCtx context.Context, c wire.Conn, f wire.Frame) error {
	wctx, cancel := context.WithTimeout(sessionCtx, writeTimeout)
	defer cancel()
	return c.WriteFrame(wctx, f)
}
