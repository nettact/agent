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
	"github.com/nettact/agent/internal/monitoreval"
	"github.com/nettact/agent/internal/proxydial"
	"github.com/nettact/agent/internal/wal"
	"github.com/nettact/protocol"
	pcfg "github.com/nettact/protocol/config"
	"github.com/nettact/protocol/permission"
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
	// ServerName is this session's key in the agent's per-server state: which WAL
	// cursor it drains and which credential it holds. It is the configured entry
	// name, not the URL or the agent id, because those are respectively editable
	// and assigned by the very enrollment the name has to survive.
	ServerName string

	ServerURL string // e.g. http://localhost:8080; scheme maps http→ws, https→wss
	Token     string // bearer token presented on the upgrade request
	Insecure  bool   // skip TLS verification (LAN self-signed dev)
	Format    string // wire.SubprotocolProtobuf or wire.SubprotocolJSON

	// Dialer establishes the session link. Nil selects the default WebSocket
	// dialer built from ServerURL/Insecure/Format. The desktop injects the
	// embedded server's in-process pipe dialer here, so no loopback socket
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

// GameApplier receives the site's game-capture configuration from DesiredState
// pushes. It is a second, independent configuration axis: game profiles and
// probe targets change at unrelated times and carry their own version numbers,
// so they are applied through separate hooks rather than one "here is the new
// state" call (see applyPush).
//
// Applying the same configuration twice must be harmless — the implementation
// is expected to compare before acting, because acting means restarting the
// sensor process.
type GameApplier interface {
	ApplyGameConfig(cfg pcfg.GameConfig)
}

// Deps are the agent-side components the session drives.
type Deps struct {
	Outbox        *wal.Store
	Configurables []Configurable
	Scheduler     IntervalSetter
	DrainInterval time.Duration // how often to drain the WAL over the socket

	// Tracker evaluates each pushed monitor against effective permissions and the
	// target-access policy, yielding the runnable subset and the full-state
	// MonitorStatus frame reported to the server.
	Tracker *monitoreval.Tracker

	// Proxies owns the egress proxies pushed alongside the targets. It is reconciled
	// from the DesiredState BEFORE the monitors are evaluated, so evaluation sees the
	// proxy set the collectors will actually dial through. Nil disables proxying: a
	// pinned target then evaluates as proxy-missing rather than dialing directly.
	Proxies *proxydial.Manager

	// Game applies the pushed game-capture configuration. Nil when this build has
	// no game sensor to configure — the ordinary case for an install that does not
	// ship one — in which case the game half of a push is simply not acted on.
	Game GameApplier

	// Effective/Granted/Supported are the agent's permission views, used to
	// classify each requested snapshot scope (collected/denied/unsupported).
	Effective permission.Set
	Granted   permission.Set
	Supported permission.Set

	// SnapshotMinInterval rate-limits back-to-back snapshot requests; SnapshotTimeout
	// bounds one collection. Zero selects sane defaults.
	SnapshotMinInterval time.Duration
	SnapshotTimeout     time.Duration

	// CollectSnapshot produces a live host snapshot for the granted scopes. Nil
	// selects hostsnapshot.Collect; tests inject a stub to avoid the CPU sample
	// window.
	CollectSnapshot func(ctx context.Context, requestID string, collect permission.Set) telemetry.HostSnapshot

	// CollectIncidentSnapshot answers one config.IncidentSnapshotRequest with an
	// immutable incident-scene snapshot (INCIDENT-002). It runs OFF the session
	// goroutine (applyPush returns immediately) and its result Frame is written
	// back by the single session writer. Nil disables the feature: the request is
	// acknowledged as handled and dropped (tests that never push it).
	CollectIncidentSnapshot func(ctx context.Context, req pcfg.IncidentSnapshotRequest) telemetry.IncidentSnapshot

	// RunTrace executes one config.TraceRequest (DIAG-001) and returns its terminal
	// telemetry.TraceResult. Like CollectIncidentSnapshot it runs off the session
	// goroutine; the engine it wraps owns the per-Agent concurrency limit.
	// receivedAt is the request's arrival instant, captured on the session
	// goroutine, so the engine anchors the request budget there instead of
	// wherever the worker happened to be scheduled. Nil disables the feature.
	RunTrace func(ctx context.Context, req pcfg.TraceRequest, receivedAt time.Time) telemetry.TraceResult
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
	if deps.SnapshotMinInterval == 0 {
		deps.SnapshotMinInterval = 3 * time.Second
	}
	if deps.SnapshotTimeout == 0 {
		deps.SnapshotTimeout = 10 * time.Second
	}

	r := &runner{
		opts:   opts,
		deps:   deps,
		dialer: opts.Dialer,
		// Start behind any real version so the server's unconditional
		// on-connect DesiredState push is always applied, even after an agent
		// restart where the server thinks we are current. Both axes start there
		// for the same reason.
		appliedConfigVersion: -1,
		appliedGameVersion:   -1,
	}

	bo := &backoff{base: opts.backoffBase, cap: opts.backoffCap}
	for {
		start := time.Now()
		err := r.session(ctx)
		// The session is gone, so nothing is draining the outbox's memory tier
		// any more: spill it now rather than waiting out its age trigger, so the
		// moment the link drops the crash-loss window closes to zero instead of
		// staying open for up to memBufferAge. Same goroutine as every other WAL
		// access; on shutdown Close flushes again, which is an idempotent no-op.
		if ferr := r.deps.Outbox.Flush(); ferr != nil {
			r.logf("flush outbox after session end: %v", ferr)
		}
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
		r.logf("session ended: %v; reconnecting in %s", err, delay.Round(time.Millisecond))
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(delay):
		}
	}
}

// runner holds the state that survives across sessions. The applied-version
// counters are in-memory only and touched exclusively by the session goroutine.
type runner struct {
	opts   Options
	deps   Deps
	dialer wire.Dialer

	appliedConfigVersion int
	// appliedGameVersion is the game-configuration serial this process has
	// installed. It is a separate counter because the server bumps it
	// separately: a profile edit leaves ConfigVersion untouched, and a monitor
	// edit leaves this untouched (see applyPush).
	appliedGameVersion int
	lastSnapshotAt     time.Time
}

// logf writes a session log line tagged with the server it belongs to. Every
// configured server has a runner of its own writing to the same log, and lines
// like "session ended, reconnecting" or "applied config v7" mean nothing without
// knowing which one said them.
func (r *runner) logf(format string, args ...any) {
	log.Printf("[%s] "+format, append([]any{r.opts.ServerName}, args...)...)
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

	// aw carries the async request machinery: incident-snapshot and traceroute
	// pushes are handled OFF this goroutine (applyPush returns immediately) but
	// their result Frames are funneled back through resultCh so the single
	// session writer stays the only thing touching the socket. The in-flight sets
	// are touched only on the session goroutine (applyPush inserts, sessionLoop
	// clears), so they need no locking. resultCh is bounded; background workers
	// drop their result if the session ends first.
	aw := &asyncWork{
		resultCh:      make(chan wire.Frame, asyncResultBuffer),
		inflightSnap:  map[string]struct{}{},
		inflightTrace: map[string]struct{}{},
	}

	go r.readLoop(sessionCtx, c, ackCh, pushCh, errCh)
	go r.pingLoop(sessionCtx, c, errCh)

	return r.sessionLoop(ctx, sessionCtx, c, ackCh, pushCh, errCh, aw)
}

// asyncWork is one session's machinery for the asynchronous server->Agent
// requests (incident snapshot, traceroute). Background workers compute a result
// and push its Frame onto resultCh; the session goroutine drains resultCh, does
// the actual socket write, and clears the matching in-flight id. Duplicate
// in-flight request ids are ignored, so a server re-push while work is running
// is idempotent.
type asyncWork struct {
	resultCh      chan wire.Frame
	inflightSnap  map[string]struct{} // keyed by IncidentSnapshotRequest.RequestID
	inflightTrace map[string]struct{} // keyed by TraceRequest.ReportID
}

// asyncResultBuffer bounds the per-session result channel. It comfortably covers
// the per-Agent traceroute concurrency (4) plus a few incident snapshots without
// the session goroutine ever being the bottleneck; a full channel only briefly
// parks a finished worker until the next drain.
const asyncResultBuffer = 16

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
		case f.DesiredState != nil, f.SnapshotRequest != nil,
			f.IncidentSnapshotRequest != nil, f.TraceRequest != nil:
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
func (r *runner) sessionLoop(ctx, sessionCtx context.Context, c wire.Conn, ackCh <-chan wire.Ack, pushCh <-chan wire.Frame, errCh <-chan error, aw *asyncWork) error {
	// Immediate first drain: a freshly-(re)connected session should flush
	// whatever accumulated while offline without waiting a full tick —
	// preserves the old loop's fast-startup behavior.
	if err := r.drain(ctx, sessionCtx, c, ackCh, pushCh, errCh, aw); err != nil {
		return err
	}
	ticker := time.NewTicker(r.deps.DrainInterval)
	defer ticker.Stop()
	// trackerUpdates is the cap-1 latest-wins channel of runtime MonitorStatus
	// transitions; nil when no tracker is wired (tests).
	var trackerUpdates <-chan wire.MonitorStatus
	if r.deps.Tracker != nil {
		trackerUpdates = r.deps.Tracker.Updates()
	}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err() // Run maps shutdown to a clean nil return
		case err := <-errCh:
			return err
		case f := <-pushCh:
			if err := r.applyPush(ctx, sessionCtx, c, f, aw); err != nil {
				return err
			}
		case f := <-aw.resultCh:
			// A background incident-snapshot/traceroute worker finished: write its
			// result on the session goroutine (single-writer invariant) and clear the
			// in-flight id so a later request with the same id can run again.
			r.clearInflight(aw, f)
			if err := r.writeFrame(sessionCtx, c, f); err != nil {
				return fmt.Errorf("write async result: %w", err)
			}
		case ms := <-trackerUpdates:
			// Runtime target-policy transition — write the full-state frame on the
			// session goroutine (single-writer invariant preserved).
			if err := r.writeFrame(sessionCtx, c, wire.Frame{MonitorStatus: &ms}); err != nil {
				return fmt.Errorf("write monitor status: %w", err)
			}
		case <-ticker.C:
			if err := r.drain(ctx, sessionCtx, c, ackCh, pushCh, errCh, aw); err != nil {
				return err
			}
		}
	}
}

// clearInflight removes the in-flight id a finished async result Frame answers,
// so a subsequent server re-push of the same request executes again.
func (r *runner) clearInflight(aw *asyncWork, f wire.Frame) {
	switch {
	case f.IncidentSnapshot != nil:
		delete(aw.inflightSnap, f.IncidentSnapshot.RequestID)
	case f.TraceResult != nil:
		delete(aw.inflightTrace, f.TraceResult.ReportID)
	}
}

// drain uploads pending WAL batches over the socket, one ack-confirmed packet
// at a time (semantics carried over from the old uploader loop: bounded per
// tick, same-sequence retry on failure, server dedups on agent_id+sequence).
// All WAL access happens here, on the session goroutine, so the store never
// sees concurrent claims.
func (r *runner) drain(ctx, sessionCtx context.Context, c wire.Conn, ackCh <-chan wire.Ack, pushCh <-chan wire.Frame, errCh <-chan error, aw *asyncWork) error {
	for i := 0; i < maxBatchesPerDrain; i++ {
		batch, ok, err := r.deps.Outbox.NextBatch(r.opts.ServerName, batchItems)
		if err != nil {
			// A WAL read error is local and usually transient (busy timeout);
			// keep the session alive and retry next tick, as the old loop did.
			r.logf("wal next batch: %v", err)
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
			GameRuns:              batch.GameRuns,
			GameBuckets:           batch.GameBuckets,
			GameGaps:              batch.GameGaps,
			GameHostSeconds:       batch.GameHostSeconds,
			ReportedConfigVersion: r.appliedConfigVersion,
		}
		if err := r.writeFrame(sessionCtx, c, wire.Frame{Packet: &pkt}); err != nil {
			return fmt.Errorf("write packet seq=%d: %w", batch.Sequence, err)
		}
		ack, err := r.awaitAck(ctx, sessionCtx, c, ackCh, pushCh, errCh, aw, batch.Sequence)
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
			r.logf("wal fast-forward to watermark=%d: %v", ack.HighestSequence, err)
			return nil
		}
		if err := r.deps.Outbox.Ack(r.opts.ServerName, batch.Sequence); err != nil {
			r.logf("wal ack seq=%d: %v", batch.Sequence, err)
		}
		r.logf("sent seq=%d metrics=%d events=%d inv=%d (watermark=%d, pending=%d)",
			batch.Sequence, len(pkt.Metrics), len(pkt.Events), len(pkt.InventoryDelta),
			ack.HighestSequence, r.deps.Outbox.Pending(r.opts.ServerName))
	}
	return nil
}

// awaitAck blocks until the in-flight packet is acknowledged. It keeps
// consuming pushCh while it waits — the deadlock guard: if pushes queued up
// unconsumed, the reader would block sending to pushCh and the ack could never
// be read off the wire.
func (r *runner) awaitAck(ctx, sessionCtx context.Context, c wire.Conn, ackCh <-chan wire.Ack, pushCh <-chan wire.Frame, errCh <-chan error, aw *asyncWork, seq uint64) (wire.Ack, error) {
	timer := time.NewTimer(r.opts.ackTimeout)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return wire.Ack{}, ctx.Err()
		case err := <-errCh:
			return wire.Ack{}, err
		case f := <-pushCh:
			if err := r.applyPush(ctx, sessionCtx, c, f, aw); err != nil {
				return wire.Ack{}, err
			}
		case f := <-aw.resultCh:
			// Keep the single-writer result path flowing while a packet ack is
			// outstanding, so a finished worker never wedges behind a full channel.
			r.clearInflight(aw, f)
			if err := r.writeFrame(sessionCtx, c, f); err != nil {
				return wire.Ack{}, fmt.Errorf("write async result: %w", err)
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
// config application and the applied-version guards stay race-free. DesiredState
// and the host SnapshotRequest are served inline (unchanged); the incident-snapshot
// and traceroute requests are dispatched to a background worker and answered
// asynchronously via aw.resultCh, so this call returns immediately and the WAL
// drain/ack/config/monitor-status flow is never blocked by diagnostic work.
func (r *runner) applyPush(ctx, sessionCtx context.Context, c wire.Conn, f wire.Frame, aw *asyncWork) error {
	switch {
	case f.DesiredState != nil:
		ds := f.DesiredState
		// One push, two independent configuration axes. The probe half and the
		// game half carry their own serials and are bumped by unrelated edits, so
		// a frame can be stale on one and fresh on the other: renaming a game
		// profile re-pushes an unchanged ConfigVersion, and adding a monitor
		// re-pushes an unchanged game Version. Each half is therefore guarded
		// separately — a stale probe version must not skip a fresh game block, and
		// vice versa.
		//
		// The game half goes first because it writes nothing to the socket and
		// cannot fail: putting it after the probe half would let a MonitorStatus
		// write failure (which ends the session) swallow a configuration the agent
		// has already been handed.
		r.applyGameConfig(ds.Game)
		if err := r.applyProbeConfig(sessionCtx, c, ds); err != nil {
			return err
		}

	case f.SnapshotRequest != nil:
		req := f.SnapshotRequest
		snap := r.collectSnapshot(ctx, req)
		// The agent ALWAYS answers a snapshot request — including the all-denied
		// case — so the console never waits out the old timeout.
		if err := r.writeFrame(sessionCtx, c, wire.Frame{HostSnapshot: &snap}); err != nil {
			return fmt.Errorf("write snapshot req=%s: %w", req.RequestID, err)
		}
		r.logf("sent host snapshot req=%s scopes=%d procs=%d conns=%d",
			req.RequestID, len(snap.Scopes), len(snap.Processes), len(snap.Connections))

	case f.IncidentSnapshotRequest != nil:
		r.dispatchIncidentSnapshot(sessionCtx, aw, *f.IncidentSnapshotRequest)

	case f.TraceRequest != nil:
		r.dispatchTrace(sessionCtx, aw, *f.TraceRequest)
	}
	return nil
}

// applyGameConfig installs the pushed game-capture configuration, if it is new
// enough to be worth installing. A nil block means the server has nothing to say
// about game capture on this push, which is not the same as an empty one — the
// latter is a deliberate "no profiles, record everything" and does get applied.
//
// Runs on the session goroutine, so appliedGameVersion needs no locking.
func (r *runner) applyGameConfig(game *pcfg.GameConfig) {
	if game == nil || r.deps.Game == nil {
		return
	}
	// Same out-of-order guard as the probe axis, on this axis's own serial.
	// Equal versions re-apply: the applier compares the resulting sensor
	// configuration and only acts on a real change, so a repeat costs nothing.
	if game.Version < r.appliedGameVersion {
		r.logf("ignoring stale game config v%d (v%d already applied)", game.Version, r.appliedGameVersion)
		return
	}
	r.deps.Game.ApplyGameConfig(*game)
	r.appliedGameVersion = game.Version
	r.logf("applied game config v%d: %d profiles (record unmatched=%v)",
		game.Version, len(game.Profiles), game.RecordUnmatched)
}

// applyProbeConfig installs the monitoring half of a DesiredState push: proxies,
// probe targets and tier intervals, followed by the full-state MonitorStatus
// frame attesting the generation now running.
func (r *runner) applyProbeConfig(sessionCtx context.Context, c wire.Conn, ds *pcfg.DesiredState) error {
	// Guard against out-of-order delivery: the server's fan-out builds
	// DesiredState on independent goroutines, so a push carrying version N
	// can arrive after N+1 was already applied. Applying it would silently
	// regress targets/intervals; equal versions re-apply harmlessly.
	if ds.ConfigVersion < r.appliedConfigVersion {
		r.logf("ignoring stale config v%d (v%d already applied)", ds.ConfigVersion, r.appliedConfigVersion)
		return nil
	}
	// Reconcile the egress proxies FIRST. Two reasons for the ordering: monitor
	// evaluation below needs the live proxy set to decide whether each pinned
	// target is runnable at all, and a proxy whose generation changed must be torn
	// down before the collectors are handed targets that reference it — otherwise
	// the first cycle of the new generation could still ride the old tunnel or the
	// old credentials.
	if r.deps.Proxies != nil {
		r.deps.Proxies.Apply(ds.Proxies)
	}
	// Evaluate every monitor against effective permissions and target policy.
	// Only the runnable subset reaches the collectors, so a permission/target
	// blocked monitor is never scheduled and produces no synthetic failure.
	runnable := ds.ProbeTargets
	var frame *wire.MonitorStatus
	if r.deps.Tracker != nil {
		run, f := r.deps.Tracker.ApplyDesired(ds.ConfigVersion, ds.ProbeTargets)
		runnable = run
		frame = &f
	}
	// Install this generation in the collectors and scheduler and advance the
	// stale-version guard BEFORE attesting it: the full-state MonitorStatus frame
	// must describe a generation the agent is actually running, never one that is
	// merely evaluated. appliedConfigVersion moves in lockstep with the targets/
	// intervals now in place, so a subsequent stale-config guard reflects what is
	// truly installed.
	for _, cfg := range r.deps.Configurables {
		cfg.SetTargets(runnable)
	}
	r.deps.Scheduler.SetIntervals(
		time.Duration(ds.Intervals.BaseSeconds)*time.Second,
		time.Duration(ds.Intervals.RegularSeconds)*time.Second,
	)
	r.appliedConfigVersion = ds.ConfigVersion
	// Emit the full-state MonitorStatus only after applying config (covers the
	// reconnect/restart reevaluation for free). A write failure here is reported
	// after the generation is fully installed, so a reconnect re-attests state
	// consistent with what the agent is running.
	if frame != nil {
		if werr := r.writeFrame(sessionCtx, c, wire.Frame{MonitorStatus: frame}); werr != nil {
			return fmt.Errorf("write monitor status: %w", werr)
		}
	}
	r.logf("applied config v%d: %d probe targets (%d runnable)", ds.ConfigVersion, len(ds.ProbeTargets), len(runnable))
	return nil
}

// dispatchIncidentSnapshot starts the asynchronous incident-scene collection for
// one request (INCIDENT-002). It is a no-op-with-dedupe on the session goroutine:
// a duplicate in-flight RequestID is ignored (the server re-push is idempotent),
// and the actual collection runs on a background goroutine bounded by the request
// budget and canceled with the session. The collector always answers within the
// budget, so the worker always produces exactly one result Frame.
func (r *runner) dispatchIncidentSnapshot(sessionCtx context.Context, aw *asyncWork, req pcfg.IncidentSnapshotRequest) {
	if r.deps.CollectIncidentSnapshot == nil {
		r.logf("ignoring incident snapshot req=%s: collector not wired", req.RequestID)
		return
	}
	if _, dup := aw.inflightSnap[req.RequestID]; dup {
		r.logf("ignoring duplicate in-flight incident snapshot req=%s", req.RequestID)
		return
	}
	aw.inflightSnap[req.RequestID] = struct{}{}
	// Anchor the budget here, on the session goroutine, rather than inside the
	// worker: the budget is defined as running from the request's arrival, and
	// scheduling the goroutine first would silently hand back whatever the delay
	// was. The collector answers every group within it; a worker that finishes
	// after the session ended drops its result (server reconnect re-push retries).
	ctx := budgetCtx(sessionCtx, req.BudgetMs)
	go func() {
		snap := r.deps.CollectIncidentSnapshot(ctx.ctx, req)
		ctx.cancel()
		r.deliver(sessionCtx, aw, wire.Frame{IncidentSnapshot: &snap})
	}()
}

// dispatchTrace starts the asynchronous traceroute for one request (DIAG-001).
// Duplicate in-flight ReportIDs are ignored idempotently; distinct reports run
// concurrently up to the engine's per-Agent limit. The engine owns clamping,
// destination resolution/policy, and terminal-status classification, so this
// only handles dedupe, cancellation scope, and single-writer delivery.
func (r *runner) dispatchTrace(sessionCtx context.Context, aw *asyncWork, req pcfg.TraceRequest) {
	if r.deps.RunTrace == nil {
		r.logf("ignoring trace req=%s: engine not wired", req.ReportID)
		return
	}
	if _, dup := aw.inflightTrace[req.ReportID]; dup {
		r.logf("ignoring duplicate in-flight trace report=%s", req.ReportID)
		return
	}
	aw.inflightTrace[req.ReportID] = struct{}{}
	// Arrival instant for the request budget, taken here rather than in the worker
	// for the same reason as the incident snapshot above.
	receivedAt := time.Now()
	go func() {
		// The engine owns the request budget and total-timeout window (so it can tell
		// an exhausted budget apart from a session cancel); it is given the raw
		// session context, which cancels the trace on reconnect/shutdown.
		res := r.deps.RunTrace(sessionCtx, req, receivedAt)
		r.deliver(sessionCtx, aw, wire.Frame{TraceResult: &res})
	}()
}

// deliver hands a finished result Frame to the session writer, or drops it if the
// session ended first (its in-flight id dies with the session; a server re-push
// on the next connection retries). It never writes to the socket itself — that
// stays the sole province of the session goroutine.
func (r *runner) deliver(sessionCtx context.Context, aw *asyncWork, f wire.Frame) {
	select {
	case aw.resultCh <- f:
	case <-sessionCtx.Done():
	}
}

// boundedCtx pairs a derived context with its cancel so a worker can release
// timer resources deterministically once its result is in hand.
type boundedCtx struct {
	ctx    context.Context
	cancel context.CancelFunc
}

// budgetCtx derives a worker context from the session context, bounded by the
// request's own budget measured from this agent's clock (config.BudgetWindow — a
// duration precisely so server/agent clock skew cannot eat the window). Callers
// invoke it at the request's arrival, so arrival and evaluation are the same
// instant. Session cancellation (reconnect/shutdown) still cancels the work; a
// spent budget yields an already-expired context, so the worker reports its
// terminal timed-out state instead of collecting.
func budgetCtx(sessionCtx context.Context, budgetMs int) boundedCtx {
	now := time.Now()
	deadline, ok := pcfg.BudgetWindow(budgetMs, now, now)
	if !ok {
		deadline = now
	}
	ctx, cancel := context.WithDeadline(sessionCtx, deadline)
	return boundedCtx{ctx: ctx, cancel: cancel}
}

// collectSnapshot classifies each requested scope (collected/denied/unsupported/
// failed), collects only the effective scopes, and merges the per-scope results.
// gopsutil is invoked only for effective scopes.
func (r *runner) collectSnapshot(ctx context.Context, req *pcfg.SnapshotRequest) telemetry.HostSnapshot {
	requested := permission.FromStrings(req.Scopes)

	// Rate-limit back-to-back requests.
	if !r.lastSnapshotAt.IsZero() && time.Since(r.lastSnapshotAt) < r.deps.SnapshotMinInterval {
		snap := telemetry.HostSnapshot{TS: time.Now().UTC(), RequestID: req.RequestID}
		for _, id := range requested.Sorted() {
			snap.Scopes = append(snap.Scopes, telemetry.SnapshotScopeResult{Scope: string(id), Status: telemetry.ScopeFailed, Reason: "rate_limited"})
		}
		return snap
	}
	r.lastSnapshotAt = time.Now()

	// Classify each requested scope; build the effective collect set.
	collect := permission.Set{}
	extra := map[string]telemetry.SnapshotScopeResult{}
	for id := range requested {
		switch {
		case r.deps.Effective.Has(id) && depsRequested(id, requested):
			collect.Add(id)
		case r.deps.Effective.Has(id):
			// The scope is granted and effective, but its base scope was not
			// requested, so no rows will carry its fields — reject it rather than
			// claim it was collected.
			extra[string(id)] = telemetry.SnapshotScopeResult{Scope: string(id), Status: telemetry.ScopeDenied, Reason: "unsatisfied_dependency"}
		case r.deps.Granted.Has(id) && !r.deps.Supported.Has(id):
			extra[string(id)] = telemetry.SnapshotScopeResult{Scope: string(id), Status: telemetry.ScopeUnsupported}
		case !isKnownScope(id):
			extra[string(id)] = telemetry.SnapshotScopeResult{Scope: string(id), Status: telemetry.ScopeFailed, Reason: "unknown_scope"}
		default:
			reason := ""
			if missingDep(id, requested, r.deps.Effective) {
				reason = "unsatisfied_dependency"
			}
			extra[string(id)] = telemetry.SnapshotScopeResult{Scope: string(id), Status: telemetry.ScopeDenied, Reason: reason}
		}
	}

	cctx, cancel := context.WithTimeout(ctx, r.deps.SnapshotTimeout)
	defer cancel()
	snap := r.deps.CollectSnapshot(cctx, req.RequestID, collect)

	// Merge the denied/unsupported/failed results, keeping canonical order.
	merged := snap.Scopes
	for _, id := range requested.Sorted() {
		if e, ok := extra[string(id)]; ok {
			merged = append(merged, e)
		}
	}
	snap.Scopes = merged
	return snap
}

// isKnownScope reports whether id is a compiled process/connection snapshot scope.
func isKnownScope(id permission.ID) bool {
	switch id {
	case permission.HostProcessBasicRead, permission.HostProcessOwnerRead,
		permission.HostProcessResourceRead, permission.HostProcessIORead,
		permission.HostConnectionSummaryRead, permission.HostConnectionLocalRead,
		permission.HostConnectionRemoteRead, permission.HostConnectionOwnerRead:
		return true
	default:
		return false
	}
}

// missingDep reports whether a denied scope is denied because a required parent
// is not effective (so the console can say "unsatisfied_dependency").
func missingDep(id permission.ID, requested, effective permission.Set) bool {
	for _, parent := range permission.Dependencies(id) {
		if !effective.Has(parent) {
			return true
		}
	}
	return false
}

// depsRequested reports whether every required base scope of id is also present
// in the request. A child scope (e.g. process.owner) carries its fields on the
// rows produced by its base scope (process.basic); if the base is not requested,
// no rows exist to carry the child's data, so it cannot be collected.
func depsRequested(id permission.ID, requested permission.Set) bool {
	for _, parent := range permission.Dependencies(id) {
		if !requested.Has(parent) {
			return false
		}
	}
	return true
}

// writeFrame sends one frame with a bounded write deadline. The codec now lives
// in the transport adapter, so this only enforces the timeout that keeps a
// stuck writer from wedging the session.
func (r *runner) writeFrame(sessionCtx context.Context, c wire.Conn, f wire.Frame) error {
	wctx, cancel := context.WithTimeout(sessionCtx, writeTimeout)
	defer cancel()
	return c.WriteFrame(wctx, f)
}
