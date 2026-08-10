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

	"github.com/nettact/agent/internal/desiredstate"
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

	// ErrAuthRejected: the server refused the credential on the upgrade request
	// (HTTP 401/403). Unlike the three above it is NOT terminal — the runner
	// keeps retrying, because the fix ("re-add the agent", "the clock skew that
	// invalidated the token is gone") is at the server end and needs no restart
	// here. It exists only so the failure classifies as auth rather than as an
	// anonymous dial error: the handshake response is the sole place that
	// distinction survives, and it is discarded a line later.
	ErrAuthRejected = errors.New("server rejected agent credential")
)

// errAckTimeout marks the "session open but not acking" failure so Classify can
// name it. It is unexported because nothing outside this package branches on
// it; the exported vocabulary for that state is ReasonAckTimeout.
var errAckTimeout = errors.New("no acknowledgement from server")

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
	// (re)connect.
	Hello wire.Hello

	// OnSession, if non-nil, is called with up=true right after the Hello frame
	// is written (the session is live) and up=false when that session ends. It
	// lets a supervisor surface connected/disconnected without treating a
	// transient reconnect as an error. Must be fast and non-blocking: it runs on
	// the session goroutine.
	OnSession func(up bool)

	// OnRetry, if non-nil, is called once per failed attempt — a dial that never
	// connected or a session that ended — with the error that ended it and the
	// delay Run will wait before redialing. Terminal outcomes return from Run
	// instead and never fire it.
	//
	// It exists because the delay is knowable in exactly one place and one
	// instant: the backoff computes it here and immediately sleeps on it, so a
	// supervisor that wants to say "retrying in 32s" cannot derive it afterwards
	// from anything Run exposes. Pairing it with the error keeps the two halves
	// of "why, and how long" from having to be re-joined by the caller.
	//
	// Must be fast and non-blocking: it runs on the session goroutine, between
	// the failure and the sleep.
	OnRetry func(err error, retryIn time.Duration)

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

// DiagApplier receives the site's path-diagnostic policy from DesiredState
// pushes. It governs the agent's OWN traceroute trigger — the server states the
// policy but no longer issues the command — so it is applied like any other half
// of a push and never answered on the socket.
//
// The pointer is passed through rather than dereferenced here because "the
// server said nothing" and "the server stated an all-zero policy" are different
// instructions, and only the applier knows what its defaults are.
type DiagApplier interface {
	ApplyDiagPolicy(p *pcfg.DiagPolicy)
}

// GameApplier receives the site's game-capture configuration from DesiredState// pushes. It is a second, independent configuration axis: game profiles and
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

// ClockAnchor is told what the server thinks the time is, so telemetry stamped
// by a wall clock nothing has set can still be uploaded under the times it
// actually happened at. Implemented by internal/clockmon.
type ClockAnchor interface {
	// Anchor states that the server's clock read serverTime at the instant this
	// agent's read localTime.
	Anchor(serverTime, localTime time.Time)
}

// serverClock is the optional half of a transport: a link that learned the
// server's clock during its own handshake.
//
// It is an interface satisfied by the WebSocket adapter rather than a method on
// wire.Conn because only that transport has an answer. The desktop's in-process
// pipe connects a server running on this very machine, reading this very clock —
// there is no skew to measure and nothing to report.
type serverClock interface {
	ServerDate() (time.Time, bool)
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

	// Diag applies the pushed path-diagnostic policy to this server's traceroute
	// trigger. Nil in tests and in builds with no trigger wired.
	Diag DiagApplier

	// Desired persists the probe half of this server's applied DesiredState, so a
	// restart while the server is unreachable restores the targets instead of
	// leaving the agent with nothing to probe. Nil (tests) simply disables the
	// restore: the session then learns its targets the way it always did.
	Desired *desiredstate.Binding

	// Clock learns how wrong this machine's wall clock is, from the server's own
	// time. Nil disables the anchor; step detection is independent of it.
	Clock ClockAnchor

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
		//
		// restoreProbeConfig below may lift these to a cached generation. That does
		// not weaken the guarantee: the guard ignores versions strictly LOWER than
		// the applied one, so the on-connect push — carrying the same version when
		// nothing changed — still installs, and with it the proxies the cache
		// deliberately never stored.
		appliedConfigVersion: -1,
		appliedGameVersion:   -1,
	}
	// Resume monitoring before the first dial. Everything downstream of the
	// collectors already survives an unreachable server; the target list was the
	// one thing that did not, which is why a router rebooted mid-outage used to
	// observe nothing at all until it reconnected.
	r.restoreProbeConfig()

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
		//
		// Each one is also an identity verdict, so each stops this server's
		// monitoring before returning. Run returns here but the pipeline behind it
		// does not stop: the collectors and the scheduler live on the process
		// context, so without quiesce they would keep executing the last target
		// list — indefinitely, and after a restart too now that the list is cached
		// on disk.
		switch wire.CloseStatus(err) {
		case wire.CloseSuperseded:
			r.quiesce("another instance took over this credential")
			return fmt.Errorf("another agent instance connected with this credential: %w", ErrSuperseded)
		case wire.CloseUnsupportedSchema:
			r.quiesce("the server rejected this agent's schema version")
			return fmt.Errorf("server rejected schema version %d; upgrade the agent or server: %w", protocol.SchemaVersion, ErrUnsupportedSchema)
		case wire.CloseRevoked:
			r.quiesce("this agent was deleted on the server")
			return fmt.Errorf("agent was deleted on the server; re-enroll to continue: %w", ErrRevoked)
		}
		// A refused credential is not terminal — the fix is at the server end and
		// needs no restart here — but it is still the server saying it does not
		// accept this identity, so the targets that identity was issued stop
		// running until it does. Quiescing on the FIRST rejection rather than after
		// some number of them is deliberate: the cost of being wrong about a
		// transient refusal is a pause in probing that the next successful session
		// undoes by itself (the on-connect push reinstalls everything), while the
		// cost of the opposite mistake is an agent that was deleted server-side
		// probing third parties on its behalf forever.
		if errors.Is(err, ErrAuthRejected) {
			r.quiesce("the server refused this agent's credential")
		}
		if time.Since(start) > stableSession {
			bo.reset()
		}
		delay := bo.next()
		if r.opts.OnRetry != nil {
			r.opts.OnRetry(err, delay)
		}
		// One line per attempt; backoff caps this at ~2 lines/min steady-state,
		// so an unreachable server doesn't flood the log. It carries the whole
		// answer on purpose — kind of failure, raw cause, when the next try is,
		// and how much is queued behind the outage — because on the platforms
		// with no status surface this line IS the status surface. Same goroutine
		// as every other outbox access here.
		r.logf("session ended (%s): %v; reconnecting in %s (pending %d)",
			Classify(err), err, delay.Round(time.Millisecond), r.deps.Outbox.Pending(r.opts.ServerName))
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
	// appliedDiagSerial is the diagnostic-policy generation installed, guarded
	// by haveDiagSerial because the serial is unsigned and cannot start behind
	// zero the way the two ints above start at -1. Its own axis for the same
	// reason as theirs: only diag_* edits move it, and DesiredState builds can
	// be delivered out of build order — unguarded, a stale enabled=true
	// arriving last would keep the tracer running after the operator switched
	// diagnostics off.
	appliedDiagSerial uint64
	haveDiagSerial    bool
	lastSnapshotAt    time.Time

	// appliedGame/appliedDiag are the blocks currently INSTALLED on their own
	// axes, kept so the cache stores what this agent is running rather than
	// whatever rode along with the last accepted probe push.
	//
	// The three axes are guarded independently and can arrive out of order, so a
	// fresh probe generation routinely carries a game or diag block that its own
	// guard rejected as stale. Persisting the incoming push would write that
	// rejected block to disk — and a restart during an outage would then restore
	// configuration the runner had explicitly refused — while a fresh game block
	// arriving on a stale probe push would never be persisted at all.
	appliedGame *pcfg.GameConfig
	appliedDiag *pcfg.DiagPolicy

	// persistedDigest is the desiredstate.Digest of the configuration currently
	// on disk, or "" when nothing is (which includes a save that failed). It —
	// not the version counter — decides whether an applied configuration needs
	// persisting; see desiredstate.Digest for why a version test is wrong twice
	// over. A failed save leaves it unchanged, so the next push retries.
	persistedDigest string
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
	// Take the clock anchor before anything is sent. The session's first act is
	// to drain whatever accumulated while this server was unreachable, and on a
	// router that backlog IS the outage — collected under a clock a power cut
	// reset. Anchoring off the first acknowledgement would arrive strictly after
	// that drain had already gone out with the wrong times on it, so the only
	// useful moment is the handshake that has just completed.
	if sc, ok := c.(serverClock); ok && r.deps.Clock != nil {
		if st, have := sc.ServerDate(); have {
			r.deps.Clock.Anchor(st, time.Now())
		}
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
	// headers. (The server pushes DesiredState unconditionally on connect, so
	// Hello carries no applied-config watermark; MonitorStatus is that signal.)
	hello := r.opts.Hello
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
	// Say so out loud. Success used to be inferable only from a later drain or
	// config line, which means a healthy agent with nothing yet to send looked
	// exactly like a broken one in the log.
	r.logf("connected to %s (agent %s)", r.opts.ServerURL, r.opts.AgentID)

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
			if err := r.applyPush(ctx, sessionCtx, c, f); err != nil {
				return err
			}
		case ms := <-trackerUpdates:
			// Runtime target-policy transition — write the full-state frame on the
			// session goroutine (single-writer invariant preserved).
			if err := r.writeFrame(sessionCtx, c, wire.Frame{MonitorStatus: &ms}); err != nil {
				return fmt.Errorf("write monitor status: %w", err)
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
// All WAL access happens here, on the session goroutine, so the store never
// sees concurrent claims.
func (r *runner) drain(ctx, sessionCtx context.Context, c wire.Conn, ackCh <-chan wire.Ack, pushCh <-chan wire.Frame, errCh <-chan error) error {
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
			SchemaVersion:      protocol.SchemaVersion,
			AgentID:            r.opts.AgentID,
			SiteID:             r.opts.SiteID,
			Sequence:           batch.Sequence,
			SentAt:             time.Now().UTC(),
			Metrics:            batch.Metrics,
			Events:             batch.Events,
			InventoryDelta:     batch.Inventory,
			InterfaceSnapshots: batch.Snapshots,
			GameRuns:           batch.GameRuns,
			GameBuckets:        batch.GameBuckets,
			GameGaps:           batch.GameGaps,
			GameHostSeconds:    batch.GameHostSeconds,
			TraceResults:       batch.TraceResults,
			SceneReports:       batch.SceneReports,
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
		// Every ack restates the server's clock. The handshake already anchored
		// this session, so in the ordinary case this only confirms it — but a
		// session that outlives an NTP failure, or one whose handshake carried no
		// Date header, learns it here instead.
		if r.deps.Clock != nil {
			r.deps.Clock.Anchor(ack.ServerTime, time.Now())
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
			return wire.Ack{}, fmt.Errorf("ack timeout for seq=%d: %w", seq, errAckTimeout)
		}
	}
}

// applyPush handles one server push. Runs only on the session goroutine, so
// config application and the applied-version guards stay race-free.
//
// Every push is served inline, and there is deliberately no machinery here for
// serving one anywhere else. There used to be: the incident-snapshot request was
// computed on a background worker and its answer funnelled back through a result
// channel so the single session writer stayed the only thing touching the socket.
// Both of the pushes that needed that are gone — the agent triggers its own
// traceroutes and its own incident scenes, and both ride the WAL — so the
// machinery went with them. Anything added here that cannot answer promptly needs
// that path rebuilt rather than blocking the drain/ack/config flow.
func (r *runner) applyPush(ctx, sessionCtx context.Context, c wire.Conn, f wire.Frame) error {
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
		// has already been handed. The diagnostic policy rides with it for the same
		// reason, on its own serial axis (see the runner fields): it governs a
		// trigger that must keep working while the session it arrived on is down,
		// so a fresh policy applies even on a frame both other halves call stale.
		r.applyGameConfig(ds.Game)
		if r.deps.Diag != nil && ds.Diag != nil {
			switch {
			case !r.haveDiagSerial || ds.Diag.Serial > r.appliedDiagSerial:
				r.deps.Diag.ApplyDiagPolicy(ds.Diag)
				r.appliedDiagSerial, r.haveDiagSerial = ds.Diag.Serial, true
				r.appliedDiag = ds.Diag
			case ds.Diag.Serial < r.appliedDiagSerial:
				r.logf("ignoring stale diag policy serial %d (serial %d already applied)",
					ds.Diag.Serial, r.appliedDiagSerial)
			}
		}
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
	r.appliedGame = game
	r.logf("applied game config v%d: %d profiles (record unmatched=%v)",
		game.Version, len(game.Profiles), game.RecordUnmatched)
}

// applyProbeConfig installs the monitoring half of a DesiredState push: proxies,
// probe targets and tier intervals, followed by the full-state MonitorStatus
// frame attesting the generation now running.
func (r *runner) applyProbeConfig(sessionCtx context.Context, c wire.Conn, ds *pcfg.DesiredState) error {
	frame, ok := r.installProbeConfig(ds)
	if !ok {
		return nil
	}
	// Emit the full-state MonitorStatus only after applying config (covers the
	// reconnect/restart reevaluation for free). A write failure here is reported
	// after the generation is fully installed, so a reconnect re-attests state
	// consistent with what the agent is running.
	if frame != nil {
		if werr := r.writeFrame(sessionCtx, c, wire.Frame{MonitorStatus: frame}); werr != nil {
			return fmt.Errorf("write monitor status: %w", werr)
		}
	}
	return nil
}

// installProbeConfig puts one probe configuration into the collectors, the
// scheduler and the disk cache, and returns the MonitorStatus frame attesting it
// (nil when no tracker is wired). ok=false means the push was stale and nothing
// was touched.
//
// It writes nothing to the socket, which is what lets the boot-time restore
// (restoreProbeConfig) reuse the exact install sequence — ordering included —
// with no session in existence. The attestation is the session's business and
// stays in applyProbeConfig.
func (r *runner) installProbeConfig(ds *pcfg.DesiredState) (*wire.MonitorStatus, bool) {
	// Guard against out-of-order delivery: the server's fan-out builds
	// DesiredState on independent goroutines, so a push carrying version N
	// can arrive after N+1 was already applied. Applying it would silently
	// regress targets/intervals; equal versions re-apply harmlessly.
	if ds.ConfigVersion < r.appliedConfigVersion {
		r.logf("ignoring stale config v%d (v%d already applied)", ds.ConfigVersion, r.appliedConfigVersion)
		return nil, false
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
	// Persist between installing and attesting. Ordering matters in one
	// direction only: what reaches the disk must already be running, so a restart
	// restores a configuration this agent actually applied rather than one it was
	// merely offered. Persisting before the attestation (rather than after) also
	// means a MonitorStatus write failure — which ends the session — cannot lose a
	// configuration the agent has already installed.
	r.persistProbeConfig(ds)
	r.logf("applied config v%d: %d probe targets (%d runnable)", ds.ConfigVersion, len(ds.ProbeTargets), len(runnable))
	return frame, true
}

// persistProbeConfig caches the applied configuration for the next boot, unless
// an identical one is already on disk.
//
// A save failure is logged and otherwise ignored: the cache is an availability
// optimization for a server that is unreachable later, never a correctness
// requirement, and an agent that cannot write it still monitors exactly as it
// did before this cache existed. persistedDigest is left untouched on failure,
// so the next push — or the on-connect re-push after any reconnect — retries.
func (r *runner) persistProbeConfig(ds *pcfg.DesiredState) {
	if r.deps.Desired == nil {
		return
	}
	cfg := desiredstate.Config{
		ConfigVersion: ds.ConfigVersion,
		ProbeTargets:  ds.ProbeTargets,
		Intervals:     ds.Intervals,
		// The APPLIED blocks, not this push's. See the runner fields: the three
		// axes are guarded independently, so the game and diag blocks riding along
		// with an accepted probe generation are routinely ones their own guards
		// rejected.
		Game: r.appliedGame,
		Diag: r.appliedDiag,
	}
	digest := desiredstate.Digest(cfg)
	if digest != "" && digest == r.persistedDigest {
		return
	}
	if err := r.deps.Desired.Save(cfg); err != nil {
		r.logf("could not cache config v%d for the next restart: %v", ds.ConfigVersion, err)
		return
	}
	r.persistedDigest = digest
}

// restoreProbeConfig installs the configuration cached by a previous run, before// any session exists. It is called once per process, from Run.
//
// This is what keeps a rebooted agent monitoring through the rest of an outage.
// The collectors and the scheduler already run independently of any session and
// queue into the WAL regardless of reachability; the target list was the only
// thing that needed a live server, so restoring it is the whole fix.
//
// Restoring does NOT make the agent believe it is configured for good: the
// stale-version guard ignores versions strictly lower than the applied one, so
// the server's unconditional on-connect push — which carries the same version
// when nothing changed — still installs, and with it everything the cache
// deliberately omits (the proxies). Targets pinned to a proxy therefore sit out
// the offline window as proxy-missing and start on the first cycle after the
// session returns, which is exactly what they would do on a first-ever boot.
func (r *runner) restoreProbeConfig() {
	if r.deps.Desired == nil {
		return
	}
	cfg, ok := r.deps.Desired.Load()
	if !ok {
		return
	}
	ds := &pcfg.DesiredState{
		ConfigVersion: cfg.ConfigVersion,
		ProbeTargets:  cfg.ProbeTargets,
		Intervals:     cfg.Intervals,
		Game:          cfg.Game,
		Diag:          cfg.Diag,
	}
	// Seed the digest from what was just read, so a restore that changes nothing
	// does not immediately rewrite the same bytes back to flash.
	r.persistedDigest = desiredstate.Digest(cfg)
	// The game and diagnostic axes are restored through the same appliers a push
	// uses, so their own serial guards advance identically — and the applied
	// blocks are recorded, so the next probe push re-persists what is running
	// rather than dropping them.
	r.applyGameConfig(ds.Game)
	if r.deps.Diag != nil && ds.Diag != nil {
		r.deps.Diag.ApplyDiagPolicy(ds.Diag)
		r.appliedDiagSerial, r.haveDiagSerial = ds.Diag.Serial, true
		r.appliedDiag = ds.Diag
	}
	frame, ok := r.installProbeConfig(ds)
	if !ok {
		return
	}
	runnable := 0
	if frame != nil {
		for _, e := range frame.Statuses {
			if e.Status == wire.MonitorStatusActive {
				runnable++
			}
		}
	}
	r.logf("restored cached config v%d from disk: %d probe targets (%d runnable); probing resumes before the server is reachable",
		ds.ConfigVersion, len(ds.ProbeTargets), runnable)
}

// quiesce stops this server's monitoring after the server has said, in one way
// or another, that it does not accept this agent's identity.
//
// It exists because returning from Run does not stop anything. The collectors,
// the scheduler and the traceroute trigger belong to the process, not to the
// session, and they keep executing whatever target list was last installed. That
// was survivable while the list died with the process; once it is cached on
// disk, an agent deleted server-side would come back after every reboot and
// probe third parties on behalf of a server that has disowned it.
//
// It clears three things, in the order that leaves nothing running at any point:
// the collectors' targets (so no new cycle starts), the tracker's evaluation
// state (so a later push is evaluated from scratch rather than diffed against a
// generation nobody is running), and the proxies (which hold real OS resources —
// tunnels, sockets — that no longer have anything to carry). Then it forgets the
// disk cache, so a restart does not undo all of it.
//
// The version counters are wound back so the next accepted session installs from
// zero: the server's on-connect push carries whatever version it likes, and none
// of them should be judged stale against a generation that has been torn down.
//
// Game capture stops too, when there was any. An earlier version of this left
// the sensor alone on the theory that it is one process shared by every server,
// so silencing it here would speak for servers that had not been refused — but
// that is not how it is wired: only the game owner (Servers[0]) is given an
// applier at all, and only its data is ever queued, so this runner having one
// means the refusal IS the owner's. Leaving it running would be worse than
// untidy now that the cache restores game configuration before the first dial:
// an agent deleted server-side would resume capturing what people play, from
// disk, on every reboot, forever. The stop is expressed in the configuration's
// own vocabulary — no profiles and no unmatched recording is exactly "capture
// nothing" — rather than as a new sensor verb.
func (r *runner) quiesce(reason string) {
	for _, cfg := range r.deps.Configurables {
		cfg.SetTargets(nil)
	}
	if r.deps.Tracker != nil {
		r.deps.Tracker.ApplyDesired(r.appliedConfigVersion, nil)
	}
	if r.deps.Proxies != nil {
		r.deps.Proxies.Apply(nil)
	}
	if r.deps.Game != nil && r.appliedGame != nil {
		// Only when capture was actually configured. The applier is wired for the
		// game owner whether or not anything has been pushed or restored, and its
		// supervisor treats the FIRST configuration as the signal to start — so an
		// unconditional stop here would spawn the sensor in order to silence it,
		// on an agent that had never been told to capture anything at all.
		//
		// Straight to the applier, not through applyGameConfig: its staleness
		// guard is about ordering pushes from a server that is still talking to
		// us, and this is the one case that has to win regardless of serial.
		r.deps.Game.ApplyGameConfig(pcfg.GameConfig{})
	}
	if r.deps.Desired != nil {
		if err := r.deps.Desired.Forget(); err != nil {
			// The cache outlives this process, so a failure here is the one part of
			// quiesce that a restart would undo. Say so plainly rather than leaving
			// a returning agent's probing unexplained.
			r.logf("could not drop the cached config after %s: %v; a restart may resume the old targets", reason, err)
		}
	}
	r.appliedConfigVersion, r.appliedGameVersion = -1, -1
	r.appliedDiagSerial, r.haveDiagSerial = 0, false
	r.appliedGame, r.appliedDiag = nil, nil
	r.persistedDigest = ""
	r.logf("stopped monitoring for this server: %s", reason)
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
