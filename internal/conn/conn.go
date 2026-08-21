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
	"math/rand"
	"sync/atomic"
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

// errEpochRotated marks a completed credential rotation (schema 8). The
// session that carried it out returns this so Run can end it and reconnect:
// the rotation result has already moved the runner's token and epoch, so the
// next session presents the rotated credential and the server re-drives the
// floor barrier for the new epoch. Run treats it like any other retryable
// session end — log, backoff, reconnect — which is why it stays unexported:
// nothing outside this package needs to branch on it, and the retry log line
// carries the epoch in its error text.
var errEpochRotated = errors.New("credential epoch rotated")

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

	// closeCauseGrace bounds how long a failed session waits for the reader to
	// report a close code the write missed. It is a race between two goroutines
	// reacting to the same TCP event, so it needs to cover scheduling, not
	// network latency.
	closeCauseGrace = 250 * time.Millisecond

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

	// WireSchema is the wire schema this runner dials with first. Zero (or the
	// native version) means the ordinary case: speak this build's own schema.
	// PreviousSchema means the agent has already learned that this particular
	// server is a release behind, and starting there saves it one refused
	// handshake per reconnect.
	//
	// It is a preference, not a lock. Whichever value it starts at, a server
	// that refuses the schema with CloseUnsupportedSchema gets one immediate
	// retry in the other one before the pairing is treated as terminal — the
	// refusal is as likely to mean "you are ahead of me" as "you are behind me",
	// and only trying tells them apart.
	WireSchema int

	// SchemaProbedAt is when this agent last offered its native schema to this
	// server. It only matters while running downgraded: the reconnect loop
	// re-offers the native schema once this is old enough, so a server that has
	// since been upgraded is picked up on its own without waiting for the agent
	// to be restarted. Zero means "not recently", which makes the first
	// reconnect of a downgraded session a probe.
	SchemaProbedAt time.Time

	// Dialer establishes the session link. Nil selects the default WebSocket
	// dialer built from ServerURL/Insecure/Format. The desktop injects the
	// embedded server's in-process pipe dialer here, so no loopback socket
	// is used and ServerURL/Format are then irrelevant.
	Dialer wire.Dialer

	// AgentID/SiteID stamp every telemetry packet (from the enrollment credential).
	AgentID string
	SiteID  string

	// EnrollmentEpoch is the credential generation this session runs under
	// (from the enrollment credential, schema 8). It gates the sequence-floor
	// barrier — no packet may be claimed or sent until the server pushes a
	// SequenceFloor for this epoch — and names the epoch a rotation request
	// signs itself out of. Zero means the credential predates schema 8: the
	// session runs without a barrier, exactly as it did before, because a
	// schema-8 server is required not to push floors to a zero-epoch Hello.
	EnrollmentEpoch uint64

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

	// OnAuthRejected, if non-nil, is called when the server refuses this agent's
	// credential on the upgrade request (HTTP 401/403), right after the runner
	// has quiesced that server's monitoring. Return true to abandon the
	// credential — Run returns ErrAuthRejected for a supervisor to re-enroll;
	// return false (or leave the hook nil) to keep retrying the credential, the
	// pre-hook behaviour, because a 401 can be transient and nothing is gained
	// by deleting a credential no token exists to replace.
	//
	// Must be fast and non-blocking: it runs on the session goroutine, and it is
	// the one place a supervisor is allowed to look at whether re-enrollment has
	// something to use without consulting the credential itself.
	OnAuthRejected func() bool

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

	// SignChallenge signs the server's epoch-rotation challenge with the ed25519
	// key this agent enrolled with, proving possession before the server issues
	// a rotated credential. agentrt wires the process key here (identity owns
	// the key file); a session that receives a challenge without a signer wired
	// is a wiring error and ends.
	SignChallenge func(challenge []byte) []byte

	// PersistRotation durably saves a rotated credential — the new bearer token
	// and epoch; the agent/site identity stay — so a crash after the rotation
	// comes back with the new credential rather than the dead one. agentrt wires
	// identity.SaveCredential here; this package deliberately never imports
	// identity.
	//
	// It runs on the session goroutine and it runs FIRST: nothing else about a
	// rotation happens until this has returned nil. It must be idempotent, since
	// a rotation the server re-issues after an interrupted attempt calls it again
	// with the same arguments. See applyRotationResult for the whole ordering
	// argument.
	PersistRotation func(epoch uint64, token string) error

	// PersistNegotiated records the wire schema this server was observed to
	// accept, so a restart does not rediscover it by being refused again. It is
	// called once per established session, on the session goroutine, and may
	// coalesce writes — it is a hint, and losing one costs a single extra
	// handshake.
	//
	// Nil disables the record entirely, which is what tests and any assembly
	// without durable state do; the session then behaves exactly as it would on
	// a first-ever run, every run.
	PersistNegotiated func(schema int) error
}

// previousSchema is the wire schema this build can still speak, one below its
// native one, kept so a server that is a single release behind can still be
// reported to.
//
// It is written out rather than derived from the native version on purpose.
// Keeping the version below speakable is a release decision — the release that
// withdraws it deletes this path — and deriving it would silently re-target the
// downgrade at a schema this binary cannot actually produce the moment the
// native version is bumped again.
const previousSchema = 7

// schemaReprobeInterval is how long a downgraded runner waits before offering
// its native schema again. The trade it balances is small in both directions: a
// probe that fails costs one refused handshake, while never probing leaves an
// agent talking the old schema to a server that was upgraded months ago — and
// nothing else would ever notice, because the downgraded session works.
//
// Jittered per runner so a fleet that was downgraded together does not re-probe
// together.
const schemaReprobeInterval = 24 * time.Hour

// otherSchema returns the schema to try when the server refuses this one. The
// set is exactly two: this build's native schema and the one below it.
func otherSchema(schema int) int {
	if schema == protocol.SchemaVersion {
		return previousSchema
	}
	return protocol.SchemaVersion
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
		schema:               protocol.SchemaVersion,
		lastNativeAt:         opts.SchemaProbedAt,
		// ±20% jitter, for the same thundering-herd reason the reconnect backoff
		// has it: a fleet downgraded by one server upgrade would otherwise all
		// re-probe in the same minute.
		reprobeAfter: time.Duration(float64(schemaReprobeInterval) * (1 + (rand.Float64()*0.4 - 0.2))),
	}
	if opts.WireSchema == previousSchema {
		r.schema = previousSchema
	}
	// Tell the outbox which enrolled identity this session runs under, before
	// anything can be claimed from it.
	//
	// Run is re-entered with a fresh AgentID whenever a revoked agent re-enrolls,
	// and without a console-issued reinstall token that enrollment mints a
	// BRAND-NEW agent. The backlog is grouped by server NAME, which survives the
	// exchange, so the first packet of this session would otherwise carry records
	// the old agent collected — and the server files every packet under the
	// identity it authenticated, putting the old agent's metrics, events,
	// traceroutes and incident scenes on the new agent's timeline. The store
	// discards them instead; see wal.Store.BindIdentity for why discard rather
	// than a handover under the old id.
	//
	// It happens here, and not in the enrollment loop that calls Run, because
	// this is the goroutine that owns this server's cursor — every NextBatch and
	// Ack runs on it — and no session has started yet, so the discard cannot race
	// the drain it exists to protect. The store logs the resulting gap itself,
	// naming both identities, so only the failure is reported here.
	if _, err := deps.Outbox.BindIdentity(opts.ServerName, opts.AgentID); err != nil {
		// Never fatal. Either this store has no cursor for the server (a wiring
		// bug the first drain reports too), or only the durable record of the
		// discard failed to land — the discard itself already stands in memory,
		// so nothing stale can go out on this session, and the next Open reaches
		// the same verdict from the identity stored beside the backlog.
		r.logf("bind outbox identity %s: %v", opts.AgentID, err)
	}
	// Reconcile the outbox's epoch with the credential this session runs under,
	// before anything can be claimed from it. Idempotent: on an ordinary start
	// it is a no-op (the rotation flow already moved the WAL, or the store
	// reloaded the persisted epoch), and after a crash between the rotation's
	// two durable writes — the WAL epoch landed, the credential write did not —
	// it re-syncs the cursor to the credential, which is the durable truth it
	// must follow. A real move re-queues the backlog for fresh sequences, the
	// same reclamation a rotation performs; see wal.Store.SetEpoch.
	if _, err := deps.Outbox.SetEpoch(opts.ServerName, opts.EnrollmentEpoch); err != nil {
		// Never fatal, and for the same reason as the identity bind above: the
		// in-memory move stands, and the next Run re-reads the credential and
		// re-drives the reconcile.
		r.logf("set outbox epoch %d: %v", opts.EnrollmentEpoch, err)
	}
	// Resume monitoring before the first dial. Everything downstream of the
	// collectors already survives an unreachable server; the target list was the
	// one thing that did not, which is why a router rebooted mid-outage used to
	// observe nothing at all until it reconnected.
	r.restoreProbeConfig()

	bo := &backoff{base: opts.backoffBase, cap: opts.backoffCap}
	for {
		// A runner that has been talking the older schema re-offers the native
		// one once the last attempt is stale enough. The timestamp is what makes
		// this safe to check on every dial: a downgrade that happened moments ago
		// set it to now, so the flip cannot undo itself, while a runner that has
		// been downgraded since a previous run picks the probe up from what that
		// run recorded. A refused probe simply flips straight back (below), so
		// the cost of an unnecessary one is a single handshake.
		if r.schema != protocol.SchemaVersion && time.Since(r.lastNativeAt) >= r.reprobeAfter {
			r.logf("offering wire schema %d again (the last attempt was %s ago)",
				protocol.SchemaVersion, time.Since(r.lastNativeAt).Round(time.Minute))
			r.schema, r.tried = protocol.SchemaVersion, nil
		}
		if r.schema == protocol.SchemaVersion {
			r.lastNativeAt = time.Now()
		}
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
			// A server that refuses the schema may simply be one release behind
			// this agent — or one ahead, after a rollback. Neither is knowable
			// from the close code, so try the other schema once, immediately and
			// without the backoff: the pairing is not broken until BOTH have been
			// refused. The tried set bounds it at two attempts per cycle and is
			// cleared the moment a session is established.
			if r.tried == nil {
				r.tried = map[int]bool{}
			}
			r.tried[r.schema] = true
			if alt := otherSchema(r.schema); !r.tried[alt] {
				r.logf("the server refused wire schema %d; retrying immediately with %d", r.schema, alt)
				r.schema = alt
				continue
			}
			r.quiesce("the server rejected this agent's schema version")
			return fmt.Errorf("server rejected wire schema %d and %d; upgrade the agent or server: %w",
				protocol.SchemaVersion, previousSchema, ErrUnsupportedSchema)
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
			// A refused credential is normally NOT terminal — the fix is at the
			// server end and needs no restart here — but the hook gives the
			// supervisor the one place to say "a fresh token is available; abandon
			// this dead credential and re-enroll". Only that verdict makes it
			// terminal; without it (or with the hook absent) the loop falls through
			// to the retry exactly as before.
			if r.opts.OnAuthRejected != nil && r.opts.OnAuthRejected() {
				return fmt.Errorf("server refused this agent's credential; a fresh token is available for re-enrollment: %w", err)
			}
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

	// schema is the wire schema the NEXT dial will use, and tried records which
	// schemas this reconnect cycle has already had refused. A cycle ends when a
	// session is established (the server answers with a frame of its own), which
	// clears tried: the two-schema search is per pairing attempt, not per
	// process, or a server that was refused once could never be reached again.
	schema int
	tried  map[int]bool
	// lastNativeAt is when the native schema was last offered to this server,
	// seeded from what a previous run recorded, and reprobeAfter is how stale
	// that may get before a downgraded runner offers it again.
	lastNativeAt time.Time
	reprobeAfter time.Duration
	// established is set by the reader the instant the server sends anything at
	// all, and negotiationRecorded says the resulting schema has already been
	// written down for this session. The first frame is the earliest honest
	// signal that the Hello was accepted: the server pushes its desired state
	// unconditionally on connect, so silence up to that point is exactly what a
	// refusal looks like.
	established         atomic.Bool
	negotiationRecorded bool

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

	// floor is the sequence floor the server pushed for THIS session (schema 8),
	// nil until it has been durably applied and the applied reply sent. It is
	// per-session state that happens to live on the runner — reset at the top of
	// session() — because the session goroutine is the sole writer of the runner
	// anyway; the barrier it gates is drain(), which checks it. While nil (and
	// the session's epoch is non-zero) nothing may be claimed or sent.
	floor *wire.SequenceFloor
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
	// Each session starts behind its own floor barrier: nothing this session
	// sends is under a floor the PREVIOUS session applied, so the server must
	// re-state it (and it does, on every connect).
	r.floor = nil
	r.established.Store(false)
	r.negotiationRecorded = false
	// The schema is read once, here, and passed to everything that needs it. The
	// reader runs on its own goroutine and outlives the return of this function
	// by an instant, while the field is reassigned by the reconnect loop — so
	// the value travels as an argument rather than being read from the runner.
	schema := r.schema
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
	hello := r.helloFor(schema)
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
	if schema == protocol.SchemaVersion {
		r.logf("connected to %s (agent %s)", r.opts.ServerURL, r.opts.AgentID)
	} else {
		r.logf("connected to %s (agent %s) speaking wire schema %d", r.opts.ServerURL, r.opts.AgentID, schema)
	}

	// One reader goroutine feeds these; the session goroutine is the ONLY
	// writer and the only place config/WAL state is touched, so no locking is
	// needed anywhere in the session.
	errCh := make(chan error, 2) // reader + pinger, at most one send each
	ackCh := make(chan wire.Ack, 1)
	ctrlCh := make(chan wire.Frame, 4)
	pushCh := make(chan wire.Frame, 4)

	go r.readLoop(sessionCtx, c, schema, ackCh, ctrlCh, pushCh, errCh)
	go r.pingLoop(sessionCtx, c, errCh)

	// The reader is still live here (endSession runs after this returns), which
	// is what lets a lost close code be recovered — see preferCloseCause.
	return r.preferCloseCause(r.sessionLoop(ctx, sessionCtx, c, schema, ackCh, ctrlCh, pushCh, errCh), errCh)
}

// preferCloseCause replaces a session error with the peer's close code when the
// reader has one and the error in hand does not.
//
// WHICH call observes a peer close is a race, not a fact about the close. A
// session with a backlog writes its first packet in the same breath as its
// Hello, so a server that answers the Hello by closing is as likely to be seen
// by that write as by the read — and the write does not see a close at all. The
// transport has already been torn down underneath it by the time it notices, so
// it reports something like "use of closed network connection", while the
// reader, the only thing that actually parses the close frame, holds the code.
//
// Losing that race must not lose the verdict. It decides whether the runner
// re-dials in the other wire schema, stops for a superseded credential, or
// deletes a revoked one — and the agents that lose it are precisely those with
// something queued to send.
func (r *runner) preferCloseCause(err error, errCh <-chan error) error {
	if err == nil || wire.CloseStatus(err) != -1 {
		return err
	}
	select {
	case readErr := <-errCh:
		if wire.CloseStatus(readErr) != -1 {
			return readErr
		}
	case <-time.After(closeCauseGrace):
		// The reader has nothing to say. Ordinary: most session failures are not
		// closes at all, and this bound is what keeps that case from waiting.
	}
	return err
}

// helloFor builds this session's Hello for the schema it is running under.
//
// The older schema's Hello is stripped of everything that schema does not
// define: no capability list and no enrollment epoch. A peer that does not know
// those keys would skip them anyway, so this is not about being understood — it
// is the sending half of the same rule the receiving half already follows.
// Declaring a capability is a promise to run its state machine, and a session
// that has deliberately turned those state machines off must not make the
// promise. The epoch goes for the same reason: it names a barrier this session
// will not be running.
func (r *runner) helloFor(schema int) wire.Hello {
	hello := r.opts.Hello
	hello.SchemaVersion = schema
	if schema != protocol.SchemaVersion {
		hello.Capabilities = nil
		hello.EnrollmentEpoch = 0
	}
	return hello
}

// noteNegotiated records the schema this session established, once. It runs on
// the session goroutine, off the flag the reader sets on the first frame it
// decodes.
//
// Establishing a session is also what closes the two-schema search: whatever
// was tried before, this pairing works, and the next refusal starts a fresh
// pair of attempts rather than inheriting a verdict from an earlier outage.
func (r *runner) noteNegotiated(schema int) {
	if r.negotiationRecorded || !r.established.Load() {
		return
	}
	r.negotiationRecorded = true
	r.tried = nil
	if r.deps.PersistNegotiated == nil {
		return
	}
	if err := r.deps.PersistNegotiated(schema); err != nil {
		// Non-fatal by construction: the record only saves a future handshake.
		r.logf("could not record the negotiated wire schema %d: %v", schema, err)
	}
}

// readLoop is the session's sole reader: it decodes each frame and routes it
// to the session goroutine. Any read/decode failure ends the session (via
// errCh) — after a transport error the frame stream cannot be trusted.
//
// The schema-8 control frames (SequenceFloor, EpochRotationChallenge,
// EpochRotationResult) get their own channel: they drive state machines the
// session goroutine runs, and mixing them into pushCh would let them queue
// behind config frames while a rotation or a barrier waits.
func (r *runner) readLoop(sessionCtx context.Context, c wire.Conn, schema int, ackCh chan<- wire.Ack, ctrlCh chan<- wire.Frame, pushCh chan<- wire.Frame, errCh chan<- error) {
	for {
		f, err := c.ReadFrame(sessionCtx)
		if err != nil {
			errCh <- err
			return
		}
		// Anything at all from the server means the Hello was accepted — the
		// earliest honest signal there is, since the server pushes its desired
		// state on connect without being asked. The session goroutine turns this
		// into the durable "this server speaks schema N" record.
		r.established.Store(true)
		switch {
		case f.Ack != nil:
			select {
			case ackCh <- *f.Ack:
			case <-sessionCtx.Done():
				return
			}
		case f.SequenceFloor != nil, f.EpochRotationChallenge != nil, f.EpochRotationResult != nil:
			if schema != protocol.SchemaVersion {
				// This session declared no capabilities and no epoch, so these
				// frames are ones the peer was told not to send. They are not
				// merely ignored: the agent has no way to answer them under this
				// schema, and half-answering a barrier or a rotation is worse
				// than not having one. End the session and reconnect — defining a
				// close code for it is the server's prerogative, not the agent's.
				errCh <- fmt.Errorf("server sent a schema-%d control frame on a schema-%d session", protocol.SchemaVersion, schema)
				return
			}
			select {
			case ctrlCh <- f:
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
			// Hello/Packet/HostSnapshot/SequenceFloorApplied/EpochRotationRequest/
			// EpochRotationChallengeRequest flow agent→server only; a server that
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
func (r *runner) sessionLoop(ctx, sessionCtx context.Context, c wire.Conn, schema int, ackCh <-chan wire.Ack, ctrlCh <-chan wire.Frame, pushCh <-chan wire.Frame, errCh <-chan error) error {
	// Immediate first drain: a freshly-(re)connected session should flush
	// whatever accumulated while offline without waiting a full tick —
	// preserves the old loop's fast-startup behavior. (It stays behind the
	// floor barrier: until the server pushes a SequenceFloor for this epoch,
	// drain is a no-op.)
	if err := r.drain(ctx, sessionCtx, c, schema, ackCh, ctrlCh, pushCh, errCh); err != nil {
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
		// Cheap and idempotent after the first time: the flag is set by the
		// reader the instant the server says anything, and this is the session
		// goroutine's first opportunity to act on it.
		r.noteNegotiated(schema)
		select {
		case <-ctx.Done():
			return ctx.Err() // Run maps shutdown to a clean nil return
		case err := <-errCh:
			return err
		case f := <-pushCh:
			if err := r.applyPush(ctx, sessionCtx, c, f); err != nil {
				return err
			}
		case f := <-ctrlCh:
			if err := r.applyControl(ctx, sessionCtx, c, f, pushCh, errCh, ctrlCh); err != nil {
				return err
			}
		case ms := <-trackerUpdates:
			// Runtime target-policy transition — write the full-state frame on the
			// session goroutine (single-writer invariant preserved).
			if err := r.writeFrame(sessionCtx, c, wire.Frame{MonitorStatus: &ms}); err != nil {
				return fmt.Errorf("write monitor status: %w", err)
			}
		case <-ticker.C:
			if err := r.drain(ctx, sessionCtx, c, schema, ackCh, ctrlCh, pushCh, errCh); err != nil {
				return err
			}
		}
	}
}

// applyControl runs one server→agent control frame: the sequence-floor
// barrier and the epoch-rotation state machine (schema 8). All of it runs on
// the session goroutine, so the WAL cursor, the runner's floor and the
// socket's single-writer invariant stay untouched by anyone else.
func (r *runner) applyControl(ctx, sessionCtx context.Context, c wire.Conn, f wire.Frame, pushCh <-chan wire.Frame, errCh <-chan error, ctrlCh <-chan wire.Frame) error {
	switch {
	case f.SequenceFloor != nil:
		return r.applySequenceFloor(sessionCtx, c, f.SequenceFloor)
	case f.EpochRotationChallenge != nil:
		return r.applyRotationChallenge(ctx, sessionCtx, c, f.EpochRotationChallenge, pushCh, errCh, ctrlCh)
	default: // EpochRotationResult
		// A result with no in-flight rotation here is the server RE-ISSUING a
		// committed rotation the agent missed (the phase-1 crash-recovery path):
		// the agent persisted the old credential before the result ever arrived,
		// and the server answers its next reconnect with the same idempotent
		// result. Accept it like a solicited one — persist and reconnect.
		if f.EpochRotationResult == nil {
			return fmt.Errorf("server sent an invalid control frame")
		}
		return r.applyRotationResult(f.EpochRotationResult)
	}
}

// applySequenceFloor applies the server's pre-claim barrier: validate the
// floor against this session's epoch, durably fast-forward the allocator past
// it, and either open the drain or — when an in-flight claim sits at or below
// the floor, which must never be re-served under its sequence — ask the server
// for an epoch rotation instead.
func (r *runner) applySequenceFloor(sessionCtx context.Context, c wire.Conn, floor *wire.SequenceFloor) error {
	if r.floor != nil {
		// One floor per session. A second one means the server is confused about
		// the phase, and anything sent from here on is of uncertain validity.
		return fmt.Errorf("server sent a second sequence floor in one session")
	}
	if floor.EnrollmentEpoch != r.opts.EnrollmentEpoch {
		// The floor is scoped to the epoch the credential names. A mismatch means
		// the server's view of this agent's credential generation differs from
		// ours — non-terminal: the session ends, and the server drives a
		// rotation challenge on the reconnect.
		return fmt.Errorf("sequence floor for epoch %d does not match this session's epoch %d",
			floor.EnrollmentEpoch, r.opts.EnrollmentEpoch)
	}
	conflict, err := r.deps.Outbox.ApplyFloor(r.opts.ServerName, floor.EnrollmentEpoch, floor.SequenceFloor)
	if err != nil {
		return fmt.Errorf("apply sequence floor %d: %w", floor.SequenceFloor, err)
	}
	if conflict {
		// An in-flight claim at or below the floor may never be served again
		// under its sequence, and the WAL never renumbers a claim in place. The
		// only way forward is a fresh epoch: ask the server to challenge us, and
		// keep the barrier closed — r.floor stays nil, so drain keeps returning
		// immediately — until the rotation lands and the session reconnects.
		if err := r.writeFrame(sessionCtx, c, wire.Frame{EpochRotationChallengeRequest: &wire.EpochRotationChallengeRequest{Reason: "claim_below_floor"}}); err != nil {
			return fmt.Errorf("write rotation challenge request: %w", err)
		}
		r.logf("in-flight claim at or below floor %d; requested an epoch rotation", floor.SequenceFloor)
		return nil
	}
	r.floor = floor
	if err := r.writeFrame(sessionCtx, c, wire.Frame{SequenceFloorApplied: &wire.SequenceFloorApplied{
		EnrollmentEpoch: floor.EnrollmentEpoch,
		SequenceFloor:   floor.SequenceFloor,
	}}); err != nil {
		return fmt.Errorf("write sequence floor applied: %w", err)
	}
	r.logf("sequence floor %d applied for epoch %d (session %s)", floor.SequenceFloor, floor.EnrollmentEpoch, floor.SessionID)
	return nil
}

// applyRotationChallenge answers a server-driven credential rotation: verify
// the challenge is usable, prove possession of the enrolled key, and await the
// server's verdict.
func (r *runner) applyRotationChallenge(ctx, sessionCtx context.Context, c wire.Conn, ch *wire.EpochRotationChallenge, pushCh <-chan wire.Frame, errCh <-chan error, ctrlCh <-chan wire.Frame) error {
	if ch.Challenge == "" {
		return fmt.Errorf("server sent an empty epoch rotation challenge")
	}
	if !ch.ExpiresAt.After(r.anchoredNow()) {
		return fmt.Errorf("epoch rotation challenge already expired at %s", ch.ExpiresAt.Format(time.RFC3339))
	}
	if r.deps.SignChallenge == nil {
		return fmt.Errorf("epoch rotation challenge received but no challenge signer is wired")
	}
	sig := r.deps.SignChallenge([]byte(ch.Challenge))
	if err := r.writeFrame(sessionCtx, c, wire.Frame{EpochRotationRequest: &wire.EpochRotationRequest{
		Challenge: ch.Challenge,
		OldEpoch:  r.opts.EnrollmentEpoch,
		Signature: sig,
	}}); err != nil {
		return fmt.Errorf("write epoch rotation request: %w", err)
	}
	r.logf("answered epoch rotation challenge (reason %q); awaiting the server's verdict", ch.Reason)
	return r.awaitRotationResult(ctx, sessionCtx, c, pushCh, errCh, ctrlCh)
}

// awaitRotationResult blocks for the server's verdict on an in-flight rotation
// request. It follows awaitAck's pattern for the same deadlock reason: config
// pushes keep being consumed inline while waiting, or the reader would stall
// sending to pushCh and the result could never be read off the wire.
func (r *runner) awaitRotationResult(ctx, sessionCtx context.Context, c wire.Conn, pushCh <-chan wire.Frame, errCh <-chan error, ctrlCh <-chan wire.Frame) error {
	timer := time.NewTimer(r.opts.ackTimeout)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-errCh:
			return err
		case f := <-pushCh:
			if err := r.applyPush(ctx, sessionCtx, c, f); err != nil {
				return err
			}
		case f := <-ctrlCh:
			if f.EpochRotationResult == nil {
				return fmt.Errorf("server sent an unexpected control frame while a rotation was in flight")
			}
			return r.applyRotationResult(f.EpochRotationResult)
		case <-timer.C:
			return fmt.Errorf("no epoch rotation result within %s: %w", r.opts.ackTimeout, errAckTimeout)
		}
	}
}

// applyRotationResult acts on the server's verdict for the rotation request
// this session sent. A denial, a retry or an unknown status is a plain session
// error and the old credential stays in force.
//
// # Why the accepted case is strictly durable-first
//
// A rotation touches three things, and the order they move in is the whole
// design — each step is the precondition of the next:
//
//  1. the credential on disk (with the desired-state cache re-keyed to it: one
//     atomic step, either both or neither);
//  2. the outbox's epoch;
//  3. the identity this process is using.
//
// Persisting first is what makes a crash survivable in the only direction that
// converges. A crash after step 1 leaves a credential the server knows about,
// and the next start presents it; a crash before step 1 leaves the OLD
// credential, which the server is required to keep honouring until the new one
// is first used, and the reconnect gets the same result re-issued idempotently.
// Either way the durable state is a credential the agent can actually
// authenticate with.
//
// The reverse — move the process onto the new token first and chase the disk
// write afterwards — was what this did before, and it trades a recoverable
// failure for an unrecoverable one: a machine that loses power between the
// switch and the write comes back holding a credential nobody ever wrote down,
// with the old one already abandoned in memory. That is a permanently
// unauthenticatable agent, and re-enrollment is the only way out of it. The
// price of the durable-first order is that a failed disk write means the
// rotation simply did not happen this time: the session ends, the OLD token
// reconnects, and the server re-drives the same rotation. That is a retry, not
// a loss.
//
// Step 2 is deliberately non-fatal on its own. The credential is already
// durable at that point, and the session start reconciles the outbox's epoch
// from the credential (see Run) — the one direction that always converges.
func (r *runner) applyRotationResult(res *wire.EpochRotationResult) error {
	switch res.Status {
	case wire.RotationOK:
		if res.NewEpoch <= r.opts.EnrollmentEpoch {
			return fmt.Errorf("server rotated to epoch %d, not above the current %d", res.NewEpoch, r.opts.EnrollmentEpoch)
		}
		if res.AgentToken == "" {
			return fmt.Errorf("server rotated the credential but issued no agent token")
		}
		// Step 1. A failure here abandons the rotation for this session: the old
		// credential is still the durable one and still valid, so ending the
		// session and reconnecting under it is both correct and recoverable.
		if err := r.persistRotation(res.NewEpoch, res.AgentToken); err != nil {
			return fmt.Errorf("rotation to epoch %d not applied — the credential could not be saved: %w", res.NewEpoch, err)
		}
		// Step 2.
		if _, err := r.deps.Outbox.SetEpoch(r.opts.ServerName, res.NewEpoch); err != nil {
			r.logf("set outbox epoch %d: %v (the credential is already durable; the next session start re-syncs it)", res.NewEpoch, err)
		}
		// Step 3.
		r.opts.Token = res.AgentToken
		r.opts.EnrollmentEpoch = res.NewEpoch
		r.opts.Hello.EnrollmentEpoch = res.NewEpoch
		return fmt.Errorf("credential rotated to epoch %d; reconnecting under the new identity: %w", res.NewEpoch, errEpochRotated)
	default:
		// Denied, retry and any unknown status share one shape: this session's
		// rotation failed, the old credential stays in force, and the server
		// re-drives a fresh challenge on the reconnect (or not, for a denial —
		// either way nothing here needs to remember the attempt).
		reason := res.Reason
		if reason == "" {
			reason = res.Status
		}
		return fmt.Errorf("epoch rotation %s: %s", res.Status, reason)
	}
}

// persistRotation durably writes one rotated credential and re-keys the
// desired-state cache to it. Both halves or neither: a credential on disk whose
// cache is still bound to the retired bearer would restore nothing after a
// restart, so a failed re-key is reported as a failed persist and the caller
// abandons the rotation.
//
// A missing hook fails the rotation rather than being ignored. Running a
// rotation with nowhere to write it is the wiring bug that produces the
// unauthenticatable agent described in applyRotationResult, and the failure
// belongs at the moment it can still be declined.
func (r *runner) persistRotation(epoch uint64, token string) error {
	if r.deps.PersistRotation == nil {
		return fmt.Errorf("no persistence hook is wired for the rotated credential (epoch %d)", epoch)
	}
	if err := r.deps.PersistRotation(epoch, token); err != nil {
		return err
	}
	if r.deps.Desired != nil {
		if err := r.deps.Desired.Rebind(token); err != nil {
			return fmt.Errorf("re-key desired-state cache to epoch %d: %w", epoch, err)
		}
	}
	r.logf("persisted the rotated credential (epoch %d)", epoch)
	return nil
}

// anchoredNow is the session's best reading of the server's current time, for
// judging server-stated deadlines (the rotation challenge's ExpiresAt). A
// wrong wall clock is the ordinary case on the devices this agent runs on, so
// a clock anchor that can produce a corrected time wins; the wall clock is the
// fallback, and it is also what an unanchored session has to be content with.
func (r *runner) anchoredNow() time.Time {
	if r.deps.Clock != nil {
		if n, ok := r.deps.Clock.(interface{ ServerNow() time.Time }); ok {
			return n.ServerNow()
		}
	}
	return time.Now()
}

// drain uploads pending WAL batches over the socket, one ack-confirmed packet
// at a time (semantics carried over from the old uploader loop: bounded per
// tick, same-sequence retry on failure, server dedups on agent_id+sequence).
// All WAL access happens here, on the session goroutine, so the store never
// sees concurrent claims.
func (r *runner) drain(ctx, sessionCtx context.Context, c wire.Conn, schema int, ackCh <-chan wire.Ack, ctrlCh <-chan wire.Frame, pushCh <-chan wire.Frame, errCh <-chan error) error {
	// The sequence-floor barrier. Until the server has pushed a floor for this
	// session's epoch and the agent has durably applied it, no packet may be
	// claimed or sent — the server enforces the same ordering on its side and
	// treats an early packet as a protocol error. A zero-epoch session (a
	// credential enrolled before the barrier existed) has no barrier: the server
	// is required not to push floors to it, so gating would stall every legacy
	// install forever.
	//
	// A session running the older schema has no barrier either, and the test is
	// on the SCHEMA rather than on the epoch. The two are independent: a server
	// rolled back to the older schema still faces an agent holding a credential
	// that was rotated to a non-zero epoch while it was current. Gating on the
	// epoch alone would leave that agent waiting forever for a floor the server
	// no longer knows how to send — an agent that is connected, healthy, and
	// silent.
	if r.floor == nil && r.opts.EnrollmentEpoch != 0 && schema == protocol.SchemaVersion {
		return nil
	}
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
			// The packet's schema follows the SESSION, not the build. The
			// receiving side validates it exactly as it validates the Hello, so a
			// downgraded session that stamped its build's native version here
			// would be refused at its first packet — with a healthy handshake and
			// a working link, which is the hardest shape of this bug to see.
			SchemaVersion:      schema,
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
		ack, err := r.awaitAck(ctx, sessionCtx, c, schema, ackCh, ctrlCh, pushCh, errCh, batch.Sequence)
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
func (r *runner) awaitAck(ctx, sessionCtx context.Context, c wire.Conn, schema int, ackCh <-chan wire.Ack, ctrlCh <-chan wire.Frame, pushCh <-chan wire.Frame, errCh <-chan error, seq uint64) (wire.Ack, error) {
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
		case f := <-ctrlCh:
			// A control frame while a claim is in flight is the schema-8 recovery
			// path: a sequence-conflict rotation challenge (the server withholds
			// the ack and challenges instead) must be answered here, not after the
			// ack timeout. Applying it inline ends the session with the rotation's
			// verdict (errEpochRotated), which abandons the in-flight claim and
			// reconnects under the new credential.
			if err := r.applyControl(ctx, sessionCtx, c, f, pushCh, errCh, ctrlCh); err != nil {
				return wire.Ack{}, err
			}
		case ack := <-ackCh:
			if ack.HighestSequence < seq {
				// A lower-water ack cannot confirm this claim: accepting it would
				// delete a packet the server never said it stored. It is exactly
				// what a stale or unsolicited ack looks like (they sit in ackCh
				// until the next awaitAck reads them), so drop it and keep
				// waiting for one that names this claim. The claim, the drain and
				// the allocator are untouched either way.
				r.logf("ignoring ack with watermark=%d below the in-flight sequence=%d", ack.HighestSequence, seq)
				continue
			}
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
