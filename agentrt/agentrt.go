// Package agentrt is the agent runtime as an importable library: one blocking
// Run that owns identity, enrollment, the collector scheduler, the status
// heartbeat, and the persistent server session. The standalone nettact-agent
// command and the desktop all-in-one both drive the same code through this
// package — the command is a thin environment→Config wrapper, and the desktop
// passes an in-process enrollment TokenSource so no token ever touches a CLI.
//
// Run never calls log.Fatal, never parses flags, and never installs signal
// handlers; the caller owns process lifecycle via ctx. All traffic stays
// agent-initiated outbound — the agent never listens on a port.
package agentrt

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	pshost "github.com/shirou/gopsutil/v3/host"

	"github.com/nettact/agent/internal/collector"
	"github.com/nettact/agent/internal/conn"
	"github.com/nettact/agent/internal/enroll"
	"github.com/nettact/agent/internal/gamesense"
	"github.com/nettact/agent/internal/clockmon"
	"github.com/nettact/agent/internal/desiredstate"
	"github.com/nettact/agent/internal/identity"
	"github.com/nettact/agent/internal/netguard"
	"github.com/nettact/agent/internal/platform"
	"github.com/nettact/agent/internal/traceroute"
	"github.com/nettact/agent/internal/wal"
	"github.com/nettact/agent/probepolicy"
	"github.com/nettact/protocol"
	pcfg "github.com/nettact/protocol/config"
	protoenroll "github.com/nettact/protocol/enroll"
	gs "github.com/nettact/protocol/gamesense"
	"github.com/nettact/protocol/permission"
	"github.com/nettact/protocol/telemetry"
	"github.com/nettact/protocol/wire"
)

// blockedSensor remembers which blocked-sensor outcome this process has already
// reported, so a supervisor that re-runs Run does not re-report an unchanged
// one. Keyed by path and reason: a sensor that becomes blocked for a different
// reason, or a different sensor, is a new fact worth an event.
var blockedSensor struct {
	sync.Mutex
	reported map[string]bool
}

// blockedSensorUnreported records this outcome and reports whether it is the
// first time this process has seen it.
func blockedSensorUnreported(path, reason string) bool {
	blockedSensor.Lock()
	defer blockedSensor.Unlock()
	key := path + "\x00" + reason
	if blockedSensor.reported[key] {
		return false
	}
	if blockedSensor.reported == nil {
		blockedSensor.reported = map[string]bool{}
	}
	blockedSensor.reported[key] = true
	return true
}

// Version is the agent version reported at enrollment and in the Hello frame.
// A var so release builds stamp the real tag via
// -ldflags "-X github.com/nettact/agent/agentrt.Version=vX.Y.Z"; unstamped
// local/dev builds report "dev".
var Version = "dev"

// reportedPlatform returns the OS identifier sent in the enrollment request and
// every Hello, used by the console to pick a per-OS icon. On Linux it prefers the
// distribution id (from /etc/os-release: "ubuntu", "debian", "arch", …) so the
// console can distinguish distros; on every other OS, and when the distro cannot
// be read, it falls back to the Go runtime OS ("windows", "darwin", "linux", …).
//
// It uses PlatformInformation (which reads only OS-release metadata) rather than
// host.Info: the latter also collects uptime, boot time, process counts, host id
// and virtualization, which the agent's permission model gates behind host.*
// families. Distro identification is OS metadata (already exposed via GOOS), not
// gated host telemetry, so PlatformInformation keeps the no-call boundary intact.
func reportedPlatform() string {
	if runtime.GOOS == "linux" {
		if platform, _, _, err := pshost.PlatformInformation(); err == nil {
			if id := strings.ToLower(strings.TrimSpace(platform)); id != "" {
				return id
			}
		}
	}
	return runtime.GOOS
}

// Terminal outcomes. A server's runner stops with one of these (wrapped) when
// retrying that server cannot help without intervention; Run returns them joined
// once every runner has stopped, so a supervisor's errors.Is checks read exactly
// as they did when an agent could only talk to one server. A caller that manages
// servers individually watches EventTerminal instead.
var (
	// ErrRevoked: the server deleted this agent. The runner deletes that server's
	// stale credential itself and re-enrolls via its TokenSource, so this is only
	// ever returned when the deletion failed.
	ErrRevoked = conn.ErrRevoked
	// ErrSuperseded: another process owns this credential. Reconnecting would
	// fight it in a 4000 loop, so that runner stops. Other servers are unaffected
	// — being kicked by one says nothing about the rest.
	ErrSuperseded = conn.ErrSuperseded
	// ErrEnroll: enrollment could not complete (no token, quota, bad token,
	// server unreachable at enroll time). Distinguishes "never initialized" from
	// a mid-run failure.
	ErrEnroll = errors.New("agent enrollment failed")
	// ErrNoEnrollmentToken: this server has no way to obtain an enrollment token
	// and holds no credential, so there is nothing to retry — only a
	// configuration change can help. A configuration loader whose TokenSource
	// exists but has nothing to hand out must wrap this, so the runner can tell
	// "misconfigured" from "the server said no": everything else backs off and
	// keeps trying, and a first run with no token would otherwise retry a
	// missing setting forever instead of failing where someone can see it.
	ErrNoEnrollmentToken = fmt.Errorf("no enrollment token available: %w", ErrEnroll)
	// ErrLocalState: this machine could not keep its own enrollment state — the
	// credential returned by a SUCCESSFUL exchange could not be written down.
	// Its own reason because every other enrollment failure is about the server
	// or the token, and this one is about the disk: on a router that means a full
	// or read-only overlay, and reporting it as a transport error sends the owner
	// to check a network that is working. It is also the one failure where the
	// retry is not free — the one-time token was already spent server-side.
	ErrLocalState = fmt.Errorf("local state could not be saved: %w", ErrEnroll)
	// ErrEnrollRejected: the server answered the enrollment and refused it — a
	// spent or expired token, a site at its agent quota. It is NOT terminal (the
	// runner keeps retrying, since the operator may fix the cause at that end
	// without touching this machine), but it is the only enrollment failure a
	// user can act on, and it must be distinguishable from "the server could not
	// be reached": telling someone their token is bad because their laptop was
	// on a train would have them throw away a token that still works.
	ErrEnrollRejected = enroll.ErrRejected
)

// EventKind identifies a lifecycle event delivered to Config.OnEvent.
type EventKind int

const (
	// EventEnrolled fires after a credential for one server is saved.
	EventEnrolled EventKind = iota
	// EventConnected fires each time a server session becomes live (after Hello).
	EventConnected
	// EventDisconnected fires each time a live session ends, including transient
	// reconnects — it is not a terminal error.
	EventDisconnected
	// EventEnrollFailed fires when enrollment at one server did not complete. The
	// runner keeps retrying with backoff, so it is a status, not an outcome: a
	// server whose token expired reports this until the user supplies a new one.
	EventEnrollFailed
	// EventTerminal fires when one server's runner gives up. Every other server
	// keeps running, so this is the only notice a caller gets that one of them
	// stopped — Run itself returns nothing until all of them have.
	EventTerminal
)

// maxGameDrainInterval bounds how long game seconds may sit in the sensor
// recorder before being written to the WAL.
//
// The recorder holds ten minutes of them, and the upload interval is
// configurable well past that, so the drain cannot simply follow it: the oldest
// seconds would age out of the ring before anything durable had seen them. A
// minute leaves an order of magnitude of headroom.
const maxGameDrainInterval = time.Minute

// Event is a lifecycle notification about one configured server.
//
// Server is that server's configured name, and it is on every event because a
// caller has no other way to attribute one: an agent connected to two servers
// reports Connected and Disconnected for each independently, and "the agent is
// connected" is no longer a single fact.
type Event struct {
	Kind    EventKind
	Server  string
	AgentID string
	Err     error
}

// Limits are the local stability controls (spec §3.1). Zero values select the
// production defaults in DefaultLimits.
type Limits struct {
	MinProbeInterval    time.Duration
	MaxProbeConcurrency int
	SnapshotMinInterval time.Duration
	// SnapshotTimeout bounds one collection — both the console's live host
	// snapshot and an incident scene. They are one knob because they are one
	// question: how long this machine may spend answering "what does it look like
	// right now" before answering partially instead.
	SnapshotTimeout time.Duration
	// MaxTraceConcurrency bounds simultaneously executing incident traceroutes
	// (distinct report ids) on this Agent; diagnostics use their own work channel,
	// never the probe scheduler.
	MaxTraceConcurrency int
}

// DefaultLimits are the spec §17.1 stability defaults.
func DefaultLimits() Limits {
	return Limits{
		MinProbeInterval:    1 * time.Second,
		MaxProbeConcurrency: 16,
		SnapshotMinInterval: 3 * time.Second,
		SnapshotTimeout:     10 * time.Second,
		MaxTraceConcurrency: 4,
	}
}

// ServerConfig is one server this agent reports to. An agent may be enrolled at
// several at once — a home desktop's built-in server and an employer's, say —
// and they are independent in every way that matters: separate credentials,
// separate probe assignments, separate permission grants, separate outages.
//
// Name is the stable handle for all of that. It keys the credential in
// agent.json and the cursor in the WAL, so it is what lets a restart pick up
// where each server left off. It cannot be the URL (which the user may edit) or
// the agent id (which the enrollment this name has to survive is what assigns).
// Renaming an entry therefore re-enrolls it and discards its queued backlog.
type ServerConfig struct {
	Name string

	// URL is the server's base address, e.g. https://nettact.example.com:12450.
	// Required unless both Dialer and Enroller are set (the desktop's in-process
	// server, which no URL addresses).
	URL string

	// Insecure skips TLS verification for this server only (LAN self-signed).
	Insecure bool

	// TokenSource supplies a one-time enrollment token, invoked ONLY when there
	// is no credential on disk for this server. The CLI returns the configured
	// token; the desktop returns srv.MintEnrollmentToken for its own server and
	// the token the user pasted for an external one. Required for first-run
	// enrollment; if nil and enrollment is needed, the runner stops with
	// ErrEnroll.
	TokenSource func(ctx context.Context) (string, error)

	// Enroller performs the enrollment exchange for a signed request. Nil selects
	// the HTTP POST to URL/api/v1/enroll (standalone, and the desktop's external
	// servers). The desktop injects a direct registry call for its own server so
	// first-run enrollment needs no HTTP round-trip.
	Enroller func(ctx context.Context, req protoenroll.EnrollRequest) (protoenroll.EnrollResponse, error)

	// Dialer establishes the session link. Nil selects a WebSocket to URL. The
	// desktop injects the embedded server's in-process pipe dialer for its own
	// server so telemetry never touches a loopback socket.
	Dialer wire.Dialer

	// Policy is this server's permission grant, overriding Config.Policy. It is
	// how one machine tells a home server it may read host metrics and processes
	// while telling an employer's it may only run basic probes. Nil inherits
	// Config.Policy.
	//
	// A grant here can only ever narrow what the machine does on this server's
	// behalf, never widen it past what the platform supports — every server's
	// effective set is still its grant intersected with this machine's
	// capabilities.
	Policy *permission.Policy

	// ProbeNarrow tightens Config.ProbeAccess for this server. The top-level
	// policy is the machine owner's floor and cannot be widened here: a target
	// must pass both, so a server may be given a smaller allowlist than the
	// machine's but never reach anything the machine forbids outright.
	ProbeNarrow *probepolicy.Policy
}

// Config drives one Run. Zero values select production defaults where noted.
type Config struct {
	// Servers is the set of servers to report to, in priority order; at least one
	// is required. Servers[0] additionally owns the game sensor — see
	// gameOwner for why frame capture cannot be shared.
	Servers []ServerConfig

	DataDir        string        // holds agent.key, agent.json, the wal/ directory
	UploadInterval time.Duration // WAL drain cadence; 0 → pcfg.DefaultUploadInterval (30s)
	WireFormat     string        // "protobuf" (default when empty) or "json"

	// Persist and PersistWindow tune the outbox's durable tier, and are read by
	// the lite (OpenWrt router) build ONLY.
	//
	// That build's outbox is a memory buffer that writes nothing to the router's
	// flash while a server's session is up, and spills that server's unsent
	// backlog once the session drops — for PersistWindow (0 → 30 minutes) after
	// the disconnect, which is the interval containing the fault's onset and the
	// one a reboot would destroy. Persist false is the older memory-only
	// behaviour: nothing is ever written and a reboot during an outage loses
	// everything buffered.
	//
	// Every other build ignores both. Its outbox is already durable and spills on
	// buffer depth and age regardless of any session, so "persist while
	// disconnected" is what it does unconditionally and a window bounding flash
	// wear has nothing to bound. They are kept on Config rather than hidden
	// behind a build tag so one configuration schema describes every build.
	Persist       bool
	PersistWindow time.Duration

	// Policy is the agent's default permission grant (spec §3), used for every
	// server entry that does not carry one of its own. The standalone binary
	// builds it from NETTACT_AGENT_PERMISSIONS (or the frozen default); the
	// desktop passes permission.FullAccess(). Run validates it is non-zero.
	Policy permission.Policy

	// ProbeAccess is the immutable target-access policy (spec §3.4) and the floor
	// every server's probes are checked against. The desktop leaves it zero (the
	// guard never consults it under FullAccess bypass).
	ProbeAccess probepolicy.Policy

	// Limits are the local stability controls. Zero fields select DefaultLimits.
	// They are per machine, not per server: two servers asking for traces share
	// one concurrency budget, because the cost they bound is the machine's.
	Limits Limits

	// OnEvent, if non-nil, receives lifecycle events. It must be fast and
	// non-blocking: it runs on agent goroutines (a session goroutine for
	// Connected/Disconnected), one per server.
	OnEvent func(Event)

	// StatusFile, when non-empty, names a JSON file the runtime keeps current
	// with each server's connection state — connected or not, why not, when the
	// next attempt is due, and how deep that server's unsent backlog is. It is
	// replaced atomically, so a reader may poll it without coordinating.
	//
	// It answers the question the agent otherwise cannot: everything it knows
	// about its own connection travels over that connection, which is precisely
	// what is broken when someone needs to know. A person with a terminal reads
	// the log instead; this exists for the installs where nobody will — the
	// OpenWrt package points it at a tmpfs path and the LuCI page renders it, so
	// a router owner can see "certificate expired, retrying in 30s" without ever
	// meeting a shell.
	//
	// Empty disables it entirely, which is the default and what the desktop
	// uses: it consumes OnEvent and has a console of its own. Put it on a
	// memory-backed filesystem wherever flash wear matters — it is rewritten on
	// every reconnect attempt.
	StatusFile string
}

// PruneCredentials forgets the enrollment credentials of every server not named
// in keep, and reports how many it removed.
//
// It exists for a host that owns the server list outright and edits it while the
// agent is stopped — the desktop, whose console adds and removes external
// servers. Removing one there has to mean the machine detaches from it: without
// this, adding a server back under the same name resumes the old identity, the
// fresh enrollment token is never spent, and the remote console shows the agent
// record the user believed they had removed.
//
// It must be called while no Run is in flight on that data directory, which for
// the desktop is the moment before the agent restarts against the new list. A
// standalone agent should NOT call it: its configuration file may legitimately
// be a hand-edited subset, and forgetting the omitted servers would cost an
// operator-issued token to recover.
func PruneCredentials(dataDir string, keep []string) (int, error) {
	// The cached target lists are pruned alongside the credentials they are bound
	// to. Leaving one behind would be harmless — its binding names a credential
	// that no longer exists, so a restore refuses it — but it would also sit there
	// forever describing monitors nobody is running.
	if _, err := desiredstate.Prune(dataDir, keep); err != nil {
		log.Printf("could not prune cached configs: %v", err)
	}
	return identity.PruneCredentials(dataDir, keep)
}

// PruneCredentialsFor is PruneCredentials over a Config's own server list.
func (c Config) PruneCredentialsFor() (int, error) {
	keep := make([]string, 0, len(c.Servers))
	for _, sc := range c.Servers {
		keep = append(keep, sc.Name)
	}
	return PruneCredentials(c.DataDir, keep)
}

func (c Config) emit(ev Event) {
	if c.OnEvent != nil {
		c.OnEvent(ev)
	}
}

// gameOwner is the index in Config.Servers of the server that owns frame
// capture.
//
// The sensor is one child process watching one machine's frame presentation, and
// what it captures is configured by a pushed list of game profiles. Two servers
// pushing different lists would restart it against each other, so ownership
// cannot be shared and has to be assigned rather than negotiated. The first
// configured server gets it, which on the desktop — the only place frame capture
// exists today — is the built-in local server: the machine the user is sitting
// at, and where they would expect to find their own games.
//
// Every other server's game configuration is ignored and no game data is ever
// queued for it. That is also the privacy answer, and the reason this is not a
// setting: adding an employer's server must not start reporting what you play.
const gameOwner = 0

// Enrollment retry bounds. Slower than the session backoff on purpose: a failed
// enrollment is nearly always something only a human can fix — an expired
// one-time token, a server that has not been stood up yet — so retrying hard
// buys nothing and fills the log.
const (
	enrollBackoffBase = 5 * time.Second
	enrollBackoffCap  = 5 * time.Minute
)

// machineCaps are the capability facts Run establishes by looking at THIS
// MACHINE, before any server's configuration is consulted. They are probed once
// per Run no matter how many servers are configured: whether a thermal sensor
// answers, or a frame-capture component is installed and working, is a property
// of the hardware, and asking twice would cost twice for the same answer.
//
// Turning them into a per-server supported set is a separate step (see
// viewsFor), because "the machine can do this" and "you may be told this
// machine can do this" are different statements.
type machineCaps struct {
	base           permission.Set // platform-independent, platform-implemented, traceroute
	temperature    bool           // a real temperature read succeeded
	gameSensorPath string         // "" when no sensor component was located
	gameProbe      gamesense.ProbeResult
	gameReasons    map[string]string
	gameSupported  permission.Set
}

// runEnv is the machine-level context every server's runner needs: the things
// that are the same no matter which server it is talking to.
type runEnv struct {
	cfg         Config
	key         ed25519.PrivateKey
	hostname    string
	platformID  string
	subprotocol string

	// status is the local connection-status file, or nil when Config.StatusFile
	// is empty. Every method on it is nil-safe, so the runners report into it
	// unconditionally.
	status *statusWriter
}

// Run starts the agent and blocks until ctx is cancelled or every configured
// server has stopped for good.
//
// It returns nil on ctx cancellation (clean shutdown, close frames sent). Any
// other return means every server gave up, and is the join of their outcomes —
// each wrapped so errors.Is still finds ErrRevoked/ErrSuperseded/ErrEnroll,
// which is exactly what a caller saw back when an agent could only talk to one
// server. A caller that manages servers individually watches EventTerminal
// instead, because one server stopping is not the agent stopping: the others
// keep monitoring, and Run keeps blocking.
//
// All goroutines it starts are stopped before it returns, and the WAL is closed,
// so re-running on the same DataDir is safe.
func Run(ctx context.Context, cfg Config) error {
	if err := cfg.normalize(); err != nil {
		return err
	}
	subprotocol, err := subprotocolFor(cfg.WireFormat)
	if err != nil {
		return err
	}
	priv, err := identity.LoadOrCreateKey(cfg.DataDir)
	if err != nil {
		return fmt.Errorf("identity: %w", err)
	}
	hostname, _ := os.Hostname()
	env := runEnv{cfg: cfg, key: priv, hostname: hostname, platformID: reportedPlatform(), subprotocol: subprotocol}

	p := platform.New()
	caps := probeMachine(ctx, cfg, p)

	views := make([]permViews, len(cfg.Servers))
	reports := make([]permission.PermissionReport, len(cfg.Servers))
	for i, sc := range cfg.Servers {
		views[i], reports[i] = viewsFor(cfg, sc, i == gameOwner, caps)
	}

	creds, err := identity.LoadCredentials(cfg.DataDir)
	if err != nil {
		return fmt.Errorf("load credentials: %w", err)
	}

	// Internal context cancelled when Run returns, so the schedulers and heartbeat
	// never outlive one Run — important when a terminal outcome (not ctx cancel)
	// makes a supervisor re-run: the previous Run's goroutines must be gone first.
	runCtx, cancel := context.WithCancel(ctx)

	names := make([]string, len(cfg.Servers))
	for i, sc := range cfg.Servers {
		names[i] = sc.Name
	}
	// One clock monitor per process. Clock error is a fact about the machine, not
	// about any one server, and every server's telemetry rides the same outbox —
	// so the correction has to be established once and applied uniformly. The
	// epoch is per PROCESS rather than per boot on purpose: a later agent process
	// shares the machine's boot but not this one's clock observations, and must
	// not have this one's corrections applied to stamps it never took.
	clock := clockmon.New(uuid.NewString())
	outbox, err := wal.Open(filepath.Join(cfg.DataDir, "wal"), names, wal.Options{
		Persist:       cfg.Persist,
		PersistWindow: cfg.PersistWindow,
		Clock:         clock,
	})
	if err != nil {
		cancel()
		return fmt.Errorf("open wal: %w", err)
	}
	// The status file reports backlog depth, so it needs the outbox; the runners
	// report into it, so it has to exist before they are built.
	env.status = newStatusWriter(cfg.StatusFile, cfg, outbox)
	owner := cfg.Servers[gameOwner].Name

	// An installed sensor that cannot collect looks identical to no sensor at all
	// in the permission report — both are simply unsupported. One of the two is
	// fixable, so it gets an event carrying the reason, addressed to the server
	// that owns frame capture (nobody else is told about a sensor whose data they
	// will never receive).
	//
	// Reported once per process for a given outcome, not once per Run: a
	// supervisor re-runs this function in the same process after a revoked or
	// dropped session, and an unchanged sensor is not news each time. Cancellation
	// is excluded outright — a probe interrupted by shutdown failed to answer,
	// which is not the same as answering "blocked", and persisting that would
	// leave a warning to be uploaded on the next start.
	if caps.gameSensorPath != "" && !caps.gameProbe.OK && ctx.Err() == nil &&
		blockedSensorUnreported(caps.gameSensorPath, caps.gameProbe.Reason) {
		log.Printf("game sensor at %s unavailable: %s", caps.gameSensorPath, caps.gameProbe.Reason)
		_, _ = outbox.Append(wal.Records{Events: []telemetry.Event{{
			ID:       uuid.NewString(),
			TS:       time.Now().UTC(),
			Type:     telemetry.EventGameSensorBlocked,
			Layer:    telemetry.LayerLocal,
			Severity: telemetry.SeverityWarn,
			Message:  "game sensor installed but unavailable",
			Attrs: map[string]string{
				"reason": caps.gameProbe.Reason,
				"path":   caps.gameSensorPath,
			},
		}}}, owner)
	}

	// One traceroute limiter for the machine, shared by every server's engine: raw
	// sockets and probe threads are a machine resource, and they do not become
	// more plentiful because a second server asked for a trace.
	traceLimit := traceroute.NewLimiter(cfg.Limits.MaxTraceConcurrency)

	// Likewise one probe budget for the machine, shared by every server's probe
	// collectors. Limits is process-level, not per server, so there is no
	// reconciling to do: an agent has one MaxProbeConcurrency however many servers
	// it reports to, which is right — the sockets and ICMP handles the probes hold
	// are the machine's, and a second server asking for the same target is more
	// probing, not more capacity. Sizing it per server would multiply the budget by
	// the number of servers and by the number of probe kinds, which is no budget.
	probeGate := collector.NewProbeGate(cfg.Limits.MaxProbeConcurrency)

	runtimes := make([]*serverRuntime, len(cfg.Servers))
	for i, sc := range cfg.Servers {
		runtimes[i] = buildServer(sc, views[i], reports[i], outbox, p,
			cfg.Limits, cfg.UploadInterval, traceLimit, probeGate, hostname, clock)
	}

	// The game sensor is a child process streaming a line per second, so unlike
	// the collectors it does not do its work on a tier and produces no metrics at
	// all: the supervisor records runs and per-second buckets, and the agent
	// drains them on the upload cadence. One sensor for the machine, wired only
	// into the owner's session.
	var gameSensor *gamesense.Supervisor
	ownerViews := views[gameOwner]
	if ownerViews.effective.Has(permission.GamePerformanceRead) && caps.gameProbe.OK {
		gameSensor = gamesense.NewSupervisor(caps.gameSensorPath, func(ev telemetry.Event) {
			_, _ = outbox.Append(wal.Records{Events: []telemetry.Event{ev}}, owner)
		})
		// The GPU flag is a permission decision, not a pushed setting, so it is
		// fixed for the life of the process and read off the owner's effective set
		// — what that server granted, narrowed to what this machine's probe
		// verified. A re-push cannot widen it.
		runtimes[gameOwner].game = gameConfigApplier{sensor: gameSensor, gpu: ownerViews.effective.Has(permission.GameGPURead)}
	}

	// Ordered shutdown, in this exact order: cancel runCtx so the sessions,
	// schedulers and heartbeat stop; join the sessions first because they are the
	// only things that claim from the WAL; then the schedulers and the sensor,
	// which are the only things that append to it; and only then close it.
	//
	// sched.Wait also joins the ping cycles still spread across their intervals
	// on their own goroutines — which is what makes closing the proxy managers
	// after it safe for an in-tunnel ping.
	var hbWG, runnersWG sync.WaitGroup
	defer func() {
		cancel()
		runnersWG.Wait()
		for _, rt := range runtimes {
			rt.sched.Wait()
			// The trigger's in-flight traces also append to the outbox, so they are
			// joined in the same phase as the schedulers that started them. The
			// scene collector is in that same phase and for that same reason.
			rt.trigger.Wait()
			rt.scene.Wait()
		}
		hbWG.Wait()
		_ = outbox.Close()
		for _, rt := range runtimes {
			rt.proxies.Close()
		}
	}()

	if gameSensor != nil {
		// Game data goes into the WAL exactly like a collector's metrics and events
		// do, rather than being attached to a packet at send time. The WAL is what
		// makes telemetry survive an unreachable server and a crash mid-upload, and
		// a run recorded while offline is precisely the data worth keeping — a game
		// played during an outage is still a game that was played. Riding the same
		// rows also puts runs and buckets under the (agent_id, sequence) dedup that
		// makes the at-least-once upload safe to replay.
		//
		// One Append per drain, so the runs, the buckets that hang from them and
		// the silences that explain the space between are one WAL group and
		// therefore one packet: the server never sees a bucket or a gap whose run
		// it has not been told about.
		flushGame := func() {
			rec := gameSensor.Drain()
			if rec.Empty() {
				// An idle desktop produces nothing for hours. Appending anyway would
				// consume a group id and write a transaction on every tick, forever.
				return
			}
			dropped, err := outbox.Append(wal.Records{
				GameRuns:        rec.Runs,
				GameBuckets:     rec.Buckets,
				GameGaps:        rec.Gaps,
				GameHostSeconds: rec.HostSeconds,
			}, owner)
			if err != nil {
				// Put them back. The drain already emptied the recorder, so
				// returning here without this turns one failed write — a full
				// disk, a moment of database contention — into a permanent hole
				// in the middle of a session.
				gameSensor.Requeue(rec)
				log.Printf("wal append game data: %v", err)
				return
			}
			if dropped > 0 {
				log.Printf("WAL over capacity: dropped %d oldest samples (data gap)", dropped)
			}
		}
		hbWG.Add(1)
		go func() {
			defer hbWG.Done()
			gameSensor.Run(runCtx)
			// Run closes the in-progress game run as it stops, so this final drain is
			// what carries that ending — and the seconds since the last tick — into
			// the WAL while it is still open.
			flushGame()
		}()
		hbWG.Add(1)
		go func() {
			defer hbWG.Done()
			// Draining on the upload cadence keeps a second at most one upload
			// behind the moment it describes, but never less often than
			// maxGameDrainInterval: the recorder holds ten minutes of seconds, and
			// a configured upload interval longer than that would let the oldest
			// ones fall out of the ring before they were ever written down. A
			// drain that outpaces the upload costs nothing — the WAL is where they
			// were going anyway, and arriving early is how they survive a crash.
			t := time.NewTicker(min(cfg.UploadInterval, maxGameDrainInterval))
			defer t.Stop()
			for {
				select {
				case <-runCtx.Done():
					return
				case <-t.C:
					flushGame()
				}
			}
		}()
	}

	for _, rt := range runtimes {
		rt.sched.Run(runCtx)
		// Arm the traceroute trigger with the same context: it launches goroutines
		// that append to the outbox, so it must start alongside the schedulers that
		// feed it and be joined in the same phase. Same for the scene trigger,
		// which additionally fires on an edge the schedulers know nothing about.
		rt.trigger.Start(runCtx)
		rt.scene.Start(runCtx)
	}

	// Watch this machine's clock for the rest of the run. It joins hbWG so it is
	// stopped before the outbox closes: the store asks it for a correction on
	// every claim, and a monitor still recording steps into a closing store would
	// be answering questions nobody can act on.
	clockStop := make(chan struct{})
	hbWG.Add(1)
	go func() {
		defer hbWG.Done()
		go func() {
			<-runCtx.Done()
			close(clockStop)
		}()
		clock.Run(clockStop)
	}()

	// Status heartbeat: uptime + WAL depth over the same WAL→WS path. Emitted per
	// server, because the backlog depth is per server — one server being
	// unreachable says nothing about how far behind another is, and a single
	// number would report the worst of them to all of them.
	//
	// It also carries the probe-overload report, which is the opposite case: the
	// concurrency budget is the machine's, so every server hears the same figure.
	// Each has monitors that went quiet because of it, and each needs to be able
	// to say why.
	start := time.Now()
	// The status file's own goroutine joins hbWG so it is stopped before the WAL
	// closes — it reads Pending, and a status write racing outbox.Close would be
	// reading a closed store.
	hbWG.Add(1)
	go func() {
		defer hbWG.Done()
		env.status.run(runCtx)
	}()
	hbWG.Add(1)
	go func() {
		defer hbWG.Done()
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		overloadSince := time.Now()
		emit := func() {
			now := time.Now().UTC()
			// Drain the refused-probe count on its own, longer cadence. Sustained
			// overload would otherwise put an event on every heartbeat — 120 an
			// hour per server — to repeat one fact the operator already acted on
			// or chose not to.
			var overload []telemetry.Event
			if window := time.Since(overloadSince); window >= probeOverloadWindow {
				if n := probeGate.TakeOverload(); n > 0 {
					overload = append(overload, probeOverloadEvent(now, n, window, cfg.Limits.MaxProbeConcurrency))
				}
				overloadSince = time.Now()
			}
			for _, name := range names {
				_, _ = outbox.Append(wal.Records{
					Metrics: []telemetry.Metric{
						{TS: now, Kind: telemetry.AgentUptime, Target: "agent", Layer: telemetry.LayerLocal, Value: time.Since(start).Seconds(), Unit: telemetry.UnitSec},
						{TS: now, Kind: telemetry.AgentWALPending, Target: "agent", Layer: telemetry.LayerLocal, Value: float64(outbox.Pending(name)), Unit: telemetry.UnitCount},
					},
					Events: overload,
				}, name)
			}
			// Same cadence, same numbers, different audience: the metrics above
			// go to the server, this keeps the machine's own status file from
			// freezing between transitions.
			env.status.refresh()
		}
		emit()
		for {
			select {
			case <-runCtx.Done():
				return
			case <-t.C:
				emit()
			}
		}
	}()

	log.Printf("telemetry wire format: %s", subprotocol)
	for i, rt := range runtimes {
		log.Printf("[%s] server %d/%d: host=%s platform=%s source=%s effective=%v",
			rt.cfg.Name, i+1, len(runtimes), hostname, runtime.GOOS,
			rt.views.sourceName(), rt.views.effective.Strings())
	}

	// One runner per server, each with its own enrollment, its own session and its
	// own terminal outcome. A server that is unreachable, revoked or superseded
	// affects nothing but its own runner.
	outcomes := make([]error, len(runtimes))
	for i, rt := range runtimes {
		runnersWG.Add(1)
		go func(i int, rt *serverRuntime) {
			defer runnersWG.Done()
			err := runServer(runCtx, env, rt, creds[rt.cfg.Name])
			outcomes[i] = err
			if err != nil {
				// Terminal is recorded before the event fires and before Run
				// tears down: it is the one state a status reader most needs,
				// because nothing further will ever change it.
				env.status.set(rt.cfg.Name, func(s *serverStatus) {
					s.State = statusTerminal
					s.Since = time.Now().Unix()
					s.NextRetryAt = 0
					s.LastError = &statusError{Code: terminalStatusCode(err), Detail: err.Error()}
				})
				cfg.emit(Event{Kind: EventTerminal, Server: rt.cfg.Name, Err: err})
			}
		}(i, rt)
	}
	runnersWG.Wait()

	var errs []error
	for i, err := range outcomes {
		if err != nil {
			errs = append(errs, fmt.Errorf("server %q: %w", runtimes[i].cfg.Name, err))
		}
	}
	return errors.Join(errs...)
}

// runServer owns one server for the life of the Run: enroll if needed, hold a
// session, and decide what a terminal close code means for that server alone.
//
// It returns nil when ctx ends (clean shutdown) and a terminal error when this
// server cannot be talked to again without intervention. Revocation is NOT
// terminal: the credential is deleted and the loop re-enrolls, which is the
// behaviour the desktop supervisor used to implement one level up and which now
// has to live here, since one server's revocation must not disturb the others.
func runServer(ctx context.Context, env runEnv, rt *serverRuntime, cred identity.Credential) error {
	enrolled := cred.AgentToken != ""
	if enrolled {
		log.Printf("[%s] resuming as %s (site %s)", rt.cfg.Name, cred.AgentID, cred.SiteID)
		env.status.set(rt.cfg.Name, func(s *serverStatus) {
			s.State = statusConnecting
			s.AgentID = cred.AgentID
			s.Since = time.Now().Unix()
		})
	}
	backoff := enrollBackoffBase

	for {
		if !enrolled {
			env.status.set(rt.cfg.Name, func(s *serverStatus) {
				if s.State != statusEnrolling {
					s.State = statusEnrolling
					s.Since = time.Now().Unix()
				}
				s.AgentID = ""
			})
			c, err := enrollServer(ctx, env, rt)
			if err != nil {
				if ctx.Err() != nil {
					return nil
				}
				if errors.Is(err, ErrNoEnrollmentToken) {
					// Nothing will change by waiting: this server has no token to
					// present and no credential to fall back on.
					return err
				}
				if errors.Is(err, ErrLocalState) {
					// Also terminal, and for a sharper reason: the exchange
					// SUCCEEDED, so the one-time token is already spent. Retrying
					// can only present a dead token and overwrite this diagnosis
					// with `enroll_rejected`, burying the disk failure that is the
					// only thing anyone can actually fix.
					return err
				}
				log.Printf("[%s] enrollment failed, retrying in %s: %v", rt.cfg.Name, backoff, err)
				env.status.set(rt.cfg.Name, func(s *serverStatus) {
					s.NextRetryAt = time.Now().Add(backoff).Unix()
					s.LastError = &statusError{Code: enrollStatusCode(err), Detail: err.Error()}
				})
				env.cfg.emit(Event{Kind: EventEnrollFailed, Server: rt.cfg.Name, Err: err})
				if !sleepCtx(ctx, backoff) {
					return nil
				}
				if backoff *= 2; backoff > enrollBackoffCap {
					backoff = enrollBackoffCap
				}
				continue
			}
			cred, enrolled, backoff = c, true, enrollBackoffBase
			log.Printf("[%s] enrolled as %s (site %s)", rt.cfg.Name, cred.AgentID, cred.SiteID)
			env.status.set(rt.cfg.Name, func(s *serverStatus) {
				s.State = statusConnecting
				s.AgentID = cred.AgentID
				s.Since = time.Now().Unix()
				s.NextRetryAt = 0
				s.LastError = nil
			})
			env.cfg.emit(Event{Kind: EventEnrolled, Server: rt.cfg.Name, AgentID: cred.AgentID})
		}

		agentID := cred.AgentID
		// Every scene records the identity it was collected under, so a later
		// re-enrollment (a revoked server comes back as a new agent) does not
		// rewrite what the old one saw.
		rt.scene.SetAgentID(agentID)
		err := conn.Run(ctx, conn.Options{
			ServerName: rt.cfg.Name,
			ServerURL:  rt.cfg.URL,
			Token:      cred.AgentToken,
			Insecure:   rt.cfg.Insecure,
			Format:     env.subprotocol,
			Dialer:     rt.cfg.Dialer,
			AgentID:    cred.AgentID,
			SiteID:     cred.SiteID,
			Hello: wire.Hello{
				SchemaVersion: protocol.SchemaVersion,
				Hostname:      env.hostname,
				Platform:      env.platformID,
				AgentVersion:  Version,
				Permissions:   rt.report,
			},
			OnSession: func(up bool) {
				// The outbox learns the edge before anything else does. On the
				// router builds this is what decides whether telemetry reaches
				// flash at all: a session that just ended means the samples now
				// buffered have nowhere to go, and the likeliest next event is
				// somebody power-cycling the box to fix the internet. On every
				// other build it is a no-op.
				rt.outbox.SetServerOnline(rt.cfg.Name, up)

				// Arm (or spend) the disconnect edge for the scene trigger. Both
				// halves are a flag write: the collection itself, if there is one,
				// is started from OnRetry and runs on a goroutine of its own —
				// this callback is on the session goroutine and must not block it.
				if up {
					rt.scene.SessionUp()
				}

				kind := EventDisconnected
				if up {
					kind = EventConnected
				}
				if up {
					// Only the up edge writes status. The down edge is followed
					// immediately by OnRetry with the reason and the delay, and
					// writing "disconnected, cause unknown" in between would put
					// a state on the router page that exists for milliseconds
					// and explains nothing.
					now := time.Now().Unix()
					env.status.set(rt.cfg.Name, func(s *serverStatus) {
						s.State = statusConnected
						s.AgentID = agentID
						s.Since = now
						s.LastConnectedAt = now
						s.NextRetryAt = 0
						s.LastError = nil
					})
				}
				env.cfg.emit(Event{Kind: kind, Server: rt.cfg.Name, AgentID: agentID})
			},
			OnRetry: func(err error, retryIn time.Duration) {
				reason := conn.Classify(err)
				// The disconnect edge is taken here rather than on OnSession(false)
				// because this hook fires for exactly the endings worth describing.
				// A superseded connection, a revoked credential and a schema
				// mismatch all end a session, but they end the RUN and never reach a
				// retry — and none of them is a network fault, so collecting for
				// them would file a picture of a healthy machine under an incident
				// that will never be opened. Shutdown is the same story. An auth
				// rejection is excluded for the opposite reason: reaching the server
				// well enough to be refused proves the network works, and the fault
				// is in the credential.
				if reason != conn.ReasonAuth {
					rt.scene.SessionLost(string(reason), time.Now())
				}
				env.status.set(rt.cfg.Name, func(s *serverStatus) {
					s.State = statusWaitingRetry
					s.Since = time.Now().Unix()
					s.NextRetryAt = time.Now().Add(retryIn).Unix()
					s.LastError = &statusError{Code: string(reason), Detail: err.Error()}
				})
			},
		}, rt.connDeps(cred, env.cfg.DataDir))

		// Run returned, so this session ended in a way that never reached the retry
		// hook — shutdown, or one of the terminal close codes. Spend the disconnect
		// arm without collecting: nothing here is a network fault, and leaving it
		// set would hand it to the first failed dial of the NEXT enrollment, which
		// would then describe a session that never existed.
		rt.scene.Disarm()

		if ctx.Err() != nil {
			return nil
		}
		if !errors.Is(err, ErrRevoked) {
			return err
		}

		// On revocation the credential is dead; delete it so the loop enrolls
		// fresh. The ed25519 key is kept: with a console-issued reinstall token
		// (AGENT-006) the next enrollment rejoins under the SAME agent_id and keeps
		// its history; without one it registers a brand-new agent. Every other
		// server's credential is untouched — being deleted at one server says
		// nothing about the rest.
		if derr := identity.DeleteCredential(env.cfg.DataDir, rt.cfg.Name); derr != nil {
			// The stale credential is still on disk (permissions, antivirus lock,
			// read-only FS), so looping would reload it and be revoked again.
			return fmt.Errorf("delete revoked credential: %w", derr)
		}
		// The cached target list goes with it. The session has already stopped
		// probing (conn quiesces on the revoke close code); this is what stops a
		// restart from resurrecting the list. Best-effort on purpose: a cache the
		// agent cannot delete is still bound to the credential just deleted, so the
		// binding check refuses to restore it anyway — this only keeps the file
		// from lingering.
		if derr := desiredstate.Delete(env.cfg.DataDir, rt.cfg.Name); derr != nil {
			log.Printf("[%s] could not drop the cached config of the revoked credential: %v", rt.cfg.Name, derr)
		}
		cred, enrolled = identity.Credential{}, false
		log.Printf("[%s] agent was deleted on the server; re-enrolling", rt.cfg.Name)
	}
}

// enrollServer performs one server's enrollment exchange and persists the
// credential it returns.
func enrollServer(ctx context.Context, env runEnv, rt *serverRuntime) (identity.Credential, error) {
	if rt.cfg.TokenSource == nil {
		return identity.Credential{}, ErrNoEnrollmentToken
	}
	token, err := rt.cfg.TokenSource(ctx)
	if err != nil {
		// A loader that had nothing to hand out wraps ErrNoEnrollmentToken, which
		// must survive to the runner as the terminal outcome it is; anything else
		// is a real failure to fetch and stays retryable.
		if errors.Is(err, ErrNoEnrollmentToken) {
			return identity.Credential{}, fmt.Errorf("obtain enrollment token: %w", err)
		}
		return identity.Credential{}, fmt.Errorf("obtain enrollment token: %v: %w", err, ErrEnroll)
	}
	// Build+sign the request, then run it through the injected Enroller (direct
	// registry call for the desktop's own server) or the default HTTP POST.
	req := enroll.BuildRequest(env.key, token, env.hostname, env.platformID, Version, rt.report)
	exchange := rt.cfg.Enroller
	if exchange == nil {
		exchange = func(ctx context.Context, r protoenroll.EnrollRequest) (protoenroll.EnrollResponse, error) {
			return enroll.Post(ctx, rt.cfg.URL, rt.cfg.Insecure, r)
		}
	}
	resp, err := exchange(ctx, req)
	if err != nil {
		// A refusal has to stay recognisable through the wrapping: it is the one
		// enrollment failure whose remedy is a person doing something, and a
		// caller that cannot tell it from an unreachable server has to describe
		// every outage as a bad token.
		if errors.Is(err, ErrEnrollRejected) {
			return identity.Credential{}, fmt.Errorf("enroll: %w", err)
		}
		// Both causes are wrapped, not just the sentinel: ErrEnroll is what the
		// runner branches on, while the transport error underneath is what says
		// whether this was a refused port, an expired certificate or a name that
		// does not resolve. Folding the latter in with %v would leave the status
		// file able to report only "enrollment failed", which is the black box
		// this is meant to open.
		return identity.Credential{}, fmt.Errorf("enroll: %w: %w", err, ErrEnroll)
	}
	cred := identity.Credential{AgentID: resp.AgentID, SiteID: resp.SiteID, AgentToken: resp.AgentToken}
	if err := identity.SaveCredential(env.cfg.DataDir, rt.cfg.Name, cred); err != nil {
		// Wrapped so the status file can say what actually happened. The exchange
		// SUCCEEDED here — the server issued a credential and marked the one-time
		// token spent — and only writing it to disk failed (a full or read-only
		// overlay, most likely). Reported as a transport failure it would read as
		// "the server could not be reached", sending someone to check the network
		// while the retry burns a token that is already gone.
		return identity.Credential{}, fmt.Errorf("save credential: %w: %w", err, ErrLocalState)
	}
	return cred, nil
}

// sleepCtx waits for d, reporting false if ctx ended first.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// normalize validates the configuration and fills in defaults, in place.
func (c *Config) normalize() error {
	if len(c.Servers) == 0 {
		return errors.New("agentrt: Config.Servers must name at least one server")
	}
	if c.Policy.Granted == nil {
		return errors.New("agentrt: Config.Policy must be set (permission grant)")
	}
	seen := make(map[string]bool, len(c.Servers))
	for i, sc := range c.Servers {
		if sc.Name == "" {
			return fmt.Errorf("agentrt: Servers[%d] has no name", i)
		}
		if seen[sc.Name] {
			// Two entries under one name would share a credential and a WAL cursor
			// while running two sessions, which is the superseded-kick loop written
			// as a configuration.
			return fmt.Errorf("agentrt: duplicate server name %q", sc.Name)
		}
		seen[sc.Name] = true
		// URL feeds the default WebSocket dialer and the default HTTP enroller.
		// When both a Dialer and an Enroller are injected (the desktop's own
		// server), no URL addresses it.
		if sc.URL == "" && (sc.Dialer == nil || sc.Enroller == nil) {
			return fmt.Errorf("agentrt: server %q needs a URL unless both Dialer and Enroller are set", sc.Name)
		}
		if sc.Policy != nil && sc.Policy.Granted == nil {
			return fmt.Errorf("agentrt: server %q has an empty permission policy; leave it nil to inherit", sc.Name)
		}
	}
	if c.UploadInterval == 0 {
		c.UploadInterval = pcfg.DefaultUploadInterval
	}
	c.Limits = fillLimits(c.Limits)
	return nil
}

// policyOf returns the grant a server runs under: its own if it carries one, the
// agent-wide default otherwise.
func (c Config) policyOf(sc ServerConfig) permission.Policy {
	if sc.Policy != nil {
		return *sc.Policy
	}
	return c.Policy
}

// probeMachine establishes this machine's capabilities once, before any server's
// view of them is built.
//
// The capability probes that cost a real read stay behind a grant, as they
// always have — but the grant that authorizes the read is now the union across
// servers, since one server granting temperature is reason enough to find out
// whether this machine has a sensor. Who is then TOLD the answer is decided per
// server in viewsFor, so a server that granted nothing learns nothing.
func probeMachine(ctx context.Context, cfg Config, p platform.Platform) machineCaps {
	caps := machineCaps{base: platformIndependentSupported(), gameReasons: map[string]string{}, gameSupported: permission.Set{}}
	for id := range p.Supports() {
		caps.base.Add(id)
	}
	// Both traceroute modes are runtime capabilities owned by the traceroute
	// engine, which is the only component that knows what observing intermediate
	// Time-Exceeded responders costs on each OS: Administrator on Windows for TCP,
	// a raw ICMP socket (root / CAP_NET_RAW) on Linux and macOS for either mode.
	// Asking it keeps one answer per mode instead of a platform layer and an
	// engine disagreeing. Effective stays supported∩granted, so desktop
	// FullAccess remains capability-gated.
	icmpTraceCap, tcpTraceCap := traceroute.Supported()
	if icmpTraceCap {
		caps.base.Add(permission.DiagnosticTracerouteICMP)
	}
	if tcpTraceCap {
		caps.base.Add(permission.DiagnosticTracerouteTCP)
	}

	anyGranted := permission.Set{}
	for _, sc := range cfg.Servers {
		for id := range cfg.policyOf(sc).Granted {
			anyGranted.Add(id)
		}
	}
	// Temperature is capability-probed only after permission is granted. The
	// collector's platform gate returns unsupported without touching a provider on
	// Windows: ACPI WMI thermal zones are not trustworthy hardware temperatures.
	// Other platforms advertise the permission only when a real read succeeds.
	caps.temperature = anyGranted.Has(permission.HostTemperatureRead) && collector.TemperatureSupported(ctx)

	// Frame data comes from a separate sensor component that most installs do not
	// ship, so the capability question is first "is it here at all" and only then
	// "can it work". Both answers are needed: a missing component is the ordinary
	// state and says nothing, while an installed one that cannot capture is a
	// fixable problem the operator would otherwise have no way to see. The probe
	// runs the component, so it stays behind the grant for the same reason the
	// temperature read does.
	//
	// Only the owning server's grant is consulted, because only it can ever
	// receive frame data (see gameOwner). Probing under another server's grant
	// would run the sensor for a server that will never be told the answer.
	ownerGranted := cfg.policyOf(cfg.Servers[gameOwner]).Granted
	//
	// "Can it work" is itself two answers, because the reads fail apart: frame
	// timings come from the game's own presentation, while GPU and VRAM telemetry
	// comes from a driver that may publish none. Plenty of machines capture frames
	// perfectly and expose no adapter telemetry — an ordinary machine, not a
	// degraded one — so the two supports have to be able to differ. Collapsing them
	// would either withhold the capture that works or advertise a read that could
	// never produce a number.
	//
	// Asking the second question is itself a read: the sensor registers a query
	// against the adapter to answer it, so `--probe --gpu` touches the protected
	// source that game.gpu.read exists to protect. It therefore goes out only under
	// that grant — the same rule the outer gate applies to the frame source, one
	// level down. Granted rather than effective, because a grant is the
	// authorization to look and the effective set is the answer that looking
	// produces; the dependency closure guarantees the parents came with it.
	//
	// The consequence is deliberate: without the grant the probe reports nothing
	// about the adapter, so game.gpu.read stays out of supported and the console
	// shows it unsupported rather than merely un-granted. That is the honest
	// report — the agent genuinely does not know, and refuses to find out. Granting
	// it and restarting re-probes with the flag and settles the question.
	if gameProbeGranted(ownerGranted) {
		if path, ok := gamesense.Locate(Version == "dev"); ok {
			caps.gameSensorPath = path
			caps.gameProbe = gamesense.Probe(ctx, path, ownerGranted.Has(permission.GameGPURead))
		}
	}
	// What the probe settled, and — for whatever it left unsupported — why. The
	// reason is the half the three sets cannot carry, and the agent is the only
	// place that has it. A path is what Locate produces when it finds a component,
	// so holding one is the same statement as having found one.
	caps.gameSupported, caps.gameReasons = gameSupport(ownerGranted, gamesense.PlatformSupported,
		caps.gameSensorPath != "", caps.gameProbe)
	return caps
}

// viewsFor turns the machine's capabilities into one server's three permission
// sets, its guard, and the report it will be sent.
//
// The supported set is per server, not a machine constant, and deliberately so.
// A capability this machine only learned about by performing a gated read —
// whether a thermal sensor answers, whether frames can be captured — is reported
// only to a server that granted that read. Handing it to a server that granted
// nothing would answer a question it never asked, using a measurement taken on
// another server's authority.
func viewsFor(cfg Config, sc ServerConfig, owns bool, caps machineCaps) (permViews, permission.PermissionReport) {
	policy := cfg.policyOf(sc)
	granted := policy.Granted
	supported := caps.base.Clone()
	if caps.temperature && granted.Has(permission.HostTemperatureRead) {
		supported.Add(permission.HostTemperatureRead)
	}

	reasons := map[string]string{}
	if owns {
		for id := range caps.gameSupported {
			supported.Add(id)
		}
		for id, why := range caps.gameReasons {
			reasons[id] = why
		}
	} else {
		// Frame capture belongs to one server (see gameOwner), so for everyone else
		// it is genuinely unsupported — and saying why matters as much here as it
		// does for a missing sensor. Without a reason the console would show a
		// machine that plainly can capture frames as one that cannot, and the
		// operator would go looking for a sensor to install.
		for _, id := range []permission.ID{permission.GameProcessDetect, permission.GamePerformanceRead, permission.GameGPURead} {
			if granted.Has(id) {
				reasons[string(id)] = gs.ReasonOwnedByAnotherServer
			}
		}
	}

	// The guard is built per server, from THIS server's policy — not from the
	// agent-wide default. The bypass bit rides on the policy, and on the desktop
	// the default policy is FullAccess: sharing one guard would hand an external
	// server the trust-boundary exemption that exists only because the local
	// server runs inside this very process. A server entry that carries its own
	// policy is by definition not that server.
	guard := netguard.New(cfg.ProbeAccess, policy.FullAccess)
	if sc.ProbeNarrow != nil {
		// The agent-wide probe-access policy is the machine owner's floor: a server
		// entry may tighten it for itself but never reach past it. Narrow enforces
		// both layers, so a target has to satisfy the machine AND this server.
		guard = guard.Narrow(*sc.ProbeNarrow)
	}

	v := permViews{
		granted:   granted,
		supported: supported,
		effective: permission.EffectiveFrom(granted, supported),
		guard:     guard,
		source:    policy.Source,
		hash:      policyHash(cfg, sc, policy),
	}
	return v, permission.PermissionReport{
		Supported:  v.supported.Strings(),
		Granted:    v.granted.Strings(),
		Effective:  v.effective.Strings(),
		Source:     string(policy.Source),
		PolicyHash: v.hash,
		// Game capture is the only capability probe with anything to explain today.
		// A second one would merge its ids into this map rather than replace it —
		// the field describes every unsupported permission that was actually asked
		// about, not one probe's answer.
		UnsupportedReasons: reasons,
	}
}

// sourceName is the policy source recorded in this server's report, used for
// logging.
func (v permViews) sourceName() string { return string(v.source) }

func subprotocolFor(format string) (string, error) {
	switch format {
	case "", "protobuf":
		return wire.SubprotocolProtobuf, nil
	case "json":
		return wire.SubprotocolJSON, nil
	default:
		return "", fmt.Errorf("wire format must be 'protobuf' or 'json', got %q", format)
	}
}

// platformIndependentSupported returns the permissions that work on every OS via
// the Go stdlib (DNS/HTTP/TCP/NAT probes) or the always-compiled gopsutil host
// metric and process/connection snapshot collectors; the platform adds ICMP,
// gateway, wifi, and neighbor support where implemented. "Always compiled" is
// not quite "always works": the one OS-shaped exception is carved out below.
func platformIndependentSupported() permission.Set {
	s := permission.NewSet(
		// Active probes backed by the Go stdlib.
		permission.ProbeDNS,
		permission.ProbeHTTP,
		permission.ProbeHTTPExtended,
		permission.ProbeTCP,
		permission.ProbeNAT,
		// Host metrics — gopsutil cpu/mem/disk/load/host/net, compiled everywhere.
		// HostTemperatureRead is deliberately absent: sensors are a per-machine
		// capability, so Run probes for one and adds the permission there. The
		// game.* permissions are absent for the same reason and one more — they
		// need a component this repository does not build, which most installs do
		// not ship at all.
		permission.HostCPURead,
		permission.HostMemoryRead,
		permission.HostDiskRead,
		permission.HostLoadRead,
		permission.HostUptimeRead,
		permission.HostNetworkIORead,
		// Process snapshot scopes — gopsutil/process, compiled everywhere.
		permission.HostProcessBasicRead,
		permission.HostProcessOwnerRead,
		permission.HostProcessResourceRead,
		// Connection snapshot scopes — gopsutil/net, compiled everywhere.
		permission.HostConnectionSummaryRead,
		permission.HostConnectionLocalRead,
		permission.HostConnectionRemoteRead,
		permission.HostConnectionOwnerRead,
	)
	// Per-process I/O counters compile everywhere but gopsutil cannot read them
	// on macOS without cgo (IOCountersWithContext returns ErrNotImplementedError
	// there), so the read always fails — advertising the permission would let it
	// be granted and shown as effective while never producing a byte of data.
	if runtime.GOOS != "darwin" {
		s.Add(permission.HostProcessIORead)
	}
	return s
}

// gameProbeGranted reports whether the local policy authorizes looking for the
// sensor component and asking it what it can do.
//
// Either grant is reason enough to ask. Unlike the temperature probe, this one
// captures nothing — it looks for the component and asks it whether a frame
// source answers — so requiring the broader permission before asking would only
// make a policy that grants detection alone report detection as unsupported on
// a machine that can do it. EffectiveFrom still removes whatever was not
// granted.
func gameProbeGranted(granted permission.Set) bool {
	return granted.Has(permission.GameProcessDetect) || granted.Has(permission.GamePerformanceRead)
}

// gameSupport settles the three game permissions from one look at the sensor
// component: the set this machine is verified to support, and, for each one it
// is not, the reason — keyed by permission id, ready for the report.
//
// platformSupported says whether a sensor component could exist on this build's
// platform at all; found says whether one was located beside the agent; probe is
// what it answered when there was one to ask.
//
// The reasons exist because "supported: false" is not enough to act on. All
// three causes look identical in the three sets, so a console reading only those
// can do no better than name the remedy it happens to know — which is how an
// operator whose middleware was installed and running was told to install it,
// when the real cause was a stale sensor speaking an older protocol. The agent
// had already worked that out; it just had nowhere to put it.
//
// The map only ever holds ids left out of the returned set, and an id absent
// from it means the question was never asked rather than "no reason" — see
// permission.PermissionReport.UnsupportedReasons, whose contract this fills.
func gameSupport(granted permission.Set, platformSupported, found bool, probe gamesense.ProbeResult) (permission.Set, map[string]string) {
	supported, reasons := permission.Set{}, map[string]string{}
	if !gameProbeGranted(granted) {
		// Nothing was located, probed or asked, so there is nothing to explain
		// about any of the three.
		return supported, reasons
	}
	if !platformSupported {
		// A platform with no sensor component in the world gets NO reason at all,
		// and this is deliberate rather than an omission to tidy away later.
		//
		// A reason is a finding about THIS machine, produced by looking at it. Which
		// platforms can host a sensor is a property of the build, which the console
		// already knows statically and renders correctly on its own. Saying anything
		// here only overrides that with something worse: a known reason outranks the
		// console's platform tables, so "sensor_missing" on Linux would replace
		// "Windows only" with an instruction to go and get a build that includes the
		// component — the exact class of true-but-wrong remedy this map exists to
		// stamp out. ReasonUnsupportedOS is no better: it describes a Windows machine
		// with no frame source behind an installed sensor, which is not this.
		//
		// Keeping quiet also leaves sensor_missing its real meaning below: a build
		// that could have shipped the component and did not.
		return supported, reasons
	}
	// The adapter read is explained beside the other two only under its own grant,
	// because that grant is what put --gpu on the probe. Without it nothing was
	// asked about the adapter, and a cause stated for a question nobody put would
	// be one invented here.
	gpuAsked := granted.Has(permission.GameGPURead)
	explain := func(reason string) {
		reasons[string(permission.GameProcessDetect)] = reason
		reasons[string(permission.GamePerformanceRead)] = reason
		if gpuAsked {
			// The same cause one level down: the probe that would have answered the
			// adapter question is the one that could not run.
			reasons[string(permission.GameGPURead)] = reason
		}
	}
	switch {
	case !found:
		// A platform that can host the component, and no component beside the agent:
		// the ordinary state of every build that ships none. Nothing about the
		// machine is wrong, which is precisely what a console must not be left to
		// guess at — there is nothing here to install, only a build to replace.
		explain(gs.ReasonSensorMissing)
	case !probe.OK:
		// The sensor's own code where it had one, and the agent's own where the
		// sensor was the thing that failed. Either way it is a fixable problem, and
		// which fix depends entirely on the code.
		explain(probe.Reason)
	default:
		supported.Add(permission.GameProcessDetect)
		supported.Add(permission.GamePerformanceRead)
		switch {
		case probe.GPUOK:
			// The adapter read the sensor separately verified, never inferred from
			// the capture working — and never claimed for a question that was not
			// asked.
			supported.Add(permission.GameGPURead)
		case gpuAsked:
			// Frames capture and the adapter publishes nothing: an ordinary machine
			// rather than a fault, and nothing to install. Saying so is the only way
			// it reads as ordinary at the other end.
			reasons[string(permission.GameGPURead)] = gs.ReasonGPUTelemetryUnavailable
		default:
			// Deliberately no entry. The probe carried no --gpu, so the sensor was
			// never asked about the adapter, and an absent key is exactly how the
			// report encodes an unasked question. A code here would report a failure
			// where the agent simply declined to look.
		}
	}
	return supported, reasons
}

// gameConfigApplier hands the site's pushed game configuration to the sensor
// supervisor. It is the whole of the agent's game-configuration policy: the
// server states what the site wants, and the translation into what the sensor is
// told happens here, once.
//
// gpu is the effective game.gpu.read decision, carried here because the site's
// pushed configuration says nothing about it: whether the sensor may read
// adapter telemetry is settled once, from the grant and this machine's probe.
type gameConfigApplier struct {
	sensor *gamesense.Supervisor
	gpu    bool
}

// ApplyGameConfig installs the pushed configuration. The supervisor compares it
// against what the sensor is already running, so a re-push of an unchanged
// configuration — which is most of them — costs nothing.
func (a gameConfigApplier) ApplyGameConfig(cfg pcfg.GameConfig) {
	a.sensor.SetConfig(sensorConfig(cfg, a.gpu))
}

// sensorConfig translates the site's game configuration into the sensor's, under
// the effective GPU decision — which comes from the permission set rather than
// the push, because the site says what it wants collected and the permission
// says what this machine is allowed and able to collect.
//
// The mode is derived here rather than pushed, because it is the site's
// record-unmatched setting under another name: "do not record processes that
// match no profile" IS strict tracking. The profile count deliberately does not
// enter into it. A site that turns the setting off before naming its first game
// — or deletes its last profile while it is off — has said that nothing
// unmatched may be recorded, and with no profiles nothing matches, so the
// correct outcome is that nothing is captured at all. Falling back to recording
// everything in that window would override the one setting that exists to
// prevent it, at exactly the moment the site has nothing else to say. Capture
// resumes the moment a profile is created. Out of the box the setting is on, so
// a fresh site still records everything.
//
// Name and MonitorIDs are deliberately dropped: neither changes what the sensor
// does, and a field the sensor carries without reading is a field that can drift.
func sensorConfig(cfg pcfg.GameConfig, gpu bool) gs.Config {
	mode := gs.ModeAll
	if !cfg.RecordUnmatched {
		mode = gs.ModeProfiles
	}
	var profiles []gs.ConfigProfile
	for _, p := range cfg.Profiles {
		profiles = append(profiles, gs.ConfigProfile{
			ID:        p.ID,
			Exe:       p.Exe,
			TargetFPS: p.TargetFPS,
			Tier:      p.Tier,
		})
	}
	return gs.Config{
		GPU:      gpu,
		Mode:     mode,
		Profiles: profiles,
	}
}

// hostMetricsEnabled reports whether any host.* metric family is effective.
func hostMetricsEnabled(effective permission.Set) bool {
	for _, id := range []permission.ID{
		permission.HostCPURead, permission.HostMemoryRead, permission.HostDiskRead,
		permission.HostLoadRead, permission.HostUptimeRead, permission.HostNetworkIORead,
		permission.HostTemperatureRead,
	} {
		if effective.Has(id) {
			return true
		}
	}
	return false
}

// fillLimits substitutes DefaultLimits for any zero field.
func fillLimits(l Limits) Limits {
	d := DefaultLimits()
	if l.MinProbeInterval <= 0 {
		l.MinProbeInterval = d.MinProbeInterval
	}
	if l.MaxProbeConcurrency <= 0 {
		l.MaxProbeConcurrency = d.MaxProbeConcurrency
	}
	if l.SnapshotMinInterval <= 0 {
		l.SnapshotMinInterval = d.SnapshotMinInterval
	}
	if l.SnapshotTimeout <= 0 {
		l.SnapshotTimeout = d.SnapshotTimeout
	}
	if l.MaxTraceConcurrency <= 0 {
		l.MaxTraceConcurrency = d.MaxTraceConcurrency
	}
	return l
}

// policyHash is the single computation site for the policy hash: SHA-256,
// lowercase hex, over a versioned canonical preimage. The supported set (a
// platform fact) is deliberately excluded. Selectors are canonicalized and
// sorted (order is semantically irrelevant — deny always wins).
//
// It is computed per server, because the policy it identifies is per server: two
// servers on one machine can hold different grants and different target-access
// narrowing, and a shared hash would tell them their policies matched when they
// did not. The preimage therefore carries both layers of target access — the
// machine's floor and this server's narrowing — since the same grant behind a
// different floor is a different effective policy. The server treats the value
// as opaque, so nothing outside this function depends on the format.
func policyHash(cfg Config, sc ServerConfig, policy permission.Policy) string {
	mode := string(cfg.ProbeAccess.Mode)
	if policy.FullAccess {
		mode = "bypass"
	}
	limits := fillLimits(cfg.Limits)
	var b strings.Builder
	b.WriteString("nettact-agent-policy/v2\n")
	b.WriteString("source=" + string(policy.Source) + "\n")
	b.WriteString("permissions=" + strings.Join(policy.Granted.Strings(), ",") + "\n")
	b.WriteString("probe_access.mode=" + mode + "\n")
	b.WriteString("probe_access.allow=" + strings.Join(cfg.ProbeAccess.AllowStrings(), ",") + "\n")
	b.WriteString("probe_access.deny=" + strings.Join(cfg.ProbeAccess.DenyStrings(), ",") + "\n")
	// Empty lines rather than omitted ones when there is no narrowing, so a server
	// that narrows to exactly the machine floor still hashes differently from one
	// that does not narrow at all — they mean the same thing today, and would stop
	// meaning the same thing the moment the floor is edited.
	if sc.ProbeNarrow != nil {
		b.WriteString("narrow.mode=" + string(sc.ProbeNarrow.Mode) + "\n")
		b.WriteString("narrow.allow=" + strings.Join(sc.ProbeNarrow.AllowStrings(), ",") + "\n")
		b.WriteString("narrow.deny=" + strings.Join(sc.ProbeNarrow.DenyStrings(), ",") + "\n")
	} else {
		b.WriteString("narrow=none\n")
	}
	b.WriteString("limits=" +
		strconv.FormatInt(int64(limits.MinProbeInterval), 10) + "," +
		strconv.Itoa(limits.MaxProbeConcurrency) + "," +
		strconv.FormatInt(int64(limits.SnapshotMinInterval), 10) + "," +
		strconv.FormatInt(int64(limits.SnapshotTimeout), 10) + "," +
		strconv.Itoa(limits.MaxTraceConcurrency) + "\n")
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:])
}
