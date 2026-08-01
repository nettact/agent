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
	"github.com/nettact/agent/internal/identity"
	"github.com/nettact/agent/internal/incidentscene"
	"github.com/nettact/agent/internal/monitoreval"
	"github.com/nettact/agent/internal/netguard"
	"github.com/nettact/agent/internal/platform"
	"github.com/nettact/agent/internal/proxydial"
	"github.com/nettact/agent/internal/scheduler"
	"github.com/nettact/agent/internal/traceegress"
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

// Terminal outcomes. Run returns one of these (wrapped) when re-running the same
// process cannot help without intervention; a supervisor uses errors.Is to pick
// its policy (re-enroll on ErrRevoked, stop on ErrSuperseded, back off on
// ErrEnroll). ErrRevoked/ErrSuperseded alias the conn sentinels so a caller need
// not import internal/conn.
var (
	// ErrRevoked: the server deleted this agent. Run deletes the stale credential
	// itself before returning, so re-running enrolls fresh via TokenSource.
	ErrRevoked = conn.ErrRevoked
	// ErrSuperseded: another process owns this credential. Re-running would fight
	// it in a 4000 loop, so the supervisor should stop, not retry.
	ErrSuperseded = conn.ErrSuperseded
	// ErrEnroll: enrollment could not complete (no token, quota, bad token,
	// server unreachable at enroll time). Distinguishes "never initialized" from
	// a mid-run failure.
	ErrEnroll = errors.New("agent enrollment failed")
)

// EventKind identifies a lifecycle event delivered to Config.OnEvent.
type EventKind int

const (
	// EventEnrolled fires once, after a first-run credential is saved.
	EventEnrolled EventKind = iota
	// EventConnected fires each time a server session becomes live (after Hello).
	EventConnected
	// EventDisconnected fires each time a live session ends, including transient
	// reconnects — it is not a terminal error.
	EventDisconnected
)

// maxGameDrainInterval bounds how long game seconds may sit in the sensor
// recorder before being written to the WAL.
//
// The recorder holds ten minutes of them, and the upload interval is
// configurable well past that, so the drain cannot simply follow it: the oldest
// seconds would age out of the ring before anything durable had seen them. A
// minute leaves an order of magnitude of headroom.
const maxGameDrainInterval = time.Minute

// Event is a non-terminal lifecycle notification. Terminal outcomes are Run's
// return value, never an Event.
type Event struct {
	Kind    EventKind
	AgentID string
	Err     error
}

// Limits are the local stability controls (spec §3.1). Zero values select the
// production defaults in DefaultLimits.
type Limits struct {
	MinProbeInterval    time.Duration
	MaxProbeConcurrency int
	SnapshotMinInterval time.Duration
	SnapshotTimeout     time.Duration
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

// Config drives one Run. Zero values select production defaults where noted.
type Config struct {
	ServerURL      string        // e.g. http://127.0.0.1:52344; required unless both Dialer and Enroller are set
	DataDir        string        // holds agent.key, agent.json, wal.db
	Insecure       bool          // skip TLS verification (LAN self-signed)
	UploadInterval time.Duration // WAL drain cadence; 0 → 5s
	WireFormat     string        // "protobuf" (default when empty) or "json"

	// Policy is the agent's immutable local permission grant (spec §3). The
	// standalone binary builds it from NETTACT_AGENT_PERMISSIONS (or the frozen
	// default); the desktop passes permission.FullAccess(). Run validates it is
	// non-zero.
	Policy permission.Policy

	// ProbeAccess is the immutable target-access policy (spec §3.4). The desktop
	// leaves it zero (the guard never consults it under FullAccess bypass).
	ProbeAccess probepolicy.Policy

	// Limits are the local stability controls. Zero fields select DefaultLimits.
	Limits Limits

	// Dialer establishes the server session. Nil selects a WebSocket to ServerURL
	// (the standalone path). The desktop injects the embedded Lite server's
	// in-process pipe dialer so telemetry never touches a loopback socket.
	Dialer wire.Dialer

	// Enroller performs the enrollment exchange for a signed request. Nil selects
	// the HTTP POST to ServerURL/api/v1/enroll (standalone). The desktop injects a
	// direct registry call so first-run enrollment needs no HTTP round-trip.
	Enroller func(ctx context.Context, req protoenroll.EnrollRequest) (protoenroll.EnrollResponse, error)

	// TokenSource supplies a one-time enrollment token, invoked ONLY when there
	// is no credential on disk. The CLI returns the enrollment token (or an
	// error); the desktop returns srv.MintEnrollmentToken. Required for first-run
	// enrollment; if nil and enrollment is needed, Run returns ErrEnroll.
	TokenSource func(ctx context.Context) (string, error)

	// OnEvent, if non-nil, receives lifecycle events. It must be fast and
	// non-blocking: it runs on agent goroutines (the session goroutine for
	// Connected/Disconnected).
	OnEvent func(Event)
}

func (c Config) emit(ev Event) {
	if c.OnEvent != nil {
		c.OnEvent(ev)
	}
}

// Run starts the agent and blocks until ctx is cancelled or a terminal outcome
// occurs. It returns nil on ctx cancellation (clean shutdown, close frame sent)
// and a wrapped ErrRevoked/ErrSuperseded/ErrEnroll (or another error) otherwise.
// All goroutines it starts are stopped before it returns, and the WAL is closed,
// so re-running on the same DataDir is safe.
func Run(ctx context.Context, cfg Config) error {
	// ServerURL feeds the default WebSocket dialer and the default HTTP enroller.
	// When the desktop injects both a Dialer and an Enroller, no URL is needed.
	if cfg.ServerURL == "" && (cfg.Dialer == nil || cfg.Enroller == nil) {
		return errors.New("agentrt: ServerURL is required unless both Dialer and Enroller are set")
	}
	if cfg.UploadInterval == 0 {
		cfg.UploadInterval = 5 * time.Second
	}
	if cfg.Policy.Granted == nil {
		return errors.New("agentrt: Config.Policy must be set (permission grant)")
	}
	cfg.Limits = fillLimits(cfg.Limits)

	subprotocol, err := subprotocolFor(cfg.WireFormat)
	if err != nil {
		return err
	}

	priv, err := identity.LoadOrCreateKey(cfg.DataDir)
	if err != nil {
		return fmt.Errorf("identity: %w", err)
	}
	hostname, _ := os.Hostname()
	platformID := reportedPlatform()
	p := platform.New()

	// The three permission views: supported (platform-independent probes plus what
	// this OS implements), granted (the local policy), effective (usable
	// intersection). Effective is computed once and immutable for this process.
	supported := platformIndependentSupported()
	for id := range p.Supports() {
		supported.Add(id)
	}
	// Both traceroute modes are runtime capabilities owned by the traceroute
	// engine, which is the only component that knows what observing intermediate
	// Time-Exceeded responders costs on each OS: Administrator on Windows for TCP,
	// a raw ICMP socket (CAP_NET_RAW/root) on Linux for either mode. Asking it
	// keeps one answer per mode instead of a platform layer and an engine
	// disagreeing. Effective stays supported∩granted, so desktop FullAccess
	// remains capability-gated.
	icmpTraceCap, tcpTraceCap := traceroute.Supported()
	if icmpTraceCap {
		supported.Add(permission.DiagnosticTracerouteICMP)
	}
	if tcpTraceCap {
		supported.Add(permission.DiagnosticTracerouteTCP)
	}
	granted := cfg.Policy.Granted
	// Temperature is capability-probed only after permission is granted. The
	// collector's platform gate returns unsupported without touching a provider on
	// Windows: ACPI WMI thermal zones are not trustworthy hardware temperatures.
	// Other platforms advertise the permission only when a real read succeeds.
	if granted.Has(permission.HostTemperatureRead) && collector.TemperatureSupported(ctx) {
		supported.Add(permission.HostTemperatureRead)
	}
	// Frame data comes from a separate sensor component that most installs do not
	// ship, so the capability question is first "is it here at all" and only then
	// "can it work". Both answers are needed: a missing component is the ordinary
	// state and says nothing, while an installed one that cannot capture is a
	// fixable problem the operator would otherwise have no way to see. The probe
	// runs the component, so it stays behind the grant for the same reason the
	// temperature read does.
	//
	// "Can it work" is itself two answers, because the reads fail apart: frame
	// timings come from the game's own presentation, while GPU and VRAM telemetry
	// comes from a driver that may publish none. Plenty of machines capture frames
	// perfectly and expose no adapter telemetry — an ordinary machine, not a
	// degraded one — so the two supports have to be able to differ. Collapsing them
	// would either withhold the capture that works or advertise a read that could
	// never produce a number.
	var gameSensorPath string
	var gameProbe gamesense.ProbeResult
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
	// Either grant is reason enough to ask. Unlike the temperature probe, this one
	// captures nothing — it looks for the component and asks it whether a frame
	// source answers — so requiring the broader permission before asking would only
	// make a policy that grants detection alone report detection as unsupported on
	// a machine that can do it. EffectiveFrom still removes whatever was not
	// granted.
	if granted.Has(permission.GameProcessDetect) || granted.Has(permission.GamePerformanceRead) {
		if path, ok := gamesense.Locate(Version == "dev"); ok {
			gameSensorPath = path
			gameProbe = gamesense.Probe(ctx, path, granted.Has(permission.GameGPURead))
			if gameProbe.OK {
				supported.Add(permission.GameProcessDetect)
				supported.Add(permission.GamePerformanceRead)
			}
			// The adapter read the sensor separately verified, never inferred from
			// the capture working — and never claimed for a question that was not
			// asked.
			if gameProbe.OK && gameProbe.GPUOK {
				supported.Add(permission.GameGPURead)
			}
		}
	}
	effective := permission.EffectiveFrom(granted, supported)

	guard := netguard.New(cfg.ProbeAccess, cfg.Policy.FullAccess)
	hash := policyHash(cfg)
	report := permission.PermissionReport{
		Supported:  supported.Strings(),
		Granted:    granted.Strings(),
		Effective:  effective.Strings(),
		Source:     string(cfg.Policy.Source),
		PolicyHash: hash,
	}

	cred, enrolled, err := identity.LoadCredential(cfg.DataDir)
	if err != nil {
		return fmt.Errorf("load credential: %w", err)
	}
	if !enrolled {
		if cfg.TokenSource == nil {
			return fmt.Errorf("first run requires an enrollment token: %w", ErrEnroll)
		}
		token, err := cfg.TokenSource(ctx)
		if err != nil {
			return fmt.Errorf("obtain enrollment token: %v: %w", err, ErrEnroll)
		}
		// Build+sign the request, then run it through the injected Enroller (direct
		// registry call in desktop) or the default HTTP POST (standalone).
		req := enroll.BuildRequest(priv, token, hostname, platformID, Version, report)
		exchange := cfg.Enroller
		if exchange == nil {
			exchange = func(ctx context.Context, r protoenroll.EnrollRequest) (protoenroll.EnrollResponse, error) {
				return enroll.Post(ctx, cfg.ServerURL, cfg.Insecure, r)
			}
		}
		resp, err := exchange(ctx, req)
		if err != nil {
			return fmt.Errorf("enroll: %v: %w", err, ErrEnroll)
		}
		cred = identity.Credential{AgentID: resp.AgentID, SiteID: resp.SiteID, AgentToken: resp.AgentToken}
		if err := identity.SaveCredential(cfg.DataDir, cred); err != nil {
			return fmt.Errorf("save credential: %w", err)
		}
		log.Printf("enrolled as %s (site %s)", cred.AgentID, cred.SiteID)
		cfg.emit(Event{Kind: EventEnrolled, AgentID: cred.AgentID})
	} else {
		log.Printf("resuming as %s (site %s)", cred.AgentID, cred.SiteID)
	}

	// Internal context cancelled when Run returns, so the scheduler and heartbeat
	// never outlive one Run — important when a terminal session error (not ctx
	// cancel) makes the supervisor re-run: the previous Run's goroutines must be
	// gone first.
	runCtx, cancel := context.WithCancel(ctx)

	outbox, err := wal.Open(filepath.Join(cfg.DataDir, "wal.db"))
	if err != nil {
		cancel()
		return fmt.Errorf("open wal: %w", err)
	}

	// An installed sensor that cannot collect looks identical to no sensor at all
	// in the permission report — both are simply unsupported. One of the two is
	// fixable, so it gets an event carrying the reason.
	//
	// Reported once per process for a given outcome, not once per Run: a
	// supervisor re-runs this function in the same process after a revoked or
	// dropped session, and an unchanged sensor is not news each time. Cancellation
	// is excluded outright — a probe interrupted by shutdown failed to answer,
	// which is not the same as answering "blocked", and persisting that would
	// leave a warning to be uploaded on the next start.
	if gameSensorPath != "" && !gameProbe.OK && ctx.Err() == nil && blockedSensorUnreported(gameSensorPath, gameProbe.Reason) {
		log.Printf("game sensor at %s unavailable: %s", gameSensorPath, gameProbe.Reason)
		_, _ = outbox.Append(wal.Records{Events: []telemetry.Event{{
			ID:       uuid.NewString(),
			TS:       time.Now().UTC(),
			Type:     telemetry.EventGameSensorBlocked,
			Layer:    telemetry.LayerLocal,
			Severity: telemetry.SeverityWarn,
			Message:  "game sensor installed but unavailable",
			Attrs: map[string]string{
				"reason": gameProbe.Reason,
				"path":   gameSensorPath,
			},
		}}})
	}

	// Construct collectors gated by effective permissions. A denied collector is
	// never built, so its OS/gopsutil operations are never invoked.
	var configurables []conn.Configurable
	var selfSched []collector.Collector
	// Egress proxies are built lazily on first use and torn down whenever a pushed
	// generation changes, so constructing the manager here costs nothing until a
	// target is actually pinned to one.
	proxies := proxydial.NewManager(guard)
	defer proxies.Close()
	tracker := monitoreval.New(effective, granted, supported, guard, proxies, hash, cfg.Limits.MinProbeInterval, cfg.UploadInterval)

	addProbe := func(c interface {
		conn.Configurable
		collector.Collector
		SetMinInterval(time.Duration)
	}) {
		c.SetMinInterval(cfg.Limits.MinProbeInterval)
		configurables = append(configurables, c)
		selfSched = append(selfSched, c)
	}
	// The gateway probe is the one kind that is never proxied: it targets the local
	// first hop, where an egress proxy has no meaning.
	if effective.Has(permission.NetworkGatewayProbe) {
		addProbe(collector.NewGatewayPingCollector(p, guard))
	}
	if effective.Has(permission.ProbeICMP) {
		addProbe(collector.NewPublicPingCollector(p, guard, proxies))
	}
	if effective.Has(permission.ProbeDNS) {
		addProbe(collector.NewDNSCollector(guard, proxies, effective))
	}
	if effective.Has(permission.ProbeHTTP) {
		addProbe(collector.NewHTTPCollector(guard, proxies, effective.Has(permission.ProbeHTTPExtended)))
	}
	if effective.Has(permission.ProbeTCP) {
		addProbe(collector.NewTCPCollector(guard, proxies))
	}
	if effective.Has(permission.ProbeNAT) {
		addProbe(collector.NewNATCollector(guard, proxies))
	}

	// The runtime-block sink routes collector policy blocks to the tracker and a
	// later clean metric back to active. Each transition carries the originating
	// target generation (ConfigSerial) so the tracker can ignore an obsolete
	// in-flight result and never let it alter the current generation's status.
	sink := func(res collector.Result) {
		for _, b := range res.Blocked {
			tracker.RuntimeBlocked(b.MonitorID, b.ConfigSerial, b.Matched, b.Reason)
		}
		for _, m := range res.Metrics {
			if m.MonitorID != "" {
				tracker.RuntimeOK(m.MonitorID, m.ConfigSerial)
			}
		}
		var snaps []telemetry.InterfaceSnapshot
		if res.InterfaceSnapshot != nil {
			snaps = []telemetry.InterfaceSnapshot{*res.InterfaceSnapshot}
		}
		dropped, err := outbox.Append(wal.Records{
			Metrics:   res.Metrics,
			Events:    res.Events,
			Inventory: res.Inventory,
			Snapshots: snaps,
		})
		if err != nil {
			log.Printf("wal append: %v", err)
			return
		}
		if dropped > 0 {
			log.Printf("WAL over capacity: dropped %d oldest samples (data gap)", dropped)
		}
	}

	// Tiered collectors: interface (status), ARP (neighbor), host metrics — each
	// gated on its permission family.
	var tiered []collector.Collector
	if effective.Has(permission.NetIfaceStatusRead) {
		tiered = append(tiered, collector.NewInterfaceCollector(
			p,
			effective.Has(permission.NetIfaceAddressRead),
			effective.Has(permission.NetIfaceAddressRead) || effective.Has(permission.NetworkGatewayProbe),
			effective.Has(permission.NetWiFiStatusRead),
			effective.Has(permission.NetWiFiSSIDRead),
		))
	}
	if effective.Has(permission.NetNeighborRead) {
		tiered = append(tiered, collector.NewARPCollector(p, effective.Has(permission.NetNeighborHostRead)))
	}
	if hostMetricsEnabled(effective) {
		tiered = append(tiered, collector.NewHostMetricsCollector(
			effective.Has(permission.HostCPURead),
			effective.Has(permission.HostMemoryRead),
			effective.Has(permission.HostDiskRead),
			effective.Has(permission.HostLoadRead),
			effective.Has(permission.HostUptimeRead),
			effective.Has(permission.HostNetworkIORead),
			effective.Has(permission.HostTemperatureRead),
		))
	}
	// The game sensor is a child process streaming a line per second, so unlike
	// the collectors above it does not do its work on a tier and produces no
	// metrics at all: the supervisor records runs and per-second buckets, and the
	// agent drains them on the upload cadence. Built here, started below, once the
	// run context and shutdown wait group exist.
	var gameSensor *gamesense.Supervisor
	if effective.Has(permission.GamePerformanceRead) && gameProbe.OK {
		gameSensor = gamesense.NewSupervisor(gameSensorPath, func(ev telemetry.Event) {
			_, _ = outbox.Append(wal.Records{Events: []telemetry.Event{ev}})
		})
	}
	// The game profiles arrive on the same DesiredState push as the probe targets
	// but on their own version axis, so the session applies them through their own
	// hook. Left nil when there is no sensor to configure — an agent that cannot
	// capture frames has nothing to do with a profile list, and a hook that exists
	// only to discard what it is given would be one more thing to keep honest.
	var gameApplier conn.GameApplier
	if gameSensor != nil {
		// The GPU flag is a permission decision, not a pushed setting, so it is
		// fixed for the life of the process and read off the effective set — what
		// the site granted, narrowed to what this machine's probe verified. A
		// re-push cannot widen it.
		gameApplier = gameConfigApplier{sensor: gameSensor, gpu: effective.Has(permission.GameGPURead)}
	}
	sched := scheduler.New(tiered, selfSched, sink)

	// Ordered shutdown, in this exact order: cancel runCtx so the scheduler and
	// heartbeat stop, join them, and only then close the WAL.
	var hbWG sync.WaitGroup
	defer func() {
		cancel()
		sched.Wait()
		hbWG.Wait()
		_ = outbox.Close()
	}()

	// Start the sensor. It joins the same wait group as the heartbeat so shutdown
	// stops it and waits for it before the WAL closes underneath the events it may
	// still be appending — and so the child process is gone before Run returns.
	if gameSensor != nil {
		// Game data goes into the WAL exactly like a collector's metrics and events
		// do, rather than being attached to a packet at send time. The WAL is what
		// makes telemetry survive an unreachable server and a crash mid-upload, and
		// a run recorded while offline is precisely the data worth keeping — a game
		// played during an outage is still a game that was played. Riding the same
		// rows also puts runs and buckets under the (agent_id, sequence) dedup that
		// makes the at-least-once upload safe to replay.
		//
		// One Append per drain, so the runs and the buckets that hang from them are
		// one WAL group and therefore one packet: the server never sees a bucket
		// whose run it has not been told about.
		flushGame := func() {
			runs, buckets := gameSensor.Drain()
			if len(runs) == 0 && len(buckets) == 0 {
				// An idle desktop produces nothing for hours. Appending anyway would
				// consume a group id and write a transaction on every tick, forever.
				return
			}
			dropped, err := outbox.Append(wal.Records{GameRuns: runs, GameBuckets: buckets})
			if err != nil {
				// Put them back. The drain already emptied the recorder, so
				// returning here without this turns one failed write — a full
				// disk, a moment of database contention — into a permanent hole
				// in the middle of a session.
				gameSensor.Requeue(runs, buckets)
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

	sched.Run(runCtx)

	// Status heartbeat: uptime + WAL depth over the same WAL→WS path.
	start := time.Now()
	hbWG.Add(1)
	go func() {
		defer hbWG.Done()
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		emit := func() {
			now := time.Now().UTC()
			_, _ = outbox.Append(wal.Records{Metrics: []telemetry.Metric{
				{TS: now, Kind: telemetry.AgentUptime, Target: "agent", Layer: telemetry.LayerLocal, Value: time.Since(start).Seconds(), Unit: telemetry.UnitSec},
				{TS: now, Kind: telemetry.AgentWALPending, Target: "agent", Layer: telemetry.LayerLocal, Value: float64(outbox.Pending()), Unit: telemetry.UnitCount},
			}})
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
	log.Printf("agent %s started (host=%s, platform=%s, source=%s, effective=%v)",
		cred.AgentID, hostname, runtime.GOOS, cfg.Policy.Source, effective.Strings())

	agentID := cred.AgentID

	// Incident-scene collector and traceroute engine (INCIDENT-002 / DIAG-001).
	// Both reuse the existing effective permissions, platform HAL, and target-
	// access guard; the engine owns the per-Agent traceroute concurrency limit.
	// They are invoked off the session goroutine and their result Frames written
	// by the single session writer, so normal collector cadence is untouched.
	sceneDeps := incidentscene.Deps{
		Platform:  p,
		Guard:     guard,
		Effective: effective,
		Granted:   granted,
		Supported: supported,
		Identity: incidentscene.Identity{
			AgentID:  cred.AgentID,
			Hostname: hostname,
			OS:       runtime.GOOS,
			Version:  Version,
		},
	}
	// traceegress.Resolver is what lets an in-tunnel trace reach the proxy manager
	// while the traceroute package stays independent of it, and it owns the
	// DIAG-004 fail-closed contract (see that package).
	traceEngine := traceroute.New(guard, effective, granted, supported, cfg.Limits.MaxTraceConcurrency,
		traceegress.Resolver(proxies))

	err = conn.Run(runCtx, conn.Options{
		ServerURL: cfg.ServerURL,
		Token:     cred.AgentToken,
		Insecure:  cfg.Insecure,
		Format:    subprotocol,
		Dialer:    cfg.Dialer,
		AgentID:   cred.AgentID,
		SiteID:    cred.SiteID,
		Hello: wire.Hello{
			SchemaVersion: protocol.SchemaVersion,
			Hostname:      hostname,
			Platform:      platformID,
			AgentVersion:  Version,
			Permissions:   report,
		},
		OnSession: func(up bool) {
			if up {
				cfg.emit(Event{Kind: EventConnected, AgentID: agentID})
			} else {
				cfg.emit(Event{Kind: EventDisconnected, AgentID: agentID})
			}
		},
	}, conn.Deps{
		Outbox:              outbox,
		Configurables:       configurables,
		Scheduler:           sched,
		DrainInterval:       cfg.UploadInterval,
		Tracker:             tracker,
		Proxies:             proxies,
		Game:                gameApplier,
		Effective:           effective,
		Granted:             granted,
		Supported:           supported,
		SnapshotMinInterval: cfg.Limits.SnapshotMinInterval,
		SnapshotTimeout:     cfg.Limits.SnapshotTimeout,
		CollectIncidentSnapshot: func(ctx context.Context, req pcfg.IncidentSnapshotRequest) telemetry.IncidentSnapshot {
			return incidentscene.Collect(ctx, req, sceneDeps)
		},
		RunTrace: func(ctx context.Context, req pcfg.TraceRequest, receivedAt time.Time) telemetry.TraceResult {
			return traceEngine.Run(ctx, req, receivedAt)
		},
	})

	// On revocation the credential is dead; delete it here so re-running enrolls
	// fresh (keeps credential-file knowledge inside the agent module and fixes the
	// standalone wart of a revoked agent redialing 4004 forever). The ed25519 key
	// is kept, so re-enrollment reuses the same identity.
	if errors.Is(err, ErrRevoked) {
		if derr := identity.DeleteCredential(cfg.DataDir); derr != nil {
			// The stale credential is still on disk (permissions, antivirus lock,
			// read-only FS), so re-running would reload it and be revoked again.
			// Downgrade the outcome from ErrRevoked (which a supervisor reads as
			// "ready to re-enroll now" and retries with no delay) to a plain terminal
			// error, so the supervisor backs off instead of tight-looping until the
			// deletion can succeed.
			return fmt.Errorf("delete revoked credential: %w", derr)
		}
	}
	return err
}

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
// gateway, wifi, and neighbor support where implemented.
func platformIndependentSupported() permission.Set {
	return permission.NewSet(
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
		permission.HostProcessIORead,
		// Connection snapshot scopes — gopsutil/net, compiled everywhere.
		permission.HostConnectionSummaryRead,
		permission.HostConnectionLocalRead,
		permission.HostConnectionRemoteRead,
		permission.HostConnectionOwnerRead,
	)
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
func policyHash(cfg Config) string {
	mode := string(cfg.ProbeAccess.Mode)
	if cfg.Policy.FullAccess {
		mode = "bypass"
	}
	limits := fillLimits(cfg.Limits)
	var b strings.Builder
	b.WriteString("nettact-agent-policy/v1\n")
	b.WriteString("source=" + string(cfg.Policy.Source) + "\n")
	b.WriteString("permissions=" + strings.Join(cfg.Policy.Granted.Strings(), ",") + "\n")
	b.WriteString("probe_access.mode=" + mode + "\n")
	b.WriteString("probe_access.allow=" + strings.Join(cfg.ProbeAccess.AllowStrings(), ",") + "\n")
	b.WriteString("probe_access.deny=" + strings.Join(cfg.ProbeAccess.DenyStrings(), ",") + "\n")
	b.WriteString("limits=" +
		strconv.FormatInt(int64(limits.MinProbeInterval), 10) + "," +
		strconv.Itoa(limits.MaxProbeConcurrency) + "," +
		strconv.FormatInt(int64(limits.SnapshotMinInterval), 10) + "," +
		strconv.FormatInt(int64(limits.SnapshotTimeout), 10) + "," +
		strconv.Itoa(limits.MaxTraceConcurrency) + "\n")
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:])
}
