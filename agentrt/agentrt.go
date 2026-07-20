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

	"github.com/nettact/agent/internal/collector"
	"github.com/nettact/agent/internal/conn"
	"github.com/nettact/agent/internal/enroll"
	"github.com/nettact/agent/internal/identity"
	"github.com/nettact/agent/internal/incidentscene"
	"github.com/nettact/agent/internal/monitoreval"
	"github.com/nettact/agent/internal/netguard"
	"github.com/nettact/agent/internal/platform"
	"github.com/nettact/agent/internal/scheduler"
	"github.com/nettact/agent/internal/traceroute"
	"github.com/nettact/agent/internal/wal"
	"github.com/nettact/agent/probepolicy"
	"github.com/nettact/protocol"
	pcfg "github.com/nettact/protocol/config"
	protoenroll "github.com/nettact/protocol/enroll"
	"github.com/nettact/protocol/permission"
	"github.com/nettact/protocol/telemetry"
	"github.com/nettact/protocol/wire"
)

// Version is the agent version reported at enrollment and in the Hello frame.
// A var so release builds stamp the real tag via
// -ldflags "-X github.com/nettact/agent/agentrt.Version=vX.Y.Z"; unstamped
// local/dev builds report "dev".
var Version = "dev"

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
	p := platform.New()

	// The three permission views: supported (platform-independent probes plus what
	// this OS implements), granted (the local policy), effective (usable
	// intersection). Effective is computed once and immutable for this process.
	supported := platformIndependentSupported()
	for id := range p.Supports() {
		supported.Add(id)
	}
	// TCP traceroute needs a raw ICMP socket to observe intermediate Time-Exceeded
	// responders (Administrator on Windows), so it is a runtime capability added to
	// supported only when the engine can actually open one. ICMP traceroute is a
	// static platform capability already advertised by p.Supports(). Effective
	// stays supported∩granted, so desktop FullAccess remains capability-gated.
	if _, tcpCap := traceroute.Supported(); tcpCap {
		supported.Add(permission.DiagnosticTracerouteTCP)
	}
	granted := cfg.Policy.Granted
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
		req := enroll.BuildRequest(priv, token, hostname, runtime.GOOS, Version, report)
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

	// Construct collectors gated by effective permissions. A denied collector is
	// never built, so its OS/gopsutil operations are never invoked.
	var configurables []conn.Configurable
	var selfSched []collector.Collector
	tracker := monitoreval.New(effective, granted, supported, guard, hash, cfg.Limits.MinProbeInterval)

	addProbe := func(c interface {
		conn.Configurable
		collector.Collector
		SetMinInterval(time.Duration)
	}) {
		c.SetMinInterval(cfg.Limits.MinProbeInterval)
		configurables = append(configurables, c)
		selfSched = append(selfSched, c)
	}
	if effective.Has(permission.NetworkGatewayProbe) {
		addProbe(collector.NewGatewayPingCollector(p, guard))
	}
	if effective.Has(permission.ProbeICMP) {
		addProbe(collector.NewPublicPingCollector(p, guard))
	}
	if effective.Has(permission.ProbeDNS) {
		addProbe(collector.NewDNSCollector(guard))
	}
	if effective.Has(permission.ProbeHTTP) {
		addProbe(collector.NewHTTPCollector(guard, effective.Has(permission.ProbeHTTPExtended)))
	}
	if effective.Has(permission.ProbeTCP) {
		addProbe(collector.NewTCPCollector(guard))
	}
	if effective.Has(permission.ProbeNAT) {
		addProbe(collector.NewNATCollector(guard))
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
		dropped, err := outbox.Append(res.Metrics, res.Events, res.Inventory, snaps)
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
		))
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
			_, _ = outbox.Append([]telemetry.Metric{
				{TS: now, Kind: telemetry.AgentUptime, Target: "agent", Layer: telemetry.LayerLocal, Value: time.Since(start).Seconds(), Unit: telemetry.UnitSec},
				{TS: now, Kind: telemetry.AgentWALPending, Target: "agent", Layer: telemetry.LayerLocal, Value: float64(outbox.Pending()), Unit: telemetry.UnitCount},
			}, nil, nil, nil)
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
	traceEngine := traceroute.New(guard, effective, granted, supported, cfg.Limits.MaxTraceConcurrency)

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
			Platform:      runtime.GOOS,
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
		Effective:           effective,
		Granted:             granted,
		Supported:           supported,
		SnapshotMinInterval: cfg.Limits.SnapshotMinInterval,
		SnapshotTimeout:     cfg.Limits.SnapshotTimeout,
		CollectIncidentSnapshot: func(ctx context.Context, req pcfg.IncidentSnapshotRequest) telemetry.IncidentSnapshot {
			return incidentscene.Collect(ctx, req, sceneDeps)
		},
		RunTrace: func(ctx context.Context, req pcfg.TraceRequest) telemetry.TraceResult {
			return traceEngine.Run(ctx, req)
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

// hostMetricsEnabled reports whether any host.* metric family is effective.
func hostMetricsEnabled(effective permission.Set) bool {
	for _, id := range []permission.ID{
		permission.HostCPURead, permission.HostMemoryRead, permission.HostDiskRead,
		permission.HostLoadRead, permission.HostUptimeRead, permission.HostNetworkIORead,
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
