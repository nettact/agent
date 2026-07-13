// Package agentrt is the agent runtime as an importable library: one blocking
// Run that owns identity, enrollment, the collector scheduler, the status
// heartbeat, and the persistent server session. The standalone nettact-agent
// command and the desktop all-in-one both drive the same code through this
// package — the command is a thin flags→Config wrapper, and the desktop passes
// an in-process enrollment TokenSource so no token ever touches a CLI.
//
// Run never calls log.Fatal, never parses flags, and never installs signal
// handlers; the caller owns process lifecycle via ctx. All traffic stays
// agent-initiated outbound — the agent never listens on a port.
package agentrt

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/nettact/agent/internal/collector"
	"github.com/nettact/agent/internal/conn"
	"github.com/nettact/agent/internal/enroll"
	"github.com/nettact/agent/internal/identity"
	"github.com/nettact/agent/internal/platform"
	"github.com/nettact/agent/internal/scheduler"
	"github.com/nettact/agent/internal/wal"
	"github.com/nettact/protocol"
	"github.com/nettact/protocol/capability"
	protoenroll "github.com/nettact/protocol/enroll"
	"github.com/nettact/protocol/telemetry"
	"github.com/nettact/protocol/wire"
)

// Version is the agent version reported at enrollment and in the Hello frame.
const Version = "0.3.0-m3"

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

// Config drives one Run. Zero values select production defaults where noted.
type Config struct {
	ServerURL      string        // e.g. http://127.0.0.1:52344; required unless both Dialer and Enroller are set
	DataDir        string        // holds agent.key, agent.json, wal.db
	Insecure       bool          // skip TLS verification (LAN self-signed)
	UploadInterval time.Duration // WAL drain cadence; 0 → 5s
	WireFormat     string        // "protobuf" (default when empty) or "json"

	// Dialer establishes the server session. Nil selects a WebSocket to ServerURL
	// (the standalone path). The desktop injects the embedded Lite server's
	// in-process pipe dialer so telemetry never touches a loopback socket.
	Dialer wire.Dialer

	// Enroller performs the enrollment exchange for a signed request. Nil selects
	// the HTTP POST to ServerURL/api/v1/enroll (standalone). The desktop injects a
	// direct registry call so first-run enrollment needs no HTTP round-trip.
	Enroller func(ctx context.Context, req protoenroll.EnrollRequest) (protoenroll.EnrollResponse, error)

	// Privacy opt-ins. All default false; the desktop bundled agent leaves them
	// false (network monitoring only). They are the sole authority for host data
	// collection: without them the agent never advertises the capability and
	// never collects, so the server can obtain nothing.
	ReportHost  bool
	ReportProcs bool
	ReportConns bool

	// TokenSource supplies a one-time enrollment token, invoked ONLY when there
	// is no credential on disk. The CLI returns --enroll-token (or an error); the
	// desktop returns srv.MintEnrollmentToken. Required for first-run enrollment;
	// if nil and enrollment is needed, Run returns ErrEnroll.
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

	// Advertised capabilities reflect only enabled opt-ins, so the console can
	// tell which agents will serve host metrics / live snapshots. TCP and NAT are
	// platform-independent and always advertised.
	caps := append([]capability.Capability(nil), p.Supports()...)
	caps = append(caps, capability.ProbeTCP, capability.ProbeNAT)
	if cfg.ReportHost {
		caps = append(caps, capability.HostStatRead)
	}
	if cfg.ReportProcs {
		caps = append(caps, capability.HostProcessRead)
	}
	if cfg.ReportConns {
		caps = append(caps, capability.HostConnectionRead)
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
		req := enroll.BuildRequest(priv, token, hostname, runtime.GOOS, Version, caps)
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

	gateway := collector.NewGatewayPingCollector(p)
	publicPing := collector.NewPublicPingCollector(p)
	iface := collector.NewInterfaceCollector(p)
	dns := collector.NewDNSCollector()
	httpc := collector.NewHTTPCollector()
	tcpc := collector.NewTCPCollector()
	natc := collector.NewNATCollector()
	configurables := []conn.Configurable{publicPing, dns, httpc, tcpc, natc}

	sink := func(res collector.Result) {
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

	arp := collector.NewARPCollector(p)
	tiered := []collector.Collector{gateway, iface, arp}
	if cfg.ReportHost {
		tiered = append(tiered, collector.NewHostMetricsCollector())
		log.Print("host metrics reporting enabled")
	}
	sched := scheduler.New(
		tiered,
		[]collector.Collector{publicPing, dns, httpc, tcpc, natc},
		sink,
	)

	// Ordered shutdown, in this exact order: cancel runCtx so the scheduler and
	// heartbeat stop, join them, and only then close the WAL. conn.Run touches the
	// WAL solely on its own goroutine and returns before this runs, so once these
	// background writers are joined nothing can append to a closed store. A
	// terminal session error returns from conn.Run WITHOUT cancelling runCtx, so
	// the explicit cancel here (not a bare defer) is what stops the loops.
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

	capStrs := make([]string, len(caps))
	for i, c := range caps {
		capStrs[i] = string(c)
	}
	log.Printf("telemetry wire format: %s", subprotocol)
	log.Printf("agent %s started (host=%s, platform=%s, caps=%v)", cred.AgentID, hostname, runtime.GOOS, p.Supports())

	agentID := cred.AgentID
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
			Capabilities:  capStrs,
		},
		OnSession: func(up bool) {
			if up {
				cfg.emit(Event{Kind: EventConnected, AgentID: agentID})
			} else {
				cfg.emit(Event{Kind: EventDisconnected, AgentID: agentID})
			}
		},
	}, conn.Deps{
		Outbox:        outbox,
		Configurables: configurables,
		Scheduler:     sched,
		DrainInterval: cfg.UploadInterval,
		ReportProcs:   cfg.ReportProcs,
		ReportConns:   cfg.ReportConns,
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
