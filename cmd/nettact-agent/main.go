// Command nettact-agent is the endpoint/site monitoring agent — a pure outbound
// client that never listens on any port (architecture §15.1). Collectors (run
// at three scheduler tiers) append to a local SQLite WAL for durability, and a
// persistent WebSocket session to the server drains batches with a persistent
// sequence — a server outage or agent crash never loses data and never
// double-counts (the server dedups on agent_id+sequence). The same socket
// carries server pushes (DesiredState config, live-snapshot requests) down.
package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
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
	"github.com/nettact/protocol/telemetry"
	"github.com/nettact/protocol/wire"
)

const agentVersion = "0.3.0-m3"

func main() {
	server := flag.String("server", "", "server base URL, e.g. http://localhost:8080 (required)")
	dataDir := flag.String("data-dir", "./agent-data", "directory for agent state (key, credential, WAL)")
	enrollToken := flag.String("enroll-token", "", "one-time enrollment token (first run only)")
	insecure := flag.Bool("insecure", false, "skip TLS verification (LAN self-signed)")
	uploadEvery := flag.Duration("upload-interval", 5*time.Second, "how often to drain the WAL over the WebSocket")
	wireFormat := flag.String("wire-format", "protobuf", "telemetry wire encoding: protobuf (compact, default) or json (debug)")
	// Host-monitoring opt-in. These flags are the SOLE authority: without them the
	// agent never collects the corresponding data, so the server cannot obtain any
	// host state from a non-opted-in agent (enforced agent-side, below).
	reportHost := flag.Bool("report-host", false, "report host CPU/memory/disk/load/uptime/network metrics (opt-in)")
	reportProcs := flag.Bool("report-processes", false, "permit on-demand live process-list snapshots (opt-in)")
	reportConns := flag.Bool("report-connections", false, "permit on-demand live network-connection snapshots (opt-in)")
	flag.Parse()

	if *server == "" {
		log.Fatal("--server is required")
	}

	// The wire format is fixed per connection via the negotiated WS subprotocol.
	var subprotocol string
	switch *wireFormat {
	case "protobuf":
		subprotocol = wire.SubprotocolProtobuf
	case "json":
		subprotocol = wire.SubprotocolJSON
	default:
		log.Fatalf("--wire-format must be 'protobuf' or 'json', got %q", *wireFormat)
	}

	priv, err := identity.LoadOrCreateKey(*dataDir)
	if err != nil {
		log.Fatalf("identity: %v", err)
	}
	hostname, _ := os.Hostname()
	p := platform.New()

	// Capabilities advertised at enroll reflect only enabled opt-in flags, so the
	// console can tell which agents will serve host metrics / live snapshots.
	caps := append([]capability.Capability(nil), p.Supports()...)
	// The TCP and NAT collectors are registered unconditionally and are
	// platform-independent (pure net/STUN), so advertise them so the console can
	// discover them.
	caps = append(caps, capability.ProbeTCP, capability.ProbeNAT)
	if *reportHost {
		caps = append(caps, capability.HostStatRead)
	}
	if *reportProcs {
		caps = append(caps, capability.HostProcessRead)
	}
	if *reportConns {
		caps = append(caps, capability.HostConnectionRead)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cred, enrolled, err := identity.LoadCredential(*dataDir)
	if err != nil {
		log.Fatalf("load credential: %v", err)
	}
	if !enrolled {
		if *enrollToken == "" {
			log.Fatal("first run requires --enroll-token (create one in the Lite console)")
		}
		cred, err = enroll.Enroll(ctx, *server, *insecure, priv, *enrollToken, hostname, runtime.GOOS, agentVersion, caps)
		if err != nil {
			log.Fatalf("enroll: %v", err)
		}
		if err := identity.SaveCredential(*dataDir, cred); err != nil {
			log.Fatalf("save credential: %v", err)
		}
		log.Printf("enrolled as %s (site %s)", cred.AgentID, cred.SiteID)
	} else {
		log.Printf("resuming as %s (site %s)", cred.AgentID, cred.SiteID)
	}

	outbox, err := wal.Open(filepath.Join(*dataDir, "wal.db"))
	if err != nil {
		log.Fatalf("open wal: %v", err)
	}
	defer outbox.Close()

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
	// gateway/iface/arp run on the fixed tier loops; publicPing/dns/httpc are
	// self-scheduling (each target probed on its own configured interval).
	arp := collector.NewARPCollector(p)
	tiered := []collector.Collector{gateway, iface, arp}
	if *reportHost {
		// Host metrics flow through the same WAL→WS→ingest→series pipeline as
		// probes, so History and the alert engine work with no server changes.
		tiered = append(tiered, collector.NewHostMetricsCollector())
		log.Print("host metrics reporting enabled (--report-host)")
	}
	sched := scheduler.New(
		tiered,
		[]collector.Collector{publicPing, dns, httpc, tcpc, natc},
		sink,
	)
	sched.Run(ctx)

	// Status heartbeat: report uptime + WAL depth outbound via the WAL/WS path
	// (the agent never exposes an endpoint).
	start := time.Now()
	go func() {
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
			case <-ctx.Done():
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
	log.Printf("telemetry wire format: %s", *wireFormat)
	log.Printf("agent %s started (host=%s, platform=%s, caps=%v)", cred.AgentID, hostname, runtime.GOOS, p.Supports())

	// The connection loop owns everything session-scoped: WAL drain, ack
	// tracking, config application, and snapshot serving. It blocks until ctx
	// is cancelled, reconnecting with backoff as needed, and sends a clean
	// WebSocket close on shutdown so the server marks us offline immediately.
	err = conn.Run(ctx, conn.Options{
		ServerURL: *server,
		Token:     cred.AgentToken,
		Insecure:  *insecure,
		Format:    subprotocol,
		AgentID:   cred.AgentID,
		SiteID:    cred.SiteID,
		Hello: wire.Hello{
			SchemaVersion: protocol.SchemaVersion,
			Hostname:      hostname,
			Platform:      runtime.GOOS,
			AgentVersion:  agentVersion,
			Capabilities:  capStrs,
		},
	}, conn.Deps{
		Outbox:        outbox,
		Configurables: configurables,
		Scheduler:     sched,
		DrainInterval: *uploadEvery,
		ReportProcs:   *reportProcs,
		ReportConns:   *reportConns,
	})
	if err != nil {
		log.Fatalf("connection: %v", err)
	}
	log.Println("agent stopping")
}
