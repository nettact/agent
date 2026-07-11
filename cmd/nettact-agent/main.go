// Command nettact-agent is the endpoint/site monitoring agent — a pure outbound
// client that never listens on any port (architecture §15.1). M3 makes the
// pipeline durable: collectors (run at three scheduler tiers) append to a local
// SQLite WAL, and a drain loop uploads batches with a persistent sequence so a
// server outage or agent crash never loses data and never double-counts (the
// server dedups on agent_id+sequence).
package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/nettact/agent/internal/collector"
	"github.com/nettact/agent/internal/enroll"
	"github.com/nettact/agent/internal/hostsnapshot"
	"github.com/nettact/agent/internal/identity"
	"github.com/nettact/agent/internal/platform"
	"github.com/nettact/agent/internal/scheduler"
	"github.com/nettact/agent/internal/uploader"
	"github.com/nettact/agent/internal/wal"
	"github.com/nettact/protocol"
	"github.com/nettact/protocol/capability"
	pcfg "github.com/nettact/protocol/config"
	"github.com/nettact/protocol/telemetry"
	"github.com/nettact/protocol/wire"
)

const agentVersion = "0.3.0-m3"

// configurable is a collector whose targets are pushed from the server.
type configurable interface {
	SetTargets([]pcfg.ProbeTarget)
}

func main() {
	server := flag.String("server", "", "server base URL, e.g. http://localhost:8080 (required)")
	dataDir := flag.String("data-dir", "./agent-data", "directory for agent state (key, credential, WAL)")
	enrollToken := flag.String("enroll-token", "", "one-time enrollment token (first run only)")
	insecure := flag.Bool("insecure", false, "skip TLS verification (LAN self-signed)")
	uploadEvery := flag.Duration("upload-interval", 5*time.Second, "how often to drain the WAL and upload")
	wireFormat := flag.String("wire-format", "protobuf", "telemetry upload encoding: protobuf (compact, default) or json (debug)")
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

	var uploadFormat string
	switch *wireFormat {
	case "protobuf":
		uploadFormat = wire.ContentTypeProtobuf
	case "json":
		uploadFormat = wire.ContentTypeJSON
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
	arp := collector.NewARPCollector(p)
	configurables := []configurable{publicPing, dns, httpc}

	sink := func(res collector.Result) {
		dropped, err := outbox.Append(res.Metrics, res.Events, res.Inventory)
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
	tiered := []collector.Collector{gateway, iface, arp}
	if *reportHost {
		// Host metrics flow through the same WAL→upload→ingest→series pipeline as
		// probes, so History and the alert engine work with no server changes.
		tiered = append(tiered, collector.NewHostMetricsCollector())
		log.Print("host metrics reporting enabled (--report-host)")
	}
	sched := scheduler.New(
		tiered,
		[]collector.Collector{publicPing, dns, httpc},
		sink,
	)
	sched.Run(ctx)

	// Status heartbeat: report uptime + WAL depth outbound via the WAL/upload
	// path (the agent never exposes an endpoint).
	start := time.Now()
	go func() {
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		emit := func() {
			now := time.Now().UTC()
			_, _ = outbox.Append([]telemetry.Metric{
				{TS: now, Kind: telemetry.AgentUptime, Target: "agent", Layer: telemetry.LayerLocal, Value: time.Since(start).Seconds(), Unit: telemetry.UnitSec},
				{TS: now, Kind: telemetry.AgentWALPending, Target: "agent", Layer: telemetry.LayerLocal, Value: float64(outbox.Pending()), Unit: telemetry.UnitCount},
			}, nil, nil)
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
	up := uploader.New(uploader.Options{
		ServerURL: *server, Token: cred.AgentToken, Hostname: hostname,
		Platform: runtime.GOOS, Version: agentVersion, Insecure: *insecure,
		Capabilities: strings.Join(capStrs, ","), Format: uploadFormat,
	})
	log.Printf("telemetry wire format: %s", *wireFormat)
	appliedConfigVersion := -1 // start behind so the server resends current config
	// pendingSnapshot holds a server-requested live snapshot until the next drain
	// sends it. It persists across drain calls (a request may arrive on one tick
	// and be served on the next), so snapshot delivery must run even when the WAL
	// is empty this tick.
	var pendingSnapshot *pcfg.SnapshotRequest

	// sendSnapshot collects a live host snapshot and uploads it in its own packet.
	// The agent-side flags are re-checked here (defense in depth): a request for a
	// cap the agent wasn't started with yields empty lists — never collected data.
	// The packet carries no metrics, so the server processes HostSnapshot outside
	// its sequence-dedup path; Sequence is irrelevant and left 0.
	sendSnapshot := func(req *pcfg.SnapshotRequest) {
		wantProcs := req.WantProcesses && *reportProcs
		wantConns := req.WantConnections && *reportConns
		snap := hostsnapshot.Collect(ctx, req.RequestID, wantProcs, wantConns)
		pkt := telemetry.Packet{
			SchemaVersion:         protocol.SchemaVersion,
			AgentID:               cred.AgentID,
			SiteID:                cred.SiteID,
			SentAt:                time.Now().UTC(),
			ReportedConfigVersion: appliedConfigVersion,
			HostSnapshot:          &snap,
		}
		if _, err := up.Upload(ctx, pkt); err != nil {
			log.Printf("snapshot upload (req=%s) failed: %v", req.RequestID, err)
			return
		}
		log.Printf("sent host snapshot req=%s procs=%d conns=%d total=%d",
			req.RequestID, len(snap.Processes), len(snap.Connections), snap.ProcessTotal)
	}

	drain := func() {
		for i := 0; i < 100; i++ { // bound work per tick; backfill spans ticks
			batch, ok, err := outbox.NextBatch(500)
			if err != nil {
				log.Printf("wal next batch: %v", err)
				break
			}
			if !ok {
				break
			}
			pkt := telemetry.Packet{
				SchemaVersion:         protocol.SchemaVersion,
				AgentID:               cred.AgentID,
				SiteID:                cred.SiteID,
				Sequence:              batch.Sequence,
				SentAt:                time.Now().UTC(),
				Metrics:               batch.Metrics,
				Events:                batch.Events,
				InventoryDelta:        batch.Inventory,
				ReportedConfigVersion: appliedConfigVersion,
			}
			ack, err := up.Upload(ctx, pkt)
			if err != nil {
				log.Printf("upload seq=%d failed: %v (will retry same sequence)", batch.Sequence, err)
				break
			}
			if err := outbox.Ack(batch.Sequence); err != nil {
				log.Printf("wal ack seq=%d: %v", batch.Sequence, err)
			}
			log.Printf("uploaded seq=%d metrics=%d events=%d inv=%d (watermark=%d, pending=%d)",
				batch.Sequence, len(pkt.Metrics), len(pkt.Events), len(pkt.InventoryDelta), ack.HighestSequence, outbox.Pending())

			if ack.DesiredState != nil {
				ds := ack.DesiredState
				for _, c := range configurables {
					c.SetTargets(ds.ProbeTargets)
				}
				sched.SetIntervals(
					time.Duration(ds.Intervals.BaseSeconds)*time.Second,
					time.Duration(ds.Intervals.RegularSeconds)*time.Second,
				)
				appliedConfigVersion = ds.ConfigVersion
				log.Printf("applied config v%d: %d probe targets", ds.ConfigVersion, len(ds.ProbeTargets))
				if ds.SnapshotRequest != nil {
					pendingSnapshot = ds.SnapshotRequest
				}
			}
			// Serve a newly-received snapshot request immediately, mid-backfill: a
			// large WAL (up to 100 batches this tick) could otherwise delay it past
			// the server's snapshot-request TTL and make the live request time out.
			if pendingSnapshot != nil {
				req := pendingSnapshot
				pendingSnapshot = nil
				sendSnapshot(req)
			}
		}
		// Also serve a request carried over from a previous tick when this tick had
		// no WAL data to upload (the loop above broke before receiving any ack).
		if pendingSnapshot != nil {
			req := pendingSnapshot
			pendingSnapshot = nil
			sendSnapshot(req)
		}
	}

	log.Printf("agent %s started (host=%s, platform=%s, caps=%v)", cred.AgentID, hostname, runtime.GOOS, p.Supports())

	// Let the first collections land, then drain; thereafter on a ticker.
	select {
	case <-ctx.Done():
		return
	case <-time.After(1500 * time.Millisecond):
	}
	drain()
	ticker := time.NewTicker(*uploadEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			log.Println("agent stopping")
			return
		case <-ticker.C:
			drain()
		}
	}
}
