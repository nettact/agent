// Command nettact-agent is the endpoint/site monitoring agent. It is a pure
// outbound client: it never listens on any port. Each cycle it runs its
// collectors and uploads a telemetry packet to the server (architecture
// §15.1). M1 ships the interface + gateway-ping collectors and an in-memory
// sequence; the durable WAL, enrollment and config downlink arrive in M2/M3.
package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/nettact/agent/internal/collector"
	"github.com/nettact/agent/internal/identity"
	"github.com/nettact/agent/internal/platform"
	"github.com/nettact/agent/internal/uploader"
	"github.com/nettact/protocol"
	"github.com/nettact/protocol/telemetry"
)

const agentVersion = "0.1.0-m1"

func main() {
	server := flag.String("server", "", "server base URL, e.g. http://localhost:8080 (required)")
	dataDir := flag.String("data-dir", "./agent-data", "directory for agent state")
	siteID := flag.String("site-id", "", "site ID hint (server assigns default if empty)")
	interval := flag.Duration("interval", 10*time.Second, "collection/upload interval")
	insecure := flag.Bool("insecure", false, "skip TLS verification (LAN self-signed)")
	flag.Parse()

	if *server == "" {
		log.Fatal("--server is required")
	}

	agentID, err := identity.LoadOrCreateAgentID(*dataDir)
	if err != nil {
		log.Fatalf("identity: %v", err)
	}
	hostname, _ := os.Hostname()

	p := platform.New()
	log.Printf("agent %s starting (host=%s, platform=%s, caps=%v)", agentID, hostname, runtime.GOOS, p.Supports())

	collectors := []collector.Collector{
		collector.NewGatewayPingCollector(p),
		collector.NewInterfaceCollector(p),
	}

	up := uploader.New(uploader.Options{
		ServerURL: *server,
		Token:     "dev", // M1 dev placeholder; real bearer token in M2
		Hostname:  hostname,
		Platform:  runtime.GOOS,
		Version:   agentVersion,
		Insecure:  *insecure,
	})

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var sequence uint64
	ticker := time.NewTicker(*interval)
	defer ticker.Stop()

	runCycle := func() {
		cycleCtx, cancel := context.WithTimeout(ctx, *interval)
		defer cancel()

		var pkt telemetry.Packet
		for _, c := range collectors {
			res, err := c.Collect(cycleCtx)
			if err != nil {
				log.Printf("collector %s error: %v", c.Name(), err)
				continue
			}
			pkt.Metrics = append(pkt.Metrics, res.Metrics...)
			pkt.Events = append(pkt.Events, res.Events...)
			pkt.InventoryDelta = append(pkt.InventoryDelta, res.Inventory...)
		}
		if len(pkt.Metrics) == 0 && len(pkt.Events) == 0 && len(pkt.InventoryDelta) == 0 {
			return
		}

		sequence++
		pkt.SchemaVersion = protocol.SchemaVersion
		pkt.AgentID = agentID
		pkt.SiteID = *siteID
		pkt.Sequence = sequence
		pkt.SentAt = time.Now().UTC()

		ack, err := up.Upload(cycleCtx, pkt)
		if err != nil {
			log.Printf("upload seq=%d failed: %v", sequence, err)
			return
		}
		log.Printf("uploaded seq=%d metrics=%d events=%d inv=%d (ack watermark=%d)",
			sequence, len(pkt.Metrics), len(pkt.Events), len(pkt.InventoryDelta), ack.HighestSequence)
	}

	runCycle() // fire immediately on start
	for {
		select {
		case <-ctx.Done():
			log.Println("agent stopping")
			return
		case <-ticker.C:
			runCycle()
		}
	}
}
