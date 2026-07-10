// Command nettact-agent is the endpoint/site monitoring agent — a pure outbound
// client that never listens on any port (architecture §15.1). On first run it
// enrolls (ed25519 keypair + one-time token) and stores a bearer credential;
// thereafter it uploads telemetry and applies the monitoring config the server
// pushes back in each ack (config downlink). M2 adds the interface + gateway +
// server-configured public-ping collectors.
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
	"github.com/nettact/agent/internal/enroll"
	"github.com/nettact/agent/internal/identity"
	"github.com/nettact/agent/internal/platform"
	"github.com/nettact/agent/internal/uploader"
	"github.com/nettact/protocol"
	"github.com/nettact/protocol/telemetry"
)

const agentVersion = "0.2.0-m2"

func main() {
	server := flag.String("server", "", "server base URL, e.g. http://localhost:8080 (required)")
	dataDir := flag.String("data-dir", "./agent-data", "directory for agent state (key, credential)")
	enrollToken := flag.String("enroll-token", "", "one-time enrollment token (first run only)")
	interval := flag.Duration("interval", 10*time.Second, "initial collection interval (server may override)")
	insecure := flag.Bool("insecure", false, "skip TLS verification (LAN self-signed)")
	flag.Parse()

	if *server == "" {
		log.Fatal("--server is required")
	}

	priv, err := identity.LoadOrCreateKey(*dataDir)
	if err != nil {
		log.Fatalf("identity: %v", err)
	}
	hostname, _ := os.Hostname()
	p := platform.New()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Enroll on first run; reuse the saved credential afterwards.
	cred, enrolled, err := identity.LoadCredential(*dataDir)
	if err != nil {
		log.Fatalf("load credential: %v", err)
	}
	if !enrolled {
		if *enrollToken == "" {
			log.Fatal("first run requires --enroll-token (create one in the Lite console)")
		}
		cred, err = enroll.Enroll(ctx, *server, *insecure, priv, *enrollToken, hostname, runtime.GOOS, agentVersion, p.Supports())
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

	gateway := collector.NewGatewayPingCollector(p)
	iface := collector.NewInterfaceCollector(p)
	publicPing := collector.NewPublicPingCollector(p)
	collectors := []collector.Collector{gateway, publicPing, iface}

	up := uploader.New(uploader.Options{
		ServerURL: *server,
		Token:     cred.AgentToken,
		Hostname:  hostname,
		Platform:  runtime.GOOS,
		Version:   agentVersion,
		Insecure:  *insecure,
	})

	log.Printf("agent %s started (host=%s, platform=%s, caps=%v)", cred.AgentID, hostname, runtime.GOOS, p.Supports())

	var sequence uint64
	appliedConfigVersion := -1 // start behind so the server always sends current config
	curInterval := *interval

	runCycle := func() {
		cycleCtx, cancel := context.WithTimeout(ctx, curInterval)
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

		sequence++
		pkt.SchemaVersion = protocol.SchemaVersion
		pkt.AgentID = cred.AgentID
		pkt.SiteID = cred.SiteID
		pkt.Sequence = sequence
		pkt.SentAt = time.Now().UTC()
		pkt.ReportedConfigVersion = appliedConfigVersion

		ack, err := up.Upload(cycleCtx, pkt)
		if err != nil {
			log.Printf("upload seq=%d failed: %v", sequence, err)
			return
		}
		log.Printf("uploaded seq=%d metrics=%d events=%d inv=%d (ack watermark=%d, server cfg=%d)",
			sequence, len(pkt.Metrics), len(pkt.Events), len(pkt.InventoryDelta), ack.HighestSequence, ack.ConfigVersion)

		if ack.DesiredState != nil {
			ds := ack.DesiredState
			publicPing.SetTargets(ds.ProbeTargets)
			appliedConfigVersion = ds.ConfigVersion
			if ds.Intervals.BaseSeconds > 0 {
				curInterval = time.Duration(ds.Intervals.BaseSeconds) * time.Second
			}
			log.Printf("applied config v%d: %d probe targets, base interval %s", ds.ConfigVersion, len(ds.ProbeTargets), curInterval)
		}
	}

	runCycle()
	ticker := time.NewTicker(curInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			log.Println("agent stopping")
			return
		case <-ticker.C:
			prev := curInterval
			runCycle()
			if curInterval != prev {
				ticker.Reset(curInterval)
			}
		}
	}
}
