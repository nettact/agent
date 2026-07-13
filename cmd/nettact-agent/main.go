// Command nettact-agent is the endpoint/site monitoring agent — a pure outbound
// client that never listens on any port (architecture §15.1). It is a thin
// wrapper over the agentrt runtime package: it parses flags, installs signal
// handling, and calls agentrt.Run. All orchestration (identity, enrollment,
// collectors, WAL, the persistent server session) lives in agentrt, shared with
// the desktop all-in-one build.
package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/nettact/agent/agentrt"
)

func main() {
	server := flag.String("server", "", "server base URL, e.g. http://localhost:8080 (required)")
	dataDir := flag.String("data-dir", "./agent-data", "directory for agent state (key, credential, WAL)")
	enrollToken := flag.String("enroll-token", "", "one-time enrollment token (first run only)")
	insecure := flag.Bool("insecure", false, "skip TLS verification (LAN self-signed)")
	uploadEvery := flag.Duration("upload-interval", 5*time.Second, "how often to drain the WAL over the WebSocket")
	wireFormat := flag.String("wire-format", "protobuf", "telemetry wire encoding: protobuf (compact, default) or json (debug)")
	// Host-monitoring opt-in. These flags are the SOLE authority: without them the
	// agent never collects the corresponding data, so the server cannot obtain any
	// host state from a non-opted-in agent (enforced agent-side, in agentrt).
	reportHost := flag.Bool("report-host", false, "report host CPU/memory/disk/load/uptime/network metrics (opt-in)")
	reportProcs := flag.Bool("report-processes", false, "permit on-demand live process-list snapshots (opt-in)")
	reportConns := flag.Bool("report-connections", false, "permit on-demand live network-connection snapshots (opt-in)")
	flag.Parse()

	if *server == "" {
		log.Fatal("--server is required")
	}
	if *wireFormat != "protobuf" && *wireFormat != "json" {
		log.Fatalf("--wire-format must be 'protobuf' or 'json', got %q", *wireFormat)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	err := agentrt.Run(ctx, agentrt.Config{
		ServerURL:      *server,
		DataDir:        *dataDir,
		Insecure:       *insecure,
		UploadInterval: *uploadEvery,
		WireFormat:     *wireFormat,
		ReportHost:     *reportHost,
		ReportProcs:    *reportProcs,
		ReportConns:    *reportConns,
		// First run only: supply the one-time enrollment token from the flag.
		TokenSource: func(context.Context) (string, error) {
			if *enrollToken == "" {
				return "", errors.New("first run requires --enroll-token (create one in the Lite console)")
			}
			return *enrollToken, nil
		},
	})
	if err != nil {
		log.Fatalf("agent: %v", err)
	}
	log.Println("agent stopping")
}
