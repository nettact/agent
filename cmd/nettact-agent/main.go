// Command nettact-agent is the endpoint/site monitoring agent — a pure outbound
// client that never listens on any port (architecture §15.1). It is a thin
// wrapper over the agentrt runtime package: it reads the NETTACT_AGENT_*
// environment (envcfg), installs signal handling, and calls agentrt.Run. All
// configuration lives in environment variables for local security — there are no
// configuration flags. Only --help and --version remain as non-configuration
// operations. All orchestration (identity, enrollment, collectors, WAL, the
// persistent server session) lives in agentrt, shared with the desktop build.
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/nettact/agent/agentrt"
	"github.com/nettact/agent/internal/envcfg"
)

const usage = `nettact-agent — NetTact monitoring agent

Configuration is via environment variables (no flags):

  NETTACT_AGENT_SERVER_URL          server base URL, e.g. http://host:8080 (required)
  NETTACT_AGENT_DATA_DIR            agent state directory (default ./agent-data)
  NETTACT_AGENT_ENROLL_TOKEN        one-time enrollment token (first run only)
  NETTACT_AGENT_ENROLL_TOKEN_FILE   path to the enrollment token (preferred; mutually exclusive)
  NETTACT_AGENT_TLS_INSECURE        skip TLS verification (default false)
  NETTACT_AGENT_UPLOAD_INTERVAL     WAL drain cadence (default 5s)
  NETTACT_AGENT_WIRE_FORMAT         protobuf (default) | json
  NETTACT_AGENT_PERMISSIONS         complete replacement permission list, or 'none'
  NETTACT_AGENT_PROBE_ACCESS_MODE   allowlist | denylist
  NETTACT_AGENT_PROBE_ALLOWLIST     selector CSV (scope:/cidr:/ip:/host:)
  NETTACT_AGENT_PROBE_DENYLIST      selector CSV, or 'none'
  NETTACT_AGENT_MIN_PROBE_INTERVAL     default 1s   [200ms,10m]
  NETTACT_AGENT_MAX_PROBE_CONCURRENCY  default 16   [1,256]
  NETTACT_AGENT_SNAPSHOT_MIN_INTERVAL  default 3s   [1s,10m]
  NETTACT_AGENT_SNAPSHOT_TIMEOUT       default 10s  [1s,60s]

Environment changes require an agent restart.
`

func main() {
	for _, arg := range os.Args[1:] {
		switch arg {
		case "--help", "-h", "help":
			fmt.Print(usage)
			return
		case "--version", "-v", "version":
			fmt.Println("nettact-agent", agentrt.Version)
			return
		default:
			log.Fatalf("unknown argument %q; configuration is via NETTACT_AGENT_* environment variables (see --help)", arg)
		}
	}

	cfg, err := envcfg.Load(os.LookupEnv)
	if err != nil {
		log.Fatalf("invalid configuration:\n%v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := agentrt.Run(ctx, cfg); err != nil {
		log.Fatalf("agent: %v", err)
	}
	log.Println("agent stopping")
}
