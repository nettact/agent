// Command nettact-agent is the endpoint/site monitoring agent — a pure outbound
// client that never listens on any port (architecture §15.1). It is a thin
// wrapper over the agentrt runtime package: it resolves configuration (an
// optional YAML file layered over the NETTACT_AGENT_* environment via envcfg),
// installs signal handling, and calls agentrt.Run. The only flag is --config
// (which config file to load); --help and --version remain as non-configuration
// operations. All orchestration (identity, enrollment, collectors, WAL, the
// persistent server session) lives in agentrt, shared with the desktop build.
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/nettact/agent/agentrt"
	"github.com/nettact/agent/internal/envcfg"
)

const usage = `nettact-agent — NetTact monitoring agent

Configuration comes from a YAML config file and/or NETTACT_AGENT_* environment
variables. Precedence (highest first): config file > environment > built-in
defaults. Each YAML key maps 1:1 to the environment variable on its line.

Config file (optional):
  --config <path>                   load this config file (missing/unreadable → startup error; empty path → startup error)
  NETTACT_AGENT_CONFIG_FILE         same, via the environment (set but empty → startup error)
  Auto-discovery (only when neither above is set; a missing file is not an error):
    1. ./nettact-agent.yaml  (working directory)
    2. %ProgramData%\NetTact\agent.yaml (Windows)  or  /etc/nettact/agent.yaml (other)
  See agent.example.yaml for an annotated template (chmod 600 recommended).

Settings (environment variable — YAML key):
  NETTACT_AGENT_SERVER_URL          server base URL, e.g. http://host:12450 (required)  — server_url
  NETTACT_AGENT_DATA_DIR            agent state directory (default ./agent-data)         — data_dir
  NETTACT_AGENT_STATUS_FILE         write a JSON connection-status file here (default: off) — status_file
  NETTACT_AGENT_ENROLL_TOKEN        one-time enrollment token (first run only)           — enroll_token
  NETTACT_AGENT_ENROLL_TOKEN_FILE   path to the enrollment token (preferred; exclusive)  — enroll_token_file
  NETTACT_AGENT_TLS_INSECURE        skip TLS verification (default false)                — tls_insecure
  NETTACT_AGENT_UPLOAD_INTERVAL     WAL drain cadence (default 30s)                      — upload_interval
  NETTACT_AGENT_WIRE_FORMAT         protobuf (default) | json                            — wire_format
  NETTACT_AGENT_PERSIST             keep an unsent backlog across a reboot (default true; router builds only) — persist
  NETTACT_AGENT_PERSIST_WINDOW      how long after a disconnect to keep doing so (default 30m) [1m,24h] — persist_window
  NETTACT_AGENT_PERMISSIONS         complete replacement permission list, or 'none'      — permissions (list or "none")
  NETTACT_AGENT_PROBE_ACCESS_MODE   allowlist | denylist                                 — probe_access.mode
  NETTACT_AGENT_PROBE_ALLOWLIST     selector CSV (scope:/cidr:/ip:/host:)                — probe_access.allowlist (list)
  NETTACT_AGENT_PROBE_DENYLIST      selector CSV, or 'none'                              — probe_access.denylist (list or "none")
  NETTACT_AGENT_MIN_PROBE_INTERVAL     default 1s   [200ms,10m]                          — min_probe_interval
  NETTACT_AGENT_MAX_PROBE_CONCURRENCY  default 16   [1,256]                              — max_probe_concurrency
  NETTACT_AGENT_SNAPSHOT_MIN_INTERVAL  default 3s   [1s,10m]                             — snapshot_min_interval
  NETTACT_AGENT_SNAPSHOT_TIMEOUT       default 10s  [1s,60s]                             — snapshot_timeout
  NETTACT_AGENT_MAX_TRACE_CONCURRENCY  default 4    [1,64]                               — max_trace_concurrency

Reporting to more than one server (config file only — a list has no environment form):
  servers:                            list of {name, url, enroll_token|enroll_token_file,
                                      tls_insecure, permissions, probe_access}
  Mutually exclusive with server_url / enroll_token / enroll_token_file / tls_insecure.
  'name' is required and unique; it keys the saved credential and the queued backlog,
  so renaming an entry re-enrolls it. The single-server form above is equivalent to one
  entry named "default". The FIRST entry owns game/frame capture.
  A per-entry 'permissions' replaces the top-level grant for that server; a per-entry
  'probe_access' can only narrow the top-level one, never widen it.
  See agent.example.yaml for an annotated example.

Configuration changes require an agent restart.
`

func main() {
	// configPath stays nil until --config is seen so ResolveConfigPath can tell an
	// absent flag from one explicitly given an empty value (which is an error).
	var configPath *string
	args := os.Args[1:]
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--help", arg == "-h", arg == "help":
			fmt.Print(usage)
			return
		case arg == "--version", arg == "-v", arg == "version":
			fmt.Println("nettact-agent", agentrt.Version)
			return
		case arg == "--config":
			if i+1 >= len(args) {
				log.Fatalf("--config requires a file path argument")
			}
			i++
			v := args[i]
			configPath = &v
		case strings.HasPrefix(arg, "--config="):
			v := strings.TrimPrefix(arg, "--config=")
			configPath = &v
		default:
			log.Fatalf("unknown argument %q; see --help", arg)
		}
	}

	// Layer a YAML config file over the environment when one is named or found.
	lookup := envcfg.Lookup(os.LookupEnv)

	// refuse ends the process the way log.Fatalf would, and additionally leaves
	// the reason in the status file when one is configured.
	//
	// This covers only the failures that happen BEFORE agentrt.Run — a config file
	// that cannot be read, a value the agent will not accept. Run records its own
	// outcome, in more detail than this can, so it is deliberately not wrapped
	// here. The path is re-read from `lookup` at each call because `lookup` gains
	// the config file's own settings partway down, and status_file is one of them.
	//
	// The reason a configuration error deserves this at all is what a supervised
	// agent does with it: a router renders its agent config from UCI, so a value
	// the settings page allowed and the agent rejects produces a process that
	// exits in well under a second and is respawned ten seconds later, forever.
	// The stderr that says why is written in the instant before the exit, which is
	// exactly the window procd's log reader loses — so without this the router's
	// owner is left with a status page that says "not running" and nothing else.
	refuse := func(format string, args ...any) {
		err := fmt.Errorf(format, args...)
		if path, ok := lookup("NETTACT_AGENT_STATUS_FILE"); ok && path != "" {
			agentrt.ReportStartupFailure(path, err)
		}
		log.Fatal(err)
	}

	path, _, err := envcfg.ResolveConfigPath(configPath, lookup)
	if err != nil {
		refuse("invalid configuration: %v", err)
	}
	var fileCfg envcfg.File
	if path != "" {
		fileCfg, err = envcfg.LoadFile(path)
		if err != nil {
			refuse("invalid configuration: %v", err)
		}
		lookup = envcfg.Layered(fileCfg, lookup)
		log.Printf("using config file %s", path)
	}

	cfg, err := envcfg.Load(lookup, fileCfg)
	if err != nil {
		refuse("invalid configuration:\n%v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := agentrt.Run(ctx, cfg); err != nil {
		log.Fatalf("agent: %v", err)
	}
	log.Println("agent stopping")
}
