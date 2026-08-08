// Package envcfg parses the standalone agent's NETTACT_AGENT_* environment into
// an immutable agentrt.Config. Configuration moved off argv to environment
// variables for local security (spec §3.1). Parsing is fail-fast and aggregated:
// every violation is collected (errors.Join), each naming the exact variable and
// a safe reason — enrollment-token contents never appear in an error. Environment
// changes require an agent restart; the policy is immutable per process.
package envcfg

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/nettact/agent/agentrt"
	"github.com/nettact/agent/probepolicy"
	pcfg "github.com/nettact/protocol/config"
	"github.com/nettact/protocol/permission"
)

// Lookup mirrors os.LookupEnv: (value, present).
type Lookup func(string) (string, bool)

// maxTokenFileBytes bounds the enrollment-token file read.
const maxTokenFileBytes = 4 << 10

// Load parses the environment into an agentrt.Config. lookup is injectable for
// tests (pass os.LookupEnv in production); file carries the one setting that has
// no environment form — the servers list — and is the zero File when there is no
// configuration file.
func Load(lookup Lookup, file File) (agentrt.Config, error) {
	var errs []error
	add := func(err error) {
		if err != nil {
			errs = append(errs, err)
		}
	}

	cfg := agentrt.Config{}

	// DATA_DIR (default ./agent-data).
	cfg.DataDir = "./agent-data"
	if v, ok := nonEmpty(lookup, "NETTACT_AGENT_DATA_DIR", &errs); ok {
		cfg.DataDir = v
	}

	// STATUS_FILE (default off). Off by design: a standalone agent's status
	// surface is its log, and writing a file nobody reads only costs disk. It is
	// set by the installs where nothing reads the log — the OpenWrt package
	// points it at tmpfs so the LuCI page can render the connection state.
	if v, ok := nonEmpty(lookup, "NETTACT_AGENT_STATUS_FILE", &errs); ok {
		cfg.StatusFile = v
	}

	// UPLOAD_INTERVAL (duration, default 30s — the protocol constant, so the
	// server's StaleAfter fallback and the agent's real cadence stay one value).
	cfg.UploadInterval = pcfg.DefaultUploadInterval
	if v, ok := nonEmpty(lookup, "NETTACT_AGENT_UPLOAD_INTERVAL", &errs); ok {
		d, err := time.ParseDuration(v)
		if err != nil || d <= 0 {
			add(fmt.Errorf("NETTACT_AGENT_UPLOAD_INTERVAL must be a positive duration, got %q", v))
		} else {
			cfg.UploadInterval = d
		}
	}

	// WIRE_FORMAT (protobuf default | json).
	cfg.WireFormat = "protobuf"
	if v, ok := nonEmpty(lookup, "NETTACT_AGENT_WIRE_FORMAT", &errs); ok {
		if v != "protobuf" && v != "json" {
			add(fmt.Errorf("NETTACT_AGENT_WIRE_FORMAT must be 'protobuf' or 'json', got %q", v))
		} else {
			cfg.WireFormat = v
		}
	}

	// PERSIST / PERSIST_WINDOW — the outbox's durable tier, read by the lite
	// (router) build only; see agentrt.Config.
	//
	// The default is ON, and it is on for every build rather than only where it
	// takes effect. This parser has no build tag and produces one Config, so a
	// build-conditional default would mean the same file describing two different
	// agents — and the builds that ignore the field ignore it because their
	// outbox already persists unconditionally, which is exactly what true says.
	cfg.Persist = true
	if v, ok := nonEmpty(lookup, "NETTACT_AGENT_PERSIST", &errs); ok {
		b, err := strconv.ParseBool(v)
		if err != nil {
			add(fmt.Errorf("NETTACT_AGENT_PERSIST must be a boolean, got %q", v))
		} else {
			cfg.Persist = b
		}
	}
	// The lower bound is a minute rather than zero: a window under one spill
	// interval would write once at the disconnect and never again, which reads
	// like a setting and behaves like a switch. Turn it off with PERSIST instead.
	cfg.PersistWindow = durVar(lookup, "NETTACT_AGENT_PERSIST_WINDOW", 30*time.Minute, time.Minute, 24*time.Hour, &errs)

	// PERMISSIONS — the agent-wide default grant, inherited by any server entry
	// that does not name its own.
	cfg.Policy = loadPolicy(lookup, &errs)

	// PROBE ACCESS — the machine's floor. A server entry may narrow it, never
	// widen it.
	cfg.ProbeAccess = loadProbeAccess(lookup, &errs)

	// LIMITS.
	cfg.Limits = loadLimits(lookup, &errs)

	// SERVERS (the list, or the single-server variables as one entry).
	cfg.Servers = loadServers(lookup, file, &errs)

	if len(errs) > 0 {
		return agentrt.Config{}, errors.Join(errs...)
	}
	return cfg, nil
}

// defaultServerName is the entry name the single-server form produces.
//
// It is fixed rather than derived so that spelling the same server out as a
// one-element servers list keeps the credential and the queued backlog: name the
// entry "default" and nothing re-enrolls. Deriving it from the URL instead would
// make editing an address look like adding a machine.
const defaultServerName = "default"

// singleServerVars are the settings that describe a server without the list
// form. They exist as the ordinary one-server spelling, and are refused
// alongside a servers list rather than merged into it — a config that says both
// has two answers for which server is first, and the first is the one that owns
// frame capture.
var singleServerVars = []string{
	"NETTACT_AGENT_SERVER_URL",
	"NETTACT_AGENT_ENROLL_TOKEN",
	"NETTACT_AGENT_ENROLL_TOKEN_FILE",
	"NETTACT_AGENT_TLS_INSECURE",
}

// loadServers builds the server list. A `servers:` list in the configuration
// file wins outright; otherwise the single-server variables describe one entry.
func loadServers(lookup Lookup, file File, errs *[]error) []agentrt.ServerConfig {
	if len(file.servers) == 0 {
		return []agentrt.ServerConfig{singleServer(lookup, errs)}
	}

	for _, name := range singleServerVars {
		if present(lookup, name) {
			*errs = append(*errs, fmt.Errorf("`servers:` and %s are mutually exclusive; put the setting inside the servers entry", name))
		}
	}

	out := make([]agentrt.ServerConfig, 0, len(file.servers))
	seen := make(map[string]bool, len(file.servers))
	for i, e := range file.servers {
		label := fmt.Sprintf("servers[%d]", i)
		sc := agentrt.ServerConfig{}

		// Every entry names itself. The name keys the credential and the queued
		// backlog, so it cannot be derived from a field the user may edit: a
		// changed URL would silently look like a different machine and re-enroll.
		switch {
		case e.Name == nil || strings.TrimSpace(*e.Name) == "":
			*errs = append(*errs, fmt.Errorf("%s: name is required", label))
		default:
			sc.Name = strings.TrimSpace(*e.Name)
			if err := validServerName(sc.Name); err != nil {
				*errs = append(*errs, fmt.Errorf("%s: %w", label, err))
			}
			if seen[sc.Name] {
				*errs = append(*errs, fmt.Errorf("%s: duplicate server name %q", label, sc.Name))
			}
			seen[sc.Name] = true
			label = fmt.Sprintf("servers[%s]", sc.Name)
		}

		if e.URL == nil || strings.TrimSpace(*e.URL) == "" {
			*errs = append(*errs, fmt.Errorf("%s: url is required", label))
		} else if v := strings.TrimSpace(*e.URL); !validServerURL(v) {
			*errs = append(*errs, fmt.Errorf("%s: url must be a http(s) URL, got %q", label, v))
		} else {
			sc.URL = v
		}

		if e.TLSInsecure != nil {
			sc.Insecure = *e.TLSInsecure
		}
		sc.TokenSource = entryTokenSource(label, e, errs)

		if e.Permissions != nil {
			granted := parsePermissions(label+".permissions", e.Permissions.csv(), errs)
			sc.Policy = &permission.Policy{Granted: granted, Source: permission.SourceServerConfig}
		}
		if e.ProbeAccess != nil {
			p := parseProbeAccess(label+".probe_access", e.ProbeAccess, errs)
			sc.ProbeNarrow = &p
		}
		out = append(out, sc)
	}
	return out
}

// singleServer builds the one entry the environment form describes.
func singleServer(lookup Lookup, errs *[]error) agentrt.ServerConfig {
	sc := agentrt.ServerConfig{Name: defaultServerName}
	if v, ok := nonEmpty(lookup, "NETTACT_AGENT_SERVER_URL", errs); ok {
		if !validServerURL(v) {
			*errs = append(*errs, fmt.Errorf("NETTACT_AGENT_SERVER_URL must be a http(s) URL, got %q", v))
		} else {
			sc.URL = v
		}
	} else if !present(lookup, "NETTACT_AGENT_SERVER_URL") {
		*errs = append(*errs, errors.New("NETTACT_AGENT_SERVER_URL is required (or configure a `servers:` list)"))
	}

	if v, ok := nonEmpty(lookup, "NETTACT_AGENT_TLS_INSECURE", errs); ok {
		b, err := strconv.ParseBool(v)
		if err != nil {
			*errs = append(*errs, fmt.Errorf("NETTACT_AGENT_TLS_INSECURE must be a boolean, got %q", v))
		} else {
			sc.Insecure = b
		}
	}
	sc.TokenSource = loadTokenSource(lookup, errs)
	return sc
}

// validServerURL reports whether v addresses a server.
func validServerURL(v string) bool {
	u, err := url.Parse(v)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != ""
}

// validServerName enforces the charset the name has to survive: it becomes a key
// in agent.json and in the WAL's state file, and appears in every log line the
// server's session writes.
func validServerName(name string) error {
	if len(name) > 64 {
		return fmt.Errorf("name %q is too long (max 64 characters)", name)
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '_':
		default:
			return fmt.Errorf("name %q may only contain lowercase letters, digits, '-' and '_'", name)
		}
	}
	return nil
}

// entryTokenSource resolves one server entry's enrollment token, applying the
// same rules the environment form does: the two sources are mutually exclusive,
// the file is read now rather than at enrollment time (so a bad path fails at
// startup, when someone is watching), and neither being set is not an error —
// the entry may already hold a credential, and the runner only asks for a token
// when it does not.
func entryTokenSource(label string, e serverEntryFile, errs *[]error) func(context.Context) (string, error) {
	tokSet := e.EnrollToken != nil
	fileSet := e.EnrollTokenFile != nil
	if tokSet && fileSet {
		*errs = append(*errs, fmt.Errorf("%s: enroll_token and enroll_token_file are mutually exclusive", label))
		return nil
	}
	if fileSet {
		token, err := readTokenFile(strings.TrimSpace(*e.EnrollTokenFile))
		if err != nil {
			*errs = append(*errs, fmt.Errorf("%s.enroll_token_file: %w", label, err))
			return nil
		}
		return func(context.Context) (string, error) { return token, nil }
	}
	if tokSet {
		token := strings.TrimSpace(*e.EnrollToken)
		if token == "" {
			*errs = append(*errs, fmt.Errorf("%s: enroll_token is set but empty", label))
			return nil
		}
		return func(context.Context) (string, error) { return token, nil }
	}
	return func(context.Context) (string, error) {
		return "", fmt.Errorf("%s: first enrollment needs enroll_token or enroll_token_file: %w", label, agentrt.ErrNoEnrollmentToken)
	}
}

// readTokenFile reads and validates an enrollment-token file. The read is
// bounded to one byte past the limit before allocating, so a huge local file
// cannot be slurped whole just to be rejected.
func readTokenFile(path string) (string, error) {
	if path == "" {
		return "", errors.New("is set but empty")
	}
	f, err := os.Open(path)
	if err != nil {
		// *PathError already renders as `open <path>: <cause>`, so it names
		// the path without this repeating it.
		return "", err
	}
	data, err := io.ReadAll(io.LimitReader(f, maxTokenFileBytes+1))
	_ = f.Close()
	if err != nil {
		return "", fmt.Errorf("reading %q failed: %w", path, err)
	}
	if len(data) > maxTokenFileBytes {
		return "", fmt.Errorf("%q is too large", path)
	}
	token := strings.TrimSpace(string(data))
	if token == "" {
		return "", fmt.Errorf("%q is empty", path)
	}
	return token, nil
}

func present(lookup Lookup, name string) bool {
	_, ok := lookup(name)
	return ok
}

// nonEmpty returns (trimmed value, true) when the variable is set to a non-empty
// value. A present-but-empty variable is an aggregated error (returns false).
func nonEmpty(lookup Lookup, name string, errs *[]error) (string, bool) {
	v, ok := lookup(name)
	if !ok {
		return "", false
	}
	t := strings.TrimSpace(v)
	if t == "" {
		*errs = append(*errs, fmt.Errorf("%s is set but empty; unset it to use the default", name))
		return "", false
	}
	return t, true
}

// loadPolicy builds the permission policy. Absent → frozen default. Present →
// full replacement. "none" (alone) → empty grant. Wildcards are rejected.
func loadPolicy(lookup Lookup, errs *[]error) permission.Policy {
	v, ok := lookup("NETTACT_AGENT_PERMISSIONS")
	if !ok {
		return permission.Policy{Granted: permission.DefaultStandalone(), Source: permission.SourceDefault}
	}
	t := strings.TrimSpace(v)
	if t == "" {
		*errs = append(*errs, errors.New("NETTACT_AGENT_PERMISSIONS is set but empty; use `none` or unset it"))
		return permission.Policy{Granted: permission.Set{}, Source: permission.SourceEnvironment}
	}
	return permission.Policy{
		Granted: parsePermissions("NETTACT_AGENT_PERMISSIONS", t, errs),
		Source:  permission.SourceEnvironment,
	}
}

// parsePermissions turns a CSV grant into a validated set. label names the
// setting in any error, so the same parser serves the environment variable and a
// per-server entry in the configuration file.
func parsePermissions(label, csv string, errs *[]error) permission.Set {
	t := strings.TrimSpace(csv)
	if strings.EqualFold(t, "none") || t == "" {
		return permission.Set{}
	}
	granted := permission.Set{}
	for _, tok := range strings.Split(t, ",") {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		if tok == "*" || strings.EqualFold(tok, "all") {
			*errs = append(*errs, fmt.Errorf("%s: wildcards (\"*\"/\"all\") are not supported; list explicit permissions", label))
			continue
		}
		granted.Add(permission.ID(tok))
	}
	if err := permission.Validate(granted); err != nil {
		*errs = append(*errs, fmt.Errorf("%s: %w", label, err))
	}
	return granted
}

// loadProbeAccess builds the probe target-access policy.
func loadProbeAccess(lookup Lookup, errs *[]error) probepolicy.Policy {
	modeV, modeSet := lookup("NETTACT_AGENT_PROBE_ACCESS_MODE")
	allowV, allowSet := lookup("NETTACT_AGENT_PROBE_ALLOWLIST")
	denyV, denySet := lookup("NETTACT_AGENT_PROBE_DENYLIST")

	if !modeSet && !allowSet && !denySet {
		return probepolicy.Default()
	}
	return buildProbeAccess(probeAccessInput{
		label:    "NETTACT_AGENT_PROBE",
		modeName: "NETTACT_AGENT_PROBE_ACCESS_MODE",
		allowLbl: "NETTACT_AGENT_PROBE_ALLOWLIST",
		denyLbl:  "NETTACT_AGENT_PROBE_DENYLIST",
		mode:     modeV,
		allow:    allowV,
		deny:     denyV,
		denySet:  denySet,
	}, errs)
}

// parseProbeAccess builds the narrowing policy of one server entry.
func parseProbeAccess(label string, pa *probeAccessFile, errs *[]error) probepolicy.Policy {
	in := probeAccessInput{
		label:    label,
		modeName: label + ".mode",
		allowLbl: label + ".allowlist",
		denyLbl:  label + ".denylist",
	}
	if pa.Mode != nil {
		in.mode = *pa.Mode
	}
	if pa.Allowlist != nil {
		in.allow = pa.Allowlist.csv()
	}
	if pa.Denylist != nil {
		in.deny = pa.Denylist.csv()
		in.denySet = true
	}
	return buildProbeAccess(in, errs)
}

// probeAccessInput is one probe-access group's raw values plus the labels used
// to report a problem with them.
type probeAccessInput struct {
	label                       string
	modeName, allowLbl, denyLbl string
	mode, allow, deny           string
	denySet                     bool
}

func buildProbeAccess(in probeAccessInput, errs *[]error) probepolicy.Policy {
	mode := probepolicy.Mode(strings.ToLower(strings.TrimSpace(in.mode)))
	if mode != probepolicy.ModeAllowlist && mode != probepolicy.ModeDenylist {
		*errs = append(*errs, fmt.Errorf("%s must be 'allowlist' or 'denylist' when any probe-access setting is present, got %q", in.modeName, in.mode))
		return probepolicy.Default()
	}

	allow := parseSelectors(in.allowLbl, in.allow, errs)
	// A literal "none" denylist means "deny nothing".
	var deny []probepolicy.Selector
	denyIsNone := in.denySet && strings.EqualFold(strings.TrimSpace(in.deny), "none")
	if !denyIsNone {
		deny = parseSelectors(in.denyLbl, in.deny, errs)
	}

	switch mode {
	case probepolicy.ModeAllowlist:
		if len(allow) == 0 {
			*errs = append(*errs, fmt.Errorf("%s must be non-empty in allowlist mode", in.allowLbl))
		}
	case probepolicy.ModeDenylist:
		if len(deny) == 0 && !denyIsNone {
			*errs = append(*errs, fmt.Errorf("%s must be non-empty (or `none`) in denylist mode", in.denyLbl))
		}
	}
	return probepolicy.Policy{Mode: mode, Allow: allow, Deny: deny}
}

// parseSelectors parses a CSV of selectors, appending each bad one as its own error.
func parseSelectors(name, csv string, errs *[]error) []probepolicy.Selector {
	var out []probepolicy.Selector
	for _, tok := range strings.Split(csv, ",") {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		sel, err := probepolicy.ParseSelector(tok)
		if err != nil {
			*errs = append(*errs, fmt.Errorf("%s: %w", name, err))
			continue
		}
		out = append(out, sel)
	}
	return out
}

// loadLimits parses the four stability variables (spec §17.1 defaults/ranges).
func loadLimits(lookup Lookup, errs *[]error) agentrt.Limits {
	l := agentrt.DefaultLimits()
	l.MinProbeInterval = durVar(lookup, "NETTACT_AGENT_MIN_PROBE_INTERVAL", l.MinProbeInterval, 200*time.Millisecond, 10*time.Minute, errs)
	l.SnapshotMinInterval = durVar(lookup, "NETTACT_AGENT_SNAPSHOT_MIN_INTERVAL", l.SnapshotMinInterval, time.Second, 10*time.Minute, errs)
	l.SnapshotTimeout = durVar(lookup, "NETTACT_AGENT_SNAPSHOT_TIMEOUT", l.SnapshotTimeout, time.Second, 60*time.Second, errs)
	l.MaxProbeConcurrency = intVar(lookup, "NETTACT_AGENT_MAX_PROBE_CONCURRENCY", l.MaxProbeConcurrency, 1, 256, errs)
	l.MaxTraceConcurrency = intVar(lookup, "NETTACT_AGENT_MAX_TRACE_CONCURRENCY", l.MaxTraceConcurrency, 1, 64, errs)
	return l
}

func durVar(lookup Lookup, name string, def, lo, hi time.Duration, errs *[]error) time.Duration {
	v, ok := lookup(name)
	if !ok {
		return def
	}
	t := strings.TrimSpace(v)
	if t == "" {
		*errs = append(*errs, fmt.Errorf("%s is set but empty; unset it to use the default", name))
		return def
	}
	d, err := time.ParseDuration(t)
	if err != nil {
		*errs = append(*errs, fmt.Errorf("%s must be a duration, got %q", name, v))
		return def
	}
	if d < lo || d > hi {
		*errs = append(*errs, fmt.Errorf("%s must be in [%s, %s], got %s", name, lo, hi, d))
		return def
	}
	return d
}

func intVar(lookup Lookup, name string, def, lo, hi int, errs *[]error) int {
	v, ok := lookup(name)
	if !ok {
		return def
	}
	t := strings.TrimSpace(v)
	if t == "" {
		*errs = append(*errs, fmt.Errorf("%s is set but empty; unset it to use the default", name))
		return def
	}
	n, err := strconv.Atoi(t)
	if err != nil {
		*errs = append(*errs, fmt.Errorf("%s must be an integer, got %q", name, v))
		return def
	}
	if n < lo || n > hi {
		*errs = append(*errs, fmt.Errorf("%s must be in [%d, %d], got %d", name, lo, hi, n))
		return def
	}
	return n
}

// loadTokenSource resolves the mutually-exclusive enrollment-token sources. The
// file is preferred and read now; errors name the path and the underlying cause,
// never contents — an open/read failure carries no token bytes, and "permission
// denied" is the difference between a one-line fix and a blind restart loop (the
// container image runs as a non-root user, so a secret file written 0600 by root
// is unreadable to it). Returns a TokenSource yielding the resolved token, or nil
// when neither is set (agentrt then errors only if a first-run enrollment is
// actually needed).
func loadTokenSource(lookup Lookup, errs *[]error) func(context.Context) (string, error) {
	tokV, tokSet := lookup("NETTACT_AGENT_ENROLL_TOKEN")
	fileV, fileSet := lookup("NETTACT_AGENT_ENROLL_TOKEN_FILE")

	if tokSet && fileSet {
		*errs = append(*errs, errors.New("NETTACT_AGENT_ENROLL_TOKEN and NETTACT_AGENT_ENROLL_TOKEN_FILE are mutually exclusive"))
		return nil
	}

	if fileSet {
		path := strings.TrimSpace(fileV)
		token, err := readTokenFile(path)
		if err != nil {
			*errs = append(*errs, fmt.Errorf("NETTACT_AGENT_ENROLL_TOKEN_FILE: %w", err))
			return nil
		}
		return func(context.Context) (string, error) { return token, nil }
	}

	if tokSet {
		token := strings.TrimSpace(tokV)
		if token == "" {
			*errs = append(*errs, errors.New("NETTACT_AGENT_ENROLL_TOKEN is set but empty"))
			return nil
		}
		return func(context.Context) (string, error) { return token, nil }
	}

	// Neither set: enrollment can only proceed from a pre-existing credential.
	return func(context.Context) (string, error) {
		return "", fmt.Errorf("first run requires NETTACT_AGENT_ENROLL_TOKEN or NETTACT_AGENT_ENROLL_TOKEN_FILE: %w", agentrt.ErrNoEnrollmentToken)
	}
}
