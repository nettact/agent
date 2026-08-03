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
// tests (pass os.LookupEnv in production).
func Load(lookup Lookup) (agentrt.Config, error) {
	var errs []error
	add := func(err error) {
		if err != nil {
			errs = append(errs, err)
		}
	}

	cfg := agentrt.Config{}

	// SERVER_URL (required).
	if v, ok := nonEmpty(lookup, "NETTACT_AGENT_SERVER_URL", &errs); ok {
		u, err := url.Parse(v)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			add(fmt.Errorf("NETTACT_AGENT_SERVER_URL must be a http(s) URL, got %q", v))
		} else {
			cfg.ServerURL = v
		}
	} else if !present(lookup, "NETTACT_AGENT_SERVER_URL") {
		add(errors.New("NETTACT_AGENT_SERVER_URL is required"))
	}

	// DATA_DIR (default ./agent-data).
	cfg.DataDir = "./agent-data"
	if v, ok := nonEmpty(lookup, "NETTACT_AGENT_DATA_DIR", &errs); ok {
		cfg.DataDir = v
	}

	// TLS_INSECURE (bool, default false).
	if v, ok := nonEmpty(lookup, "NETTACT_AGENT_TLS_INSECURE", &errs); ok {
		b, err := strconv.ParseBool(v)
		if err != nil {
			add(fmt.Errorf("NETTACT_AGENT_TLS_INSECURE must be a boolean, got %q", v))
		} else {
			cfg.Insecure = b
		}
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

	// PERMISSIONS.
	cfg.Policy = loadPolicy(lookup, &errs)

	// PROBE ACCESS.
	cfg.ProbeAccess = loadProbeAccess(lookup, &errs)

	// LIMITS.
	cfg.Limits = loadLimits(lookup, &errs)

	// TOKEN (mutually exclusive sources; read the file now).
	cfg.TokenSource = loadTokenSource(lookup, &errs)

	if len(errs) > 0 {
		return agentrt.Config{}, errors.Join(errs...)
	}
	return cfg, nil
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
	if strings.EqualFold(t, "none") {
		return permission.Policy{Granted: permission.Set{}, Source: permission.SourceEnvironment}
	}
	granted := permission.Set{}
	for _, tok := range strings.Split(t, ",") {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		if tok == "*" || strings.EqualFold(tok, "all") {
			*errs = append(*errs, errors.New("NETTACT_AGENT_PERMISSIONS: wildcards (\"*\"/\"all\") are not supported; list explicit permissions"))
			continue
		}
		granted.Add(permission.ID(tok))
	}
	if err := permission.Validate(granted); err != nil {
		*errs = append(*errs, fmt.Errorf("NETTACT_AGENT_PERMISSIONS: %w", err))
	}
	return permission.Policy{Granted: granted, Source: permission.SourceEnvironment}
}

// loadProbeAccess builds the probe target-access policy.
func loadProbeAccess(lookup Lookup, errs *[]error) probepolicy.Policy {
	modeV, modeSet := lookup("NETTACT_AGENT_PROBE_ACCESS_MODE")
	allowV, allowSet := lookup("NETTACT_AGENT_PROBE_ALLOWLIST")
	denyV, denySet := lookup("NETTACT_AGENT_PROBE_DENYLIST")

	if !modeSet && !allowSet && !denySet {
		return probepolicy.Default()
	}

	mode := probepolicy.Mode(strings.ToLower(strings.TrimSpace(modeV)))
	if mode != probepolicy.ModeAllowlist && mode != probepolicy.ModeDenylist {
		*errs = append(*errs, fmt.Errorf("NETTACT_AGENT_PROBE_ACCESS_MODE must be 'allowlist' or 'denylist' when any probe-access variable is set, got %q", modeV))
		return probepolicy.Default()
	}

	allow := parseSelectors("NETTACT_AGENT_PROBE_ALLOWLIST", allowV, errs)
	// A literal "none" denylist means "deny nothing".
	var deny []probepolicy.Selector
	denyIsNone := denySet && strings.EqualFold(strings.TrimSpace(denyV), "none")
	if !denyIsNone {
		deny = parseSelectors("NETTACT_AGENT_PROBE_DENYLIST", denyV, errs)
	}

	switch mode {
	case probepolicy.ModeAllowlist:
		if len(allow) == 0 {
			*errs = append(*errs, errors.New("NETTACT_AGENT_PROBE_ALLOWLIST must be non-empty in allowlist mode"))
		}
	case probepolicy.ModeDenylist:
		if len(deny) == 0 && !denyIsNone {
			*errs = append(*errs, errors.New("NETTACT_AGENT_PROBE_DENYLIST must be non-empty (or `none`) in denylist mode"))
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
		if path == "" {
			*errs = append(*errs, errors.New("NETTACT_AGENT_ENROLL_TOKEN_FILE is set but empty"))
			return nil
		}
		// Bound the read to one byte past the limit before allocating, so a huge
		// local file cannot be slurped whole just to be rejected.
		f, err := os.Open(path)
		if err != nil {
			// *PathError already renders as `open <path>: <cause>`, so it names
			// the path without this repeating it.
			*errs = append(*errs, fmt.Errorf("NETTACT_AGENT_ENROLL_TOKEN_FILE: %w", err))
			return nil
		}
		data, err := io.ReadAll(io.LimitReader(f, maxTokenFileBytes+1))
		_ = f.Close()
		if err != nil {
			*errs = append(*errs, fmt.Errorf("NETTACT_AGENT_ENROLL_TOKEN_FILE: reading %q failed: %w", path, err))
			return nil
		}
		if len(data) > maxTokenFileBytes {
			*errs = append(*errs, fmt.Errorf("NETTACT_AGENT_ENROLL_TOKEN_FILE: %q is too large", path))
			return nil
		}
		token := strings.TrimSpace(string(data))
		if token == "" {
			*errs = append(*errs, fmt.Errorf("NETTACT_AGENT_ENROLL_TOKEN_FILE: %q is empty", path))
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
		return "", errors.New("first run requires NETTACT_AGENT_ENROLL_TOKEN or NETTACT_AGENT_ENROLL_TOKEN_FILE")
	}
}
