// File-based configuration for the standalone agent. A YAML config file layers
// on top of the NETTACT_AGENT_* environment: LoadFile parses the file into a
// map keyed by the exact environment-variable names, and Layered wraps that map
// over os.LookupEnv so a file key wins over the same environment variable while
// every other setting falls through to the environment. Load then runs the one
// existing validation/range/aggregation path over the layered view, so the file
// path reuses all env semantics (including the token vs token-file mutual
// exclusion and the "set but empty" rejection) and every error still names the
// NETTACT_AGENT_* variable — scalar YAML keys correspond 1:1 to those variables.
//
// The one exception is `servers:`. A list of records has no environment form —
// the whole model here is one key, one variable, one string — so it is carried
// beside the map rather than flattened into it, and validated by Load like
// everything else. It is the file-only setting because it is the one setting
// with no scalar shape, not because files are privileged.
//
// Precedence: config file > environment > built-in defaults. Parsing is strict
// (unknown keys and syntax errors fail with a locating message); a config
// changes still requires an agent restart.
package envcfg

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// configFileEnv names the environment variable that points at the config file
// (an alternative to --config). workingDirConfig is the working-directory
// default filename tried when no explicit path is given.
const (
	configFileEnv    = "NETTACT_AGENT_CONFIG_FILE"
	workingDirConfig = "nettact-agent.yaml"
)

// File is a parsed configuration file: the scalar settings flattened onto their
// environment-variable names, plus the servers list, which has no such form. The
// zero File means "no configuration file", so a caller with only an environment
// passes it and nothing changes.
type File struct {
	env     map[string]string
	servers []serverEntryFile
}

// fileConfig mirrors the YAML schema. Every scalar field is a pointer so an
// omitted key (or an explicit YAML null) stays nil ("unset", falls through to
// the environment), while a present key — even an empty string — flattens onto
// its environment variable and carries the env "set but empty" semantics.
// Unknown keys are rejected by the strict decoder in LoadFile.
type fileConfig struct {
	Servers             []serverEntryFile `yaml:"servers"`
	ServerURL           *string           `yaml:"server_url"`
	DataDir             *string           `yaml:"data_dir"`
	StatusFile          *string           `yaml:"status_file"`
	EnrollToken         *string           `yaml:"enroll_token"`
	EnrollTokenFile     *string           `yaml:"enroll_token_file"`
	TLSInsecure         *bool             `yaml:"tls_insecure"`
	UploadInterval      *string           `yaml:"upload_interval"`
	WireFormat          *string           `yaml:"wire_format"`
	Permissions         *scalarOrList     `yaml:"permissions"`
	ProbeAccess         *probeAccessFile  `yaml:"probe_access"`
	MinProbeInterval    *string           `yaml:"min_probe_interval"`
	MaxProbeConcurrency *int              `yaml:"max_probe_concurrency"`
	SnapshotMinInterval *string           `yaml:"snapshot_min_interval"`
	SnapshotTimeout     *string           `yaml:"snapshot_timeout"`
	MaxTraceConcurrency *int              `yaml:"max_trace_concurrency"`
}

// serverEntryFile is one entry of the `servers:` list — everything that can
// differ between two servers this agent reports to.
//
// permissions and probe_access appear here as well as at the top level, and the
// two levels do NOT mean the same thing. A top-level permissions list is the
// default grant an entry inherits when it names none; an entry's own list
// replaces it. A top-level probe_access is the machine's floor, and an entry's
// can only narrow it further — a server can be told to reach less than the
// machine allows, never more.
type serverEntryFile struct {
	Name            *string          `yaml:"name"`
	URL             *string          `yaml:"url"`
	EnrollToken     *string          `yaml:"enroll_token"`
	EnrollTokenFile *string          `yaml:"enroll_token_file"`
	TLSInsecure     *bool            `yaml:"tls_insecure"`
	Permissions     *scalarOrList    `yaml:"permissions"`
	ProbeAccess     *probeAccessFile `yaml:"probe_access"`
}

// probeAccessFile is the nested probe_access group. It is a plain struct (no
// custom Unmarshaler) so the strict decoder still rejects unknown keys under it.
type probeAccessFile struct {
	Mode      *string       `yaml:"mode"`
	Allowlist *scalarOrList `yaml:"allowlist"`
	Denylist  *scalarOrList `yaml:"denylist"`
}

// scalarOrList accepts either a YAML scalar string (e.g. the literal "none") or
// a sequence of strings. csv renders it to the CSV form the env loaders parse:
// list selectors/permissions join on ",", while a scalar (like "none") passes
// through verbatim so its whole-replacement semantics reach loadPolicy /
// loadProbeAccess unchanged.
type scalarOrList struct {
	isScalar bool
	scalar   string
	list     []string
}

func (s *scalarOrList) UnmarshalYAML(node *yaml.Node) error {
	switch node.Kind {
	case yaml.SequenceNode:
		var list []string
		if err := node.Decode(&list); err != nil {
			return err
		}
		s.list = list
		return nil
	case yaml.ScalarNode:
		var str string
		if err := node.Decode(&str); err != nil {
			return err
		}
		s.isScalar = true
		s.scalar = str
		return nil
	default:
		return fmt.Errorf("line %d: must be a string (e.g. \"none\") or a list of strings", node.Line)
	}
}

func (s *scalarOrList) csv() string {
	if s.isScalar {
		return s.scalar
	}
	return strings.Join(s.list, ",")
}

// flatten renders the parsed file onto a map keyed by NETTACT_AGENT_* variable
// names. Only present keys are emitted; a present-but-empty value is emitted as
// "" so Load reports it exactly as it would an empty environment variable.
func (fc *fileConfig) flatten() map[string]string {
	m := map[string]string{}
	put := func(name string, v *string) {
		if v != nil {
			m[name] = *v
		}
	}
	put("NETTACT_AGENT_SERVER_URL", fc.ServerURL)
	put("NETTACT_AGENT_DATA_DIR", fc.DataDir)
	// Process-wide, not per server: the file is one document describing every
	// server, so it has no place in a `servers:` entry.
	put("NETTACT_AGENT_STATUS_FILE", fc.StatusFile)
	put("NETTACT_AGENT_ENROLL_TOKEN", fc.EnrollToken)
	put("NETTACT_AGENT_ENROLL_TOKEN_FILE", fc.EnrollTokenFile)
	if fc.TLSInsecure != nil {
		m["NETTACT_AGENT_TLS_INSECURE"] = strconv.FormatBool(*fc.TLSInsecure)
	}
	put("NETTACT_AGENT_UPLOAD_INTERVAL", fc.UploadInterval)
	put("NETTACT_AGENT_WIRE_FORMAT", fc.WireFormat)
	if fc.Permissions != nil {
		m["NETTACT_AGENT_PERMISSIONS"] = fc.Permissions.csv()
	}
	if fc.ProbeAccess != nil {
		put("NETTACT_AGENT_PROBE_ACCESS_MODE", fc.ProbeAccess.Mode)
		if fc.ProbeAccess.Allowlist != nil {
			m["NETTACT_AGENT_PROBE_ALLOWLIST"] = fc.ProbeAccess.Allowlist.csv()
		}
		if fc.ProbeAccess.Denylist != nil {
			m["NETTACT_AGENT_PROBE_DENYLIST"] = fc.ProbeAccess.Denylist.csv()
		}
	}
	put("NETTACT_AGENT_MIN_PROBE_INTERVAL", fc.MinProbeInterval)
	if fc.MaxProbeConcurrency != nil {
		m["NETTACT_AGENT_MAX_PROBE_CONCURRENCY"] = strconv.Itoa(*fc.MaxProbeConcurrency)
	}
	put("NETTACT_AGENT_SNAPSHOT_MIN_INTERVAL", fc.SnapshotMinInterval)
	put("NETTACT_AGENT_SNAPSHOT_TIMEOUT", fc.SnapshotTimeout)
	if fc.MaxTraceConcurrency != nil {
		m["NETTACT_AGENT_MAX_TRACE_CONCURRENCY"] = strconv.Itoa(*fc.MaxTraceConcurrency)
	}
	return m
}

// LoadFile reads and strictly parses a YAML config file. The scalar settings
// come back keyed by NETTACT_AGENT_* variable names, suitable for Layered; the
// servers list rides along beside them (see File). Unknown keys and syntax
// errors fail with the file name and the decoder's line/field location. An empty
// or comment-only file yields an empty File (equivalent to pure-env operation).
func LoadFile(path string) (File, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return File{}, fmt.Errorf("config file %q: %w", path, err)
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var fc fileConfig
	if err := dec.Decode(&fc); err != nil {
		if errors.Is(err, io.EOF) {
			return File{env: map[string]string{}}, nil
		}
		return File{}, fmt.Errorf("config file %q: %w", path, err)
	}
	// The config is a single mapping; a second document is almost certainly a
	// mistake (a stray `---`), so reject it rather than silently ignore it.
	if err := dec.Decode(new(yaml.Node)); !errors.Is(err, io.EOF) {
		return File{}, fmt.Errorf("config file %q: expected a single YAML document", path)
	}
	return File{env: fc.flatten(), servers: fc.Servers}, nil
}

// Layered returns a Lookup that resolves a name from file first (a parsed config
// file), falling back to fallback (typically os.LookupEnv) on a miss. This makes
// file values win per-key over the environment while unset file keys inherit the
// environment — and because both token sources can now come from different
// layers, Load's existing token/token-file mutual-exclusion still triggers.
func Layered(file File, fallback Lookup) Lookup {
	return func(name string) (string, bool) {
		if v, ok := file.env[name]; ok {
			return v, true
		}
		return fallback(name)
	}
}

// ResolveConfigPath decides which config file to load. Precedence:
//
//  1. explicitPath (from --config), when the flag is present
//  2. NETTACT_AGENT_CONFIG_FILE, when set
//  3. ./nettact-agent.yaml (working directory), when it exists
//  4. the platform default, when it exists
//     (Windows: %ProgramData%\NetTact\agent.yaml; other: /etc/nettact/agent.yaml)
//
// explicitPath is nil when --config was not passed and non-nil (possibly the
// empty string) when it was. Naming a config source but leaving it blank —
// `--config=`, `--config ""`, or a set-but-blank NETTACT_AGENT_CONFIG_FILE — is a
// hard error rather than a silent fall-through to auto-discovery: an operator who
// pointed at a config source and supplied nothing has almost certainly made a
// deployment mistake we should surface, not paper over.
//
// explicit is true for cases 1–2 (a path the operator named): the caller must
// treat a missing/unreadable file there as fatal — LoadFile surfaces that error.
// For the discovered defaults (3–4) a non-existent file returns ("", false, nil)
// and the agent runs from the environment alone. lookup supplies the environment
// (os.LookupEnv in production, injectable in tests).
func ResolveConfigPath(explicitPath *string, lookup Lookup) (path string, explicit bool, err error) {
	if explicitPath != nil {
		if p := strings.TrimSpace(*explicitPath); p != "" {
			return p, true, nil
		}
		return "", false, errors.New("--config requires a path")
	}
	if v, ok := lookup(configFileEnv); ok {
		if p := strings.TrimSpace(v); p != "" {
			return p, true, nil
		}
		return "", false, fmt.Errorf("%s is set but empty", configFileEnv)
	}
	if fileExists(workingDirConfig) {
		return workingDirConfig, false, nil
	}
	if p := platformConfigPath(lookup); p != "" && fileExists(p) {
		return p, false, nil
	}
	return "", false, nil
}

// platformConfigPath returns the OS-conventional config path, or "" when it
// cannot be determined (Windows without %ProgramData%). It is a var so tests can
// inject a hermetic path, keeping auto-discovery independent of whatever the host
// happens to have installed at the real default location.
var platformConfigPath = func(lookup Lookup) string {
	if runtime.GOOS == "windows" {
		if pd, ok := lookup("ProgramData"); ok {
			if pd = strings.TrimSpace(pd); pd != "" {
				return filepath.Join(pd, "NetTact", "agent.yaml")
			}
		}
		return ""
	}
	return "/etc/nettact/agent.yaml"
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}
