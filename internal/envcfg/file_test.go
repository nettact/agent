package envcfg

import (
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nettact/agent/agentrt"
	"github.com/nettact/agent/probepolicy"
	"github.com/nettact/protocol/permission"
)

// writeYAML writes body to a temp file and returns its path.
func writeYAML(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "agent.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// loadLayered parses a YAML file and layers it over env, returning the final config.
func loadLayered(t *testing.T, body string, env map[string]string) (agentrt.Config, error) {
	t.Helper()
	file, err := LoadFile(writeYAML(t, body))
	if err != nil {
		return agentrt.Config{}, err
	}
	return Load(Layered(file, mapLookup(env)))
}

func TestFileLayersOverEnvPerKey(t *testing.T) {
	body := `
server_url: https://yaml.example
upload_interval: 9s
tls_insecure: true
wire_format: json
max_probe_concurrency: 32
`
	env := map[string]string{
		"NETTACT_AGENT_SERVER_URL":      "https://env.example", // overridden by file
		"NETTACT_AGENT_UPLOAD_INTERVAL": "1s",                  // overridden by file
		"NETTACT_AGENT_DATA_DIR":        "/env/data",           // falls through (no file key)
	}
	file, err := LoadFile(writeYAML(t, body))
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	cfg, err := Load(Layered(file, mapLookup(env)))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.ServerURL != "https://yaml.example" {
		t.Errorf("ServerURL = %q, want file value to win", cfg.ServerURL)
	}
	if cfg.UploadInterval != 9*time.Second {
		t.Errorf("UploadInterval = %v, want 9s from file", cfg.UploadInterval)
	}
	if cfg.DataDir != "/env/data" {
		t.Errorf("DataDir = %q, want env fall-through", cfg.DataDir)
	}
	if !cfg.Insecure {
		t.Error("Insecure = false, want true from file bool")
	}
	if cfg.WireFormat != "json" {
		t.Errorf("WireFormat = %q, want json", cfg.WireFormat)
	}
	if cfg.Limits.MaxProbeConcurrency != 32 {
		t.Errorf("MaxProbeConcurrency = %d, want 32", cfg.Limits.MaxProbeConcurrency)
	}
}

func TestEmptyFileIsPureEnv(t *testing.T) {
	file, err := LoadFile(writeYAML(t, "# just a comment, no keys\n"))
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	if len(file) != 0 {
		t.Fatalf("comment-only file flattened to %v, want empty", file)
	}
	env := map[string]string{"NETTACT_AGENT_SERVER_URL": "https://env.example"}
	cfg, err := Load(Layered(file, mapLookup(env)))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.ServerURL != "https://env.example" || cfg.DataDir != "./agent-data" {
		t.Fatalf("pure-env config = %+v, want env server + default data dir", cfg)
	}
}

func TestFileTokenVsEnvTokenFileMutualExclusion(t *testing.T) {
	body := `
server_url: https://server.example
enroll_token: secret-from-file
`
	env := map[string]string{
		"NETTACT_AGENT_ENROLL_TOKEN_FILE": filepath.Join(t.TempDir(), "token"),
	}
	_, err := loadLayered(t, body, env)
	if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("cross-source token conflict error = %v, want mutual-exclusion rejection", err)
	}
}

func TestFileUnknownKeyRejected(t *testing.T) {
	_, err := LoadFile(writeYAML(t, "server_url: https://x\nbogus_key: 1\n"))
	if err == nil || !strings.Contains(err.Error(), "bogus_key") {
		t.Fatalf("unknown-key error = %v, want the offending key named", err)
	}
}

func TestFileUnknownNestedKeyRejected(t *testing.T) {
	body := `
probe_access:
  mode: allowlist
  typo_list: [scope:lan]
`
	_, err := LoadFile(writeYAML(t, body))
	if err == nil || !strings.Contains(err.Error(), "typo_list") {
		t.Fatalf("nested unknown-key error = %v, want the offending key named", err)
	}
}

func TestFileSyntaxErrorLocated(t *testing.T) {
	_, err := LoadFile(writeYAML(t, "server_url: \"unterminated\n"))
	if err == nil {
		t.Fatal("malformed YAML accepted, want a syntax error")
	}
	if !strings.Contains(err.Error(), "config file") || !strings.Contains(err.Error(), "line") {
		t.Fatalf("syntax error = %v, want file name and a line location", err)
	}
}

func TestFilePresentButEmptyValueRejected(t *testing.T) {
	body := `
server_url: https://server.example
upload_interval: ""
`
	_, err := loadLayered(t, body, nil)
	if err == nil || !strings.Contains(err.Error(), "NETTACT_AGENT_UPLOAD_INTERVAL is set but empty") {
		t.Fatalf("empty-string value error = %v, want present-but-empty rejection", err)
	}
}

func TestFilePermissionsListAndNone(t *testing.T) {
	list := `
server_url: https://server.example
permissions: [host.process.basic.read, host.process.owner.read]
`
	cfg, err := loadLayered(t, list, nil)
	if err != nil {
		t.Fatalf("Load(list): %v", err)
	}
	want := []string{"host.process.basic.read", "host.process.owner.read"}
	if got := cfg.Policy.Granted.Strings(); !reflect.DeepEqual(got, want) {
		t.Fatalf("permissions grant = %v, want %v", got, want)
	}
	if cfg.Policy.Source != permission.SourceEnvironment {
		t.Fatalf("permissions source = %v, want environment (explicit list)", cfg.Policy.Source)
	}

	none := "server_url: https://server.example\npermissions: none\n"
	cfg, err = loadLayered(t, none, nil)
	if err != nil {
		t.Fatalf("Load(none): %v", err)
	}
	if len(cfg.Policy.Granted) != 0 {
		t.Fatalf("permissions none grant = %v, want empty", cfg.Policy.Granted.Strings())
	}
}

// TestInstallScriptConfigShape pins the exact file install.sh and install.ps1
// write when the operator picks a permission set at enrollment: JSON-quoted
// scalars plus a quoted block list. Those installers are the main way a policy
// reaches an Agent, and a mismatch between what they emit and what this parser
// accepts would only surface as a machine that refuses to start after install.
func TestInstallScriptConfigShape(t *testing.T) {
	// The installers always point enroll_token_file at a real file they just
	// wrote, and the loader reads it eagerly, so the test needs one too.
	tokenFile := filepath.Join(t.TempDir(), "enroll.token")
	if err := os.WriteFile(tokenFile, []byte("tok"), 0o600); err != nil {
		t.Fatal(err)
	}
	body := `server_url: "https://server.example:12450"
data_dir: "/var/lib/nettact-agent"
enroll_token_file: ` + strconv.Quote(tokenFile) + `
permissions:
  - "probe.icmp"
  - "probe.dns"
  - "host.cpu.read"
`
	cfg, err := loadLayered(t, body, nil)
	if err != nil {
		t.Fatalf("installer-written config must load: %v", err)
	}
	want := []string{"probe.icmp", "probe.dns", "host.cpu.read"}
	got := cfg.Policy.Granted
	if len(got) != len(want) {
		t.Fatalf("granted = %v, want %v", got.Strings(), want)
	}
	for _, id := range want {
		if !got.Has(permission.ID(id)) {
			t.Fatalf("granted = %v, missing %q", got.Strings(), id)
		}
	}
	if cfg.Policy.Source != permission.SourceEnvironment {
		t.Fatalf("policy source = %v, want environment (an explicit list)", cfg.Policy.Source)
	}
	if cfg.ServerURL != "https://server.example:12450" {
		t.Fatalf("server_url = %q", cfg.ServerURL)
	}
}

func TestFileProbeAccessDenylistNone(t *testing.T) {
	body := `
server_url: https://server.example
probe_access:
  mode: denylist
  denylist: none
`
	cfg, err := loadLayered(t, body, nil)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.ProbeAccess.Mode != probepolicy.ModeDenylist {
		t.Fatalf("probe mode = %q, want denylist", cfg.ProbeAccess.Mode)
	}
	if len(cfg.ProbeAccess.Deny) != 0 {
		t.Fatalf("denylist none produced %v, want deny-nothing", cfg.ProbeAccess.DenyStrings())
	}
}

func TestFileProbeAccessAllowlist(t *testing.T) {
	body := `
server_url: https://server.example
probe_access:
  mode: allowlist
  allowlist: [scope:lan, ip:1.2.3.4]
`
	cfg, err := loadLayered(t, body, nil)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.ProbeAccess.Mode != probepolicy.ModeAllowlist || len(cfg.ProbeAccess.Allow) != 2 {
		t.Fatalf("allowlist = %+v, want two selectors in allowlist mode", cfg.ProbeAccess)
	}
}

func TestFileMaxTraceConcurrency(t *testing.T) {
	// From the file.
	cfg, err := loadLayered(t, "server_url: https://server.example\nmax_trace_concurrency: 8\n", nil)
	if err != nil {
		t.Fatalf("Load(file): %v", err)
	}
	if cfg.Limits.MaxTraceConcurrency != 8 {
		t.Fatalf("MaxTraceConcurrency(file) = %d, want 8", cfg.Limits.MaxTraceConcurrency)
	}

	// From the environment alone.
	cfg, err = Load(mapLookup(map[string]string{
		"NETTACT_AGENT_SERVER_URL":            "https://server.example",
		"NETTACT_AGENT_MAX_TRACE_CONCURRENCY": "7",
	}))
	if err != nil {
		t.Fatalf("Load(env): %v", err)
	}
	if cfg.Limits.MaxTraceConcurrency != 7 {
		t.Fatalf("MaxTraceConcurrency(env) = %d, want 7", cfg.Limits.MaxTraceConcurrency)
	}

	// Out of range.
	_, err = loadLayered(t, "server_url: https://server.example\nmax_trace_concurrency: 100\n", nil)
	if err == nil || !strings.Contains(err.Error(), "NETTACT_AGENT_MAX_TRACE_CONCURRENCY must be in [1, 64]") {
		t.Fatalf("out-of-range trace concurrency error = %v, want range rejection", err)
	}
}

// TestExampleConfigParses guards the shipped template against drift: it must
// stay valid under the strict decoder (so no unknown key or YAML slips in) and
// carry the one required, uncommented setting.
func TestExampleConfigParses(t *testing.T) {
	m, err := LoadFile("../../agent.example.yaml")
	if err != nil {
		t.Fatalf("agent.example.yaml must parse under the strict decoder: %v", err)
	}
	if _, ok := m["NETTACT_AGENT_SERVER_URL"]; !ok {
		t.Fatalf("example flattened to %v, want at least server_url", m)
	}
}

func strPtr(s string) *string { return &s }

func TestResolveConfigPath(t *testing.T) {
	empty := mapLookup(nil)

	// Keep auto-discovery hermetic: point the platform default at a path that does
	// not exist yet, so a host-installed /etc/nettact/agent.yaml (or the Windows
	// default) can never leak into a result that must resolve to "no config".
	platformDefault := filepath.Join(t.TempDir(), "platform-agent.yaml")
	origPlatform := platformConfigPath
	t.Cleanup(func() { platformConfigPath = origPlatform })
	platformConfigPath = func(Lookup) string { return platformDefault }

	// Explicit path (flag) is honored verbatim and marked explicit, even if absent.
	if path, explicit, err := ResolveConfigPath(strPtr("/no/such/agent.yaml"), empty); err != nil || path != "/no/such/agent.yaml" || !explicit {
		t.Fatalf("explicit flag = (%q,%v,%v), want the path marked explicit", path, explicit, err)
	}
	// And a missing explicit file is a hard error at load time.
	if _, err := LoadFile("/no/such/agent.yaml"); err == nil {
		t.Fatal("LoadFile(missing explicit) succeeded, want error")
	}

	// NETTACT_AGENT_CONFIG_FILE is also explicit.
	envLookup := mapLookup(map[string]string{"NETTACT_AGENT_CONFIG_FILE": "/etc/from-env.yaml"})
	if path, explicit, err := ResolveConfigPath(nil, envLookup); err != nil || path != "/etc/from-env.yaml" || !explicit {
		t.Fatalf("env config file = (%q,%v,%v), want explicit", path, explicit, err)
	}

	// An explicitly empty --config value is a hard error, not a fall-through to
	// auto-discovery — both `--config=` (empty) and `--config ""` / whitespace.
	for _, raw := range []string{"", "   "} {
		if _, _, err := ResolveConfigPath(strPtr(raw), envLookup); err == nil || !strings.Contains(err.Error(), "--config requires a path") {
			t.Fatalf("empty --config %q error = %v, want a --config-requires-a-path rejection", raw, err)
		}
	}

	// A set-but-blank NETTACT_AGENT_CONFIG_FILE is likewise a hard error.
	for _, blank := range []string{"", "   "} {
		lookup := mapLookup(map[string]string{"NETTACT_AGENT_CONFIG_FILE": blank})
		if _, _, err := ResolveConfigPath(nil, lookup); err == nil || !strings.Contains(err.Error(), "NETTACT_AGENT_CONFIG_FILE is set but empty") {
			t.Fatalf("blank env config file %q error = %v, want a set-but-empty rejection", blank, err)
		}
	}

	// No path set and no default present: silent pure-env operation.
	t.Chdir(t.TempDir())
	if path, explicit, err := ResolveConfigPath(nil, empty); err != nil || path != "" || explicit {
		t.Fatalf("no-config = (%q,%v,%v), want ('',false,nil)", path, explicit, err)
	}

	// The injected platform default is discovered (non-explicit) once it exists —
	// exercising case 4 without depending on the host's real /etc path.
	if err := os.WriteFile(platformDefault, []byte("server_url: https://x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if path, explicit, err := ResolveConfigPath(nil, empty); err != nil || path != platformDefault || explicit {
		t.Fatalf("platform discovery = (%q,%v,%v), want (%q,false,nil)", path, explicit, err, platformDefault)
	}

	// A working-directory nettact-agent.yaml wins over the platform default and is
	// auto-discovered (non-explicit).
	if err := os.WriteFile(workingDirConfig, []byte("server_url: https://x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if path, explicit, err := ResolveConfigPath(nil, empty); err != nil || path != workingDirConfig || explicit {
		t.Fatalf("working-dir discovery = (%q,%v,%v), want (%q,false,nil)", path, explicit, err, workingDirConfig)
	}
}
