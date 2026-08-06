package envcfg

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/nettact/agent/probepolicy"
	"github.com/nettact/protocol/permission"
)

func mapLookup(values map[string]string) Lookup {
	return func(name string) (string, bool) {
		v, ok := values[name]
		return v, ok
	}
}

func TestLoadPermissionModesAndDefaults(t *testing.T) {
	base := map[string]string{"NETTACT_AGENT_SERVER_URL": "https://server.example"}
	cfg, err := Load(mapLookup(base), File{})
	if err != nil {
		t.Fatalf("Load(defaults): %v", err)
	}
	if cfg.Policy.Source != permission.SourceDefault || !reflect.DeepEqual(cfg.Policy.Granted.Strings(), permission.DefaultStandalone().Strings()) {
		t.Fatalf("default policy = %+v, want frozen standalone default", cfg.Policy)
	}
	if cfg.ProbeAccess.Mode != probepolicy.ModeAllowlist {
		t.Fatalf("default probe mode = %q, want allowlist", cfg.ProbeAccess.Mode)
	}

	none := map[string]string{
		"NETTACT_AGENT_SERVER_URL":  "https://server.example",
		"NETTACT_AGENT_PERMISSIONS": "none",
	}
	cfg, err = Load(mapLookup(none), File{})
	if err != nil {
		t.Fatalf("Load(none): %v", err)
	}
	if cfg.Policy.Source != permission.SourceEnvironment || len(cfg.Policy.Granted) != 0 {
		t.Fatalf("none policy = %+v, want empty environment grant", cfg.Policy)
	}

	explicit := map[string]string{
		"NETTACT_AGENT_SERVER_URL":  "https://server.example",
		"NETTACT_AGENT_PERMISSIONS": "host.process.basic.read,host.process.owner.read",
	}
	cfg, err = Load(mapLookup(explicit), File{})
	if err != nil {
		t.Fatalf("Load(explicit): %v", err)
	}
	want := []string{"host.process.basic.read", "host.process.owner.read"}
	if got := cfg.Policy.Granted.Strings(); !reflect.DeepEqual(got, want) {
		t.Fatalf("explicit grant = %v, want replacement %v", got, want)
	}
	if cfg.Policy.Granted.Has(permission.ProbeICMP) {
		t.Fatal("explicit permission list merged the default probe.icmp grant")
	}
}

func TestLoadRejectsInvalidPermissionSets(t *testing.T) {
	for _, tt := range []struct {
		name, value, want string
	}{
		{name: "missing dependency", value: "host.process.owner.read", want: "requires \"host.process.basic.read\""},
		{name: "wildcard", value: "all", want: "wildcards"},
		{name: "unknown", value: "probe.future", want: "unknown permission"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Load(mapLookup(map[string]string{
				"NETTACT_AGENT_SERVER_URL":  "https://server.example",
				"NETTACT_AGENT_PERMISSIONS": tt.value,
			}), File{})
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Load(%q) error = %v, want substring %q", tt.value, err, tt.want)
			}
		})
	}
}

func TestLoadRejectsOversizedTokenFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte(strings.Repeat("x", maxTokenFileBytes+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Load(mapLookup(map[string]string{
		"NETTACT_AGENT_SERVER_URL":        "https://server.example",
		"NETTACT_AGENT_ENROLL_TOKEN_FILE": path,
	}), File{})
	if err == nil || !strings.Contains(err.Error(), "is too large") {
		t.Fatalf("oversized token error = %v, want safe size rejection", err)
	}
}
