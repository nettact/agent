// Package identity manages the agent's ed25519 keypair and the server-issued
// credential (architecture §11). The private key never leaves the host; the
// bearer token is obtained once at enrollment and reused for telemetry.
package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// LoadOrCreateKey returns the agent's persisted ed25519 private key, generating
// one on first run. The 32-byte seed is stored at dataDir/agent.key (0600).
func LoadOrCreateKey(dataDir string) (ed25519.PrivateKey, error) {
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return nil, err
	}
	path := filepath.Join(dataDir, "agent.key")
	if b, err := os.ReadFile(path); err == nil {
		if seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b))); err == nil && len(seed) == ed25519.SeedSize {
			return ed25519.NewKeyFromSeed(seed), nil
		}
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(priv.Seed())), 0o600); err != nil {
		return nil, err
	}
	return priv, nil
}

// Credential is the server-issued agent identity persisted after enrollment.
type Credential struct {
	AgentID    string `json:"agent_id"`
	SiteID     string `json:"site_id"`
	AgentToken string `json:"agent_token"`
}

// LoadCredential returns the saved credential and whether the agent is enrolled.
func LoadCredential(dataDir string) (Credential, bool, error) {
	b, err := os.ReadFile(filepath.Join(dataDir, "agent.json"))
	if errors.Is(err, os.ErrNotExist) {
		return Credential{}, false, nil
	}
	if err != nil {
		return Credential{}, false, err
	}
	var c Credential
	if err := json.Unmarshal(b, &c); err != nil {
		return Credential{}, false, err
	}
	return c, c.AgentToken != "", nil
}

// SaveCredential persists the credential (0600).
func SaveCredential(dataDir string, c Credential) error {
	b, _ := json.MarshalIndent(c, "", "  ")
	return os.WriteFile(filepath.Join(dataDir, "agent.json"), b, 0o600)
}

// DeleteCredential removes the persisted credential so the next run re-enrolls.
// Used when the server revokes the agent (WS close 4004): the bearer token is
// dead, and keeping agent.json would loop a redial into the same rejection. The
// ed25519 key (agent.key) is intentionally kept: a reinstall token minted against
// this agent (AGENT-006) makes the next enrollment rejoin under the same agent_id
// with its history intact. Missing file is not an error.
func DeleteCredential(dataDir string) error {
	err := os.Remove(filepath.Join(dataDir, "agent.json"))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}
