// Package identity manages the agent's stable identity. M1 persists a random
// agent ID to the data dir so restarts keep the same identity. M2 replaces this
// with an ed25519 keypair + server-issued credential (architecture §11).
package identity

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/google/uuid"
)

// LoadOrCreateAgentID returns the persisted agent ID under dataDir, creating
// one on first run.
func LoadOrCreateAgentID(dataDir string) (string, error) {
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return "", err
	}
	path := filepath.Join(dataDir, "agent_id")
	if b, err := os.ReadFile(path); err == nil {
		if id := strings.TrimSpace(string(b)); id != "" {
			return id, nil
		}
	}
	id := "agent_" + uuid.NewString()
	if err := os.WriteFile(path, []byte(id), 0o600); err != nil {
		return "", err
	}
	return id, nil
}
