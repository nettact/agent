// Package identity manages the agent's ed25519 keypair and the server-issued
// credentials (architecture §11). The private key never leaves the host; a
// bearer token is obtained once per server at enrollment and reused for
// telemetry.
//
// One agent may be enrolled at several servers at once. The keypair is shared —
// enrollment proves possession by signing a fresh nonce, so the same key can
// prove itself to any number of servers, and each mints an agent_id of its own
// that means nothing to the others. The credentials are therefore a map keyed by
// the server's configured name: it is the only stable handle the agent has (a
// URL can be edited, an agent_id is assigned by the very exchange the credential
// records), and the same key identifies that server's WAL cursor.
package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

const (
	credentialFile = "agent.json"
	// credentialFormat is stamped into agent.json. It is checked exactly, and an
	// unreadable or unknown file means "not enrolled anywhere" rather than a hard
	// failure: re-enrolling is a working recovery (the operator's token is what
	// gates it), while refusing to start would leave a machine with a corrupt
	// 200-byte file permanently silent.
	credentialFormat = 2
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

// Credential is one server's issued agent identity, persisted after enrollment.
type Credential struct {
	AgentID    string `json:"agent_id"`
	SiteID     string `json:"site_id"`
	AgentToken string `json:"agent_token"`

	// ConsumedTokenHash is the sha256 of the one-time enrollment token this
	// credential was last enrolled with, or "" for a credential written before
	// the field existed (every legacy install). The 401-recovery supervisor
	// compares it against the currently configured token to tell a *different*
	// (possibly fresh) token apart from the one that already enrolled this
	// agent: equal hashes mean the configured token is the consumed one and must
	// not be tried again.
	//
	// It is additive to the v2 format: an older binary ignores the key on read
	// (json.Unmarshal skips unknown fields) and drops it on write (its struct
	// has no such field), which merely reverts that credential to the legacy
	// "unknown" classification — never a hard failure.
	ConsumedTokenHash string `json:"consumed_token_hash,omitempty"`
}

// credentialFile is the on-disk shape of agent.json.
type credentialsFile struct {
	V       int                   `json:"v"`
	Servers map[string]Credential `json:"servers"`
}

// credMu serializes the whole load-modify-save of agent.json.
//
// The atomic rename makes each publish all-or-nothing for a READER, which is a
// different guarantee from the one this needs: two servers finishing their first
// enrollment at the same moment would both read the pre-enrollment map, each add
// only its own entry, and the second publish would erase the first. Every
// mutation therefore holds this for its entire read-modify-write, not just for
// the write.
//
// A process-level mutex is the whole scope of the problem: the only writers are
// this agent's own server runners, and a second agent instance sharing one data
// directory is already excluded — it would be fighting over the same credentials
// and superseding its own sessions.
var credMu sync.Mutex

// LoadCredentials returns every persisted credential, keyed by server name. A
// missing, malformed, or wrong-version file yields an empty map and no error:
// each server's runner independently sees "not enrolled" and enrolls, which is
// the same path a first run takes.
func LoadCredentials(dataDir string) (map[string]Credential, error) {
	credMu.Lock()
	defer credMu.Unlock()
	return loadLocked(dataDir)
}

// loadLocked is LoadCredentials without the lock. Caller holds credMu.
func loadLocked(dataDir string) (map[string]Credential, error) {
	b, err := os.ReadFile(filepath.Join(dataDir, credentialFile))
	if errors.Is(err, os.ErrNotExist) {
		return map[string]Credential{}, nil
	}
	if err != nil {
		return nil, err
	}
	var f credentialsFile
	if err := json.Unmarshal(b, &f); err != nil || f.V != credentialFormat {
		return map[string]Credential{}, nil
	}
	out := make(map[string]Credential, len(f.Servers))
	for name, c := range f.Servers {
		if c.AgentToken == "" {
			continue // half-written or hand-edited; treat as not enrolled
		}
		out[name] = c
	}
	return out, nil
}

// SaveCredential persists one server's credential, leaving the others alone.
//
// It is a read-modify-write of the whole file under credMu, published by rename:
// several server runners enroll concurrently on first start, so the read and the
// write have to be one operation (see credMu) as well as each being atomic.
// Holding the whole file in one object also keeps the credentials for N servers
// in one fsync rather than N.
func SaveCredential(dataDir, server string, c Credential) error {
	if server == "" {
		return errors.New("identity: credential needs a server name")
	}
	credMu.Lock()
	defer credMu.Unlock()

	creds, err := loadLocked(dataDir)
	if err != nil {
		return err
	}
	creds[server] = c
	return saveAll(dataDir, creds)
}

// DeleteCredential removes one server's credential so the next run re-enrolls
// with it. Used when that server revokes the agent (WS close 4004): the bearer
// token is dead, and keeping it would loop a redial into the same rejection.
// Every other server's credential — and the ed25519 key (agent.key) — is
// intentionally kept: revocation by one server says nothing about the others,
// and a reinstall token minted against this agent (AGENT-006) makes the next
// enrollment rejoin under the same agent_id with its history intact. A server
// that has no credential is not an error.
func DeleteCredential(dataDir, server string) error {
	credMu.Lock()
	defer credMu.Unlock()

	creds, err := loadLocked(dataDir)
	if err != nil {
		return err
	}
	if _, ok := creds[server]; !ok {
		return nil
	}
	delete(creds, server)
	return saveAll(dataDir, creds)
}

// PruneCredentials deletes the credentials of every server not named in keep,
// and reports how many it removed.
//
// It is the credential half of what wal.Open already does with its cursors: a
// server that is no longer configured stops being remembered. Without it, a host
// that removes a server and later adds one back under the same name silently
// resumes the OLD identity — the fresh enrollment token is never spent, the
// remote server sees the agent record the user thought they had detached, and
// nothing on either side reports the mismatch.
//
// Only a caller whose configuration is the complete and authoritative list may
// use it. That is true of the desktop, which owns its list outright; it is NOT
// true of a standalone agent started with a hand-edited subset, where deleting
// the omitted servers' credentials would cost an operator-issued token to undo.
func PruneCredentials(dataDir string, keep []string) (int, error) {
	credMu.Lock()
	defer credMu.Unlock()

	creds, err := loadLocked(dataDir)
	if err != nil {
		return 0, err
	}
	wanted := make(map[string]struct{}, len(keep))
	for _, name := range keep {
		wanted[name] = struct{}{}
	}
	removed := 0
	for name := range creds {
		if _, ok := wanted[name]; !ok {
			delete(creds, name)
			removed++
		}
	}
	if removed == 0 {
		return 0, nil
	}
	return removed, saveAll(dataDir, creds)
}

// saveAll publishes agent.json via a temp file in the same directory, so the
// rename is within one filesystem and therefore atomic. Caller holds credMu.
func saveAll(dataDir string, creds map[string]Credential) error {
	b, err := json.MarshalIndent(credentialsFile{V: credentialFormat, Servers: creds}, "", "  ")
	if err != nil {
		return err
	}
	path := filepath.Join(dataDir, credentialFile)
	f, err := os.CreateTemp(dataDir, "agent-*.json.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() {
		if tmp != "" {
			f.Close()
			os.Remove(tmp)
		}
	}()

	if err := f.Chmod(0o600); err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("identity: publish %s: %w", credentialFile, err)
	}
	tmp = "" // published; the deferred cleanup must not delete it
	return os.Chmod(path, 0o600)
}
