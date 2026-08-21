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
	"time"
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

	// EnrollmentEpoch is the server-generated credential generation (schema 8):
	// the counter the server bumps every time it rotates this agent's credential
	// and sequence space. It rides the Hello on every connect, gates the WAL's
	// sequence-floor barrier, and is re-persisted (with the new bearer token)
	// when a rotation completes.
	//
	// It is additive to the v2 format for the same reason and with the same
	// downgrade shape as ConsumedTokenHash: a credential written before schema 8
	// reads as zero, which the wire protocol defines as "unknown epoch" — a
	// schema-8 server then skips the floor barrier for that agent until its next
	// enrollment or rotation, and nothing breaks.
	EnrollmentEpoch uint64 `json:"enrollment_epoch,omitempty"`

	// PrevTokenFingerprint is the SHA-256 of the bearer token this credential
	// replaced (set when a controlled rotation retires the old token). It lets
	// the desired-state cache accept a snapshot written under the old bearer
	// after a crash interrupted the rotation between the credential write and
	// the cache re-key. Additive to the v2 format, like the two above.
	PrevTokenFingerprint string `json:"prev_token_fingerprint,omitempty"`
}

// Negotiated records what wire schema one server was last observed to speak,
// so a restart does not have to rediscover it by being refused again.
//
// It is a top-level map in agent.json, beside the credentials rather than
// inside them, because it describes the SERVER's capability and not this
// credential's properties. The difference is load-bearing exactly once, and it
// is the moment that matters most: when a server revokes the agent, the
// credential is deleted and the very next act is a fresh enrollment — which
// needs this record to decide what schema to declare. Kept inside the
// credential it would be gone precisely when it is needed.
//
// It is additive to the existing file format and the format number must NOT be
// bumped for it: an unknown format number makes the whole file read as "not
// enrolled anywhere", so a bump would silently discard every credential on a
// downgrade. As an added key it is invisible to an older binary in both
// directions — that binary ignores it on read and drops it on write, which
// merely costs the next run one refused handshake to rediscover.
type Negotiated struct {
	// Schema is the wire schema last established with this server. Zero (or a
	// missing entry) means nothing has been learned yet and the agent should
	// prefer its native schema.
	Schema int `json:"schema,omitempty"`

	// AgentVersion is the agent build that reached that conclusion. A different
	// build is reason enough to re-try the native schema: what this agent can
	// speak, and what the server accepted from it, are both properties of a
	// binary that has just been replaced.
	AgentVersion string `json:"agent_version,omitempty"`

	// DecidedAt is when the conclusion was reached, and LastProbe when the
	// native schema was last attempted against this server. LastProbe is what
	// bounds how long a downgraded agent can stay downgraded after the server
	// has been upgraded: the retry cadence is measured from it, and it is
	// therefore also written when a probe FAILS and the agent falls back.
	DecidedAt time.Time `json:"decided_at"`
	LastProbe time.Time `json:"last_probe"`
}

// credentialsFile is the on-disk shape of agent.json.
type credentialsFile struct {
	V       int                   `json:"v"`
	Servers map[string]Credential `json:"servers"`
	// Negotiated is keyed by the same configured server name as Servers. It is
	// carried through every read-modify-write of this file so a credential save
	// never drops it (and vice versa); see Negotiated for why the format number
	// stays at 2.
	Negotiated map[string]Negotiated `json:"negotiated,omitempty"`
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
	f, err := loadLocked(dataDir)
	if err != nil {
		return nil, err
	}
	return f.Servers, nil
}

// LoadNegotiated returns every server's remembered wire-schema decision, keyed
// by server name. An unreadable, malformed or wrong-format file yields an empty
// map and no error, exactly as for the credentials it lives beside: a missing
// record means "nothing learned", which is the same starting point a first run
// has and costs at most one refused handshake to re-learn.
func LoadNegotiated(dataDir string) (map[string]Negotiated, error) {
	credMu.Lock()
	defer credMu.Unlock()
	f, err := loadLocked(dataDir)
	if err != nil {
		return nil, err
	}
	return f.Negotiated, nil
}

// SaveNegotiated persists one server's wire-schema decision, leaving the other
// servers' records — and every credential in the file — alone. Same
// read-modify-write under credMu, published by the same atomic rename, for the
// same reason: several runners write this file concurrently.
func SaveNegotiated(dataDir, server string, rec Negotiated) error {
	if server == "" {
		return errors.New("identity: negotiation record needs a server name")
	}
	credMu.Lock()
	defer credMu.Unlock()

	f, err := loadLocked(dataDir)
	if err != nil {
		return err
	}
	if f.Negotiated == nil {
		f.Negotiated = map[string]Negotiated{}
	}
	f.Negotiated[server] = rec
	return saveAll(dataDir, f)
}

// loadLocked reads agent.json whole. Caller holds credMu.
//
// It returns the entire file rather than just the credentials so that every
// mutation can write back the parts it does not care about: the credentials and
// the negotiation records share one document, and a save that reconstructed the
// document from only its own half would erase the other.
func loadLocked(dataDir string) (credentialsFile, error) {
	empty := credentialsFile{V: credentialFormat, Servers: map[string]Credential{}, Negotiated: map[string]Negotiated{}}
	b, err := os.ReadFile(filepath.Join(dataDir, credentialFile))
	if errors.Is(err, os.ErrNotExist) {
		return empty, nil
	}
	if err != nil {
		return credentialsFile{}, err
	}
	var f credentialsFile
	if err := json.Unmarshal(b, &f); err != nil || f.V != credentialFormat {
		return empty, nil
	}
	out := make(map[string]Credential, len(f.Servers))
	for name, c := range f.Servers {
		if c.AgentToken == "" {
			continue // half-written or hand-edited; treat as not enrolled
		}
		out[name] = c
	}
	f.Servers = out
	if f.Negotiated == nil {
		f.Negotiated = map[string]Negotiated{}
	}
	return f, nil
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

	f, err := loadLocked(dataDir)
	if err != nil {
		return err
	}
	f.Servers[server] = c
	return saveAll(dataDir, f)
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

	f, err := loadLocked(dataDir)
	if err != nil {
		return err
	}
	if _, ok := f.Servers[server]; !ok {
		return nil
	}
	delete(f.Servers, server)
	// The negotiation record deliberately stays: it describes what the server
	// speaks, which a revocation says nothing about, and the re-enrollment that
	// follows a deleted credential is the single place it is most needed.
	return saveAll(dataDir, f)
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

	f, err := loadLocked(dataDir)
	if err != nil {
		return 0, err
	}
	wanted := make(map[string]struct{}, len(keep))
	for _, name := range keep {
		wanted[name] = struct{}{}
	}
	removed := 0
	for name := range f.Servers {
		if _, ok := wanted[name]; !ok {
			delete(f.Servers, name)
			removed++
		}
	}
	// A server that is no longer configured takes its negotiation record with
	// it: unlike a revocation, this says the entry itself is gone, and leaving
	// the record would apply a stale conclusion to whatever is later configured
	// under the same name. Counted separately from removed, which reports
	// credentials — the caller logs it as "identities forgotten".
	prunedRecords := false
	for name := range f.Negotiated {
		if _, ok := wanted[name]; !ok {
			delete(f.Negotiated, name)
			prunedRecords = true
		}
	}
	if removed == 0 && !prunedRecords {
		return 0, nil
	}
	return removed, saveAll(dataDir, f)
}

// saveAll publishes agent.json via a temp file in the same directory, so the
// rename is within one filesystem and therefore atomic. Caller holds credMu.
func saveAll(dataDir string, doc credentialsFile) error {
	doc.V = credentialFormat
	if len(doc.Negotiated) == 0 {
		// Keep a file that has learned nothing byte-identical to what earlier
		// builds wrote, so an install that never downgrades never grows the key.
		doc.Negotiated = nil
	}
	b, err := json.MarshalIndent(doc, "", "  ")
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
