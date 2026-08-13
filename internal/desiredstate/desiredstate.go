// Package desiredstate persists the probe half of the last DesiredState each
// server applied, so an agent that restarts while that server is unreachable
// keeps monitoring instead of going silent until it reconnects.
//
// # Why this exists
//
// The collectors, the scheduler and the WAL all run independently of any
// session: samples are produced on a timer and queued for upload whether or not
// a server is reachable. The one thing that does NOT survive a restart is the
// target list, because it only ever arrives over a live session. So a router
// that loses its uplink and is then power-cycled by its owner — the single most
// likely sequence after an outage starts — comes back up and probes nothing at
// all until the server it cannot reach tells it what to probe. The outage's
// second half leaves no evidence anywhere, and the server's incident says only
// "the agent went quiet".
//
// Persisting the applied configuration closes that hole: the agent restores what
// it was last told to do and keeps producing evidence into the WAL, which the
// existing replay machinery uploads once the link returns.
//
// # Why the cache is bound to a credential, not to a server name
//
// A server name is a local label and a URL can be re-pointed; either can be
// reused for a genuinely different server. A cache keyed on the name alone would
// let configuration from the old server be restored against the new one — and
// because the session's staleness guard only ignores versions strictly LOWER
// than the applied one, a restored v50 would make the new server's v1 push
// permanently ignored. The agent would then probe the old server's targets
// forever while reporting itself configured.
//
// Every snapshot therefore records the SHA-256 of the bearer token that was in
// force when it was written, plus the agent and site ids that token belongs to.
// A snapshot whose binding does not match the credential in hand is discarded
// rather than restored: losing one outage's offline coverage is a bounded cost,
// and running someone else's monitors is not.
//
// # What is deliberately not persisted
//
// Proxies. DesiredState.Proxies carries egress credentials — passwords and
// WireGuard private keys — that travel inside the already-authenticated session
// and are documented as never being written to agent disk. Keeping that promise
// costs nothing in coverage: a target pinned to a proxy the agent has not been
// handed evaluates as proxy-missing and un-runnable (monitoreval fails closed;
// there is no direct-dial fallback by design), so restoring such a target would
// not have probed anything anyway. The moment a session comes up, the server's
// unconditional on-connect push re-supplies the proxies — the guard lets an
// equal version through precisely so that re-push installs — and the pinned
// targets start on the next cycle.
//
// The game and diagnostic blocks ARE persisted. Neither carries a secret, and
// both change behaviour while offline in ways the operator configured
// deliberately: a nil DiagPolicy re-enables the agent's built-in traceroute
// defaults, which is the opposite of what an install that turned diagnostics
// down asked for, and a game played during an outage is still a game that was
// played.
//
// # Format
//
// One JSON file for every server, versioned and published by rename, following
// the same conventions as the credential file next to it (see identity): an
// unreadable, malformed or wrong-version file means "nothing to restore" rather
// than an error, because starting with no targets is exactly the behaviour that
// preceded this package and re-learning them costs one session.
package desiredstate

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	pcfg "github.com/nettact/protocol/config"
)

const (
	stateFile = "desired.json"
	// stateFormat is stamped into desired.json and checked exactly. There is no
	// migration path by design: the file is a cache of something the server
	// re-sends on every connect, so discarding it costs one session's worth of
	// offline coverage and never any durable data.
	stateFormat = 1
)

// Config is the restorable part of one server's applied DesiredState.
//
// It mirrors the fields of pcfg.DesiredState explicitly instead of embedding it
// with Proxies blanked. The explicit copy is the point: a field added to
// DesiredState later must not start being written to disk merely because it was
// added, since the next such field could be another credential. Adding it here
// is a deliberate act with this file's rationale in view.
//
// Game and Diag carry their own serials inside themselves (GameConfig.Version,
// DiagPolicy.Serial), so restoring them restores the applied generation of each
// independent axis without separate bookkeeping.
type Config struct {
	ConfigVersion int                `json:"config_version"`
	ProbeTargets  []pcfg.ProbeTarget `json:"probe_targets"`
	Intervals     pcfg.Intervals     `json:"intervals"`
	Game          *pcfg.GameConfig   `json:"game,omitempty"`
	Diag          *pcfg.DiagPolicy   `json:"diag,omitempty"`
}

// snapshot is the on-disk entry: a Config plus the credential binding that says
// whose configuration it is.
type snapshot struct {
	// CredFingerprint is the SHA-256 of the bearer token in force when this was
	// written. It — not the map key — is what authorizes a restore.
	CredFingerprint string `json:"cred_fingerprint"`
	AgentID         string `json:"agent_id"`
	SiteID          string `json:"site_id"`
	Config          Config `json:"config"`
}

// stateDoc is the on-disk shape of desired.json.
type stateDoc struct {
	V       int                 `json:"v"`
	Servers map[string]snapshot `json:"servers"`
}

// mu serializes the whole load-modify-write of desired.json, for the same
// reason identity.credMu does: the atomic rename makes one publish
// all-or-nothing for a reader, which does not stop two servers' runners from
// each reading the same map, adding only their own entry, and having the second
// publish erase the first.
var mu sync.Mutex

// Fingerprint is the binding hash of a bearer token. Exported so callers can
// compare a restored snapshot's origin without holding the token's plaintext
// next to it.
func Fingerprint(token string) string {
	if token == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// Binding is one server's handle on the store, tied to the credential that
// server currently holds. Every method is safe for concurrent use.
type Binding struct {
	dir         string
	server      string
	fingerprint string
	// prev is the fingerprint of the credential that was in force immediately
	// before this one (set by Rebind during a rotation, or restored from the
	// credential's PrevTokenFingerprint after a restart). A snapshot written
	// under prev is still this agent's own configuration — the rotation kept
	// the same agent and the same targets — so Load accepts it and the next
	// Save re-keys it under the current token.
	prev    string
	agentID string
	siteID  string
}

// Bind returns the store handle for one server. A caller with no token yet (a
// runner that has not enrolled) gets a binding whose Load always misses and
// whose Save is a no-op, so callers need no nil checks around enrollment order.
func Bind(dataDir, server, agentToken, agentID, siteID string) *Binding {
	return &Binding{
		dir:         dataDir,
		server:      server,
		fingerprint: Fingerprint(agentToken),
		agentID:     agentID,
		siteID:      siteID,
	}
}

// Rebind moves the binding to a new credential (a controlled rotation) and
// re-keys the on-disk cache to match, eagerly: the snapshot is rewritten under
// the new token whenever it still carries the binding's previous fingerprint,
// so consecutive rotations never let the cache drift more than one token
// behind (a digest-gated Save would otherwise leave it on an arbitrarily old
// bearer). The re-key is GUARDED — it runs only when the snapshot matches the
// previous fingerprint AND this binding's agent/site ids, so a foreign or
// missing snapshot is never authorized; it stays discarded and the on-connect
// push re-establishes it. The previous fingerprint is remembered so Load keeps
// accepting the old-keyed cache across a crash that lands between the
// credential write and this re-key. Returns the save error so the caller's
// persistence retry can re-attempt; a later call is idempotent.
func (b *Binding) Rebind(newToken string) error {
	if b == nil {
		return nil
	}
	next := Fingerprint(newToken)
	if next != b.fingerprint {
		b.prev = b.fingerprint
		b.fingerprint = next
	}
	return b.rekeyDisk(b.prev)
}

// rekeyDisk rewrites this server's snapshot from `from` to the binding's
// current fingerprint, only when it actually matches `from` and the binding's
// ids. A snapshot already at the current fingerprint (a retry after a
// successful re-key) or one at neither (foreign/missing) is a no-op.
func (b *Binding) rekeyDisk(from string) error {
	mu.Lock()
	defer mu.Unlock()

	doc, err := loadLocked(b.dir)
	if err != nil {
		return err
	}
	s, ok := doc[b.server]
	if !ok || s.CredFingerprint != from || s.AgentID != b.agentID || s.SiteID != b.siteID {
		return nil
	}
	s.CredFingerprint = b.fingerprint
	doc[b.server] = s
	return saveAll(b.dir, doc)
}

// SetPrev restores the previous credential's fingerprint, re-arming the
// old-token acceptance after a restart that landed between a rotation's
// credential write and its cache re-key.
func (b *Binding) SetPrev(prevFingerprint string) {
	if b == nil {
		return
	}
	b.prev = prevFingerprint
}

// Load returns the persisted configuration for this server, or ok=false when
// there is none, it cannot be read, or it belongs to a different credential.
func (b *Binding) Load() (Config, bool) {
	if b == nil || b.fingerprint == "" {
		return Config{}, false
	}
	mu.Lock()
	defer mu.Unlock()

	doc, err := loadLocked(b.dir)
	if err != nil {
		return Config{}, false
	}
	s, ok := doc[b.server]
	if !ok {
		return Config{}, false
	}
	// All three must match. The fingerprint alone would already stop a foreign
	// server's configuration from being restored; the ids are checked too because
	// a token that authenticates to the same server under a different agent record
	// (a re-enrollment that minted a new agent_id) is just as wrong a target list
	// to run, and the mismatch is otherwise invisible.
	fpOK := s.CredFingerprint == b.fingerprint || (b.prev != "" && s.CredFingerprint == b.prev)
	if !fpOK || s.AgentID != b.agentID || s.SiteID != b.siteID {
		return Config{}, false
	}
	return s.Config, true
}

// Save persists this server's configuration, leaving every other server's entry
// untouched.
func (b *Binding) Save(c Config) error {
	if b == nil || b.fingerprint == "" {
		return nil
	}
	if b.server == "" {
		return errors.New("desiredstate: save needs a server name")
	}
	mu.Lock()
	defer mu.Unlock()

	doc, err := loadLocked(b.dir)
	if err != nil {
		return err
	}
	doc[b.server] = snapshot{
		CredFingerprint: b.fingerprint,
		AgentID:         b.agentID,
		SiteID:          b.siteID,
		Config:          c,
	}
	return saveAll(b.dir, doc)
}

// Forget drops this server's entry. Called when the server revokes the agent or
// refuses its credential: the configuration was issued to an identity that no
// longer exists there, and restoring it on the next boot would put the agent
// back to probing targets nobody is asking for.
func (b *Binding) Forget() error {
	if b == nil {
		return nil
	}
	return Delete(b.dir, b.server)
}

// Delete removes one server's entry. A server with no entry is not an error.
func Delete(dataDir, server string) error {
	mu.Lock()
	defer mu.Unlock()

	doc, err := loadLocked(dataDir)
	if err != nil {
		return err
	}
	if _, ok := doc[server]; !ok {
		return nil
	}
	delete(doc, server)
	return saveAll(dataDir, doc)
}

// Prune drops the entries of every server not named in keep, and reports how
// many it removed. Same contract as identity.PruneCredentials: only a caller
// whose configuration is the complete and authoritative server list may use it.
func Prune(dataDir string, keep []string) (int, error) {
	mu.Lock()
	defer mu.Unlock()

	doc, err := loadLocked(dataDir)
	if err != nil {
		return 0, err
	}
	wanted := make(map[string]struct{}, len(keep))
	for _, name := range keep {
		wanted[name] = struct{}{}
	}
	removed := 0
	for name := range doc {
		if _, ok := wanted[name]; !ok {
			delete(doc, name)
			removed++
		}
	}
	if removed == 0 {
		return 0, nil
	}
	return removed, saveAll(dataDir, doc)
}

// loadLocked reads desired.json. A missing, malformed or wrong-version file
// yields an empty map and no error — see the package comment. Caller holds mu.
func loadLocked(dataDir string) (map[string]snapshot, error) {
	b, err := os.ReadFile(filepath.Join(dataDir, stateFile))
	if errors.Is(err, os.ErrNotExist) {
		return map[string]snapshot{}, nil
	}
	if err != nil {
		return nil, err
	}
	var doc stateDoc
	if err := json.Unmarshal(b, &doc); err != nil || doc.V != stateFormat {
		return map[string]snapshot{}, nil
	}
	out := make(map[string]snapshot, len(doc.Servers))
	for name, s := range doc.Servers {
		if s.CredFingerprint == "" {
			continue // half-written or hand-edited; unbindable, so unusable
		}
		out[name] = s
	}
	return out, nil
}

// saveAll publishes desired.json via a temp file in the same directory, so the
// rename is within one filesystem and therefore atomic. Caller holds mu.
func saveAll(dataDir string, doc map[string]snapshot) error {
	b, err := json.Marshal(stateDoc{V: stateFormat, Servers: doc})
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return err
	}
	path := filepath.Join(dataDir, stateFile)
	f, err := os.CreateTemp(dataDir, "desired-*.json.tmp")
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
		return fmt.Errorf("desiredstate: publish %s: %w", stateFile, err)
	}
	tmp = "" // published; the deferred cleanup must not delete it
	return os.Chmod(path, 0o600)
}

// Digest is the change key for one Config: two Configs with the same digest are
// byte-identical as persisted.
//
// The session persists on a digest change rather than on a version change. A
// version-only test is wrong twice over: the payload a server sends for one
// ConfigVersion is per-agent (permission scope and group membership decide which
// targets an agent is even told about), so two pushes can share a version and
// differ in content; and a save that failed once would never be retried, leaving
// the agent to restore stale targets after a restart while believing itself
// current.
func Digest(c Config) string {
	b, err := json.Marshal(c)
	if err != nil {
		// Unmarshalable config cannot be persisted either, so returning a value
		// that never matches simply keeps the caller retrying, which is the same
		// behaviour a failing write gets.
		return ""
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
