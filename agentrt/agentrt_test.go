package agentrt

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/nettact/agent/internal/identity"
	protoenroll "github.com/nettact/protocol/enroll"
	"github.com/nettact/protocol/permission"
	"github.com/nettact/protocol/wire"
)

func TestSubprotocolFor(t *testing.T) {
	for _, tc := range []struct {
		in, want string
	}{
		{"", wire.SubprotocolProtobuf},
		{"protobuf", wire.SubprotocolProtobuf},
		{"json", wire.SubprotocolJSON},
	} {
		got, err := subprotocolFor(tc.in)
		if err != nil || got != tc.want {
			t.Fatalf("subprotocolFor(%q) = %q, %v; want %q", tc.in, got, err, tc.want)
		}
	}
	if _, err := subprotocolFor("xml"); err == nil {
		t.Fatal("subprotocolFor(xml) succeeded")
	}
}

// TestConfigNormalizeServerRules pins what a server list has to satisfy before
// any of it is acted on. Each rule guards something that would otherwise fail
// far from its cause: an unnamed entry has nowhere to keep its credential, two
// entries under one name share a credential and a WAL cursor while running two
// sessions (the superseded-kick loop written as a configuration), and an entry
// with neither a URL nor an injected transport has nothing to dial.
func TestConfigNormalizeServerRules(t *testing.T) {
	policy := permission.Policy{Granted: permission.DefaultStandalone(), Source: permission.SourceDefault}
	dialer := wire.Dialer(func(context.Context, string) (wire.Conn, error) { return nil, errors.New("unused") })
	enroller := func(context.Context, protoenroll.EnrollRequest) (protoenroll.EnrollResponse, error) {
		return protoenroll.EnrollResponse{}, errors.New("unused")
	}

	for _, tc := range []struct {
		name    string
		servers []ServerConfig
		want    string // "" means the configuration must be accepted
	}{{
		name: "no servers",
		want: "must name at least one server",
	}, {
		name:    "nameless entry",
		servers: []ServerConfig{{URL: "https://home.example"}},
		want:    "Servers[0] has no name",
	}, {
		name: "duplicate names",
		servers: []ServerConfig{
			{Name: "home", URL: "https://a.example"},
			{Name: "home", URL: "https://b.example"},
		},
		want: `duplicate server name "home"`,
	}, {
		name:    "no url and no injected transport",
		servers: []ServerConfig{{Name: "home"}},
		want:    "needs a URL unless both Dialer and Enroller are set",
	}, {
		// Half of the injected pair is not enough: the default HTTP enroller still
		// needs a URL to POST to.
		name:    "url-less with only a dialer",
		servers: []ServerConfig{{Name: "home", Dialer: dialer}},
		want:    "needs a URL unless both Dialer and Enroller are set",
	}, {
		name:    "url-less with only an enroller",
		servers: []ServerConfig{{Name: "home", Enroller: enroller}},
		want:    "needs a URL unless both Dialer and Enroller are set",
	}, {
		// The desktop's own server: nothing addresses it by URL, and both halves of
		// the exchange are injected.
		name:    "url-less with both injected",
		servers: []ServerConfig{{Name: "local", Dialer: dialer, Enroller: enroller}},
	}, {
		name:    "ordinary single server",
		servers: []ServerConfig{{Name: "default", URL: "https://home.example"}},
	}} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Config{Servers: tc.servers, Policy: policy}
			err := cfg.normalize()
			if tc.want == "" {
				if err != nil {
					t.Fatalf("normalize() = %v, want the configuration accepted", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("normalize() = %v, want substring %q", err, tc.want)
			}
		})
	}
}

// agentDataDir returns a DataDir for a Run, removed at test end with a retry.
//
// Deliberately not t.TempDir(): Run's WAL writes and renames segment files right
// up to the moment it closes, and Windows can keep a just-closed file in the
// directory listing a fraction longer than Close suggests — long enough for
// t.TempDir's single RemoveAll to fail with "The directory is not empty" and
// fail an otherwise passing test. Same workaround, for the same reason, as the
// conn package's WAL tests.
func agentDataDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "nettact-agentrt-test-")
	if err != nil {
		t.Fatalf("make temp dir: %v", err)
	}
	t.Cleanup(func() {
		deadline := time.Now().Add(2 * time.Second)
		for {
			err := os.RemoveAll(dir)
			if err == nil {
				if _, statErr := os.Stat(dir); os.IsNotExist(statErr) {
					return
				}
			}
			if time.Now().After(deadline) {
				t.Errorf("remove temp dir %s: %v", dir, err)
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	})
	return dir
}

// TestRevokedCredentialOutcomeDependsOnDeletion pins what a 4004 does to the
// runner, which turns entirely on whether the dead credential could be removed.
//
// Revocation is no longer terminal: the runner deletes that server's credential
// and re-enrolls in place, so one server being deleted cannot stop the others.
// This Config carries no TokenSource, so the re-enrollment has nothing to enroll
// with and the runner stops with ErrEnroll — proof it got as far as trying. When
// the deletion fails instead, the stale credential is still on disk and looping
// would only be revoked again, so the runner stops on that failure and never
// reaches enrollment.
func TestRevokedCredentialOutcomeDependsOnDeletion(t *testing.T) {
	for _, tc := range []struct {
		name          string
		blockDeletion bool
	}{
		{name: "deleted"},
		{name: "delete-fails", blockDeletion: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dataDir := agentDataDir(t)
			if err := identity.SaveCredential(dataDir, "default", identity.Credential{
				AgentID: "agent-test", SiteID: "site-test", AgentToken: "test-token",
			}); err != nil {
				t.Fatalf("save credential: %v", err)
			}

			mutated := make(chan struct{})
			var mutateOnce sync.Once
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				c, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{wire.SubprotocolJSON}})
				if err != nil {
					t.Errorf("accept: %v", err)
					return
				}
				defer c.CloseNow() //nolint:errcheck
				// Generous on purpose. This bounds how long the test waits for two
				// frames the agent sends immediately; it is not a latency the agent
				// promises, so the only thing a tight value buys is a failure
				// whenever the machine is busy — which `go test ./...` makes it,
				// by running other packages alongside this one.
				readCtx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
				defer cancel()
				if _, _, err := c.Read(readCtx); err != nil {
					t.Errorf("read hello: %v", err)
					return
				}
				// The runtime emits an immediate heartbeat packet. Read it before the
				// application close so the client observes close code 4004 while awaiting
				// its Ack, rather than racing a normal write error and reconnecting.
				if _, _, err := c.Read(readCtx); err != nil {
					t.Errorf("read first packet: %v", err)
					return
				}
				mutateOnce.Do(func() {
					if tc.blockDeletion {
						path := filepath.Join(dataDir, "agent.json")
						if err := os.Remove(path); err != nil {
							t.Errorf("remove credential fixture: %v", err)
							return
						}
						if err := os.Mkdir(path, 0o755); err != nil {
							t.Errorf("make blocking directory: %v", err)
							return
						}
						if err := os.WriteFile(filepath.Join(path, "keep"), []byte("x"), 0o600); err != nil {
							t.Errorf("make directory non-empty: %v", err)
							return
						}
					}
					close(mutated)
				})
				_ = c.Close(websocket.StatusCode(4004), "revoked")
			}))
			defer srv.Close()

			// An upper bound, not a schedule: the run ends when the server closes
			// with 4004, which normally takes well under a second. Sizing it to
			// how long that usually takes only produces a graceful shutdown
			// mid-handshake — and a failure about the revocation step never being
			// reached — whenever the machine is under load.
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			err := Run(ctx, Config{
				Servers: []ServerConfig{{Name: "default", URL: srv.URL}},
				DataDir: dataDir, WireFormat: "json",
				// Short, not long. The session drains once on connect and then on
				// this interval; an hour-long one means that if the first drain
				// happens to run before the heartbeat has written anything, the
				// packet this handler waits for does not exist for an hour. That
				// ordering is a race the machine's load decides, which is why it
				// showed up as an occasional failure rather than a constant one.
				UploadInterval: 200 * time.Millisecond,
				Policy:         permission.Policy{Granted: permission.DefaultStandalone(), Source: permission.SourceDefault},
			})
			select {
			case <-mutated:
			default:
				t.Fatal("server did not reach the revocation step")
			}
			if err == nil {
				t.Fatal("revoked session returned nil; want a terminal outcome")
			}
			if tc.blockDeletion {
				// The failure the runner stopped on is the deletion, not an
				// enrollment it must never have attempted with a live credential
				// still on disk.
				if !strings.Contains(err.Error(), "delete revoked credential") {
					t.Fatalf("blocked-deletion outcome = %v, want the deletion failure named", err)
				}
				if errors.Is(err, ErrEnroll) {
					t.Fatalf("blocked-deletion outcome = %v, want no re-enrollment attempt", err)
				}
				return
			}
			// The deletion succeeded, so the runner re-enrolled — and with no
			// TokenSource that is where it stopped.
			if !errors.Is(err, ErrEnroll) {
				t.Fatalf("post-deletion outcome = %v, want ErrEnroll from the re-enrollment", err)
			}
			creds, loadErr := identity.LoadCredentials(dataDir)
			if loadErr != nil {
				t.Fatalf("load credentials: %v", loadErr)
			}
			if _, ok := creds["default"]; ok {
				t.Fatalf("revoked credential still on disk: %+v", creds)
			}
		})
	}
}

// TestAuthRejectedReenrollsWithADifferentToken pins the 401 self-heal: a refused
// credential is dead, and when the configured INLINE token differs from the one
// that enrolled this credential (or the credential predates the field, so the
// match is unknowable) the runner deletes the credential and re-enrolls with it.
// The same token, or no inline token, must NOT escalate — the runner keeps
// retrying the credential exactly as before.
func TestAuthRejectedReenrollsWithADifferentToken(t *testing.T) {
	hashOf := func(s string) string {
		sum := sha256.Sum256([]byte(s))
		return hex.EncodeToString(sum[:])
	}
	// inlineHash mirrors envcfg: no inline token → "", else the sha256. (hashOf
	// of "" is a real hash, and a "no token" config must not look configured.)
	inlineHash := func(s string) string {
		if s == "" {
			return ""
		}
		return hashOf(s)
	}

	for _, tc := range []struct {
		name            string
		consumedHash    string
		configuredToken string
		wantReenroll    bool
	}{
		{name: "different-token", consumedHash: hashOf("old"), configuredToken: "new", wantReenroll: true},
		{name: "legacy-credential", consumedHash: "", configuredToken: "fresh", wantReenroll: true},
		{name: "same-token", consumedHash: hashOf("t"), configuredToken: "t"},
		{name: "no-inline-token"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dataDir := agentDataDir(t)
			if err := identity.SaveCredential(dataDir, "default", identity.Credential{
				AgentID: "agent-old", SiteID: "site-old", AgentToken: "old-token",
				ConsumedTokenHash: tc.consumedHash,
			}); err != nil {
				t.Fatalf("save credential: %v", err)
			}

			// Every upgrade is refused, so no session can ever open; whether the
			// agent escalates is decided purely by the hook.
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				http.Error(w, "no", http.StatusUnauthorized)
			}))
			t.Cleanup(srv.Close)

			var enrolls atomic.Int32
			enroller := func(_ context.Context, req protoenroll.EnrollRequest) (protoenroll.EnrollResponse, error) {
				enrolls.Add(1)
				return protoenroll.EnrollResponse{AgentID: "agent-new", SiteID: "site-new", AgentToken: "new-token"}, nil
			}

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			errCh := make(chan error, 1)
			go func() { errCh <- Run(ctx, Config{
				Servers: []ServerConfig{{
					Name:        "default",
					URL:         srv.URL,
					TokenHash:   inlineHash(tc.configuredToken),
					TokenSource: func(context.Context) (string, error) { return tc.configuredToken, nil },
					Enroller:    enroller,
				}},
				DataDir: dataDir, WireFormat: "json",
				Policy: permission.Policy{Granted: permission.DefaultStandalone(), Source: permission.SourceDefault},
			}) }()

			// Run must never return in this scenario: it either keeps retrying the
			// credential or re-enrolls once and then retries the new one. The
			// assertions below watch for the escalation side effects instead.
			defer func() {
				select {
				case err := <-errCh:
					t.Errorf("Run returned %v; want it to keep running", err)
				default:
				}
			}()

			// Wait on the PERSISTED credential, not the enroller's entry: the
			// enroller increments its counter before SaveCredential runs, so a
			// counter poll can race ahead of the write and read a half-updated
			// agent.json.
			waitForPersisted := func() bool {
				deadline := time.Now().Add(10 * time.Second)
				for time.Now().Before(deadline) {
					creds, err := identity.LoadCredentials(dataDir)
					if err == nil {
						if c, ok := creds["default"]; ok && c.AgentID == "agent-new" {
							return true
						}
					}
					time.Sleep(10 * time.Millisecond)
				}
				return false
			}

			if tc.wantReenroll {
				if !waitForPersisted() {
					t.Fatal("re-enrollment never persisted despite a different configured token")
				}
				// The new credential must be on disk, carrying the consumed hash of
				// the token that enrolled it — so a later 401 no longer escalates.
				creds, err := identity.LoadCredentials(dataDir)
				if err != nil {
					t.Fatalf("load credentials: %v", err)
				}
				got := creds["default"]
				if got.AgentID != "agent-new" {
					t.Fatalf("credential after re-enroll = %+v, want agent-new", got)
				}
				if got.ConsumedTokenHash != hashOf(tc.configuredToken) {
					t.Fatalf("consumed_token_hash = %q, want %q", got.ConsumedTokenHash, hashOf(tc.configuredToken))
				}
			} else {
				// A grace period long enough for a re-enrollment to have happened
				// if it were going to; the credential must be untouched.
				time.Sleep(300 * time.Millisecond)
				if enrolls.Load() != 0 {
					t.Fatalf("enrolled %d time(s) with the same/no token; want none", enrolls.Load())
				}
				creds, err := identity.LoadCredentials(dataDir)
				if err != nil {
					t.Fatalf("load credentials: %v", err)
				}
				if got := creds["default"]; got.AgentID != "agent-old" {
					t.Fatalf("credential changed to %+v; want the original kept", got)
				}
			}
		})
	}
}

// TestEnrollServerConsumesTheToken runs the enrollment path directly and asserts
// the two side effects that make self-heal coherent: the saved credential
// records the consumed token's hash, and TokenConsumed is called after the
// exchange succeeds (so the OpenWrt package can clear the UCI enroll_token).
func TestEnrollServerConsumesTheToken(t *testing.T) {
	dataDir := agentDataDir(t)
	key, err := identity.LoadOrCreateKey(dataDir)
	if err != nil {
		t.Fatalf("load key: %v", err)
	}
	var consumedCalled atomic.Int32
	rt := &serverRuntime{cfg: ServerConfig{
		Name: "default",
		TokenSource: func(context.Context) (string, error) {
			return "the-one-time-token", nil
		},
		TokenConsumed: func() error {
			consumedCalled.Add(1)
			return nil
		},
		// The default Enroller would POST to a server; inject one.
		Enroller: func(_ context.Context, req protoenroll.EnrollRequest) (protoenroll.EnrollResponse, error) {
			if req.EnrollmentToken != "the-one-time-token" {
				t.Errorf("enrollment token = %q, want the one from TokenSource", req.EnrollmentToken)
			}
			return protoenroll.EnrollResponse{AgentID: "agent-x", SiteID: "site-x", AgentToken: "tok"}, nil
		},
	}}
	env := runEnv{cfg: Config{DataDir: dataDir}, key: key, hostname: "test", platformID: "test"}

	cred, err := enrollServer(context.Background(), env, rt)
	if err != nil {
		t.Fatalf("enrollServer: %v", err)
	}
	if consumedCalled.Load() != 1 {
		t.Fatalf("TokenConsumed called %d times, want 1", consumedCalled.Load())
	}
	sum := sha256.Sum256([]byte("the-one-time-token"))
	if cred.ConsumedTokenHash != hex.EncodeToString(sum[:]) {
		t.Fatalf("ConsumedTokenHash = %q, want the hash of the used token", cred.ConsumedTokenHash)
	}
	saved, err := identity.LoadCredentials(dataDir)
	if err != nil {
		t.Fatalf("load credentials: %v", err)
	}
	if saved["default"].ConsumedTokenHash != cred.ConsumedTokenHash {
		t.Fatalf("saved credential lost the consumed hash: %+v", saved["default"])
	}
}
