package agentrt

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/nettact/agent/internal/identity"
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

func TestRevokedCredentialOutcomeDependsOnDeletion(t *testing.T) {
	for _, tc := range []struct {
		name          string
		blockDeletion bool
		wantRevoked   bool
	}{
		{name: "deleted", wantRevoked: true},
		{name: "delete-fails", blockDeletion: true, wantRevoked: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dataDir := t.TempDir()
			if err := identity.SaveCredential(dataDir, identity.Credential{
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
				readCtx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
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

			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			err := Run(ctx, Config{
				ServerURL: srv.URL, DataDir: dataDir, WireFormat: "json", UploadInterval: time.Hour,
			})
			select {
			case <-mutated:
			default:
				t.Fatal("server did not reach the revocation step")
			}
			if got := errors.Is(err, ErrRevoked); got != tc.wantRevoked {
				t.Fatalf("errors.Is(%v, ErrRevoked) = %v; want %v", err, got, tc.wantRevoked)
			}
			if tc.wantRevoked {
				if _, statErr := os.Stat(filepath.Join(dataDir, "agent.json")); !errors.Is(statErr, os.ErrNotExist) {
					t.Fatalf("credential still exists after revocation: %v", statErr)
				}
			} else if err == nil {
				t.Fatal("deletion failure returned nil")
			}
		})
	}
}
