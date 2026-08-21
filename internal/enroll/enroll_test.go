package enroll

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/nettact/protocol"
	protoenroll "github.com/nettact/protocol/enroll"
	"github.com/nettact/protocol/permission"
)

// The wire schema an enrollment declares is checked before anything else the
// request carries, and a server that does not know it answers with an HTTP 500
// whose body names the mismatch. That shape — 500, plus the phrase — is what
// the downgrade retry keys on, and these tests pin both halves of the
// discrimination: it must fire for that answer, and it must not fire for any
// other 500, because an unavailable server is a thing to wait out and not a
// reason to change what the agent speaks.

func testKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return priv
}

// startEnrollServer answers POST /api/v1/enroll with whatever answer returns
// for the declared schema, recording every request it saw.
func startEnrollServer(t *testing.T, answer func(req protoenroll.EnrollRequest, w http.ResponseWriter),
	seen *[]protoenroll.EnrollRequest, mu *sync.Mutex) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/enroll" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		var req protoenroll.EnrollRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decode enrollment request: %v", err)
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		mu.Lock()
		*seen = append(*seen, req)
		mu.Unlock()
		answer(req, w)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// legacyRefusal is the answer measured from a server released before the
// current schema boundary: the shared schema check produces the message and the
// HTTP layer, having no dedicated status for it, returns it as an internal
// error.
func legacyRefusal(w http.ResponseWriter, schema, speaks int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusInternalServerError)
	_, _ = w.Write([]byte(`{"error":"unsupported schema_version ` +
		itoa(schema) + ` (this build speaks ` + itoa(speaks) + `; upgrade the other side)"}`))
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

func TestSchemaRefusalIsRecognisedAndNothingElseIs(t *testing.T) {
	for name, tc := range map[string]struct {
		status int
		body   string
		want   bool
	}{
		"the measured refusal": {
			status: http.StatusInternalServerError,
			body:   `{"error":"unsupported schema_version 8 (this build speaks 7; upgrade the other side)"}`,
			want:   true,
		},
		"an unrelated internal error": {
			status: http.StatusInternalServerError,
			body:   `{"error":"database is locked"}`,
			want:   false,
		},
		"a gateway with no server behind it": {
			status: http.StatusBadGateway,
			body:   `<html><body>502 Bad Gateway</body></html>`,
			want:   false,
		},
		"a refused token": {
			status: http.StatusBadRequest,
			body:   `{"error":"token already used"}`,
			want:   false,
		},
		// A 4xx that happens to name a schema is still a 4xx: the class boundary
		// is what makes the terminal "a person must fix this" verdict reliable,
		// and a downgrade must not be able to reach across it.
		"a 4xx naming a schema": {
			status: http.StatusBadRequest,
			body:   `{"error":"unsupported schema_version 8"}`,
			want:   false,
		},
		// The refusal reaches us through whatever sits in front of the server, and
		// a proxy is free to re-badge the origin's 500 as its own 5xx. Pinning the
		// exact code would turn that rewrite into a silent no-downgrade, so the
		// body is what decides and the status only has to stay out of 4xx.
		"a proxy re-badged the refusal as 502": {
			status: http.StatusBadGateway,
			body:   `{"error":"unsupported schema_version 8 (this build speaks 7; upgrade the other side)"}`,
			want:   true,
		},
		"a refusal arriving as 503": {
			status: http.StatusServiceUnavailable,
			body:   `{"error":"unsupported schema_version 8"}`,
			want:   true,
		},
	} {
		t.Run(name, func(t *testing.T) {
			err := &StatusError{
				StatusCode: tc.status,
				Status:     http.StatusText(tc.status),
				Body:       tc.body,
			}
			if got := SchemaRefused(err); got != tc.want {
				t.Errorf("SchemaRefused = %v, want %v", got, tc.want)
			}
		})
	}
	if SchemaRefused(errors.New("connection refused")) {
		t.Error("SchemaRefused matched a transport error; only an ANSWER can be a schema refusal")
	}
	if SchemaRefused(nil) {
		t.Error("SchemaRefused(nil) is true")
	}
}

// The classification of an answer must be unchanged for everything that is not
// a schema refusal: 4xx stays terminal-and-named, 5xx stays retryable, and both
// keep the wording the status file and the logs already show.
func TestAnswerClassificationIsUnchanged(t *testing.T) {
	key := testKey(t)
	for name, tc := range map[string]struct {
		status      int
		body        string
		wantRejects bool
	}{
		"unauthorized":  {http.StatusUnauthorized, "bad token", true},
		"forbidden":     {http.StatusForbidden, "site at quota", true},
		"bad request":   {http.StatusBadRequest, "invalid signature", true},
		"internal":      {http.StatusInternalServerError, "database is locked", false},
		"bad gateway":   {http.StatusBadGateway, "no upstream", false},
		"unavailable":   {http.StatusServiceUnavailable, "starting up", false},
		"gateway timeo": {http.StatusGatewayTimeout, "upstream timeout", false},
	} {
		t.Run(name, func(t *testing.T) {
			var mu sync.Mutex
			var seen []protoenroll.EnrollRequest
			srv := startEnrollServer(t, func(_ protoenroll.EnrollRequest, w http.ResponseWriter) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}, &seen, &mu)

			req := BuildRequest(0, key, "tok", "host", "linux", "v0", permission.PermissionReport{})
			_, err := Post(context.Background(), srv.URL, false, req)
			if err == nil {
				t.Fatal("Post returned nil for a non-2xx answer")
			}
			if got := errors.Is(err, ErrRejected); got != tc.wantRejects {
				t.Fatalf("errors.Is(err, ErrRejected) = %v, want %v (err %v)", got, tc.wantRejects, err)
			}
			if !strings.Contains(err.Error(), tc.body) {
				t.Errorf("error text %q drops the server's own message %q", err, tc.body)
			}
			var se *StatusError
			if !errors.As(err, &se) || se.StatusCode != tc.status {
				t.Errorf("error does not carry the answer's status: %v", err)
			}
		})
	}
}

// BuildRequest declares the schema it is given, and the native one when given
// nothing — the second is what every existing caller relies on.
func TestBuildRequestDeclaresTheGivenSchema(t *testing.T) {
	key := testKey(t)
	if got := BuildRequest(0, key, "tok", "h", "linux", "v0", permission.PermissionReport{}); got.SchemaVersion != protocol.SchemaVersion {
		t.Errorf("BuildRequest(0) declared schema %d, want the native %d", got.SchemaVersion, protocol.SchemaVersion)
	}
	got := BuildRequest(PreviousSchema, key, "tok", "h", "linux", "v0", permission.PermissionReport{})
	if got.SchemaVersion != PreviousSchema {
		t.Errorf("BuildRequest(%d) declared schema %d", PreviousSchema, got.SchemaVersion)
	}
	// The proof of possession must still be over this request's own nonce.
	if !ed25519.Verify(key.Public().(ed25519.PublicKey), []byte(got.Nonce), got.Signature) {
		t.Error("the downgraded request's possession proof does not verify")
	}
}

// The end-to-end shape a caller sees: an older server refuses the native schema
// with the measured answer and accepts the previous one.
func TestPostAgainstAServerOneReleaseBehind(t *testing.T) {
	key := testKey(t)
	var mu sync.Mutex
	var seen []protoenroll.EnrollRequest
	srv := startEnrollServer(t, func(req protoenroll.EnrollRequest, w http.ResponseWriter) {
		if req.SchemaVersion != PreviousSchema {
			legacyRefusal(w, req.SchemaVersion, PreviousSchema)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(protoenroll.EnrollResponse{
			AgentID: "agent-1", SiteID: "site-1", AgentToken: "issued",
		})
	}, &seen, &mu)

	native := BuildRequest(0, key, "tok", "h", "linux", "v0", permission.PermissionReport{})
	_, err := Post(context.Background(), srv.URL, false, native)
	if !SchemaRefused(err) {
		t.Fatalf("Post with the native schema: err = %v; want a recognised schema refusal", err)
	}
	if errors.Is(err, ErrRejected) {
		t.Fatal("a schema refusal was classified as a terminal rejection; the token is still good and the retry needs it")
	}

	previous := BuildRequest(PreviousSchema, key, "tok", "h", "linux", "v0", permission.PermissionReport{})
	resp, err := Post(context.Background(), srv.URL, false, previous)
	if err != nil {
		t.Fatalf("Post with the previous schema: %v", err)
	}
	if resp.AgentToken != "issued" {
		t.Fatalf("response = %+v; want the issued credential", resp)
	}
	// Nothing about the retry is implicit inside Post: it makes exactly one
	// request per call, and the schema it declares is the one it was handed.
	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 2 {
		t.Fatalf("requests = %d, want 2 — one per Post call", len(seen))
	}
	if seen[0].SchemaVersion != protocol.SchemaVersion || seen[1].SchemaVersion != PreviousSchema {
		t.Fatalf("schemas declared = %d, %d", seen[0].SchemaVersion, seen[1].SchemaVersion)
	}
	// A response from a server that predates the epoch reads as epoch zero,
	// which is what makes the session that follows barrier-free and self
	// consistent.
	if resp.EnrollmentEpoch != 0 {
		t.Fatalf("enrollment epoch = %d, want 0", resp.EnrollmentEpoch)
	}
}
