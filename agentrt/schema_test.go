package agentrt

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/nettact/agent/internal/enroll"
	"github.com/nettact/agent/internal/identity"
	"github.com/nettact/protocol"
	protoenroll "github.com/nettact/protocol/enroll"
	"github.com/nettact/protocol/permission"
	"github.com/nettact/protocol/wire"
)

// Enrollment is where a brand-new install first meets a server, and it happens
// before any handshake — so it is the only place that install can discover the
// other side is a release away. These tests pin the retry that discovery
// enables and, just as importantly, everything it must NOT change.

// legacySchemaRefusal is the answer measured from a server released before the
// current schema boundary. Its shape, not its wording in this file, is the
// contract: an HTTP 5xx whose body names the schema it does not know.
func legacySchemaRefusal(schema, speaks int) error {
	return &enroll.StatusError{
		StatusCode: 500,
		Status:     "500 Internal Server Error",
		Body: `{"error":"unsupported schema_version ` + itoa(schema) +
			` (this build speaks ` + itoa(speaks) + `; upgrade the other side)"}`,
	}
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

// enrollFixture is one server's enrollment endpoint as a function, recording
// the schema each attempt declared.
type enrollFixture struct {
	mu sync.Mutex
	// accept is the schema this endpoint issues credentials for; every other
	// schema is refused the way an older release refuses one.
	accept   int
	declared []int
	// refuseAll makes even the accepted schema fail, for the bounded-attempts
	// case: a retry budget that is not a budget shows up here as a third try.
	refuseAll bool
}

func (f *enrollFixture) exchange(_ context.Context, req protoenroll.EnrollRequest) (protoenroll.EnrollResponse, error) {
	f.mu.Lock()
	f.declared = append(f.declared, req.SchemaVersion)
	f.mu.Unlock()
	if f.refuseAll || req.SchemaVersion != f.accept {
		return protoenroll.EnrollResponse{}, legacySchemaRefusal(req.SchemaVersion, f.accept)
	}
	return protoenroll.EnrollResponse{AgentID: "agent-1", SiteID: "site-1", AgentToken: "issued"}, nil
}

func (f *enrollFixture) attempts() []int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]int(nil), f.declared...)
}

func newEnrollRuntime(name string, f *enrollFixture) *serverRuntime {
	return &serverRuntime{cfg: ServerConfig{
		Name:        name,
		URL:         "https://example.invalid",
		TokenSource: func(context.Context) (string, error) { return "one-time", nil },
		Enroller:    f.exchange,
	}}
}

func enrollEnv(t *testing.T) runEnv {
	t.Helper()
	dir := agentDataDir(t)
	key, err := identity.LoadOrCreateKey(dir)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	return runEnv{cfg: Config{DataDir: dir}, key: key, hostname: "host", platformID: "linux"}
}

// TestEnrollmentRetriesOnceInTheOtherSchema: the server refuses the schema the
// request declared, so the same token is presented again in the other one.
//
// The token survives the refusal because the schema is checked before the
// signature and long before the token is marked spent — which is what makes a
// retry possible at all rather than burning an operator-issued token to learn
// the server's version.
func TestEnrollmentRetriesOnceInTheOtherSchema(t *testing.T) {
	env := enrollEnv(t)
	f := &enrollFixture{accept: enroll.PreviousSchema}
	rt := newEnrollRuntime("work", f)

	cred, used, err := enrollServer(context.Background(), env, rt, protocol.SchemaVersion)
	if err != nil {
		t.Fatalf("enrollServer: %v", err)
	}
	if cred.AgentToken != "issued" {
		t.Fatalf("credential = %+v; want the issued one", cred)
	}
	if used != enroll.PreviousSchema {
		t.Fatalf("reported schema = %d, want %d — the caller has to learn which one worked", used, enroll.PreviousSchema)
	}
	if got := f.attempts(); len(got) != 2 || got[0] != protocol.SchemaVersion || got[1] != enroll.PreviousSchema {
		t.Fatalf("schemas declared = %v; want the native one then exactly one retry in %d", got, enroll.PreviousSchema)
	}
	// A server that predates the epoch issues none, and zero is what makes the
	// session that follows barrier-free.
	if cred.EnrollmentEpoch != 0 {
		t.Fatalf("credential epoch = %d, want 0", cred.EnrollmentEpoch)
	}
}

// The search is symmetric. An agent that remembers a downgrade and meets a
// server that has since been upgraded has the same problem in the other
// direction, and the same single retry solves it.
func TestEnrollmentRetryIsSymmetric(t *testing.T) {
	env := enrollEnv(t)
	f := &enrollFixture{accept: protocol.SchemaVersion}
	rt := newEnrollRuntime("work", f)

	_, used, err := enrollServer(context.Background(), env, rt, enroll.PreviousSchema)
	if err != nil {
		t.Fatalf("enrollServer: %v", err)
	}
	if used != protocol.SchemaVersion {
		t.Fatalf("reported schema = %d, want the native %d", used, protocol.SchemaVersion)
	}
	if got := f.attempts(); len(got) != 2 || got[0] != enroll.PreviousSchema || got[1] != protocol.SchemaVersion {
		t.Fatalf("schemas declared = %v", got)
	}
}

// The budget is two, because the set this build can speak has two members. A
// third attempt means the retry is a loop, and a loop here spends an operator's
// one-time token rediscovering the same answer.
func TestEnrollmentRetryIsBounded(t *testing.T) {
	env := enrollEnv(t)
	f := &enrollFixture{accept: protocol.SchemaVersion, refuseAll: true}
	rt := newEnrollRuntime("work", f)

	if _, _, err := enrollServer(context.Background(), env, rt, protocol.SchemaVersion); err == nil {
		t.Fatal("enrollServer succeeded against a server that refuses everything")
	}
	if got := f.attempts(); len(got) != 2 {
		t.Fatalf("attempts = %v; want exactly 2 — one per schema this build speaks", got)
	}
}

// Everything that is not a schema refusal keeps its existing treatment. A
// refused token is terminal and stays terminal; an unreachable server is
// retryable and stays retryable; neither may trigger a downgrade, because a
// downgrade taken on a transient failure would leave the agent talking an old
// schema to a current server for no reason at all.
func TestNonSchemaFailuresDoNotDowngrade(t *testing.T) {
	for name, injected := range map[string]error{
		"refused token":       errRejectedForTest,
		"unreachable server":  errors.New("dial tcp: connection refused"),
		"unrelated 500":       &enroll.StatusError{StatusCode: 500, Status: "500 Internal Server Error", Body: `{"error":"database is locked"}`},
		"gateway with no app": &enroll.StatusError{StatusCode: 502, Status: "502 Bad Gateway", Body: "no upstream"},
	} {
		t.Run(name, func(t *testing.T) {
			env := enrollEnv(t)
			var declared []int
			var mu sync.Mutex
			rt := &serverRuntime{cfg: ServerConfig{
				Name:        "work",
				URL:         "https://example.invalid",
				TokenSource: func(context.Context) (string, error) { return "tok", nil },
				Enroller: func(_ context.Context, req protoenroll.EnrollRequest) (protoenroll.EnrollResponse, error) {
					mu.Lock()
					declared = append(declared, req.SchemaVersion)
					mu.Unlock()
					return protoenroll.EnrollResponse{}, injected
				},
			}}
			_, used, err := enrollServer(context.Background(), env, rt, protocol.SchemaVersion)
			if err == nil {
				t.Fatal("enrollServer returned nil for an injected failure")
			}
			mu.Lock()
			defer mu.Unlock()
			if len(declared) != 1 {
				t.Fatalf("attempts = %v; want exactly one — nothing here says the schema is wrong", declared)
			}
			if used != protocol.SchemaVersion {
				t.Fatalf("reported schema = %d; the preference must not move", used)
			}
			if name == "refused token" && !errors.Is(err, ErrEnrollRejected) {
				t.Fatalf("err = %v; a refused token must stay terminal", err)
			}
			if name != "refused token" && errors.Is(err, ErrEnrollRejected) {
				t.Fatalf("err = %v; a transient failure must not read as a refusal", err)
			}
		})
	}
}

// TestPreferredSchemaTriggers pins the two reasons a remembered downgrade is
// re-examined at assembly time. The third — enough elapsed time — belongs to
// the reconnect loop, because only it knows when a reconnect happens.
func TestPreferredSchemaTriggers(t *testing.T) {
	now := time.Now().UTC()
	for name, tc := range map[string]struct {
		rec  identity.Negotiated
		want int
	}{
		"nothing recorded": {
			rec:  identity.Negotiated{},
			want: protocol.SchemaVersion,
		},
		"recorded native": {
			rec:  identity.Negotiated{Schema: protocol.SchemaVersion, AgentVersion: Version, DecidedAt: now, LastProbe: now},
			want: protocol.SchemaVersion,
		},
		"recorded downgrade by this build": {
			rec:  identity.Negotiated{Schema: enroll.PreviousSchema, AgentVersion: Version, DecidedAt: now, LastProbe: now},
			want: enroll.PreviousSchema,
		},
		// A different binary is reason enough to try the native schema again:
		// both halves of the old conclusion — what the agent can speak, and what
		// the server accepted from it — belong to something just replaced.
		"recorded downgrade by another build": {
			rec:  identity.Negotiated{Schema: enroll.PreviousSchema, AgentVersion: "v0.0.1-ancient", DecidedAt: now, LastProbe: now},
			want: protocol.SchemaVersion,
		},
	} {
		t.Run(name, func(t *testing.T) {
			if got := preferredSchema(tc.rec); got != tc.want {
				t.Errorf("preferredSchema(%+v) = %d, want %d", tc.rec, got, tc.want)
			}
		})
	}
}

// TestRecordNegotiatedIsPerServerAndBounded: the record of one server's schema
// must reach that server's entry and nothing else — a whole-map write would
// erase what every other runner had learned — and an unchanged conclusion must
// not be rewritten on every reconnect of a flapping link.
func TestRecordNegotiatedIsPerServerAndBounded(t *testing.T) {
	dir := agentDataDir(t)
	alpha := identity.Negotiated{}
	beta := identity.Negotiated{}

	if err := recordNegotiated(dir, "alpha", &alpha, protocol.SchemaVersion); err != nil {
		t.Fatalf("record alpha: %v", err)
	}
	if err := recordNegotiated(dir, "beta", &beta, enroll.PreviousSchema); err != nil {
		t.Fatalf("record beta: %v", err)
	}
	recs, err := identity.LoadNegotiated(dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if recs["alpha"].Schema != protocol.SchemaVersion {
		t.Fatalf("alpha's record = %+v; beta's downgrade overwrote it", recs["alpha"])
	}
	if recs["beta"].Schema != enroll.PreviousSchema {
		t.Fatalf("beta's record = %+v", recs["beta"])
	}

	// An unchanged conclusion, recorded again immediately, is not rewritten:
	// the file is flash on the devices this runs on and the record is a hint.
	before := recs["beta"]
	if err := recordNegotiated(dir, "beta", &beta, enroll.PreviousSchema); err != nil {
		t.Fatalf("re-record beta: %v", err)
	}
	recs, err = identity.LoadNegotiated(dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !recs["beta"].LastProbe.Equal(before.LastProbe) {
		t.Fatalf("an unchanged conclusion was rewritten: %+v then %+v", before, recs["beta"])
	}

	// A CHANGED conclusion is written at once — that is the whole point of the
	// record, and delaying it would send the next start to the schema that was
	// just refused.
	if err := recordNegotiated(dir, "beta", &beta, protocol.SchemaVersion); err != nil {
		t.Fatalf("change beta: %v", err)
	}
	recs, err = identity.LoadNegotiated(dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if recs["beta"].Schema != protocol.SchemaVersion {
		t.Fatalf("beta's changed record = %+v", recs["beta"])
	}
	if recs["alpha"].Schema != protocol.SchemaVersion {
		t.Fatalf("alpha's record was disturbed by beta's change: %+v", recs["alpha"])
	}
}

// TestEnrollmentRecordsWhatWorked: the runner writes down the schema the
// enrollment succeeded under before the session starts, so a crash in between
// does not send the next start back to the one just refused.
func TestEnrollmentRecordsWhatWorked(t *testing.T) {
	env := enrollEnv(t)
	f := &enrollFixture{accept: enroll.PreviousSchema}
	rt := newEnrollRuntime("work", f)

	_, used, err := enrollServer(context.Background(), env, rt, protocol.SchemaVersion)
	if err != nil {
		t.Fatalf("enrollServer: %v", err)
	}
	neg := identity.Negotiated{}
	if err := recordNegotiated(env.cfg.DataDir, "work", &neg, used); err != nil {
		t.Fatalf("recordNegotiated: %v", err)
	}
	recs, err := identity.LoadNegotiated(env.cfg.DataDir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	got := recs["work"]
	if got.Schema != enroll.PreviousSchema {
		t.Fatalf("record = %+v, want schema %d", got, enroll.PreviousSchema)
	}
	if got.AgentVersion != Version {
		t.Fatalf("record = %+v; the build that reached the conclusion must be named, or the upgrade trigger cannot fire", got)
	}
	if got.LastProbe.IsZero() {
		t.Fatalf("record = %+v; the probe timestamp is what schedules the next one", got)
	}
	// Two attempts got here, and the first — the schema refusal — must never
	// have looked like a spent token to anything downstream.
	if got := f.attempts(); len(got) != 2 {
		t.Fatalf("attempts = %v, want 2", got)
	}
}

// TestCloseCodeCredentialRadius pins the split that a mistake here would make
// silently destructive: which close codes delete a credential, and whose.
//
// Two servers, both enrolled, in one process. One takes over the session with a
// supersede close; the other deletes the agent. The supersede must leave its
// credential exactly where it is — it is a perfectly valid credential that
// another process is currently using, and deleting it would cost an
// operator-issued token to undo. The revocation must delete its own credential
// and nothing else, because being deleted at one server says nothing about the
// others.
func TestCloseCodeCredentialRadius(t *testing.T) {
	dataDir := agentDataDir(t)
	for name, tok := range map[string]string{"kept": "token-kept", "revoked": "token-revoked"} {
		if err := identity.SaveCredential(dataDir, name, identity.Credential{
			AgentID: "agent-" + name, SiteID: "site", AgentToken: tok,
		}); err != nil {
			t.Fatalf("save credential %q: %v", name, err)
		}
	}

	closer := func(code int) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{wire.SubprotocolJSON}})
			if err != nil {
				t.Errorf("accept: %v", err)
				return
			}
			defer c.CloseNow() //nolint:errcheck
			readCtx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
			defer cancel()
			if _, _, err := c.Read(readCtx); err != nil {
				return // hello
			}
			_ = c.Close(websocket.StatusCode(code), "closed")
		}))
	}
	kept := closer(int(wire.CloseSuperseded))
	defer kept.Close()
	revoked := closer(int(wire.CloseRevoked))
	defer revoked.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	err := Run(ctx, Config{
		Servers: []ServerConfig{
			{Name: "kept", URL: kept.URL},
			{Name: "revoked", URL: revoked.URL},
		},
		DataDir: dataDir, WireFormat: "json",
		UploadInterval: 200 * time.Millisecond,
		Policy:         permission.Policy{Granted: permission.DefaultStandalone(), Source: permission.SourceDefault},
	})
	if err == nil {
		t.Fatal("Run returned nil; both servers ended terminally")
	}

	creds, loadErr := identity.LoadCredentials(dataDir)
	if loadErr != nil {
		t.Fatalf("load credentials: %v", loadErr)
	}
	if c, ok := creds["kept"]; !ok || c.AgentToken != "token-kept" {
		t.Fatalf("the superseded server lost its credential (have %+v); it is valid and in use by another process", creds)
	}
	if _, ok := creds["revoked"]; ok {
		t.Fatalf("the revoked server kept its dead credential: %+v", creds)
	}
}
