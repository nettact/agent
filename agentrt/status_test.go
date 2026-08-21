package agentrt

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/nettact/agent/internal/conn"
	"github.com/nettact/agent/internal/identity"
	"github.com/nettact/agent/internal/wal"
	"github.com/nettact/protocol"
	protoenroll "github.com/nettact/protocol/enroll"
	"github.com/nettact/protocol/permission"
	"github.com/nettact/protocol/wire"
)

// readStatus polls the status file until cond is satisfied, and reports the
// last document it managed to read when it gives up.
//
// Every read must succeed once the file exists: the writer replaces it with a
// rename precisely so a poller like this — or the router page it stands in for —
// never observes a partial document. A parse failure here is the interesting
// failure, so it is reported rather than retried away.
func readStatus(t *testing.T, path string, what string, cond func(statusDoc) bool) statusDoc {
	t.Helper()
	var last statusDoc
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(path)
		if err == nil {
			if err := json.Unmarshal(data, &last); err != nil {
				t.Fatalf("status file did not parse (a torn write?): %v; contents: %q", err, data)
			}
			if cond(last) {
				return last
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s; last status: %+v", what, last)
	return last
}

// TestStatusFileReportsAConnectedSession: the whole point of the file is that a
// machine can answer "is this agent talking to the server" without asking the
// server. A live session must therefore be visible locally, named, and dated.
func TestStatusFileReportsAConnectedSession(t *testing.T) {
	dataDir := agentDataDir(t)
	if err := identity.SaveCredential(dataDir, "default", identity.Credential{
		AgentID: "agent-test", SiteID: "site-test", AgentToken: "test-token",
	}); err != nil {
		t.Fatalf("save credential: %v", err)
	}
	statusPath := filepath.Join(dataDir, "status.json")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{wire.SubprotocolJSON}})
		if err != nil {
			return
		}
		defer c.CloseNow() //nolint:errcheck
		// Hold the session open: read until the client goes away.
		for {
			if _, _, err := c.Read(r.Context()); err != nil {
				return
			}
		}
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = Run(ctx, Config{
			Servers:    []ServerConfig{{Name: "default", URL: srv.URL}},
			DataDir:    dataDir,
			WireFormat: "json",
			StatusFile: statusPath,
			Policy:     permission.Policy{Granted: permission.DefaultStandalone(), Source: permission.SourceDefault},
		})
	}()

	doc := readStatus(t, statusPath, "the session to show as connected", func(d statusDoc) bool {
		return len(d.Servers) == 1 && d.Servers[0].State == statusConnected
	})
	if doc.Schema != statusFileSchema {
		t.Errorf("schema = %d, want %d", doc.Schema, statusFileSchema)
	}
	if doc.PID != os.Getpid() {
		t.Errorf("pid = %d, want this process (%d)", doc.PID, os.Getpid())
	}
	s := doc.Servers[0]
	if s.Name != "default" || s.URL != srv.URL {
		t.Errorf("server identity = %q at %q, want %q at %q", s.Name, s.URL, "default", srv.URL)
	}
	if s.AgentID != "agent-test" {
		t.Errorf("agent_id = %q, want the enrolled id", s.AgentID)
	}
	if s.LastConnectedAt == 0 {
		t.Error("last_connected_at is unset on a live session")
	}
	if s.LastError != nil {
		t.Errorf("last_error = %+v on a live session, want none", s.LastError)
	}
	if s.NextRetryAt != 0 {
		t.Error("next_retry_at is set on a live session; a reader would render a countdown")
	}

	cancel()
	<-done

	// A file left behind by a stopped agent reads as a live status frozen at the
	// last transition, which is worse than no file at all.
	if _, err := os.Stat(statusPath); !os.IsNotExist(err) {
		t.Errorf("status file still present after shutdown (stat err = %v)", err)
	}
}

// TestStatusFileExplainsAFailedConnection pins the case the feature exists for:
// an agent that cannot reach its server must say so on the machine itself, with
// a reason to act on and a countdown to the next attempt.
func TestStatusFileExplainsAFailedConnection(t *testing.T) {
	dataDir := agentDataDir(t)
	if err := identity.SaveCredential(dataDir, "default", identity.Credential{
		AgentID: "agent-test", SiteID: "site-test", AgentToken: "test-token",
	}); err != nil {
		t.Fatalf("save credential: %v", err)
	}
	statusPath := filepath.Join(dataDir, "status.json")

	// A server that refuses every upgrade: the dial fails, always, the way an
	// expired credential or a wrong URL would.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "no", http.StatusUnauthorized)
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = Run(ctx, Config{
			Servers:    []ServerConfig{{Name: "default", URL: srv.URL}},
			DataDir:    dataDir,
			WireFormat: "json",
			StatusFile: statusPath,
			Policy:     permission.Policy{Granted: permission.DefaultStandalone(), Source: permission.SourceDefault},
		})
	}()

	before := time.Now().Unix()
	doc := readStatus(t, statusPath, "a failed attempt to be explained", func(d statusDoc) bool {
		return len(d.Servers) == 1 && d.Servers[0].State == statusWaitingRetry
	})
	cancel()
	<-done

	s := doc.Servers[0]
	if s.LastError == nil {
		t.Fatal("no last_error on a failed connection; the state alone tells nobody what to fix")
	}
	if s.LastError.Code != "auth" {
		t.Errorf("last_error.code = %q, want %q for a refused credential", s.LastError.Code, "auth")
	}
	if s.LastError.Detail == "" {
		t.Error("last_error.detail is empty; the code alone cannot name the host")
	}
	if s.NextRetryAt < before {
		t.Errorf("next_retry_at = %d, want an instant at or after the failure (%d)", s.NextRetryAt, before)
	}
}

// TestEnrollFailureKeepsItsCause: enrollment folds two things into one error —
// the sentinel the runner branches on, and the transport failure that says what
// actually went wrong. Both have to survive, or the status file can report only
// "enrollment failed" for a refused port, an expired certificate and a name
// that does not resolve alike. That was the original behaviour, and it is the
// exact black box this feature exists to open.
func TestEnrollFailureKeepsItsCause(t *testing.T) {
	_, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	env := runEnv{cfg: Config{DataDir: t.TempDir()}, key: key, hostname: "h", platformID: "test"}

	cause := &net.DNSError{Err: "no such host", Name: "nettact.invalid", IsNotFound: true}
	rt := &serverRuntime{cfg: ServerConfig{
		Name: "default",
		URL:  "https://nettact.invalid",
		TokenSource: func(context.Context) (string, error) {
			return "token", nil
		},
		Enroller: func(context.Context, protoenroll.EnrollRequest) (protoenroll.EnrollResponse, error) {
			return protoenroll.EnrollResponse{}, fmt.Errorf("post enrollment: %w", cause)
		},
	}}

	_, _, err = enrollServer(context.Background(), env, rt, protocol.SchemaVersion)
	if err == nil {
		t.Fatal("enrollServer succeeded against a failing exchange")
	}
	if !errors.Is(err, ErrEnroll) {
		t.Errorf("errors.Is(err, ErrEnroll) = false for %v; the runner branches on it", err)
	}
	if got := enrollStatusCode(err); got != string(conn.ReasonDNS) {
		t.Errorf("enrollStatusCode(%v) = %q, want %q — the cause did not survive wrapping",
			err, got, conn.ReasonDNS)
	}
}

// TestStatusWriterCoalescesWithoutTearing hammers the writer with transitions
// while reading the file, because the two things it promises — never blocking a
// session goroutine, and never showing a half-written document — are only ever
// both true under concurrency.
func TestStatusWriterCoalescesWithoutTearing(t *testing.T) {
	dir := agentDataDir(t)
	path := filepath.Join(dir, "nested", "status.json") // also proves the parent is created
	outbox, err := wal.Open(filepath.Join(dir, "wal"), []string{"a", "b"}, wal.Options{})
	if err != nil {
		t.Fatalf("open wal: %v", err)
	}
	t.Cleanup(func() { _ = outbox.Close() })

	w := newStatusWriter(path, Config{Servers: []ServerConfig{
		{Name: "a", URL: "https://a.example"},
		{Name: "b", URL: "https://b.example"},
	}}, outbox)

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		w.run(ctx)
	}()

	var writers sync.WaitGroup
	for _, name := range []string{"a", "b"} {
		writers.Add(1)
		go func(name string) {
			defer writers.Done()
			for i := 0; i < 200; i++ {
				w.set(name, func(s *serverStatus) {
					s.State = statusWaitingRetry
					s.LastError = &statusError{Code: "network", Detail: "attempt"}
				})
				w.set(name, func(s *serverStatus) {
					s.State = statusConnected
					s.LastError = nil
				})
			}
		}(name)
	}
	writers.Wait()

	readStatus(t, path, "both servers to appear", func(d statusDoc) bool {
		return len(d.Servers) == 2
	})

	cancel()
	wg.Wait()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("status file survived the writer (stat err = %v)", err)
	}
}

// TestStatusWriterIsDisabledByAnEmptyPath: the default is off, and every call
// site must stay unconditional.
func TestStatusWriterIsDisabledByAnEmptyPath(t *testing.T) {
	w := newStatusWriter("", Config{Servers: []ServerConfig{{Name: "a"}}}, nil)
	if w != nil {
		t.Fatalf("newStatusWriter(\"\") = %+v, want nil", w)
	}
	// None of these may panic on the nil writer.
	w.set("a", func(*serverStatus) { t.Error("mutate ran on a disabled writer") })
	w.refresh()
	w.run(context.Background())
}

// A terminal outcome is the one state that has to outlive the process that
// recorded it. The runner sets it and Run returns immediately, so the cancel and
// the pending write are ready at the same instant — and a select with two ready
// cases picks at random. Removing the file there (or losing the write to that
// coin flip) deletes the only sentence that says why the agent gave up, and the
// respawn that follows shows startup states forever.
func TestStatusFileSurvivesATerminalOutcome(t *testing.T) {
	dir := agentDataDir(t)
	path := filepath.Join(dir, "status.json")
	outbox, err := wal.Open(filepath.Join(dir, "wal"), []string{"default"}, wal.Options{})
	if err != nil {
		t.Fatalf("open wal: %v", err)
	}
	t.Cleanup(func() { _ = outbox.Close() })
	w := newStatusWriter(path, Config{Servers: []ServerConfig{{Name: "default", URL: "http://s"}}}, outbox)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		w.run(ctx)
	}()

	// Exactly the shape runServer produces, then an immediate cancel.
	w.set("default", func(s *serverStatus) {
		s.State = statusTerminal
		s.LastError = &statusError{Code: statusCodeNoToken, Detail: "no enrollment token available"}
	})
	cancel()
	<-done

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("status file was removed after a terminal outcome: %v", err)
	}
	var doc statusDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("unmarshal status: %v", err)
	}
	if len(doc.Servers) != 1 || doc.Servers[0].State != statusTerminal {
		t.Fatalf("state = %+v, want one server in %q", doc.Servers, statusTerminal)
	}
	if doc.Servers[0].LastError == nil || doc.Servers[0].LastError.Code != statusCodeNoToken {
		t.Fatalf("last_error = %+v, want code %q", doc.Servers[0].LastError, statusCodeNoToken)
	}
}

// The complement, and the reason removal is the default: a file left behind by
// an agent that merely shut down would read as a live status frozen at whatever
// the last transition happened to be.
func TestStatusFileIsRemovedOnAnOrdinaryShutdown(t *testing.T) {
	dir := agentDataDir(t)
	path := filepath.Join(dir, "status.json")
	outbox, err := wal.Open(filepath.Join(dir, "wal"), []string{"default"}, wal.Options{})
	if err != nil {
		t.Fatalf("open wal: %v", err)
	}
	t.Cleanup(func() { _ = outbox.Close() })
	w := newStatusWriter(path, Config{Servers: []ServerConfig{{Name: "default", URL: "http://s"}}}, outbox)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		w.run(ctx)
	}()

	w.set("default", func(s *serverStatus) { s.State = statusConnected })
	cancel()
	<-done

	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("os.Stat(%s) = %v, want the file to be gone", path, err)
	}
}

// TestRunRecordsAStartupFailure: the failures that kill the agent BEFORE it has
// a server to have an opinion about are the ones a router owner has no way at
// all to see. procd respawns the process in under a second, its stderr is
// written in the instant before it exits (which is the window procd's log reader
// loses), and the status page is left able to say only "not running".
//
// Run must therefore leave the reason behind even when it never got as far as
// building a status writer — which is the whole point: no writer means no
// document, and no document means no explanation.
func TestRunRecordsAStartupFailure(t *testing.T) {
	dir := agentDataDir(t)
	path := filepath.Join(dir, "status.json")

	// A WAL directory that cannot be opened, produced the way a router would:
	// a plain file where the agent expects to create a directory.
	if err := os.WriteFile(filepath.Join(dir, "wal"), []byte("not a directory"), 0o644); err != nil {
		t.Fatalf("plant the wal blocker: %v", err)
	}

	err := Run(context.Background(), Config{
		Servers:    []ServerConfig{{Name: "default", URL: "http://127.0.0.1:1"}},
		DataDir:    dir,
		WireFormat: "json",
		StatusFile: path,
		Policy:     permission.Policy{Granted: permission.DefaultStandalone(), Source: permission.SourceDefault},
	})
	if err == nil {
		t.Fatal("Run succeeded with an unopenable WAL")
	}

	raw, rerr := os.ReadFile(path)
	if rerr != nil {
		t.Fatalf("no status file after a startup failure (%v); the reason reached nobody", rerr)
	}
	var doc statusDoc
	if uerr := json.Unmarshal(raw, &doc); uerr != nil {
		t.Fatalf("unmarshal status: %v; contents %q", uerr, raw)
	}
	if doc.Fatal == "" {
		t.Fatalf("fatal is empty in %q, want the reason Run refused to start with", raw)
	}
	if doc.Schema != statusFileSchema {
		t.Errorf("schema = %d, want %d", doc.Schema, statusFileSchema)
	}
	if doc.PID != os.Getpid() {
		t.Errorf("pid = %d, want this process (%d)", doc.PID, os.Getpid())
	}
	// A reader iterating servers must find a list, not null.
	if doc.Servers == nil {
		t.Error("servers is null; a reader that iterates it would break on the one document that matters")
	}
	// And the shell must be able to lift it out with the expression launch.sh
	// uses, which needs the raw bytes to carry no escape in that value.
	if got := fatalByShellRule(t, raw); got != doc.Fatal {
		t.Errorf("sed-equivalent extraction = %q, want %q", got, doc.Fatal)
	}
}

// TestStatusFileSurvivesAProcessLevelFailure: `fatal` has to keep the document
// alive on its own. A process that dies before any server row exists has no
// terminal state to be recognised by, so a rule that only looked for one would
// delete the only sentence there is — which is precisely the case this field was
// added for.
func TestStatusFileSurvivesAProcessLevelFailure(t *testing.T) {
	dir := agentDataDir(t)
	path := filepath.Join(dir, "status.json")
	outbox, err := wal.Open(filepath.Join(dir, "wal"), []string{"default"}, wal.Options{})
	if err != nil {
		t.Fatalf("open wal: %v", err)
	}
	t.Cleanup(func() { _ = outbox.Close() })
	w := newStatusWriter(path, Config{Servers: []ServerConfig{{Name: "default", URL: "http://s"}}}, outbox)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		w.run(ctx)
	}()

	// No server ever leaves statusConnecting: only the process-level record says
	// anything happened.
	w.setFatal(errors.New("server \"default\": enroll: unsupported schema_version 3"))
	cancel()
	<-done

	raw, rerr := os.ReadFile(path)
	if rerr != nil {
		t.Fatalf("status file was removed despite a fatal reason: %v", rerr)
	}
	var doc statusDoc
	if uerr := json.Unmarshal(raw, &doc); uerr != nil {
		t.Fatalf("unmarshal status: %v", uerr)
	}
	if doc.Fatal == "" {
		t.Fatalf("fatal is empty in %q", raw)
	}
	if got := fatalByShellRule(t, raw); got != doc.Fatal {
		t.Errorf("sed-equivalent extraction = %q, want %q", got, doc.Fatal)
	}
}

// TestShellSafeReasonSurvivesSedExtraction pins the property the OpenWrt scripts
// depend on and cannot check for themselves.
//
// launch.sh lifts the reason out with `sed -n 's/.*"fatal":"\([^"]*\)".*/\1/p'`,
// because there is no JSON parser in BusyBox ash. That expression is exact only
// while the encoded value contains no quote and no backslash — and the reasons
// that matter most are the ones most likely to contain both, since a rejected
// enrollment carries the server's JSON error body inside its own message. Left
// unsanitised, the sentence would be cut off at the first escape, which is
// exactly where it starts naming the problem.
func TestShellSafeReasonSurvivesSedExtraction(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want string
	}{{
		name: "the failure this was written for",
		err: errors.New(`server "default": enroll: enroll failed (500 Internal Server Error): ` +
			`{"error":"unsupported schema_version 3 (this build speaks 5; upgrade the other side)"}`),
		want: `server default: enroll: enroll failed (500 Internal Server Error): ` +
			`{error:unsupported schema_version 3 (this build speaks 5; upgrade the other side)}`,
	}, {
		name: "a multi-line join keeps one line",
		err:  errors.New("server \"a\": no token\nserver \"b\": no token"),
		want: "server a: no token server b: no token",
	}, {
		name: "a windows path does not escape into a backslash",
		err:  errors.New(`open C:\data\agent.key: permission denied`),
		want: "open C: data agent.key: permission denied",
	}}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := shellSafe(tc.err)
			if got != tc.want {
				t.Errorf("shellSafe() = %q, want %q", got, tc.want)
			}
			raw, err := json.Marshal(statusDoc{Schema: statusFileSchema, Fatal: got})
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			if extracted := fatalByShellRule(t, raw); extracted != got {
				t.Errorf("the shell would read %q, not %q", extracted, got)
			}
		})
	}

	// The cap keeps a syslog line and a status panel readable; the untruncated
	// text is still on each server's own row.
	long := errors.New(strings.Repeat("x", shellSafeMax*2))
	if got := shellSafe(long); len(got) > shellSafeMax {
		t.Errorf("shellSafe() returned %d bytes, want at most %d", len(got), shellSafeMax)
	}
}

// fatalByShellRule extracts `fatal` from raw document bytes the way launch.sh
// does — a plain scan for the unescaped key, taking everything up to the next
// quote. Written against the bytes rather than against a parsed document on
// purpose: the point is what the SHELL will see, and a parser would paper over
// exactly the escaping the shell cannot handle.
func fatalByShellRule(t *testing.T, raw []byte) string {
	t.Helper()
	const key = `"fatal":"`
	i := strings.Index(string(raw), key)
	if i < 0 {
		return ""
	}
	rest := string(raw)[i+len(key):]
	j := strings.IndexByte(rest, '"')
	if j < 0 {
		return ""
	}
	return rest[:j]
}
