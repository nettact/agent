package agentrt

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/nettact/agent/internal/conn"
	"github.com/nettact/agent/internal/wal"
)

// statusFileSchema versions the document written to Config.StatusFile. A reader
// that does not recognise the number must show nothing rather than guess: the
// fields are a contract with a LuCI page that ships and upgrades separately from
// the agent, so the two are routinely different vintages on the same device.
const statusFileSchema = 2

// Connection states reported per server. They are a reader's vocabulary, not an
// internal state machine — conn and the enrollment loop have their own — and are
// deliberately few, because a status line that distinguishes six kinds of "not
// working" helps nobody standing in front of a router.
//
// There is no "dialing": a reader that sees waitingRetry with its countdown
// elapsed renders "connecting", which costs one comparison and saves a write
// (and a file rewrite) on every single reconnect attempt.
const (
	statusEnrolling    = "enrolling"     // no credential yet; retrying the exchange
	statusConnecting   = "connecting"    // credential in hand, first session not yet live
	statusConnected    = "connected"     // session live
	statusWaitingRetry = "waiting_retry" // attempt failed, sleeping until next_retry_at
	statusTerminal     = "terminal"      // this server's runner gave up; needs a human
)

// statusError is a failure a reader can act on: a stable code to translate and
// the raw text to show underneath it. Both matter — the code alone cannot name
// which host or which certificate, and the text alone cannot be translated or
// turned into a link to the right documentation section.
type statusError struct {
	Code   string `json:"code"`
	Detail string `json:"detail,omitempty"`
}

// serverStatus is one configured server's live connection state.
//
// Times are Unix seconds rather than RFC 3339 because every reader of this file
// is a shell script or a router web page doing arithmetic on them, and because
// next_retry_at is an absolute instant on purpose: a countdown computed from a
// remaining-seconds field starts lying the moment the file goes stale, whereas
// an absolute one stays correct no matter when it is read.
type serverStatus struct {
	Name string `json:"name"`
	URL  string `json:"url,omitempty"`

	State   string `json:"state"`
	AgentID string `json:"agent_id,omitempty"`

	// Since is when the current State was entered — what turns "connected" into
	// "connected for three days".
	Since int64 `json:"since"`

	// LastConnectedAt is the last time a session went live in THIS process. It
	// is deliberately not persisted across restarts: the file describes a
	// running agent, and a timestamp that survived the process it belongs to
	// would be read as "still fine" during a crash loop.
	LastConnectedAt int64 `json:"last_connected_at,omitempty"`

	// NextRetryAt is when the next attempt is due, set only while enrolling or
	// waiting out a backoff.
	NextRetryAt int64 `json:"next_retry_at,omitempty"`

	LastError *statusError `json:"last_error,omitempty"`

	// Pending is this server's unacked backlog depth. It is the one number that
	// says whether an outage is costing data, and it is per server because the
	// WAL cursor is.
	Pending int `json:"pending"`
}

// statusDoc is the whole file.
type statusDoc struct {
	Schema       int    `json:"schema"`
	PID          int    `json:"pid"`
	AgentVersion string `json:"agent_version"`
	StartedAt    int64  `json:"started_at"`
	UpdatedAt    int64  `json:"updated_at"`

	// Fatal is why this PROCESS gave up, in one sentence, or empty while it is
	// still running. It exists beside the per-server rows below rather than
	// instead of them, because the two answer different questions and one of
	// them has no row to live in.
	//
	// A configuration the agent refuses, an unreadable key, a WAL it cannot open:
	// none of those belong to any server, and they happen before a single server
	// row exists. On a router they are also the worst case there is — the process
	// dies in under a second, procd respawns it ten seconds later forever, and
	// the reason goes to stderr where nobody will ever read it (procd's log
	// reader routinely loses the last line a process writes before exiting, which
	// is exactly this one). Without this field the status page can only report
	// what the router can observe from outside — "not running" — which is the
	// black box this whole file exists to open.
	//
	// It is a plain string, and it is sanitised, because its first reader is
	// BusyBox sh. launch.sh republishes it to syslog on the next respawn, using
	// `sed -n 's/.*"fatal":"\([^"]*\)".*/\1/p'`, and that expression is only
	// correct if the value can never contain a quote or a backslash — a JSON
	// string carrying `\"` would be truncated at the escape, cutting the sentence
	// off exactly where it starts being useful. Encoding it as a nested object
	// like LastError below would push the same problem one level deeper without
	// solving it: there is no JSON parser in launch.sh. So the agent guarantees
	// the property instead of asking the reader to handle it (see shellSafe).
	Fatal string `json:"fatal,omitempty"`

	Servers []serverStatus `json:"servers"`
}

// shellSafeMax caps the sanitised reason. Syslog truncates long lines, the LuCI
// log panel shows thirty of them, and every failure worth reporting says what it
// is in its first sentence; the untruncated text is still in Servers.LastError
// for the page that can render it.
const shellSafeMax = 300

// shellSafe renders err as a single line that survives both JSON encoding and a
// sed extraction unchanged: no quote, no backslash, no control character, no run
// of blanks.
//
// The two offending characters are treated differently on purpose. A quote is a
// delimiter — dropping it cannot run two words together — while a backslash
// separates (`C:\data\agent.key`), so it becomes a space rather than nothing.
// Control characters and newlines go the same way as the backslash: the joined
// error of several servers is multi-line, and one line is what syslog and the
// status panel each show.
func shellSafe(err error) string {
	if err == nil {
		return ""
	}
	var b strings.Builder
	space := false
	for _, r := range err.Error() {
		switch {
		case r == '"':
			// Dropped outright, leaving `server "default": …` as `server default: …`.
		case r == '\\' || r == ' ' || r == '\t' || r < 0x20 || r == 0x7f:
			space = b.Len() > 0
		default:
			if space {
				b.WriteRune(' ')
				space = false
			}
			b.WriteRune(r)
		}
	}
	s := b.String()
	if len(s) > shellSafeMax {
		// ToValidUTF8 drops the rune the cut landed inside, so the result is never
		// a byte sequence a JSON encoder has to escape its way around.
		s = strings.ToValidUTF8(s[:shellSafeMax], "")
	}
	return s
}

// ReportStartupFailure records, in the status file, why the agent is refusing to
// start at all — the failures that happen before Run can be called and therefore
// before Run can report anything itself.
//
// It is exported for one caller shape: a supervised agent whose configuration is
// rejected (a UCI value the router's own settings page produced, say) exits
// before it has a status writer, a server list or a log anyone reads. On a
// router that is indistinguishable from every other kind of silence, and the
// status file is the only surface the LuCI page and the launch script can both
// see. A caller that got as far as calling Run must not call this as well: Run
// already reports its own failures, in more detail than a single line can carry,
// and this replaces the whole document rather than adding to it.
//
// Doing nothing when path is empty is the ordinary case (a standalone agent's
// status surface is its log), and every error here is swallowed on purpose —
// this is a diagnostic, and a diagnostic that can fail the thing it is
// diagnosing is worse than none.
func ReportStartupFailure(path string, err error) {
	if path == "" || err == nil {
		return
	}
	now := time.Now().Unix()
	data, merr := json.Marshal(statusDoc{
		Schema:       statusFileSchema,
		PID:          os.Getpid(),
		AgentVersion: Version,
		StartedAt:    now,
		UpdatedAt:    now,
		Fatal:        shellSafe(err),
		// Empty rather than absent: a reader that iterates the servers must find a
		// list to iterate, not null. There genuinely are none — that is the point
		// of this document.
		Servers: []serverStatus{},
	})
	if merr != nil {
		return
	}
	_ = replaceStatusFile(path, data)
}

// Status codes for the failures that are agentrt's rather than conn's. Every
// other code comes straight from conn.Classify, so the vocabulary a reader has
// to translate is one list with two origins and no overlap.
const (
	statusCodeNoToken        = "no_token"        // nothing to enroll with; only a config change helps
	statusCodeEnrollRejected = "enroll_rejected" // the server answered and refused the token
	statusCodeStopped        = "stopped"         // terminal for a reason none of the others name
	statusCodeLocalState     = "local_state"     // the exchange worked; this machine could not write the result down
)

// terminalStatusCode names why a server's runner gave up, for the one state a
// reader can do nothing about but must still be told about precisely — "stopped"
// with no reason is the black box this whole file exists to open.
func terminalStatusCode(err error) string {
	switch {
	case errors.Is(err, ErrNoEnrollmentToken):
		return statusCodeNoToken
	case errors.Is(err, ErrEnrollRejected):
		return statusCodeEnrollRejected
	// Without this the classifier below folds a filesystem error into the
	// `stopped` catch-all, which is the exact "terminal for a reason none of the
	// others name" that this code exists to stop happening.
	case errors.Is(err, ErrLocalState):
		return statusCodeLocalState
	case errors.Is(err, ErrSuperseded):
		return string(conn.ReasonSuperseded)
	case errors.Is(err, ErrRevoked):
		return string(conn.ReasonRevoked)
	case errors.Is(err, conn.ErrUnsupportedSchema):
		return string(conn.ReasonSchemaMismatch)
	}
	if r := conn.Classify(err); r != "" && r != conn.ReasonNetwork {
		return string(r)
	}
	return statusCodeStopped
}

// enrollStatusCode names an enrollment attempt's failure. It separates "your
// token is bad" from "the server could not be reached", which is the same
// distinction ErrEnrollRejected exists to preserve: a user told their token was
// refused because their laptop was on a train would throw away a token that
// still works.
func enrollStatusCode(err error) string {
	switch {
	case errors.Is(err, ErrEnrollRejected):
		return statusCodeEnrollRejected
	case errors.Is(err, ErrNoEnrollmentToken):
		return statusCodeNoToken
	// Checked before the transport classifier, which would otherwise fold a
	// filesystem error into its `network` catch-all and blame a server that in
	// fact answered.
	case errors.Is(err, ErrLocalState):
		return statusCodeLocalState
	}
	return string(conn.Classify(err))
}

// statusWriter keeps Config.StatusFile current.
//
// It exists because the agent is otherwise a black box to the machine it runs
// on: everything it knows about its own connection goes out over that
// connection, which is exactly the channel that is broken when someone needs to
// know. A log line answers this for a person with a terminal; a file answers it
// for the OpenWrt status page, whose whole job is to explain a router to someone
// who will never open one.
//
// The producing callbacks run on session goroutines and must not block, so they
// only take a mutex, mutate a struct, and nudge a one-slot channel. All I/O
// happens on the writer goroutine, and coalesces: a burst of transitions
// collapses into one write, and losing an intermediate state is fine because
// only the current one is ever displayed.
type statusWriter struct {
	path   string
	outbox *wal.Store

	mu    sync.Mutex
	doc   statusDoc
	index map[string]int

	dirty chan struct{}
}

// newStatusWriter returns nil when path is empty, which is the ordinary case: a
// standalone agent's status surface is its log, and the desktop watches
// OnEvent. Every method is nil-safe so call sites stay unconditional.
func newStatusWriter(path string, cfg Config, outbox *wal.Store) *statusWriter {
	if path == "" {
		return nil
	}
	now := time.Now().Unix()
	w := &statusWriter{
		path:   path,
		outbox: outbox,
		doc: statusDoc{
			Schema:       statusFileSchema,
			PID:          os.Getpid(),
			AgentVersion: Version,
			StartedAt:    now,
			UpdatedAt:    now,
			Servers:      make([]serverStatus, len(cfg.Servers)),
		},
		index: make(map[string]int, len(cfg.Servers)),
		dirty: make(chan struct{}, 1),
	}
	for i, sc := range cfg.Servers {
		// Configured servers appear immediately, before any of them has been
		// reached. A page that lists nothing until the first success cannot
		// distinguish "still starting" from "misconfigured".
		w.doc.Servers[i] = serverStatus{Name: sc.Name, URL: sc.URL, State: statusConnecting, Since: now}
		w.index[sc.Name] = i
	}
	return w
}

// set applies mutate to one server's entry, refreshes its backlog depth, and
// asks the writer goroutine for a write. Safe to call from any goroutine.
func (w *statusWriter) set(server string, mutate func(*serverStatus)) {
	if w == nil {
		return
	}
	w.mu.Lock()
	if i, ok := w.index[server]; ok {
		mutate(&w.doc.Servers[i])
		w.doc.Servers[i].Pending = w.outbox.Pending(server)
		w.doc.UpdatedAt = time.Now().Unix()
	}
	w.mu.Unlock()
	w.nudge()
}

// setFatal records why the whole process is giving up, so the document that
// outlives it says so at the top rather than leaving a reader to infer it from a
// list of servers that may well be empty. Safe to call from any goroutine, and
// like every method here a no-op when there is no status file.
//
// It must be called BEFORE Run's teardown cancels the context: finish() below is
// what persists the document, and it decides between persisting and removing by
// asking whether there is anything worth keeping.
func (w *statusWriter) setFatal(err error) {
	if w == nil || err == nil {
		return
	}
	w.mu.Lock()
	w.doc.Fatal = shellSafe(err)
	w.doc.UpdatedAt = time.Now().Unix()
	w.mu.Unlock()
	w.nudge()
}

// refresh re-reads every server's backlog depth and stamps the document.
//
// Transitions alone would leave a connected agent's file frozen at the instant
// it connected, so a reader could not tell a healthy idle agent from one whose
// process died — and the backlog, the number that says whether a long outage is
// costing data, would never move while the outage lasted.
func (w *statusWriter) refresh() {
	if w == nil {
		return
	}
	w.mu.Lock()
	for i := range w.doc.Servers {
		w.doc.Servers[i].Pending = w.outbox.Pending(w.doc.Servers[i].Name)
	}
	w.doc.UpdatedAt = time.Now().Unix()
	w.mu.Unlock()
	w.nudge()
}

// nudge signals the writer without ever blocking the caller. A full channel
// already means "a write is pending", so dropping the signal loses nothing:
// the writer marshals whatever the latest state is when it gets there.
func (w *statusWriter) nudge() {
	select {
	case w.dirty <- struct{}{}:
	default:
	}
}

// run owns the file until ctx ends, then decides whether it should survive.
//
// For every state but one, removal is the honest report: the file describes a
// running agent, and one left behind by a stopped agent would read as a live
// status frozen at whatever the last transition was. A killed agent cannot clean
// up, so readers are expected to trust this file only while the service is
// actually running — the OpenWrt status method checks procd before looking at it.
//
// The exception is a terminal outcome, and it is the whole reason a reader wants
// this file. `no_token`, `enroll_rejected` and `stopped` mean the runner gave up
// and Run is returning, which on a router means procd respawns the agent into
// the same wall. Removing the file there deletes the only actionable sentence
// anyone had and leaves the status page cycling through startup states forever.
func (w *statusWriter) run(ctx context.Context) {
	if w == nil {
		return
	}
	for {
		select {
		case <-ctx.Done():
			w.finish()
			return
		case <-w.dirty:
			if err := w.write(); err != nil {
				// One line, not a retry loop: the next transition writes again,
				// and a status file that cannot be written must never be the
				// reason an agent stops monitoring.
				log.Printf("write status file %s: %v", w.path, err)
			}
		}
	}
}

// finish is the last thing run does: persist a terminal outcome, or remove the
// file.
//
// The final write is not optional. A terminal state is recorded by the runner
// goroutine and then Run returns immediately, so the cancel and the pending
// dirty signal are ready at the same moment — and a select with two ready cases
// picks between them at random. Half the time the loop above would exit without
// ever writing the state it exists to report.
func (w *statusWriter) finish() {
	if !w.hasFinalOutcome() {
		_ = os.Remove(w.path)
		return
	}
	if err := w.write(); err != nil {
		log.Printf("write status file %s: %v", w.path, err)
		// Better nothing than a document frozen mid-run that claims to describe
		// an agent which has in fact given up.
		_ = os.Remove(w.path)
	}
}

// hasFinalOutcome reports whether this document says something that must outlive
// the process — a server that gave up, or a process-level failure that means no
// server ever got a chance to.
func (w *statusWriter) hasFinalOutcome() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.doc.Fatal != "" {
		return true
	}
	for i := range w.doc.Servers {
		if w.doc.Servers[i].State == statusTerminal {
			return true
		}
	}
	return false
}

// write serialises the current document and replaces the file atomically.
//
// The rename is what lets a reader poll it without coordination: a page that
// refreshes every five seconds would otherwise eventually catch a half-written
// document and render an empty panel with no error anywhere. Marshalling holds
// the lock; the I/O does not, so a slow flash write never stalls a session
// goroutine reporting a state change. (The lock cannot be dropped any earlier
// than the marshal: the document owns a slice of server rows that session
// goroutines mutate in place, so handing the struct out and encoding it
// afterwards would be a copy of the header and a race on the rows.)
func (w *statusWriter) write() error {
	w.mu.Lock()
	data, err := json.Marshal(w.doc)
	w.mu.Unlock()
	if err != nil {
		return err
	}
	return replaceStatusFile(w.path, data)
}

// replaceStatusFile is the file half of write, split out so a process that never
// got as far as building a statusWriter can still leave the one document that
// explains why (see ReportStartupFailure).
func replaceStatusFile(path string, data []byte) error {
	data = append(data, '\n')

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	// Same directory as the target: rename is only atomic within a filesystem,
	// and on a router /tmp and the target could easily be different ones.
	tmp, err := os.CreateTemp(dir, ".status-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }() // no-op once the rename succeeded
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, 0o644); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
