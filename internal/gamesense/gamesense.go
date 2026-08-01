// Package gamesense turns frame-presentation data into game runs and buckets.
//
// The agent does not observe frames itself. Reading them means consuming the OS
// graphics event stream, which is a large platform-specific surface with its own
// licensing and signing story, so it lives in a separate sensor executable that
// the agent locates beside its own binary, supervises as a child process, and
// reads line-delimited JSON from. This package is the whole agent-side half of
// that contract: discovery, the capability probe, the supervisor, and the
// recorder that turns the sensor's per-second lines into the records the server
// stores.
//
// The sensor is optional by design. An install without it — the standalone
// agent, or any build that ships only the open-source pieces — reports the
// game.* permissions as unsupported and behaves exactly as it did before. That
// is the first of three states this package distinguishes:
//
//   - absent: no sensor executable. Nothing is reported beyond the unsupported
//     permission, because there is nothing to say.
//   - blocked: a sensor is installed but cannot capture (the middleware is
//     missing, its service is not answering, the two are different builds).
//     Still unsupported, but an event carries the reason, because this state is
//     fixable and indistinguishable from "absent" to anyone reading only the
//     permission report.
//   - working: runs and buckets flow.
//
// Nothing here listens on a port: the agent stays outbound-only. The sensor is a
// child process wired to pipes, and a job object makes the OS kill it if the
// agent dies without getting the chance to.
package gamesense

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/uuid"
	gs "github.com/nettact/protocol/gamesense"
	"github.com/nettact/protocol/telemetry"
)

// ProtoVersion is the sensor protocol this build speaks. Taken from the protocol
// package rather than restated, so the number the agent demands of a sensor and
// the number the shared types describe cannot drift apart.
const ProtoVersion = gs.ProtoVersion

// ExeName is the sensor executable, looked up beside the agent's own binary.
const ExeName = "nettact-sensor.exe"

// PathEnv overrides the sensor location. This exists for development, where the
// agent runs from a build directory and the sensor from its own: it is a
// discovery override, not agent configuration, so it is read here rather than
// threaded through the config file.
const PathEnv = "NETTACT_SENSOR_PATH"

// The reasons a sensor gives for being unable to capture. They are named here so
// the agent's own vocabulary is one list rather than two half-lists, but they are
// the protocol's constants: a reason travels from the sensor through the agent to
// the console unchanged, and a copy of the string here would be a second place
// for it to be wrong.
const (
	ReasonUnsupportedOS      = gs.ReasonUnsupportedOS
	ReasonPresentMonMissing  = gs.ReasonPresentMonMissing
	ReasonServiceUnavailable = gs.ReasonServiceUnavailable
	ReasonVersionMismatch    = gs.ReasonVersionMismatch
	ReasonSessionLost        = gs.ReasonSessionLost
)

// The reasons the agent produces itself, for the failures a sensor cannot report
// because it is the thing that failed.
const (
	// ReasonProbeFailed is the agent's own code for a sensor that did not answer
	// the probe at all — crashed, timed out, or emitted something unparseable.
	ReasonProbeFailed = "probe_failed"
	// ReasonProtoMismatch is a sensor speaking a protocol version this agent does
	// not implement.
	ReasonProtoMismatch = "proto_mismatch"
	// ReasonSensorExited is the fallback when a sensor stopped without naming a
	// reason on the way out. It says only what the agent actually observed.
	ReasonSensorExited = "sensor_exited"
)

// ProbeResult is the answer to "can this machine capture frames right now". OK is
// the only field the permission decision reads; the rest explains a negative
// answer to a human.
type ProbeResult struct {
	OK            bool
	Proto         int
	Reason        string
	SensorVersion string
	// PMVersion is the frame source's version as the sensor read it. Diagnostic
	// only — it appears in logs and support reports, never in a decision.
	PMVersion string
}

// parseProbeLine turns the single line a `--probe` run prints into a result. A
// sensor that answers "no" keeps its own reason; anything unparseable is the
// agent's own probe_failed.
func parseProbeLine(b []byte) ProbeResult {
	var env gs.Envelope
	if err := json.Unmarshal(b, &env); err != nil || env.Type != gs.TypeProbe {
		return ProbeResult{Reason: ReasonProbeFailed}
	}
	var p gs.Probe
	if err := json.Unmarshal(b, &p); err != nil {
		return ProbeResult{Reason: ReasonProbeFailed}
	}
	if p.Proto != ProtoVersion {
		// The version fields are still worth keeping: they are what turns "the
		// sensor is wrong" into "this build of the sensor is wrong" in a log.
		return ProbeResult{Proto: p.Proto, SensorVersion: p.SensorVersion, Reason: ReasonProtoMismatch}
	}
	res := ProbeResult{
		OK:            p.OK,
		Proto:         p.Proto,
		Reason:        p.Reason,
		SensorVersion: p.SensorVersion,
		PMVersion:     p.PMVersion,
	}
	if !res.OK && res.Reason == "" {
		// A sensor that says it cannot capture without saying why is still
		// blocked; give the state a code rather than an empty string.
		res.Reason = ReasonProbeFailed
	}
	return res
}

// maxBuffered bounds the bucket buffer. At one bucket per second this is ten
// minutes of backlog, far more than the seconds an upload cycle actually takes
// to drain it — the cap exists so a wedged drain cannot grow the buffer without
// limit, not as a working size.
const maxBuffered = 600

// Recorder assembles the sensor's line stream into the records the server
// stores: runs, and the per-second buckets that hang from them.
//
// The grouping is the whole job. A sensor reports seconds and transitions; only
// something that remembers what it last saw can say that two seconds belong to
// the same session, and that is the unit a player recognizes. The rules for what
// survives inside one run are on Run in the protocol package — a launcher handing
// the game a new pid, and a window title changing between menu and match, are
// both the same run.
//
// Runs are handed out again on every drain in which they changed, because the
// server upserts them: an ending recorded after the last upload of its buckets
// still reaches the server, and a run interrupted by a disconnect is completed
// on reconnect rather than left open forever.
type Recorder struct {
	mu sync.Mutex
	// source and caps describe how the current sensor process measures, taken
	// from its hello. They belong to the sensor run, not to any one game run, so
	// they outlive the runs started from them.
	source string
	caps   []string

	cur    *gs.Run
	curPID int
	// lastBucketTS is the second the current run was last seen presenting. It is
	// what a run ends at: the sensor's own last observed second is a fact, while
	// the agent's clock at the moment it noticed the game stopped is an artifact
	// of when the status line happened to arrive.
	lastBucketTS time.Time
	// parked holds runs that stopped presenting but whose process is still alive
	// enough to come back, keyed by that process id. See reviveWindow.
	parked map[int]*gs.Run

	dirty    []*gs.Run
	dirtySet map[string]bool

	buckets []gs.Bucket
	dropped int
}

// reviveWindow is how long a process that stops presenting keeps its run.
//
// A person moves between windows constantly, and every move used to end one
// session and begin another — an evening came back as a row per alt-tab, each
// with figures describing a fragment nobody played. Coming back to the same
// process id is coming back to the same thing, so its run is reopened rather
// than replaced.
//
// The key is the process id and not the executable name because the name is not
// unique: two windows of the same browser, or two copies of a game, are
// different sessions that happen to share a program.
const reviveWindow = time.Hour

// hello records how this sensor process measures. Every run started from here on
// carries it, so a later comparison of two runs can tell a change in the machine
// apart from a change in what could be observed about it.
func (r *Recorder) hello(h gs.Hello) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.source = h.Source
	r.caps = append([]string(nil), h.Caps...)
}

// status applies one sensor transition. Idle and error both mean nothing is
// presenting any more; a state this build does not know is ignored, so a newer
// sensor can name a state without ending runs on older agents.
func (r *Recorder) status(st gs.Status) {
	r.mu.Lock()
	defer r.mu.Unlock()
	switch st.State {
	case gs.StateTracking:
		pid := 0
		if st.PID != nil {
			pid = *st.PID
		}
		r.track(pid, st.Proc, st.Title)
	case gs.StateIdle, gs.StateError:
		// Parked rather than closed outright: a session that stopped presenting
		// long enough to be called over is exactly the one a person returns to,
		// and the same process id coming back inside the window is the same
		// session resuming. The ending recorded here stands unless it does.
		r.parkCurrent(time.Now().UTC())
	}
}

// track folds a tracking status into the current run, or moves to another one.
// Caller holds mu.
func (r *Recorder) track(pid int, proc, title string) {
	if proc == "" {
		// A run is identified by its process, and there is nothing to identify
		// this one by. The sec lines that follow name it, so the data is not lost.
		return
	}
	if r.cur != nil && (pid == r.curPID || proc == r.cur.Proc) {
		// Still the session in progress. The process id identifies it, but the
		// program running under it also does while that session is live: a
		// launcher handing the game off replaces the id mid-session, and treating
		// that as a new session would split exactly the case the handoff rule
		// exists for. The id it is now known by moves with it.
		//
		// The id is what identifies a session that has STOPPED — see switchTo.
		// Two launches of the same program are two sessions, and only the id
		// tells them apart once neither is running.
		if pid > 0 {
			r.curPID = pid
		}
		// An absent title is "no window could be read", which is ordinary for a
		// game mid-launch — clearing a title we already have on that basis would
		// replace a fact with the absence of one.
		r.retitle(title)
		return
	}
	r.switchTo(pid, proc, title, time.Now().UTC())
}

func (r *Recorder) retitle(title string) {
	if title != "" && title != r.cur.Title {
		r.cur.Title = title
		r.markDirty(r.cur)
	}
}

// switchTo makes pid the process being recorded, reopening its run when it has
// one from the recent past. Caller holds mu.
//
// The current run is parked rather than forgotten, because the person is very
// likely coming back to it — that is what alt-tab is.
func (r *Recorder) switchTo(pid int, proc, title string, now time.Time) {
	r.parkCurrent(now)
	r.sweepParked(now)

	if run := r.parked[pid]; run != nil && run.Proc == proc {
		// Reopening: the end recorded when it was parked was provisional, and the
		// server takes the newer report. Its extent grows to cover the gap, which
		// is honest — the session did span it, with a pause in the middle that the
		// absent seconds already describe.
		delete(r.parked, pid)
		run.EndedAt = nil
		r.cur, r.curPID, r.lastBucketTS = run, pid, time.Time{}
		r.retitle(title)
		r.markDirty(run)
		return
	}
	r.start(pid, proc, title, now)
}

// start opens a run at startedAt. Caller holds mu.
func (r *Recorder) start(pid int, proc, title string, startedAt time.Time) {
	run := &gs.Run{
		ID:         uuid.NewString(),
		Proc:       proc,
		Title:      title,
		StartedAt:  startedAt,
		LastSeenAt: startedAt,
		Source:     r.source,
		Caps:       append([]string(nil), r.caps...),
	}
	r.cur, r.curPID = run, pid
	r.lastBucketTS = time.Time{}
	r.markDirty(run)
}

// parkCurrent sets the current run aside, ended but reopenable. Caller holds mu.
func (r *Recorder) parkCurrent(now time.Time) {
	if r.cur == nil {
		return
	}
	run, pid := r.cur, r.curPID
	r.closeRun()
	if pid <= 0 {
		// Nothing to recognize it by later. It stays ended.
		return
	}
	if r.parked == nil {
		r.parked = map[int]*gs.Run{}
	}
	r.parked[pid] = run
	// Swept here as well as on the way back in, so a machine that parks sessions
	// and never returns to any of them does not hold every one of them forever.
	r.sweepParked(now)
}

// sweepParked forgets runs whose process has been quiet past the window.
//
// The window runs from when the run was last SEEN, not from when it began: a
// six-hour session interrupted for a minute is one session, and measuring from
// its start would refuse to reopen it. Caller holds mu.
func (r *Recorder) sweepParked(now time.Time) {
	for pid, run := range r.parked {
		if now.Sub(run.LastSeenAt) > reviveWindow {
			delete(r.parked, pid)
		}
	}
}

// closeRun ends the current run, if there is one. Caller holds mu.
func (r *Recorder) closeRun() {
	if r.cur == nil {
		return
	}
	ended := r.lastBucketTS
	if ended.IsZero() {
		// Tracking began and stopped without a single second of frames. There is
		// no observed moment to end at, so the agent's own clock is all there is.
		ended = time.Now().UTC()
	}
	r.cur.EndedAt = &ended
	r.markDirty(r.cur)
	r.cur, r.curPID, r.lastBucketTS = nil, 0, time.Time{}
}

// endRun ends the current run from outside the line stream — the sensor process
// stopped, so nothing is being observed whether or not it said so.
//
// Parked, like any other ending: the supervisor restarts a failed sensor within
// seconds, and the game it was watching is still running. Losing the session to
// a sensor crash would be the component reporting on its own reliability rather
// than on the game.
func (r *Recorder) endRun() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.parkCurrent(time.Now().UTC())
}

// sec records one second of presentation.
func (r *Recorder) sec(m gs.Sec) {
	ts := m.TS
	if ts.IsZero() {
		// A second with no timestamp would land at the zero time and sort before
		// every real point in the run.
		ts = time.Now()
	}
	ts = ts.UTC()

	r.mu.Lock()
	defer r.mu.Unlock()
	if m.Proc == "" && r.cur == nil {
		// Frames arrived before anything could name the process that drew them.
		// Opening a run here would be worse than losing the second: the run has
		// nothing to identify it in a list, and when the name does arrive on the
		// next status this recorder would close the nameless run and open a
		// second one — turning one session into two, which is the thing runs
		// exist to prevent.
		log.Printf("gamesense: discarding a second whose process could not be named")
		return
	}
	switch {
	case r.cur == nil:
		// Frames before any status, or after a session the sensor declared over.
		// The second happened, so it gets a run — reopening the one this process
		// id already had, when it has one. A sec line names its process but never
		// its window, so a new run stays untitled rather than carrying a guess.
		r.switchTo(m.PID, m.Proc, "", ts)
	case m.PID != r.curPID && m.Proc != r.cur.Proc:
		// A different program is drawing. The status line normally says so first;
		// arriving here means the seconds moved before the transition did, and
		// attributing them to the previous session would put one game's frames in
		// another game's record.
		r.switchTo(m.PID, m.Proc, "", ts)
	case m.PID != r.curPID:
		// Same program, new process id: a launcher handing the game off. One
		// session, and the id it is now known by moves with it.
		r.curPID = m.PID
	}
	r.cur.LastSeenAt = ts
	r.lastBucketTS = ts
	r.markDirty(r.cur)
	r.push(gs.Bucket{RunID: r.cur.ID, TS: ts, Sample: m.Sample})
}

// markDirty queues a run to be sent on the next drain. Caller holds mu.
func (r *Recorder) markDirty(run *gs.Run) {
	if r.dirtySet[run.ID] {
		return
	}
	if r.dirtySet == nil {
		r.dirtySet = map[string]bool{}
	}
	r.dirtySet[run.ID] = true
	r.dirty = append(r.dirty, run)
}

// push records one bucket, dropping the oldest when the buffer is full. Dropping
// the oldest keeps the most recent seconds, which is what a live chart shows.
// Caller holds mu.
//
// Overflow is logged rather than counted quietly. Reaching this point means ten
// minutes of play went unrecorded, and the gap it leaves in a session is
// indistinguishable from a game that was not running — so the one place that
// knows the difference has to say so.
func (r *Recorder) push(b gs.Bucket) {
	if len(r.buckets) >= maxBuffered {
		copy(r.buckets, r.buckets[1:])
		r.buckets = r.buckets[:len(r.buckets)-1]
		r.dropped++
		if r.dropped == 1 || r.dropped%maxBuffered == 0 {
			log.Printf("gamesense: dropped %d buffered second(s); the upload path is not keeping up", r.dropped)
		}
	}
	r.buckets = append(r.buckets, b)
}

// Drain removes and returns the runs that changed since the last drain and every
// buffered bucket. A run still in progress is returned as it stands now, which is
// what makes it visible on the server before it ends.
func (r *Recorder) Drain() ([]gs.Run, []gs.Bucket) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var runs []gs.Run
	if len(r.dirty) > 0 {
		runs = make([]gs.Run, len(r.dirty))
		for i, run := range r.dirty {
			runs[i] = *run
		}
		r.dirty, r.dirtySet = nil, nil
	}
	buckets := r.buckets
	r.buckets = nil
	return runs, buckets
}

// Requeue puts drained records back after the caller failed to persist them.
//
// Draining empties the recorder, so a caller that drops what it took loses those
// seconds for good — a full disk or a locked database for one upload cycle would
// take a gap out of the middle of a session rather than delaying it. Buckets go
// back at the front because they are older than anything recorded since, and the
// buffer is ordered by time; the runs are simply marked dirty again, since the
// recorder holds the live copy and re-sending is what the server's upsert is for.
func (r *Recorder) Requeue(runs []gs.Run, buckets []gs.Bucket) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(buckets) > 0 {
		r.buckets = append(buckets, r.buckets...)
		// The combined length can exceed the cap, so trim from the front, which
		// is the same oldest-first rule push follows.
		if extra := len(r.buckets) - maxBuffered; extra > 0 {
			r.buckets = r.buckets[extra:]
			r.dropped += extra
			log.Printf("gamesense: dropped %d requeued second(s) that no longer fit", extra)
		}
	}
	for i := range runs {
		run := r.cur
		if run == nil || run.ID != runs[i].ID {
			// The run has already ended, so the recorder no longer holds it; keep
			// the copy that was handed back. Without this, an ending that failed
			// to persist would never be sent and the run would stay open forever.
			ended := runs[i]
			run = &ended
		}
		r.markDirty(run)
	}
}

// peek returns the buffered buckets without draining, for tests that need to
// watch a live stream fill.
func (r *Recorder) peek() []gs.Bucket {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]gs.Bucket(nil), r.buckets...)
}

// DroppedCount reports how many buckets the buffer has discarded.
func (r *Recorder) DroppedCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.dropped
}

// Supervisor runs the sensor and records what it produces.
//
// It owns the process lifetime: spawn, read, restart with backoff, and stop when
// its context is cancelled. What arrives goes into the embedded Recorder, which
// the agent drains on its own schedule — decoupling the sensor's one-second
// cadence from the upload cycle without either waiting on the other.
type Supervisor struct {
	path string
	emit func(telemetry.Event)
	// run performs one sensor run. It is a field so the restart policy can be
	// exercised on every platform, including the ones where spawning the sensor
	// is a compile-time stub.
	run func(context.Context) error

	// Recorder is embedded rather than owned behind an accessor: the agent's only
	// interest in a supervisor is what it recorded, so Drain reads the same on
	// both.
	Recorder

	reasonMu sync.Mutex
	// reason is the last failure the sensor named on its own way out. The process
	// exit code says only that it stopped; this says why, in the vocabulary the
	// console can explain.
	reason string
}

// NewSupervisor returns a supervisor for the sensor at path. emit delivers
// lifecycle events; it may be nil, and is called from the supervisor goroutine.
func NewSupervisor(path string, emit func(telemetry.Event)) *Supervisor {
	s := &Supervisor{path: path, emit: emit}
	s.run = s.runOnce
	return s
}

// setReason records the failure the sensor named for itself.
func (s *Supervisor) setReason(r string) {
	s.reasonMu.Lock()
	s.reason = r
	s.reasonMu.Unlock()
}

// takeReason returns the recorded failure reason and clears it, so one run's
// reason can never be attributed to the next.
func (s *Supervisor) takeReason() string {
	s.reasonMu.Lock()
	defer s.reasonMu.Unlock()
	r := s.reason
	s.reason = ""
	return r
}

// event delivers a lifecycle event if an emitter was supplied.
func (s *Supervisor) event(t telemetry.EventType, sev telemetry.Severity, msg string, attrs map[string]string) {
	if s.emit == nil {
		return
	}
	s.emit(telemetry.Event{
		ID:       uuid.NewString(),
		TS:       time.Now().UTC(),
		Type:     t,
		Layer:    telemetry.LayerLocal,
		Severity: sev,
		Message:  msg,
		Attrs:    attrs,
	})
}

// Backoff schedule for restarts. A sensor exits for ordinary reasons too — a
// driver reset, a display topology change — so the first retries are quick and
// only a persistent failure backs off to the ceiling. Vars so tests can compress
// the schedule rather than wait it out.
var (
	backoffMin = 1 * time.Second
	backoffMax = 60 * time.Second
	// healthyFor is how long a run must last to count as healthy and reset the
	// backoff. Shorter than this and the sensor is failing on startup, however
	// far apart the attempts are spaced.
	healthyFor = 2 * time.Minute
)

// failuresBeforeEvent is how many consecutive short runs are reported. One or
// two are noise; a third means the sensor is not going to start on its own.
const failuresBeforeEvent = 3

// Run supervises the sensor until ctx is cancelled. It returns only on
// cancellation: a sensor that keeps failing keeps being retried at the backoff
// ceiling, because the conditions that stop it (a game exiting, a driver
// hiccup, a transient permission change) are the kind that come back on their
// own, and a permanent stop would need an agent restart to recover from.
func (s *Supervisor) Run(ctx context.Context) {
	backoff := backoffMin
	failures := 0
	reported := false

	for ctx.Err() == nil {
		s.takeReason() // a new run does not inherit the last one's failure

		errCh := make(chan error, 1)
		go func() { errCh <- s.run(ctx) }()

		// Health is a property of a run that is *still going*, not of one that
		// ended. A working sensor runs until the agent stops it, so waiting for the
		// run to return before calling it healthy would mean never calling it
		// healthy — and never clearing a failure that has already been reported.
		healthy := time.NewTimer(healthyFor)
		var err error
		var wasHealthy bool
		select {
		case err = <-errCh:
			healthy.Stop()
		case <-healthy.C:
			wasHealthy = true
			if reported {
				s.event(telemetry.EventGameSensorRecovered, telemetry.SeverityInfo,
					"game sensor recovered", nil)
				reported = false
			}
			backoff, failures = backoffMin, 0
			// Keep waiting for the run itself; the loop only turns over when the
			// sensor actually stops.
			err = <-errCh
		}
		// The sensor is gone, so nothing is observing the game any more. Closing the
		// run here rather than waiting for a status that will never come is what
		// keeps a restart from stitching the seconds either side of the gap into one
		// continuous session.
		s.endRun()
		if ctx.Err() != nil {
			return
		}

		if !wasHealthy {
			failures++
			if failures >= failuresBeforeEvent && !reported {
				attrs := map[string]string{"path": s.path, "reason": ReasonSensorExited}
				// The sensor names its own failure on the way out; that code is what
				// distinguishes a lost capture session from missing middleware, and it
				// is the only part of this event anything can act on.
				if reason := s.takeReason(); reason != "" {
					attrs["reason"] = reason
				}
				if err != nil {
					attrs["detail"] = err.Error()
				}
				s.event(telemetry.EventGameSensorFailed, telemetry.SeverityWarn,
					"game sensor keeps exiting", attrs)
				reported = true
			}
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		if backoff *= 2; backoff > backoffMax {
			backoff = backoffMax
		}
	}
}

// maxLineBytes caps one sensor line. A sec line with a full histogram is a couple
// of kilobytes; this leaves room to grow while keeping a sensor that starts
// emitting garbage from being able to exhaust memory one line at a time.
const maxLineBytes = 64 * 1024

// consume reads the sensor's line stream into the recorder until the stream
// ends. Malformed lines are skipped rather than fatal: one garbled line must not
// end a session that is otherwise producing data.
//
// Each line is decoded twice — the envelope for its type, then the struct that
// type names. A single union struct would be cheaper by one pass, but probe and
// hello have never agreed on the shape of their capability field, so one struct
// cannot describe both without one of them being wrong.
//
// It returns the reason the stream stopped being usable, or nil at a clean end.
// A line past the cap is not merely skipped: a Scanner stops for good at that
// point, and the pipe it was reading is one the sensor is still writing to, so
// abandoning it silently would leave the sensor blocked on a full pipe with the
// agent waiting for it to exit. Reporting the failure lets runOnce drain the
// rest and end the run, which is what puts restart and reporting in motion.
func (s *Supervisor) consume(r io.Reader) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 8*1024), maxLineBytes)
	for sc.Scan() {
		line := sc.Bytes()
		var env gs.Envelope
		if err := json.Unmarshal(line, &env); err != nil {
			continue
		}
		switch env.Type {
		case gs.TypeSec:
			var m gs.Sec
			if json.Unmarshal(line, &m) != nil {
				continue
			}
			s.sec(m)
		case gs.TypeStatus:
			var st gs.Status
			if json.Unmarshal(line, &st) != nil {
				continue
			}
			// A sensor about to give up names the reason first. Keeping it is what
			// turns "the sensor exited" into "the capture session was lost", which is
			// the difference between an event an operator can act on and one they
			// cannot.
			if st.State == gs.StateError && st.Reason != "" {
				s.setReason(st.Reason)
			}
			s.status(st)
		case gs.TypeHello:
			var h gs.Hello
			if json.Unmarshal(line, &h) != nil {
				continue
			}
			s.hello(h)
		default:
			// A message a newer sensor added. Ignoring it is what lets the sensor
			// grow without the agent having to be taught first.
		}
	}
	return sc.Err()
}

// locateBeside returns the sensor path for an agent executable at exePath.
func locateBeside(exePath string) string {
	return filepath.Join(filepath.Dir(exePath), ExeName)
}

// Locate finds the sensor executable, preferring the development override.
// It reports false when no sensor is installed, which is the ordinary case for
// every build that does not ship one.
//
// dev must be true only for an unstamped developer build. It unlocks a search
// of the working directory, which a release build must never do: the result is
// an executable this agent then spawns, so honouring an inherited cwd would let
// whoever controls it choose that program. The same guard, and the same reason,
// as the desktop console's dev dist lookup.
func Locate(dev bool) (string, bool) {
	if !platformSupported {
		return "", false
	}
	if p := os.Getenv(PathEnv); p != "" {
		if fileExists(p) {
			return p, true
		}
		// An explicit override that points nowhere is a mistake worth surfacing as
		// "no sensor" rather than quietly resolving to a different one.
		return "", false
	}
	if exe, err := os.Executable(); err == nil {
		if p := locateBeside(exe); fileExists(p) {
			return p, true
		}
	}
	// `go run` builds the executable into a temporary directory, so "beside the
	// agent" finds nothing and a developer would otherwise have to set the
	// override on every run. Look where the sensor is actually built instead.
	if dev {
		if cwd, err := os.Getwd(); err == nil {
			for _, candidate := range []string{
				filepath.Join(cwd, "..", devBuildDir, "dist", ExeName),
				filepath.Join(cwd, devBuildDir, "dist", ExeName),
			} {
				if fileExists(candidate) {
					return filepath.Clean(candidate), true
				}
			}
		}
	}
	return "", false
}

// devBuildDir is the workspace module whose dist directory a locally built
// sensor lands in, reached as a sibling of the module the developer is running
// from.
const devBuildDir = "desktop"

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}
