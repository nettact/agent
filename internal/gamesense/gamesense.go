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
	"reflect"
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

// ProbeResult is the answer to "can this machine capture frames right now". OK
// and GPUOK are the fields the permission decision reads; the rest explains a
// negative answer to a human.
type ProbeResult struct {
	OK bool
	// GPUOK is the narrower second answer: the sensor also registered a GPU
	// telemetry query. It is a separate capability because the two fail apart —
	// a driver that publishes no adapter telemetry still presents frames — so a
	// false here alongside a true OK is an ordinary machine, not a fault, and
	// carries no reason of its own.
	GPUOK         bool
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
		OK: p.OK,
		// A sensor that cannot open a frame session at all cannot have registered a
		// GPU query either, so a gpu_ok riding on a false ok is a contradiction the
		// agent resolves rather than passes on: the narrower capability never
		// outlives the one it is collected on.
		GPUOK:         p.OK && p.GPUOK,
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
	// now is where this component reads the wall clock. Every moment that decides
	// a run's lifetime comes from here: when a parked run falls out of
	// reviveWindow, the ending given to a run that produced no seconds, and the
	// stamp put on a second the sensor did not date.
	//
	// It is a seam for the tests, and specifically so a test can state where its
	// fixture seconds sit relative to reviveWindow instead of inheriting that from
	// the hour the suite happens to run at. Fixtures are written with fixed
	// timestamps; measured against a real time.Now they are inside the window on
	// the day they are written and outside it forever after, which turned the
	// run-continuity tests into a suite that went red the following morning.
	//
	// Set once, at construction, before anything is fed to the recorder — so
	// reading it needs no lock, which matters because sec stamps its second before
	// taking one.
	now func() time.Time
	// source and caps describe how the current sensor process measures, taken
	// from its hello. They belong to the sensor run, not to any one game run, so
	// they outlive the runs started from them.
	source string
	caps   []string
	// tiers maps profile id to the tier the running sensor was configured with.
	// It is what turns a run's profile into the depth it was captured at, which
	// the hello cannot say: a sensor declares its capabilities once for the whole
	// process, while the depth it actually collects at is decided per tracked
	// process from this table. Fixed for the life of one sensor process, because
	// changing it is what restarts the sensor.
	tiers map[string]string

	cur    *session
	curPID int
	// lastBucketTS is the second the current run was last seen presenting. It is
	// what a run ends at: the sensor's own last observed second is a fact, while
	// the agent's clock at the moment it noticed the game stopped is an artifact
	// of when the status line happened to arrive.
	lastBucketTS time.Time
	// parked holds runs that stopped presenting but whose process is still alive
	// enough to come back, keyed by that process id. See reviveWindow.
	parked map[int]*session

	dirty    []*gs.Run
	dirtySet map[string]bool

	buckets []gs.Bucket
	dropped int
}

// session is a run plus what the recorder knows about it that the record itself
// does not carry.
type session struct {
	run *gs.Run
	// profiled records that a tracking status has told this recorder which
	// profile the run belongs to — including the answer "none".
	//
	// It exists because "we have not been told yet" and "we were told it matches
	// nothing" have to behave differently. A run opened by a sec line, before any
	// status, has no assignment yet, and the first status that names one stamps it
	// in place. A run that HAS an assignment never changes it: a later status
	// naming a different one (or none) describes a different game, and the run
	// ends there so its seconds keep the assignment they were collected under.
	profiled bool
	// depth is how deeply this run's seconds were measured — gs.TierDiag when the
	// profile it matched is configured for diagnostics, gs.TierBase otherwise,
	// which includes every unprofiled process. It is a property of the run and
	// not of the sensor process: one sensor collects at both depths at once, deep
	// for the games the site is diagnosing and shallow for everything else, so a
	// process-wide answer would be wrong for half the runs in a mixed
	// configuration.
	//
	// It is immutable for the same reason the assignment is, and it is what the
	// run's Caps are cut to: a run declaring a capability it never fills leaves
	// the console rendering an empty diagnostic chart, which reads as "measured,
	// nothing was wrong" rather than "never measured".
	depth string
}

// profileClaim is what one sensor line says about which game a run belongs to. A
// tracking status always makes a claim, possibly the claim that the process
// matched no profile; a sec line makes none at all. The difference decides
// whether a run continues or a new one begins, so the two cannot be represented
// by the same empty string.
type profileClaim struct {
	id    string
	known bool
}

// claimed is the claim a tracking status makes; id may be empty, which is the
// positive claim that the process matched no profile.
func claimed(id string) profileClaim { return profileClaim{id: id, known: true} }

// unclaimed is what a sec line says about the profile: nothing.
var unclaimed = profileClaim{}

// accepts reports whether a line making this claim, for a run that would now be
// captured at depth, belongs to the session.
//
// A claimless line always does — a sec line says nothing about the profile and
// must never split a run over it. A claim on a run with no assignment yet
// establishes it. Otherwise only the identical assignment AT THE SAME DEPTH
// continues the run, which is what makes both immutable once known.
//
// Depth is checked beside the id because the same profile can be measured two
// ways: switching a game between base and diag changes what its seconds contain,
// and stitching the two together would produce one run whose first half silently
// lacks the breakdowns its capabilities promise. The change can only reach the
// sensor through a restart, which is the same boundary a reassignment crosses.
func (s *session) accepts(c profileClaim, depth string) bool {
	if !c.known || !s.profiled {
		return true
	}
	return s.run.ProfileID == c.id && s.depth == depth
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

// diagCaps are the capabilities only a diag-depth capture fills. A sensor
// declares them once, for the process, because it CAN collect them here; whether
// it does is decided per tracked game from its tier. Stripping them from a run
// the sensor was never going to collect them for is the difference between a
// console that shows a game had no diagnostics and one that shows six charts
// that will never draw a point.
var diagCaps = map[string]bool{
	gs.CapCPUSplit:    true,
	gs.CapGPUSplit:    true,
	gs.CapLatency:     true,
	gs.CapGPUTel:      true,
	gs.CapProcVRAM:    true,
	gs.CapBusiestCore: true,
}

// setProfileTiers adopts the configuration the sensor is being run with, as the
// table that turns a run's profile into the depth it is captured at.
func (r *Recorder) setProfileTiers(cfg gs.Config) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.tiers = nil
	if len(cfg.Profiles) == 0 {
		return
	}
	r.tiers = make(map[string]string, len(cfg.Profiles))
	for _, p := range cfg.Profiles {
		r.tiers[p.ID] = p.Tier
	}
}

// depthFor is the depth a run matching this profile is captured at. Everything
// the site has not asked for diagnostics on — including every process matching
// no profile at all — is base, which is the floor rather than a guess: base is
// what the sensor collects for anything it was not told to go deeper on.
// Caller holds mu.
func (r *Recorder) depthFor(profileID string) string {
	if profileID != "" && r.tiers[profileID] == gs.TierDiag {
		return gs.TierDiag
	}
	return gs.TierBase
}

// capsFor cuts the sensor's declared capabilities down to what a run at this
// depth will actually carry. Caller holds mu.
func (r *Recorder) capsFor(depth string) []string {
	if depth == gs.TierDiag {
		return append([]string(nil), r.caps...)
	}
	caps := make([]string, 0, len(r.caps))
	for _, c := range r.caps {
		if !diagCaps[c] {
			caps = append(caps, c)
		}
	}
	return caps
}

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
		r.track(pid, st.Proc, st.Title, claimed(st.ProfileID))
	case gs.StateIdle, gs.StateError:
		// Parked rather than closed outright: a session that stopped presenting
		// long enough to be called over is exactly the one a person returns to,
		// and the same process id coming back inside the window is the same
		// session resuming. The ending recorded here stands unless it does.
		r.parkCurrent(r.now().UTC())
	}
}

// track folds a tracking status into the current run, or moves to another one.
// Caller holds mu.
func (r *Recorder) track(pid int, proc, title string, profile profileClaim) {
	if proc == "" {
		// A run is identified by its process, and there is nothing to identify
		// this one by. The sec lines that follow name it, so the data is not lost.
		return
	}
	if r.cur != nil && (pid == r.curPID || proc == r.cur.run.Proc) && r.cur.accepts(profile, r.depthFor(profile.id)) {
		// Still the session in progress. The process id identifies it, but the
		// program running under it also does while that session is live: a
		// launcher handing the game off replaces the id mid-session, and treating
		// that as a new session would split exactly the case the handoff rule
		// exists for. The id it is now known by moves with it.
		//
		// The id is what identifies a session that has STOPPED — see switchTo.
		// Two launches of the same program are two sessions, and only the id
		// tells them apart once neither is running.
		//
		// A changed profile assignment is the one thing that does NOT continue the
		// run, however well the process matches: see stampProfile.
		if pid > 0 {
			r.curPID = pid
		}
		// An absent title is "no window could be read", which is ordinary for a
		// game mid-launch — clearing a title we already have on that basis would
		// replace a fact with the absence of one.
		r.retitle(title)
		r.stampProfile(profile)
		return
	}
	r.switchTo(pid, proc, title, profile, r.now().UTC())
}

func (r *Recorder) retitle(title string) {
	if title != "" && title != r.cur.run.Title {
		r.cur.run.Title = title
		r.markDirty(r.cur.run)
	}
}

// stampProfile records which game the current run is, the first time a status
// says so. Caller holds mu, and has established that the run accepts the claim.
//
// A profile assignment is written once and never rewritten. It describes how the
// seconds already collected were captured — which games the site was recording,
// and under which rules — so moving it would retroactively file a whole session
// under a game it was not being recorded as. When the assignment changes, the run
// ends and a new one begins instead (see accepts and switchTo); the change can
// only happen across a sensor restart, because a running sensor's configuration
// is fixed.
//
// The first stamp is not a change. A run opened by a sec line, before any status
// could name the process's profile, has no assignment yet, and the status that
// arrives next fills it in place rather than splitting a session in two over its
// own first second.
func (r *Recorder) stampProfile(profile profileClaim) {
	if !profile.known || r.cur.profiled {
		return
	}
	r.cur.profiled = true
	if profile.id != "" {
		r.cur.run.ProfileID = profile.id
		r.markDirty(r.cur.run)
	}
	// The depth is stamped with the assignment, because it is derived from it. A
	// run held at base while nothing had named its profile is not a run that was
	// captured shallowly — it is one whose depth was not knowable yet, and the
	// sensor was already collecting at the game's real depth for the seconds it
	// covers. Widening here is the same first stamp, not a change: only a later,
	// different assignment moves a run, and that splits it.
	if depth := r.depthFor(profile.id); depth != r.cur.depth {
		r.cur.depth = depth
		r.cur.run.Caps = r.capsFor(depth)
		r.markDirty(r.cur.run)
	}
}

// switchTo makes pid the process being recorded, reopening its run when it has
// one from the recent past. Caller holds mu.
//
// The current run is parked rather than forgotten, because the person is very
// likely coming back to it — that is what alt-tab is.
func (r *Recorder) switchTo(pid int, proc, title string, profile profileClaim, now time.Time) {
	r.parkCurrent(now)
	r.sweepParked(now)

	// The parked run is reopened only if it is the same program AND the same game
	// measured the same way: a process that comes back matching a different
	// profile than it was recorded under — or the same profile now recorded at a
	// different depth — is a new run, so the seconds either side of the restart
	// keep the assignment and the depth each was collected with.
	if s := r.parked[pid]; s != nil && s.run.Proc == proc && s.accepts(profile, r.depthFor(profile.id)) {
		// Reopening: the end recorded when it was parked was provisional, and the
		// server takes the newer report. Its extent grows to cover the gap, which
		// is honest — the session did span it, with a pause in the middle that the
		// absent seconds already describe.
		delete(r.parked, pid)
		s.run.EndedAt = nil
		r.cur, r.curPID, r.lastBucketTS = s, pid, time.Time{}
		r.retitle(title)
		r.stampProfile(profile)
		r.markDirty(s.run)
		return
	}
	r.start(pid, proc, title, profile, now)
}

// start opens a run at startedAt. Caller holds mu.
func (r *Recorder) start(pid int, proc, title string, profile profileClaim, startedAt time.Time) {
	depth := r.depthFor(profile.id)
	run := &gs.Run{
		ID:         uuid.NewString(),
		Proc:       proc,
		Title:      title,
		ProfileID:  profile.id,
		StartedAt:  startedAt,
		LastSeenAt: startedAt,
		Source:     r.source,
		Caps:       r.capsFor(depth),
	}
	r.cur, r.curPID = &session{run: run, profiled: profile.known, depth: depth}, pid
	r.lastBucketTS = time.Time{}
	r.markDirty(run)
}

// parkCurrent sets the current run aside, ended but reopenable. Caller holds mu.
func (r *Recorder) parkCurrent(now time.Time) {
	if r.cur == nil {
		return
	}
	s, pid := r.cur, r.curPID
	r.closeRun()
	if pid <= 0 {
		// Nothing to recognize it by later. It stays ended.
		return
	}
	if r.parked == nil {
		r.parked = map[int]*session{}
	}
	r.parked[pid] = s
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
	for pid, s := range r.parked {
		if now.Sub(s.run.LastSeenAt) > reviveWindow {
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
		ended = r.now().UTC()
	}
	r.cur.run.EndedAt = &ended
	r.markDirty(r.cur.run)
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
	r.parkCurrent(r.now().UTC())
}

// sec records one second of presentation.
func (r *Recorder) sec(m gs.Sec) {
	ts := m.TS
	if ts.IsZero() {
		// A second with no timestamp would land at the zero time and sort before
		// every real point in the run.
		ts = r.now()
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
		// id already had, when it has one. A sec line names neither its window nor
		// its profile, so a new run carries neither rather than a guess; the status
		// line that names them stamps them when it arrives. Saying nothing about
		// the profile is also why a sec line can never split a run over one.
		r.switchTo(m.PID, m.Proc, "", unclaimed, ts)
	case m.PID != r.curPID && m.Proc != r.cur.run.Proc:
		// A different program is drawing. The status line normally says so first;
		// arriving here means the seconds moved before the transition did, and
		// attributing them to the previous session would put one game's frames in
		// another game's record.
		r.switchTo(m.PID, m.Proc, "", unclaimed, ts)
	case m.PID != r.curPID:
		// Same program, new process id: a launcher handing the game off. One
		// session, and the id it is now known by moves with it.
		r.curPID = m.PID
	}
	r.cur.run.LastSeenAt = ts
	r.lastBucketTS = ts
	r.markDirty(r.cur.run)
	r.push(gs.Bucket{RunID: r.cur.run.ID, TS: ts, Sample: m.Sample})
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
		var run *gs.Run
		if r.cur != nil && r.cur.run.ID == runs[i].ID {
			run = r.cur.run
		} else {
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

	cfgMu sync.Mutex
	// cfg is the configuration the next sensor run will be started with. The
	// sensor is configured once, at spawn, so this is the only place a change can
	// be held until there is a process to hand it to.
	cfg gs.Config
	// configured records whether cfg came from the server or is still the
	// placeholder. Nothing is captured before it is true — see configuredCh.
	configured bool
	// configuredCh is closed by the first SetConfig of the process. Run waits on
	// it before spawning anything, so an agent that has not been told what it may
	// capture captures nothing.
	configuredCh chan struct{}
	// restart stops the sensor run in progress so the loop can spawn a new one
	// with a changed configuration. Nil while no run is in flight.
	restart context.CancelFunc
	// reconfigured records that the run that just ended was stopped on purpose by
	// SetConfig. A restart the agent asked for is not a sensor failure: it must
	// not count toward the failure streak, grow the backoff, or delay the
	// replacement, all of which would punish the sensor for doing as it was told.
	reconfigured bool

	reasonMu sync.Mutex
	// reason is the last failure the sensor named on its own way out. The process
	// exit code says only that it stopped; this says why, in the vocabulary the
	// console can explain.
	reason string
}

// NewSupervisor returns a supervisor for the sensor at path. emit delivers
// lifecycle events; it may be nil, and is called from the supervisor goroutine.
//
// The supervisor starts unconfigured and captures nothing until SetConfig is
// called; the placeholder configuration below exists only so a run started by
// mistake would still be a well-formed one.
func NewSupervisor(path string, emit func(telemetry.Event)) *Supervisor {
	s := &Supervisor{
		path:         path,
		emit:         emit,
		cfg:          gs.Config{Type: gs.TypeConfig, Proto: ProtoVersion, Mode: gs.ModeAll},
		configuredCh: make(chan struct{}),
	}
	s.now = time.Now
	s.run = s.runOnce
	return s
}

// SetConfig installs the configuration the sensor captures under, starting or
// restarting a sensor as needed to hand it over.
//
// The restart is the mechanism: a sensor is configured once, at spawn, so a
// changed mode or profile list can only reach it through a new process. That is
// deliberate — it keeps the sensor free of reconfiguration state and keeps every
// second of a capture run described by one set of rules. The run the player is
// having survives it, because a process that comes back inside the revive window
// resumes its run rather than starting another (see reviveWindow).
//
// The FIRST call is also what releases Run to spawn anything at all (see
// waitForConfig), so it is never filtered out as a no-op change however closely
// it resembles the placeholder.
//
// Type and Proto are stamped here rather than trusted from the caller: they
// describe the protocol this build speaks, which is not something a caller
// assembling profiles has any business deciding.
func (s *Supervisor) SetConfig(cfg gs.Config) {
	cfg.Type, cfg.Proto = gs.TypeConfig, ProtoVersion

	s.cfgMu.Lock()
	first := !s.configured
	if !first && reflect.DeepEqual(s.cfg, cfg) {
		// The server re-pushes the whole configuration on every reconnect and on
		// every unrelated edit. Restarting the sensor for a configuration it is
		// already running would interrupt capture for no reason at all.
		s.cfgMu.Unlock()
		return
	}
	s.cfg, s.configured = cfg, true
	// The recorder is told the tiers under the same lock that stores the config,
	// so the table it describes runs by can never disagree with the configuration
	// the next sensor is started with. A sensor is configured once at spawn, so
	// from the recorder's side the table is fixed for the life of a process —
	// which is what makes a run's depth immutable and a tier edit a split.
	s.setProfileTiers(cfg)
	restart := s.restart
	s.reconfigured = restart != nil
	s.cfgMu.Unlock()

	if first {
		close(s.configuredCh)
	}
	if restart != nil {
		restart()
	}
}

// waitForConfig blocks until the server's first game configuration arrives, or
// ctx ends. It reports whether a configuration was received.
//
// Nothing is captured before that point, and the reason is the site's own
// privacy setting: a site that has named its games and turned off "record
// everything else" means it, and an agent that captured every presenting window
// for the seconds — or, with the server unreachable, the hours — before the
// first push would be overriding that decision precisely when nobody could see
// it happening. Recording only what has been asked for is the conservative
// default, and the WAL keeps whatever is recorded, so there is no such thing as
// capturing "just until the push arrives".
//
// It also matches how the probe side already behaves: nothing here is persisted
// across restarts (the data directory holds the key, the credential and the
// WAL), so the collectors likewise sit with no targets until a DesiredState
// arrives. Both halves of the agent wait to be told what to do.
func (s *Supervisor) waitForConfig(ctx context.Context) bool {
	select {
	case <-s.configuredCh:
		return true
	case <-ctx.Done():
		return false
	}
}

// currentConfig returns the configuration to start a sensor with.
func (s *Supervisor) currentConfig() gs.Config {
	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()
	return s.cfg
}

// configLine returns the single line the agent writes to a freshly spawned
// sensor's stdin, newline included.
func (s *Supervisor) configLine() ([]byte, error) {
	b, err := json.Marshal(s.currentConfig())
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// beginRun registers the cancel that SetConfig uses to stop this run, and clears
// the flag the previous run left behind.
func (s *Supervisor) beginRun(cancel context.CancelFunc) {
	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()
	s.restart, s.reconfigured = cancel, false
}

// finishRun unregisters the run's cancel and reports whether it was a
// configuration change that ended it.
func (s *Supervisor) finishRun() bool {
	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()
	s.restart = nil
	return s.reconfigured
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
		TS:       s.now().UTC(),
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
//
// These deliberately do NOT run on the recorder's clock. They are waits, not
// readings: nothing here asks what time it is, and no value derived from them
// reaches a Run, a Bucket or an event, so no test outcome can depend on the date
// through them. Driving them from a func() time.Time would not work either —
// real timers have to fire — and compressing the schedule is already the seam
// tests need, so putting them on the clock would be a second mechanism for a job
// one already does.
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
//
// It spawns nothing until the server's first game configuration arrives — see
// waitForConfig. A SetConfig that happened before Run was called satisfies that
// immediately.
func (s *Supervisor) Run(ctx context.Context) {
	if !s.waitForConfig(ctx) {
		return
	}

	backoff := backoffMin
	failures := 0
	reported := false

	for ctx.Err() == nil {
		s.takeReason() // a new run does not inherit the last one's failure

		// Each run gets its own context so a configuration change can end that run
		// alone: cancelling it takes the ordinary stop path (stdin closes, the
		// sensor shuts its trace session down cleanly), and the loop then spawns a
		// replacement carrying the new configuration.
		runCtx, stopRun := context.WithCancel(ctx)
		s.beginRun(stopRun)

		errCh := make(chan error, 1)
		go func() { errCh <- s.run(runCtx) }()

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
		reconfigured := s.finishRun()
		stopRun()
		// The sensor is gone, so nothing is observing the game any more. Closing the
		// run here rather than waiting for a status that will never come is what
		// keeps a restart from stitching the seconds either side of the gap into one
		// continuous session.
		s.endRun()
		if ctx.Err() != nil {
			return
		}
		if reconfigured {
			// The agent stopped this sensor to hand it a new configuration. Nothing
			// failed, so nothing is counted, reported, or waited out: the replacement
			// starts immediately, and the game the player is in the middle of resumes
			// into the same run.
			continue
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
	if !PlatformSupported {
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
