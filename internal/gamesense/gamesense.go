// Package gamesense turns frame-presentation data into game.* metrics.
//
// The agent does not observe frames itself. Reading them means consuming the OS
// graphics event stream, which is a large platform-specific surface with its own
// licensing and signing story, so it lives in a separate sensor executable that
// the agent locates beside its own binary, supervises as a child process, and
// reads line-delimited JSON from. This package is the whole agent-side half of
// that contract: discovery, the capability probe, the supervisor, and the
// collector that drains buffered samples into metrics.
//
// The sensor is optional by design. An install without it — the standalone
// agent, or any build that ships only the open-source pieces — reports the
// game.* permissions as unsupported and behaves exactly as it did before. That
// is the first of three states this package distinguishes:
//
//   - absent: no sensor executable. Nothing is reported beyond the unsupported
//     permission, because there is nothing to say.
//   - blocked: a sensor is installed but cannot open a trace session (typically
//     because the agent is not running with the rights the OS requires). Still
//     unsupported, but an event carries the reason, because this state is
//     fixable and indistinguishable from "absent" to anyone reading only the
//     permission report.
//   - working: metrics flow.
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
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/nettact/agent/internal/collector"
	"github.com/nettact/protocol/telemetry"
)

// ProtoVersion is the sensor protocol this build speaks. The agent requires an
// exact match: a sensor is shipped with the agent, not independently, so a
// mismatch means a broken install rather than a version to negotiate with.
const ProtoVersion = 1

// ExeName is the sensor executable, looked up beside the agent's own binary.
const ExeName = "nettact-sensor.exe"

// PathEnv overrides the sensor location. This exists for development, where the
// agent runs from a build directory and the sensor from its own: it is a
// discovery override, not agent configuration, so it is read here rather than
// threaded through the config file.
const PathEnv = "NETTACT_SENSOR_PATH"

// Blocked-reason codes reported by the sensor's probe. They are a closed set so
// the console can explain the state and, later, offer the matching fix.
const (
	ReasonETWAccessDenied     = "etw_access_denied"
	ReasonPresentMonMissing   = "presentmon_missing"
	ReasonPresentMonStartFail = "presentmon_start_failed"
	ReasonUnsupportedOS       = "unsupported_os"
	// ReasonServiceUnavailable: the sensor found the PresentMon middleware but
	// no service answered — installed and stopped, or version-mismatched. Kept
	// distinct from the missing/denied reasons because its remedy is "start or
	// repair the PresentMon service", which the console can guide directly.
	ReasonServiceUnavailable = "service_unavailable"
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

// ProbeResult is the answer to "can this machine produce frame metrics right
// now". OK is the only field the permission decision reads; the rest explains a
// negative answer to a human.
type ProbeResult struct {
	OK            bool
	Proto         int
	PresentMon    bool
	ETWSession    bool
	Reason        string
	SensorVersion string
}

// Sample is one second of presentation data for one process.
type Sample struct {
	TS         time.Time
	PID        int
	Proc       string
	FPS        float64
	FrameAvgMs float64
	FrameP95Ms float64
	Frames     int
	Presented  int
	Dropped    int
}

// Wire messages. Every sensor line is one of these, discriminated by Type;
// unknown types are ignored so a newer sensor can add messages without
// coordination.
const (
	msgProbe  = "probe"
	msgHello  = "hello"
	msgFPS    = "fps"
	msgStatus = "status"
)

// Sensor states carried by a status message. Only the error state needs reading:
// it is the one that names something the agent cannot observe for itself.
const stateError = "error"

type sensorCaps struct {
	PresentMon bool `json:"presentmon"`
	ETWSession bool `json:"etw_session"`
}

// sensorLine is the union of every v1 message. One struct rather than a
// discriminated decode keeps the parser a single pass, which matters on a
// stream that produces a line per second forever.
type sensorLine struct {
	Type    string     `json:"type"`
	Proto   int        `json:"proto"`
	Version string     `json:"sensor_version"`
	Caps    sensorCaps `json:"caps"`
	Reason  string     `json:"reason"`

	TS        time.Time `json:"ts"`
	PID       int       `json:"pid"`
	Proc      string    `json:"proc"`
	FPS       float64   `json:"fps"`
	Frames    int       `json:"frames"`
	FrameAvg  float64   `json:"ft_avg_ms"`
	FrameP95  float64   `json:"ft_p95_ms"`
	Presented int       `json:"presented"`
	Dropped   int       `json:"dropped"`

	State string `json:"state"`
}

// parseProbeLine turns the single line a `--probe` run prints into a result. A
// probe that answers but reports a false capability is a *blocked* sensor and
// keeps its own reason; anything unparseable is the agent's own probe_failed.
func parseProbeLine(b []byte) ProbeResult {
	var l sensorLine
	if err := json.Unmarshal(b, &l); err != nil || l.Type != msgProbe {
		return ProbeResult{Reason: ReasonProbeFailed}
	}
	if l.Proto != ProtoVersion {
		return ProbeResult{Proto: l.Proto, SensorVersion: l.Version, Reason: ReasonProtoMismatch}
	}
	res := ProbeResult{
		Proto:         l.Proto,
		PresentMon:    l.Caps.PresentMon,
		ETWSession:    l.Caps.ETWSession,
		Reason:        l.Reason,
		SensorVersion: l.Version,
	}
	res.OK = res.PresentMon && res.ETWSession
	if !res.OK && res.Reason == "" {
		// A sensor that reports a missing capability without saying which is still
		// blocked; give the state a code rather than an empty string.
		res.Reason = ReasonProbeFailed
	}
	return res
}

// maxBuffered bounds the sample buffer. At one sample per second this is ten
// minutes of backlog, far more than the seconds a collection tier actually takes
// to drain it — the cap exists so a wedged scheduler cannot grow the buffer
// without limit, not as a working size.
const maxBuffered = 600

// Supervisor runs the sensor and buffers what it produces.
//
// It owns the process lifetime: spawn, read, restart with backoff, and stop when
// its context is cancelled. Samples land in a buffer that the collector drains
// on its own schedule, which decouples the sensor's one-second cadence from the
// agent's collection tier without either waiting on the other.
type Supervisor struct {
	path string
	emit func(telemetry.Event)
	// run performs one sensor run. It is a field so the restart policy can be
	// exercised on every platform, including the ones where spawning the sensor
	// is a compile-time stub.
	run func(context.Context) error

	mu      sync.Mutex
	samples []Sample
	dropped int
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

// push records one sample, dropping the oldest when the buffer is full. Dropping
// the oldest keeps the most recent seconds, which is what a live chart shows.
func (s *Supervisor) push(sm Sample) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.samples) >= maxBuffered {
		copy(s.samples, s.samples[1:])
		s.samples = s.samples[:len(s.samples)-1]
		s.dropped++
	}
	s.samples = append(s.samples, sm)
}

// Drain removes and returns every buffered sample.
func (s *Supervisor) Drain() []Sample {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.samples) == 0 {
		return nil
	}
	out := s.samples
	s.samples = nil
	return out
}

// setReason records the failure the sensor named for itself.
func (s *Supervisor) setReason(r string) {
	s.mu.Lock()
	s.reason = r
	s.mu.Unlock()
}

// takeReason returns the recorded failure reason and clears it, so one run's
// reason can never be attributed to the next.
func (s *Supervisor) takeReason() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	r := s.reason
	s.reason = ""
	return r
}

// peek returns the buffered samples without draining, for tests that need to
// watch a live stream fill.
func (s *Supervisor) peek() []Sample {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Sample(nil), s.samples...)
}

// DroppedCount reports how many samples the buffer has discarded.
func (s *Supervisor) DroppedCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.dropped
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
		if ctx.Err() != nil {
			return
		}

		if !wasHealthy {
			failures++
			if failures >= failuresBeforeEvent && !reported {
				attrs := map[string]string{"path": s.path, "reason": ReasonSensorExited}
				// The sensor names its own failure on the way out; that code is what
				// distinguishes a lost trace session from a missing payload, and it is
				// the only part of this event anything can act on.
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

// maxLineBytes caps one sensor line. The largest v1 message is a few hundred
// bytes; this leaves room to grow while keeping a sensor that starts emitting
// garbage from being able to exhaust memory one line at a time.
const maxLineBytes = 64 * 1024

// consume reads the sensor's line stream, buffering samples until the stream
// ends. Malformed lines are skipped rather than fatal: one garbled line must not
// end a session that is otherwise producing data.
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
		var l sensorLine
		if err := json.Unmarshal(sc.Bytes(), &l); err != nil {
			continue
		}
		switch l.Type {
		case msgFPS:
			ts := l.TS
			if ts.IsZero() {
				ts = time.Now().UTC()
			}
			if l.Proc == "" {
				// Without a process name the sample has no series to belong to.
				continue
			}
			s.push(Sample{
				TS:         ts.UTC(),
				PID:        l.PID,
				Proc:       l.Proc,
				FPS:        l.FPS,
				FrameAvgMs: l.FrameAvg,
				FrameP95Ms: l.FrameP95,
				Frames:     l.Frames,
				Presented:  l.Presented,
				Dropped:    l.Dropped,
			})
		case msgStatus:
			// A sensor about to give up names the reason first. Keeping it is what
			// turns "the sensor exited" into "the trace session was lost", which is
			// the difference between an event an operator can act on and one they
			// cannot. Idle and tracking need no action: the metrics themselves
			// already say which of the two is true.
			if l.State == stateError && l.Reason != "" {
				s.setReason(l.Reason)
			}
		case msgHello:
			// The capability probe at startup already asked this question, and asked
			// it of the same sensor. Reading the answer again here would only add a
			// second source for one fact.
		default:
			// A message a newer sensor added. Ignoring it is what lets the sensor
			// grow without the agent having to be taught first.
		}
	}
	return sc.Err()
}

// Collector drains buffered samples into metrics.
//
// It emits nothing when the buffer is empty, which is the normal state: the
// sensor only produces samples while something is presenting, so an idle machine
// leaves a gap in the series rather than a run of zeros. A zero would claim the
// machine rendered nothing, which is a different fact from not having rendered
// at all.
type Collector struct {
	sup *Supervisor
}

// NewCollector returns the collector draining sup.
func NewCollector(sup *Supervisor) *Collector { return &Collector{sup: sup} }

func (c *Collector) Name() string         { return "gamesense" }
func (c *Collector) Tier() collector.Tier { return collector.TierBase }

// Collect drains the buffer. Each sample keeps its own timestamp, so the
// per-second resolution survives being batched into a coarser collection tier.
func (c *Collector) Collect(_ context.Context) (collector.Result, error) {
	samples := c.sup.Drain()
	if len(samples) == 0 {
		return collector.Result{}, nil
	}
	metrics := make([]telemetry.Metric, 0, len(samples)*3)
	for _, sm := range samples {
		metrics = append(metrics,
			telemetry.Metric{
				TS: sm.TS, Kind: telemetry.GameFPS, Target: sm.Proc,
				Layer: telemetry.LayerLocal, Value: sm.FPS, Unit: telemetry.UnitFPS,
			},
			telemetry.Metric{
				TS: sm.TS, Kind: telemetry.GameFrameTimeAvg, Target: sm.Proc,
				Layer: telemetry.LayerLocal, Value: sm.FrameAvgMs, Unit: telemetry.UnitMs,
			},
			telemetry.Metric{
				TS: sm.TS, Kind: telemetry.GameFrameTimeP95, Target: sm.Proc,
				Layer: telemetry.LayerLocal, Value: sm.FrameP95Ms, Unit: telemetry.UnitMs,
			},
		)
	}
	return collector.Result{Metrics: metrics}, nil
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

// devBuildDir is the sensor component's directory in a development workspace,
// as a sibling of the module the developer is running from.
const devBuildDir = "sensor-win"

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}
