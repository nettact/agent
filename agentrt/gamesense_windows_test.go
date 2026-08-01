//go:build windows

package agentrt

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/nettact/agent/internal/gamesense"
	"github.com/nettact/agent/internal/identity"
	pcfg "github.com/nettact/protocol/config"
	gs "github.com/nettact/protocol/gamesense"
	"github.com/nettact/protocol/permission"
	"github.com/nettact/protocol/telemetry"
	"github.com/nettact/protocol/wire"
)

// The sensor component is closed and not built here, so the test binary plays it:
// TestMain sees the scenario variable and runs as nettact-sensor.exe instead of a
// test. That makes the whole path testable — probe, spawn, record, upload —
// without the component, which is exactly the situation the agent's own CI is in.

const mockSensorEnv = "NETTACT_AGENTRT_MOCK_SENSOR"

func TestMain(m *testing.M) {
	switch os.Getenv(mockSensorEnv) {
	case "":
		os.Exit(m.Run())
	case "ok":
		os.Exit(runMockSensor(os.Args[1:]))
	case "blocked":
		fmt.Println(`{"type":"probe","proto":3,"sensor_version":"0.2.0-mock",` +
			`"ok":false,"reason":"service_unavailable"}`)
		os.Exit(0)
	default:
		os.Exit(2)
	}
}

// mockProc is the process the mock claims to be watching. A profile matching it
// is what makes the mock report a profile id, exactly as the real sensor decides
// that for itself from the config it was handed.
const mockProc = "mock-game.exe"

func runMockSensor(args []string) int {
	if len(args) > 0 && args[0] == "--probe" {
		fmt.Println(`{"type":"probe","proto":3,"sensor_version":"0.2.0-mock","ok":true,"pm_version":"2.3.0"}`)
		return 0
	}
	// A capture run is configured before it captures: the agent writes exactly one
	// config line to stdin right after spawn, and the sensor reads it before doing
	// anything else. Reading it here is not ceremony — the mock would otherwise
	// mistake it for the stdin close that means stop.
	stdin := bufio.NewReader(os.Stdin)
	line, err := stdin.ReadBytes('\n')
	if err != nil {
		fmt.Fprintf(os.Stderr, "mock sensor: no config line: %v\n", err)
		return 3
	}
	var cfg gs.Config
	if err := json.Unmarshal(line, &cfg); err != nil || cfg.Type != gs.TypeConfig || cfg.Proto != gs.ProtoVersion {
		fmt.Fprintf(os.Stderr, "mock sensor: bad config line %q: %v\n", line, err)
		return 3
	}
	// The sensor owns the matching rule and reports its verdict; the agent copies
	// the id rather than matching the process name a second time.
	matched, ok := cfg.Match(mockProc)
	var profile string
	if ok {
		profile = fmt.Sprintf(`,"profile_id":%q`, matched.ID)
	}

	fmt.Println(`{"type":"hello","proto":3,"sensor_version":"0.2.0-mock","source":"presentmon_service",` +
		`"pm_version":"2.3.0","caps":["displayed","frame_type","present_meta","per_frame_complete"]}`)
	if cfg.Mode == gs.ModeProfiles && !ok {
		// Strict tracking, and this process is not one of the site's games — so it
		// is not watched at all. With no profiles defined that is every process,
		// which is the whole point of the setting rather than a state to work
		// around.
		fmt.Println(`{"type":"status","state":"idle"}`)
		_, _ = io.Copy(io.Discard, stdin)
		return 0
	}
	fmt.Printf(`{"type":"status","state":"tracking","pid":4242,"proc":%q,"title":"Mock Game"%s}`+"\n",
		mockProc, profile)
	// One line per second, the cadence the contract specifies, so the volume the
	// agent buffers and uploads here is the volume it will see in production.
	go func() {
		for i := 0; ; i++ {
			fmt.Printf(`{"type":"sec","ts":"%s","pid":4242,"proc":%q,`+
				`"frames":{"presented":%d,"displayed":%d,"dropped":1,"app":%d,"generated":0},`+
				`"ft":{"avg":16.667,"p50":16.6,"p95":19.2,"p99":22.1,"max":31.4,"sd":2.2},`+
				`"ft_hist":{"layout":"log24_v1","counts":[0,0,0,0,0,0,0,0,0,0,0,0,58,2,0,0,0,0,0,0,0,0,0,0]},`+
				`"disp_ft":{"avg":16.9,"p95":20.1},`+
				`"present":{"mode":"hardware_independent_flip","sync":0,"tearing":false,"api":"dxgi"}}`+"\n",
				time.Now().UTC().Format("2006-01-02T15:04:05.000Z"), mockProc, 60+i%3, 59+i%3, 60+i%3)
			time.Sleep(time.Second)
		}
	}()
	// Exit when the agent closes stdin — the same pipe the config arrived on.
	_, _ = io.Copy(io.Discard, stdin)
	return 0
}

// TestGameDataReachesTheServer is the end-to-end proof for the agent half: a
// sensor beside the agent turns into runs and per-second buckets on an uploaded
// packet, and the permission report says so.
//
// The record-everything configuration is pushed rather than assumed: capture
// starts when the server says what may be captured, and this is the block a
// site with no profiles yet produces.
func TestGameDataReachesTheServer(t *testing.T) {
	t.Setenv(mockSensorEnv, "ok")
	t.Setenv(gamesense.PathEnv, testExecutable(t))

	f := newFake(t, hasGameBucket)
	f.pushGameConfig(pcfg.GameConfig{Version: 1, RecordUnmatched: true})
	runAgent(t, f)
	report, _, _ := f.snapshot()

	for _, id := range []permission.ID{permission.GameProcessDetect, permission.GamePerformanceRead} {
		if !contains(report.Supported, string(id)) {
			t.Errorf("supported = %v, want %q", report.Supported, id)
		}
		if !contains(report.Effective, string(id)) {
			t.Errorf("effective = %v, want %q", report.Effective, id)
		}
	}
	runs, buckets := f.game()
	assertGameRecords(t, runs, buckets, 1)
}

// The game-profile path end to end on the agent side: a profile pushed with the
// DesiredState reaches the sensor as its configuration, the sensor reports which
// profile the process it is watching matched, and the uploaded run carries that
// id — so the server can say which game a session was without ever re-matching
// the process name itself.
//
// It is deliberately the harder ordering: capture starts under a
// record-everything configuration, and the profile is created while the sensor
// is already running, so it can only reach the sensor through a new process.
// That makes this the end-to-end cover for the reconfiguration restart — and for
// what a restart that CHANGES a run's game must do to the record. The seconds
// already collected were collected as an ordinary process, so they stay that
// way: the session ends and the profiled one begins, rather than the whole
// evening being retroactively filed under a game it was not being recorded as.
//
// The second push carries an UNCHANGED ConfigVersion, which is what a profile
// edit produces: the probe half no-ops while the game half applies.
func TestPushedGameProfileStampsTheUploadedRun(t *testing.T) {
	t.Setenv(mockSensorEnv, "ok")
	t.Setenv(gamesense.PathEnv, testExecutable(t))

	f := newFake(t, hasProfiledRun)
	f.pushGameConfig(pcfg.GameConfig{Version: 1, RecordUnmatched: true})
	f.editGameConfigOnceCapturing(pcfg.GameConfig{
		Version: 2,
		Profiles: []pcfg.GameProfile{{
			ID: "prof-1", Name: "Mock Game", Exe: []string{"MOCK-GAME.EXE"}, Tier: "diag",
		}},
	})
	runAgent(t, f)

	runs, buckets := f.game()
	byID := assertGameRecords(t, runs, buckets, 2)

	var before, after gs.Run
	for _, r := range byID {
		switch r.ProfileID {
		case "":
			before = r
		case "prof-1":
			after = r
		default:
			t.Fatalf("run %+v carries a profile nobody pushed", r)
		}
	}
	if before.ID == "" || after.ID == "" {
		t.Fatalf("runs = %+v, want the unprofiled session and the profiled one that replaced it", runs)
	}
	if before.EndedAt == nil {
		t.Errorf("run = %+v, want the pre-profile session ended where the profile began", before)
	}
	if after.EndedAt != nil {
		t.Errorf("run = %+v, want the profiled session still open", after)
	}
	if !after.StartedAt.Before(time.Now()) || after.StartedAt.Before(before.StartedAt) {
		t.Errorf("the profiled run started at %v, before the session it replaced (%v)", after.StartedAt, before.StartedAt)
	}
}

// A capable sensor sitting beside an agent the server has told nothing about
// game capture must capture nothing at all.
//
// This is the site's privacy setting being honoured at the only moment it can
// be: before the first push, the agent does not know whether the site records
// every window or only the games it named, and the WAL keeps whatever is
// recorded — so a sensor started "just until the configuration arrives" would
// have already overridden the answer by the time it came. With the server
// unreachable there may be no answer for hours.
func TestNoGameConfigMeansNoCapture(t *testing.T) {
	t.Setenv(mockSensorEnv, "ok")
	t.Setenv(gamesense.PathEnv, testExecutable(t))

	// No pushGameConfig: the DesiredState carries no game block at all. The agent
	// is then left running well past the second or so the mock needs to announce
	// itself and produce a second, so "nothing arrived" means nothing was
	// captured rather than that the test looked too early.
	f := newFake(t, hasAnyPacket)
	runAgentThenLinger(t, f, 3*time.Second)

	report, _, _ := f.snapshot()
	// The capability is a property of the machine, not of the configuration: the
	// console must still be able to offer game capture on an agent that could do
	// it, or nobody would ever configure one.
	if !contains(report.Effective, string(permission.GamePerformanceRead)) {
		t.Errorf("effective = %v, want %q — capability does not depend on configuration",
			report.Effective, permission.GamePerformanceRead)
	}
	if runs, buckets := f.game(); len(runs) != 0 || len(buckets) != 0 {
		t.Fatalf("captured %d runs and %d buckets before any configuration was pushed", len(runs), len(buckets))
	}
}

// Strict tracking with no profiles yet records nothing, rather than falling back
// to recording everything.
//
// This is the window a user creates by turning "record other processes" off
// before naming their first game, or by deleting their last profile while it is
// off. Deriving the mode from the profile count would quietly record every window
// on the machine for exactly as long as that window lasts — which is the one
// thing the setting they just changed exists to prevent. Capture resumes the
// moment a profile exists.
func TestStrictModeWithNoProfilesCapturesNothing(t *testing.T) {
	t.Setenv(mockSensorEnv, "ok")
	t.Setenv(gamesense.PathEnv, testExecutable(t))

	f := newFake(t, hasAnyPacket)
	f.pushGameConfig(pcfg.GameConfig{Version: 1, RecordUnmatched: false})
	runAgentThenLinger(t, f, 3*time.Second)

	if runs, buckets := f.game(); len(runs) != 0 || len(buckets) != 0 {
		t.Fatalf("captured %d runs and %d buckets under strict tracking with no profiles", len(runs), len(buckets))
	}
}

// A sensor that is installed but cannot collect must not be reported as capable,
// and must not leave the operator guessing why: the event carries the reason
// that the permission report structurally cannot.
func TestBlockedSensorIsUnsupportedAndExplained(t *testing.T) {
	t.Setenv(mockSensorEnv, "blocked")
	t.Setenv(gamesense.PathEnv, testExecutable(t))

	f := newFake(t, hasEvent(telemetry.EventGameSensorBlocked))
	runAgent(t, f)
	report, _, events := f.snapshot()

	for _, id := range []permission.ID{permission.GameProcessDetect, permission.GamePerformanceRead} {
		if contains(report.Supported, string(id)) {
			t.Errorf("supported = %v, want %q absent for a blocked sensor", report.Supported, id)
		}
	}

	var found int
	for _, ev := range events {
		if ev.Type != telemetry.EventGameSensorBlocked {
			continue
		}
		found++
		if ev.Attrs["reason"] != gamesense.ReasonServiceUnavailable {
			t.Errorf("reason = %q, want %q", ev.Attrs["reason"], gamesense.ReasonServiceUnavailable)
		}
		if ev.Attrs["path"] == "" {
			t.Error("event does not say which sensor is blocked")
		}
	}
	if found != 1 {
		t.Fatalf("got %d blocked events, want exactly 1 per process start", found)
	}
}

// With no sensor installed — every build that does not ship one — the agent must
// behave exactly as it did before the feature existed.
func TestNoSensorIsSimplyUnsupported(t *testing.T) {
	t.Setenv(gamesense.PathEnv, absentSensorPath(t))

	f := newFake(t, hasAnyPacket)
	runAgent(t, f)
	report, _, events := f.snapshot()
	runs, buckets := f.game()

	for _, id := range []permission.ID{permission.GameProcessDetect, permission.GamePerformanceRead} {
		if contains(report.Supported, string(id)) {
			t.Errorf("supported = %v, want %q absent with no sensor", report.Supported, id)
		}
	}
	if len(runs) != 0 || len(buckets) != 0 {
		t.Errorf("uploaded %d runs and %d buckets without a sensor", len(runs), len(buckets))
	}
	// Nothing installed is the ordinary state, not a problem to report.
	for _, ev := range events {
		if ev.Type == telemetry.EventGameSensorBlocked {
			t.Errorf("reported %q with no sensor installed", ev.Type)
		}
	}
}

// assertGameRecords checks what the server can actually do with an upload: a run
// it can name and address buckets to, and seconds that carry both their own
// summary and the histogram a whole-run figure is later computed from. wantRuns
// is how many distinct runs the session should have produced — one per stretch
// the game was recorded under the same profile. It returns them by id.
func assertGameRecords(t *testing.T, runs []gs.Run, buckets []gs.Bucket, wantRuns int) map[string]gs.Run {
	t.Helper()
	if len(runs) == 0 {
		t.Fatal("no game run in the uploaded packets")
	}
	if len(buckets) == 0 {
		t.Fatal("no game bucket in the uploaded packets")
	}

	byID := map[string]gs.Run{}
	for _, r := range runs {
		if r.ID == "" {
			t.Fatalf("run %+v has no id; buckets cannot be addressed to it", r)
		}
		if r.Proc != "mock-game.exe" {
			t.Errorf("run proc = %q, want the process name", r.Proc)
		}
		if r.Title != "Mock Game" {
			t.Errorf("run title = %q, want the window title", r.Title)
		}
		if r.Source != gs.SourcePresentMonService {
			t.Errorf("run source = %q, want %q", r.Source, gs.SourcePresentMonService)
		}
		if len(r.Caps) == 0 {
			t.Error("run records no capabilities; two runs cannot be compared without them")
		}
		if r.StartedAt.IsZero() || r.LastSeenAt.IsZero() {
			t.Errorf("run %+v is not bounded in time", r)
		}
		byID[r.ID] = r
	}
	// The mock plays one game, so a second belongs to a new run only where the
	// recording rules changed under it — never merely because it was re-sent.
	if len(byID) != wantRuns {
		t.Errorf("got %d distinct runs, want %d: %+v", len(byID), wantRuns, runs)
	}

	for _, b := range buckets {
		if _, ok := byID[b.RunID]; !ok {
			t.Fatalf("bucket %+v hangs off a run the server was never sent", b)
		}
		if b.TS.IsZero() {
			t.Errorf("bucket %+v has no timestamp", b)
		}
		if b.Frames.Presented == 0 {
			t.Errorf("bucket %+v records no presented frames", b)
		}
		// Absent means "not measured". The mock declares the displayed capability,
		// so these must have arrived rather than defaulted.
		if b.Frames.Displayed == nil || b.Frames.Dropped == nil {
			t.Errorf("bucket %+v lost the displayed/dropped counts the sensor sent", b)
		}
		if b.Hist.Layout != gs.HistLayoutLog24V1 || len(b.Hist.Counts) != gs.HistBins {
			t.Errorf("bucket histogram = %+v, want a full %s histogram", b.Hist, gs.HistLayoutLog24V1)
		}
		if b.Present == nil || b.Present.Sync == nil || b.Present.Tearing == nil {
			t.Errorf("bucket %+v lost the presentation detail, where zero and false are observations", b)
		}
	}
	return byID
}

// fake is a server that speaks just enough of the protocol to observe one agent:
// it records the permission report from Hello, acks packets, and stops the test
// as soon as a frame satisfies the caller's condition.
type fake struct {
	srv  *httptest.Server
	done chan struct{}

	mu      sync.Mutex
	report  permission.PermissionReport
	metrics []telemetry.Metric
	events  []telemetry.Event
	runs    []gs.Run
	buckets []gs.Bucket
	// gameCfg is the game-capture configuration pushed with the DesiredState. Nil
	// is a server that has nothing to say about game capture — under which the
	// agent captures nothing at all.
	gameCfg *pcfg.GameConfig
	// gameEdit is a second configuration pushed once game data is flowing, and
	// gameEdited records that it has gone out.
	gameEdit   *pcfg.GameConfig
	gameEdited bool
}

// pushGameConfig arms the game block the fake sends with its DesiredState. Call
// it before the agent runs.
func (f *fake) pushGameConfig(cfg pcfg.GameConfig) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.gameCfg = &cfg
}

func (f *fake) gameConfig() *pcfg.GameConfig {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.gameCfg
}

// editGameConfigOnceCapturing arms a second game block, pushed as soon as game
// data starts arriving — a profile created while the agent is already capturing,
// which is the case the sensor has to be restarted for.
func (f *fake) editGameConfigOnceCapturing(cfg pcfg.GameConfig) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.gameEdit = &cfg
}

// gameEditFor returns the DesiredState carrying that edit, once and only once
// the agent has uploaded game data. ConfigVersion is unchanged from the first
// push, because a profile edit bumps only the game serial.
func (f *fake) gameEditFor(fr wire.Frame) *pcfg.DesiredState {
	if fr.Packet == nil || len(fr.Packet.GameBuckets) == 0 {
		return nil
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.gameEdit == nil || f.gameEdited {
		return nil
	}
	f.gameEdited = true
	return &pcfg.DesiredState{
		ConfigVersion: 1,
		Intervals:     pcfg.Intervals{BaseSeconds: 1, RegularSeconds: 60},
		Game:          f.gameEdit,
	}
}

// newFake starts the server. want is called for every frame; the first true ends
// the wait. The frame's metrics and events are captured either way, so a test
// can assert on what did arrive as well as on what it was waiting for.
func newFake(t *testing.T, want func(wire.Frame) bool) *fake {
	t.Helper()
	f := &fake{done: make(chan struct{})}
	var once sync.Once

	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{wire.SubprotocolJSON}})
		if err != nil {
			return
		}
		defer c.CloseNow() //nolint:errcheck
		// The library default is 32 KiB, which a single drained batch exceeds. Match
		// what the real hub allows so this harness fails on the agent's behaviour
		// rather than on its own ceiling.
		c.SetReadLimit(8 << 20)

		ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
		defer cancel()

		write := func(fr wire.Frame) error {
			b, err := wire.MarshalFrame(fr, wire.ContentTypeJSON)
			if err != nil {
				return err
			}
			return c.Write(ctx, websocket.MessageText, b)
		}

		for {
			_, data, err := c.Read(ctx)
			if err != nil {
				return
			}
			fr, err := wire.UnmarshalFrame(data, wire.ContentTypeJSON)
			if err != nil {
				continue
			}
			if fr.Hello != nil {
				f.mu.Lock()
				f.report = fr.Hello.Permissions
				f.mu.Unlock()
				// A one-second base tier, so the test does not wait out the default
				// ten. This is the same push a real server makes.
				ds := pcfg.DesiredState{
					ConfigVersion: 1,
					Intervals:     pcfg.Intervals{BaseSeconds: 1, RegularSeconds: 60},
					Game:          f.gameConfig(),
				}
				if err := write(wire.Frame{DesiredState: &ds}); err != nil {
					return
				}
				continue
			}
			if fr.Packet != nil {
				f.mu.Lock()
				f.metrics = append(f.metrics, fr.Packet.Metrics...)
				f.events = append(f.events, fr.Packet.Events...)
				f.runs = append(f.runs, fr.Packet.GameRuns...)
				f.buckets = append(f.buckets, fr.Packet.GameBuckets...)
				f.mu.Unlock()
				if err := write(wire.Frame{Ack: &wire.Ack{HighestSequence: fr.Packet.Sequence}}); err != nil {
					return
				}
				// A profile created while the agent is already capturing — pushed
				// mid-session, exactly as the console's edit would be.
				if ds := f.gameEditFor(fr); ds != nil {
					if err := write(wire.Frame{DesiredState: ds}); err != nil {
						return
					}
				}
			}
			if want(fr) {
				once.Do(func() { close(f.done) })
			}
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fake) snapshot() (permission.PermissionReport, []telemetry.Metric, []telemetry.Event) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.report, append([]telemetry.Metric(nil), f.metrics...), append([]telemetry.Event(nil), f.events...)
}

// game returns every game record the server has received. Runs accumulate as
// they arrive rather than being deduplicated: an upsert stream is what the agent
// is supposed to produce, and collapsing it here would hide a run whose id
// changed mid-session.
func (f *fake) game() ([]gs.Run, []gs.Bucket) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]gs.Run(nil), f.runs...), append([]gs.Bucket(nil), f.buckets...)
}

// hasGameBucket is the condition for "the whole path worked".
func hasGameBucket(fr wire.Frame) bool {
	return fr.Packet != nil && len(fr.Packet.GameBuckets) > 0
}

// hasProfiledRun waits for the configuration to have gone all the way around:
// pushed down, restarted into the sensor, matched there, and stamped on a run on
// its way back up.
func hasProfiledRun(fr wire.Frame) bool {
	if fr.Packet == nil {
		return false
	}
	for _, r := range fr.Packet.GameRuns {
		if r.ProfileID != "" {
			return true
		}
	}
	return false
}

func hasEvent(kind telemetry.EventType) func(wire.Frame) bool {
	return func(fr wire.Frame) bool {
		if fr.Packet == nil {
			return false
		}
		for _, ev := range fr.Packet.Events {
			if ev.Type == kind {
				return true
			}
		}
		return false
	}
}

// hasAnyPacket is the condition for tests asserting on an absence: it proves the
// agent got far enough to upload, so "no game metric" means it produced none
// rather than that the test looked too early.
func hasAnyPacket(fr wire.Frame) bool { return fr.Packet != nil }

// runAgent runs an enrolled session against the fake until its condition is met,
// then shuts the agent down. The agent reconnects on its own, so nothing here
// waits for Run to return by itself — only cancellation ends it.
func runAgent(t *testing.T, f *fake) {
	t.Helper()
	runAgentThenLinger(t, f, 0)
}

// runAgentThenLinger keeps the session alive for linger after the condition is
// met. It is how a test asserts that something never happens: the condition
// proves the agent got far enough to upload, and the extra window is the time in
// which the thing it must not do would have happened.
func runAgentThenLinger(t *testing.T, f *fake, linger time.Duration) {
	t.Helper()
	dataDir := t.TempDir()
	if err := identity.SaveCredential(dataDir, identity.Credential{
		AgentID: "agent-test", SiteID: "site-test", AgentToken: "test-token",
	}); err != nil {
		t.Fatalf("save credential: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		// FullAccess is what the desktop grants, so capability is the only gate —
		// the situation this feature actually ships in.
		_ = Run(ctx, Config{
			ServerURL: f.srv.URL, DataDir: dataDir, WireFormat: "json",
			UploadInterval: 200 * time.Millisecond,
			Policy:         permission.FullAccess(),
		})
	}()

	var timedOut bool
	select {
	case <-f.done:
		if linger > 0 {
			time.Sleep(linger)
		}
	case <-time.After(30 * time.Second):
		timedOut = true
	}

	cancel()
	select {
	case <-stopped:
	case <-time.After(20 * time.Second):
		t.Fatal("agent did not shut down after cancellation")
	}
	if timedOut {
		t.Fatal("the server never saw what the test was waiting for")
	}
}

func testExecutable(t *testing.T) string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return exe
}

// absentSensorPath returns a path where no sensor exists.
func absentSensorPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), gamesense.ExeName)
}

func contains(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}
