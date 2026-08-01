//go:build windows

package agentrt

import (
	"context"
	"fmt"
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
		fmt.Println(`{"type":"probe","proto":2,"sensor_version":"0.2.0-mock",` +
			`"ok":false,"reason":"service_unavailable"}`)
		os.Exit(0)
	default:
		os.Exit(2)
	}
}

func runMockSensor(args []string) int {
	if len(args) > 0 && args[0] == "--probe" {
		fmt.Println(`{"type":"probe","proto":2,"sensor_version":"0.2.0-mock","ok":true,"pm_version":"2.3.0"}`)
		return 0
	}
	fmt.Println(`{"type":"hello","proto":2,"sensor_version":"0.2.0-mock","source":"presentmon_service",` +
		`"pm_version":"2.3.0","caps":["displayed","frame_type","present_meta","per_frame_complete"]}`)
	fmt.Println(`{"type":"status","state":"tracking","pid":4242,"proc":"mock-game.exe","title":"Mock Game"}`)
	// One line per second, the cadence the contract specifies, so the volume the
	// agent buffers and uploads here is the volume it will see in production.
	go func() {
		for i := 0; ; i++ {
			fmt.Printf(`{"type":"sec","ts":"%s","pid":4242,"proc":"mock-game.exe",`+
				`"frames":{"presented":%d,"displayed":%d,"dropped":1,"app":%d,"generated":0},`+
				`"ft":{"avg":16.667,"p50":16.6,"p95":19.2,"p99":22.1,"max":31.4,"sd":2.2},`+
				`"ft_hist":{"layout":"log24_v1","counts":[0,0,0,0,0,0,0,0,0,0,0,0,58,2,0,0,0,0,0,0,0,0,0,0]},`+
				`"disp_ft":{"avg":16.9,"p95":20.1},`+
				`"present":{"mode":"hardware_independent_flip","sync":0,"tearing":false,"api":"dxgi"}}`+"\n",
				time.Now().UTC().Format("2006-01-02T15:04:05.000Z"), 60+i%3, 59+i%3, 60+i%3)
			time.Sleep(time.Second)
		}
	}()
	// Exit when the agent closes stdin.
	_, _ = os.Stdin.Read(make([]byte, 1))
	return 0
}

// TestGameDataReachesTheServer is the end-to-end proof for the agent half: a
// sensor beside the agent turns into runs and per-second buckets on an uploaded
// packet, and the permission report says so.
func TestGameDataReachesTheServer(t *testing.T) {
	t.Setenv(mockSensorEnv, "ok")
	t.Setenv(gamesense.PathEnv, testExecutable(t))

	f := newFake(t, hasGameBucket)
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
	assertGameRecords(t, runs, buckets)
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
// summary and the histogram a whole-run figure is later computed from.
func assertGameRecords(t *testing.T, runs []gs.Run, buckets []gs.Bucket) {
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
	// The mock plays one game, so every second belongs to the same run however
	// many times that run was re-sent.
	if len(byID) != 1 {
		t.Errorf("got %d distinct runs for one game: %+v", len(byID), runs)
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
				ds := pcfg.DesiredState{ConfigVersion: 1, Intervals: pcfg.Intervals{BaseSeconds: 1, RegularSeconds: 60}}
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
