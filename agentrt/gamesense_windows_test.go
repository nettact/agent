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
	"github.com/nettact/protocol/permission"
	"github.com/nettact/protocol/telemetry"
	"github.com/nettact/protocol/wire"
)

// The sensor component is closed and not built here, so the test binary plays it:
// TestMain sees the scenario variable and runs as nettact-sensor.exe instead of a
// test. That makes the whole path testable — probe, spawn, collect, upload —
// without the component, which is exactly the situation the agent's own CI is in.

const mockSensorEnv = "NETTACT_AGENTRT_MOCK_SENSOR"

func TestMain(m *testing.M) {
	switch os.Getenv(mockSensorEnv) {
	case "":
		os.Exit(m.Run())
	case "ok":
		os.Exit(runMockSensor(os.Args[1:]))
	case "blocked":
		fmt.Println(`{"type":"probe","proto":1,"sensor_version":"0.1.0-mock",` +
			`"caps":{"presentmon":true,"etw_session":false},"reason":"etw_access_denied"}`)
		os.Exit(0)
	default:
		os.Exit(2)
	}
}

func runMockSensor(args []string) int {
	if len(args) > 0 && args[0] == "--probe" {
		fmt.Println(`{"type":"probe","proto":1,"sensor_version":"0.1.0-mock",` +
			`"caps":{"presentmon":true,"etw_session":true},"reason":""}`)
		return 0
	}
	fmt.Println(`{"type":"hello","proto":1,"sensor_version":"0.1.0-mock",` +
		`"caps":{"presentmon":true,"etw_session":true}}`)
	fmt.Println(`{"type":"status","state":"tracking","pid":4242,"proc":"mock-game.exe"}`)
	// One line per second, the cadence the contract specifies, so the volume the
	// agent buffers and uploads here is the volume it will see in production.
	go func() {
		for i := 0; ; i++ {
			fmt.Printf(`{"type":"fps","ts":"%s","pid":4242,"proc":"mock-game.exe",`+
				`"fps":%d,"frames":%d,"ft_avg_ms":16.7,"ft_p95_ms":19.2,"presented":%d,"dropped":0}`+"\n",
				time.Now().UTC().Format("2006-01-02T15:04:05.000Z"), 60+i%3, 60+i%3, 60+i%3)
			time.Sleep(time.Second)
		}
	}()
	// Exit when the agent closes stdin.
	_, _ = os.Stdin.Read(make([]byte, 1))
	return 0
}

// TestGameMetricsReachTheServer is the end-to-end proof for the agent half: a
// sensor beside the agent turns into game.* metrics in an uploaded packet, and
// the permission report says so.
func TestGameMetricsReachTheServer(t *testing.T) {
	t.Setenv(mockSensorEnv, "ok")
	t.Setenv(gamesense.PathEnv, testExecutable(t))

	f := newFake(t, hasGameMetric)
	runAgent(t, f)
	report, metrics, _ := f.snapshot()

	for _, id := range []permission.ID{permission.GameProcessDetect, permission.GamePerformanceRead} {
		if !contains(report.Supported, string(id)) {
			t.Errorf("supported = %v, want %q", report.Supported, id)
		}
		if !contains(report.Effective, string(id)) {
			t.Errorf("effective = %v, want %q", report.Effective, id)
		}
	}
	assertGameSeries(t, metrics)
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
		if ev.Attrs["reason"] != gamesense.ReasonETWAccessDenied {
			t.Errorf("reason = %q, want %q", ev.Attrs["reason"], gamesense.ReasonETWAccessDenied)
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
	report, metrics, events := f.snapshot()

	for _, id := range []permission.ID{permission.GameProcessDetect, permission.GamePerformanceRead} {
		if contains(report.Supported, string(id)) {
			t.Errorf("supported = %v, want %q absent with no sensor", report.Supported, id)
		}
	}
	for _, m := range metrics {
		if m.Kind == telemetry.GameFPS {
			t.Errorf("game metric %+v produced without a sensor", m)
		}
	}
	// Nothing installed is the ordinary state, not a problem to report.
	for _, ev := range events {
		if ev.Type == telemetry.EventGameSensorBlocked {
			t.Errorf("reported %q with no sensor installed", ev.Type)
		}
	}
}

func assertGameSeries(t *testing.T, metrics []telemetry.Metric) {
	t.Helper()
	seen := map[telemetry.MetricKind]bool{}
	for _, m := range metrics {
		switch m.Kind {
		case telemetry.GameFPS, telemetry.GameFrameTimeAvg, telemetry.GameFrameTimeP95:
		default:
			continue
		}
		seen[m.Kind] = true
		if m.Target != "mock-game.exe" {
			t.Errorf("%s target = %q, want the process name", m.Kind, m.Target)
		}
		if m.Layer != telemetry.LayerLocal {
			t.Errorf("%s layer = %q, want %q", m.Kind, m.Layer, telemetry.LayerLocal)
		}
		if m.MonitorID != "" {
			t.Errorf("%s carries monitor id %q, want none", m.Kind, m.MonitorID)
		}
		if m.TS.IsZero() {
			t.Errorf("%s has no timestamp", m.Kind)
		}
	}
	for _, kind := range []telemetry.MetricKind{
		telemetry.GameFPS, telemetry.GameFrameTimeAvg, telemetry.GameFrameTimeP95,
	} {
		if !seen[kind] {
			t.Errorf("no %s metric in the uploaded packet", kind)
		}
	}
	if u := unitOf(metrics, telemetry.GameFPS); u != telemetry.UnitFPS {
		t.Errorf("%s unit = %q, want %q", telemetry.GameFPS, u, telemetry.UnitFPS)
	}
	if u := unitOf(metrics, telemetry.GameFrameTimeP95); u != telemetry.UnitMs {
		t.Errorf("%s unit = %q, want %q", telemetry.GameFrameTimeP95, u, telemetry.UnitMs)
	}
}

func unitOf(metrics []telemetry.Metric, kind telemetry.MetricKind) string {
	for _, m := range metrics {
		if m.Kind == kind {
			return m.Unit
		}
	}
	return ""
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

// hasGameMetric is the condition for "the whole path worked".
func hasGameMetric(fr wire.Frame) bool {
	if fr.Packet == nil {
		return false
	}
	for _, m := range fr.Packet.Metrics {
		if m.Kind == telemetry.GameFPS {
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
