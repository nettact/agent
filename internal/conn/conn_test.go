package conn

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/nettact/agent/internal/wal"
	"github.com/nettact/protocol"
	pcfg "github.com/nettact/protocol/config"
	"github.com/nettact/protocol/telemetry"
	"github.com/nettact/protocol/wire"
)

// startServer runs an httptest server that checks bearer auth, upgrades to a
// WebSocket, and hands each accepted connection to script. Scripts use
// t.Errorf (never Fatalf — they run off the test goroutine) and signal the
// test via channels.
func startServer(t *testing.T, script func(ctx context.Context, c *websocket.Conn)) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
			t.Errorf("upgrade Authorization = %q, want bearer test-token", got)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		c, err := websocket.Accept(w, r, &websocket.AcceptOptions{
			Subprotocols: []string{wire.SubprotocolProtobuf, wire.SubprotocolJSON},
		})
		if err != nil {
			t.Logf("accept: %v", err)
			return
		}
		defer c.CloseNow() //nolint:errcheck
		script(r.Context(), c)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// srvRead decodes one frame in the connection's negotiated format.
func srvRead(ctx context.Context, c *websocket.Conn) (wire.Frame, error) {
	_, data, err := c.Read(ctx)
	if err != nil {
		return wire.Frame{}, err
	}
	return wire.UnmarshalFrame(data, wire.SubprotocolContentType(c.Subprotocol()))
}

// srvWrite encodes and sends one frame in the connection's negotiated format.
func srvWrite(ctx context.Context, c *websocket.Conn, f wire.Frame) error {
	ct := wire.SubprotocolContentType(c.Subprotocol())
	data, err := wire.MarshalFrame(f, ct)
	if err != nil {
		return err
	}
	mt := websocket.MessageBinary
	if ct == wire.ContentTypeJSON {
		mt = websocket.MessageText
	}
	return c.Write(ctx, mt, data)
}

type fakeConfigurable struct {
	mu      sync.Mutex
	targets []pcfg.ProbeTarget
	calls   int
}

func (f *fakeConfigurable) SetTargets(ts []pcfg.ProbeTarget) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.targets = ts
	f.calls++
}

func (f *fakeConfigurable) lastTargets() []pcfg.ProbeTarget {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.targets
}

func (f *fakeConfigurable) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

type fakeScheduler struct {
	mu            sync.Mutex
	base, regular time.Duration
}

func (f *fakeScheduler) SetIntervals(base, regular time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.base, f.regular = base, regular
}

func (f *fakeScheduler) intervals() (base, regular time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.base, f.regular
}

// newTestDeps builds Deps around a real temp-dir WAL, recording fakes, and a
// stub snapshot collector (the real one burns a ~300ms CPU sample window).
func newTestDeps(t *testing.T) (Deps, *wal.Store, *fakeConfigurable, *fakeScheduler) {
	t.Helper()
	outbox, err := wal.Open(filepath.Join(t.TempDir(), "wal.db"))
	if err != nil {
		t.Fatalf("open wal: %v", err)
	}
	t.Cleanup(func() { outbox.Close() })
	fc := &fakeConfigurable{}
	fs := &fakeScheduler{}
	deps := Deps{
		Outbox:        outbox,
		Configurables: []Configurable{fc},
		Scheduler:     fs,
		DrainInterval: 50 * time.Millisecond,
		CollectSnapshot: func(_ context.Context, requestID string, _, _ bool) telemetry.HostSnapshot {
			return telemetry.HostSnapshot{TS: time.Now().UTC(), RequestID: requestID}
		},
	}
	return deps, outbox, fc, fs
}

// testOptions returns Options tuned for tests: tiny backoff so reconnect tests
// run fast, short ack timeout so failures surface quickly.
func testOptions(serverURL, format string) Options {
	return Options{
		ServerURL: serverURL,
		Token:     "test-token",
		Format:    format,
		AgentID:   "agent-1",
		SiteID:    "site-1",
		Hello: wire.Hello{
			SchemaVersion: protocol.SchemaVersion,
			Hostname:      "test-host",
			Platform:      "test",
			AgentVersion:  "0.0.0-test",
			Capabilities:  []string{"probe.icmp"},
		},
		dialTimeout: 2 * time.Second,
		ackTimeout:  2 * time.Second,
		backoffBase: 10 * time.Millisecond,
		backoffCap:  50 * time.Millisecond,
	}
}

// runAgent starts Run in the background and guarantees it exits cleanly at
// test end. The returned cancel triggers shutdown early for tests that need it.
func runAgent(t *testing.T, opts Options, deps Deps) (cancel context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := Run(ctx, opts, deps); err != nil {
			t.Errorf("Run returned error: %v", err)
		}
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("Run did not return within 5s of cancel")
		}
	})
	return cancel
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestDeriveWSURL(t *testing.T) {
	for in, want := range map[string]string{
		"http://localhost:8080":  "ws://localhost:8080/api/v1/agent/ws",
		"https://nettact.lan":    "wss://nettact.lan/api/v1/agent/ws",
		"https://host:9443/base": "wss://host:9443/base/api/v1/agent/ws",
	} {
		got, err := deriveWSURL(in)
		if err != nil || got != want {
			t.Errorf("deriveWSURL(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	if _, err := deriveWSURL("ftp://x"); err == nil {
		t.Error("deriveWSURL(ftp://x): want scheme error, got nil")
	}
}

func TestRunRejectsBadServerURL(t *testing.T) {
	deps, _, _, _ := newTestDeps(t)
	if err := Run(context.Background(), testOptions("ftp://nope", wire.SubprotocolJSON), deps); err == nil {
		t.Fatal("Run with ftp:// server URL: want error, got nil")
	}
}

// TestHelloThenDrainAck covers the core uplink in both wire formats: Hello is
// the first frame (with ReportedConfigVersion -1), a WAL batch goes out as a
// Packet, and the server's Ack clears it from the WAL.
func TestHelloThenDrainAck(t *testing.T) {
	for name, format := range map[string]string{
		"protobuf": wire.SubprotocolProtobuf,
		"json":     wire.SubprotocolJSON,
	} {
		t.Run(name, func(t *testing.T) {
			deps, outbox, _, _ := newTestDeps(t)
			if _, err := outbox.Append([]telemetry.Metric{
				{TS: time.Now().UTC(), Kind: telemetry.AgentUptime, Target: "agent", Value: 1, Unit: telemetry.UnitSec},
			}, nil, nil, nil); err != nil {
				t.Fatalf("wal append: %v", err)
			}

			type session struct {
				hello wire.Hello
				pkt   telemetry.Packet
			}
			gotCh := make(chan session, 1)
			srv := startServer(t, func(ctx context.Context, c *websocket.Conn) {
				if got := c.Subprotocol(); got != format {
					t.Errorf("negotiated subprotocol = %q, want %q", got, format)
				}
				first, err := srvRead(ctx, c)
				if err != nil || first.Hello == nil {
					t.Errorf("first frame: %+v, err %v; want Hello", first, err)
					return
				}
				second, err := srvRead(ctx, c)
				if err != nil || second.Packet == nil {
					t.Errorf("second frame: %+v, err %v; want Packet", second, err)
					return
				}
				if err := srvWrite(ctx, c, wire.Frame{Ack: &wire.Ack{
					HighestSequence: second.Packet.Sequence, ServerTime: time.Now().UTC(),
				}}); err != nil {
					t.Errorf("write ack: %v", err)
					return
				}
				gotCh <- session{*first.Hello, *second.Packet}
				_, _ = srvRead(ctx, c) // hold the connection open until the client leaves
			})

			runAgent(t, testOptions(srv.URL, format), deps)

			var got session
			select {
			case got = <-gotCh:
			case <-time.After(5 * time.Second):
				t.Fatal("server never received hello+packet")
			}
			if got.hello.ReportedConfigVersion != -1 {
				t.Errorf("hello ReportedConfigVersion = %d, want -1", got.hello.ReportedConfigVersion)
			}
			if got.hello.Hostname != "test-host" || got.hello.SchemaVersion != protocol.SchemaVersion {
				t.Errorf("hello identity fields wrong: %+v", got.hello)
			}
			if got.pkt.AgentID != "agent-1" || got.pkt.SiteID != "site-1" || len(got.pkt.Metrics) != 1 {
				t.Errorf("packet = %+v, want agent-1/site-1 with 1 metric", got.pkt)
			}
			// The ack must delete the batch — the WAL drains to empty.
			waitFor(t, "WAL cleared after ack", func() bool { return outbox.Pending() == 0 })
		})
	}
}

// TestDrainFastForwardsResetWAL reproduces WIFI-010 end to end: the local WAL
// starts at sequence 1 while the server ACK reports a much higher retained
// watermark. The in-flight packet remains sequence 1, then the next newly
// claimed packet must jump directly to watermark+1.
func TestDrainFastForwardsResetWAL(t *testing.T) {
	for name, format := range map[string]string{
		"protobuf": wire.SubprotocolProtobuf,
		"json":     wire.SubprotocolJSON,
	} {
		t.Run(name, func(t *testing.T) {
			deps, outbox, _, _ := newTestDeps(t)
			if _, err := outbox.Append([]telemetry.Metric{{
				TS: time.Now().UTC(), Kind: telemetry.AgentUptime, Target: "agent", Value: 1,
			}}, nil, nil, nil); err != nil {
				t.Fatalf("append first: %v", err)
			}

			const watermark uint64 = 33711
			firstAcked := make(chan struct{})
			seqs := make(chan [2]uint64, 1)
			srv := startServer(t, func(ctx context.Context, c *websocket.Conn) {
				if f, err := srvRead(ctx, c); err != nil || f.Hello == nil {
					t.Errorf("first frame: %+v err=%v; want Hello", f, err)
					return
				}
				first, err := srvRead(ctx, c)
				if err != nil || first.Packet == nil {
					t.Errorf("first packet: %+v err=%v", first, err)
					return
				}
				if err := srvWrite(ctx, c, wire.Frame{Ack: &wire.Ack{HighestSequence: watermark, ServerTime: time.Now().UTC()}}); err != nil {
					t.Errorf("write high-watermark ack: %v", err)
					return
				}
				close(firstAcked)

				second, err := srvRead(ctx, c)
				if err != nil || second.Packet == nil {
					t.Errorf("second packet: %+v err=%v", second, err)
					return
				}
				_ = srvWrite(ctx, c, wire.Frame{Ack: &wire.Ack{HighestSequence: second.Packet.Sequence, ServerTime: time.Now().UTC()}})
				seqs <- [2]uint64{first.Packet.Sequence, second.Packet.Sequence}
				_, _ = srvRead(ctx, c)
			})

			cancel := runAgent(t, testOptions(srv.URL, format), deps)
			select {
			case <-firstAcked:
			case <-time.After(5 * time.Second):
				t.Fatal("server never acknowledged first packet")
			}
			if _, err := outbox.Append([]telemetry.Metric{{
				TS: time.Now().UTC(), Kind: telemetry.AgentUptime, Target: "agent", Value: 2,
			}}, nil, nil, nil); err != nil {
				t.Fatalf("append second: %v", err)
			}

			select {
			case got := <-seqs:
				if got[0] != 1 || got[1] != watermark+1 {
					t.Fatalf("packet sequences=%v want [1 %d]", got, watermark+1)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("server never received fast-forwarded packet")
			}
			waitFor(t, "WAL cleared after fast-forwarded ack", func() bool { return outbox.Pending() == 0 })
			cancel()
		})
	}
}

// TestDesiredStateApplied covers the config downlink: a pushed DesiredState
// reaches every configurable and the scheduler, and the next packet reports
// the new config version.
func TestDesiredStateApplied(t *testing.T) {
	deps, outbox, fc, fs := newTestDeps(t)
	pktCh := make(chan telemetry.Packet, 1)
	srv := startServer(t, func(ctx context.Context, c *websocket.Conn) {
		if f, err := srvRead(ctx, c); err != nil || f.Hello == nil {
			t.Errorf("first frame: %+v, err %v; want Hello", f, err)
			return
		}
		if err := srvWrite(ctx, c, wire.Frame{DesiredState: &pcfg.DesiredState{
			ConfigVersion: 7,
			ProbeTargets:  []pcfg.ProbeTarget{{Kind: "icmp", Target: "1.1.1.1"}},
			Intervals:     pcfg.Intervals{BaseSeconds: 5, RegularSeconds: 60},
		}}); err != nil {
			t.Errorf("write desired state: %v", err)
			return
		}
		for { // ack every packet; forward the first to the test
			f, err := srvRead(ctx, c)
			if err != nil {
				return
			}
			if f.Packet == nil {
				continue
			}
			_ = srvWrite(ctx, c, wire.Frame{Ack: &wire.Ack{HighestSequence: f.Packet.Sequence, ServerTime: time.Now().UTC()}})
			select {
			case pktCh <- *f.Packet:
			default:
			}
		}
	})

	runAgent(t, testOptions(srv.URL, wire.SubprotocolJSON), deps)

	waitFor(t, "targets applied", func() bool { return len(fc.lastTargets()) == 1 })
	if base, regular := fs.intervals(); base != 5*time.Second || regular != 60*time.Second {
		t.Errorf("intervals = %v/%v, want 5s/60s", base, regular)
	}
	// A packet sent after the push must carry the applied version.
	if _, err := outbox.Append([]telemetry.Metric{
		{TS: time.Now().UTC(), Kind: telemetry.AgentUptime, Target: "agent", Value: 2, Unit: telemetry.UnitSec},
	}, nil, nil, nil); err != nil {
		t.Fatalf("wal append: %v", err)
	}
	select {
	case pkt := <-pktCh:
		if pkt.ReportedConfigVersion != 7 {
			t.Errorf("packet ReportedConfigVersion = %d, want 7", pkt.ReportedConfigVersion)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no packet after DesiredState push")
	}
}

// TestSnapshotRequestServed covers the on-demand snapshot path, including the
// agent-side opt-in re-check: connections were NOT enabled at launch, so a
// request wanting both must collect processes only.
func TestSnapshotRequestServed(t *testing.T) {
	deps, _, _, _ := newTestDeps(t)
	deps.ReportProcs = true // ReportConns deliberately left false
	var mu sync.Mutex
	var collectedProcs, collectedConns bool
	deps.CollectSnapshot = func(_ context.Context, requestID string, wantProcs, wantConns bool) telemetry.HostSnapshot {
		mu.Lock()
		collectedProcs, collectedConns = wantProcs, wantConns
		mu.Unlock()
		return telemetry.HostSnapshot{TS: time.Now().UTC(), RequestID: requestID, ProcessTotal: 42}
	}

	snapCh := make(chan telemetry.HostSnapshot, 1)
	srv := startServer(t, func(ctx context.Context, c *websocket.Conn) {
		if f, err := srvRead(ctx, c); err != nil || f.Hello == nil {
			t.Errorf("first frame: %+v, err %v; want Hello", f, err)
			return
		}
		if err := srvWrite(ctx, c, wire.Frame{SnapshotRequest: &pcfg.SnapshotRequest{
			RequestID: "r1", WantProcesses: true, WantConnections: true,
		}}); err != nil {
			t.Errorf("write snapshot request: %v", err)
			return
		}
		for {
			f, err := srvRead(ctx, c)
			if err != nil {
				return
			}
			if f.HostSnapshot != nil {
				select {
				case snapCh <- *f.HostSnapshot:
				default:
				}
			}
		}
	})

	runAgent(t, testOptions(srv.URL, wire.SubprotocolJSON), deps)

	select {
	case snap := <-snapCh:
		if snap.RequestID != "r1" || snap.ProcessTotal != 42 {
			t.Errorf("snapshot = %+v, want RequestID r1 / ProcessTotal 42", snap)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no HostSnapshot frame after SnapshotRequest")
	}
	mu.Lock()
	defer mu.Unlock()
	if !collectedProcs || collectedConns {
		t.Errorf("collected procs=%v conns=%v, want procs only (conns not opted in)", collectedProcs, collectedConns)
	}
}

// TestReconnectAfterServerClose: when the server drops the connection the
// client must redial (with backoff) and resend Hello on the new session.
func TestReconnectAfterServerClose(t *testing.T) {
	deps, _, _, _ := newTestDeps(t)
	var dials atomic.Int32
	reconnected := make(chan struct{})
	srv := startServer(t, func(ctx context.Context, c *websocket.Conn) {
		n := dials.Add(1)
		f, err := srvRead(ctx, c)
		if err != nil || f.Hello == nil {
			t.Errorf("dial %d first frame: %+v, err %v; want Hello", n, f, err)
			return
		}
		if n == 1 {
			_ = c.Close(websocket.StatusGoingAway, "server restart")
			return
		}
		if n == 2 {
			close(reconnected)
		}
		_, _ = srvRead(ctx, c) // hold open
	})

	runAgent(t, testOptions(srv.URL, wire.SubprotocolJSON), deps)

	select {
	case <-reconnected:
	case <-time.After(5 * time.Second):
		t.Fatalf("client did not reconnect after server close (dials=%d)", dials.Load())
	}
}

// TestSupersededStopsReconnecting: a 4000 close means another process owns the
// credential; redialing would kick that one back in an endless loop, so Run
// must return an error instead of backing off.
func TestSupersededStopsReconnecting(t *testing.T) {
	deps, _, _, _ := newTestDeps(t)
	var dials atomic.Int32
	srv := startServer(t, func(ctx context.Context, c *websocket.Conn) {
		dials.Add(1)
		if f, err := srvRead(ctx, c); err != nil || f.Hello == nil {
			t.Errorf("first frame: %+v, err %v; want Hello", f, err)
			return
		}
		_ = c.Close(statusSuperseded, "superseded")
	})

	errCh := make(chan error, 1)
	go func() { errCh <- Run(context.Background(), testOptions(srv.URL, wire.SubprotocolJSON), deps) }()
	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("Run returned nil after superseded close; want an error")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run kept running after superseded close (reconnect loop?)")
	}
	if n := dials.Load(); n != 1 {
		t.Errorf("dials = %d, want exactly 1 (no reconnect after superseded)", n)
	}
}

// TestStaleDesiredStateIgnored: the server's fan-out can deliver an older
// config version after a newer one; the agent must skip it rather than regress
// targets and appliedConfigVersion.
func TestStaleDesiredStateIgnored(t *testing.T) {
	deps, _, fc, _ := newTestDeps(t)
	push := func(v int, target string) wire.Frame {
		return wire.Frame{DesiredState: &pcfg.DesiredState{
			ConfigVersion: v,
			ProbeTargets:  []pcfg.ProbeTarget{{Kind: "icmp", Target: target}},
			Intervals:     pcfg.Intervals{BaseSeconds: 5, RegularSeconds: 60},
		}}
	}
	srv := startServer(t, func(ctx context.Context, c *websocket.Conn) {
		if f, err := srvRead(ctx, c); err != nil || f.Hello == nil {
			t.Errorf("first frame: %+v, err %v; want Hello", f, err)
			return
		}
		// FIFO on one connection: v7 applies, stale v5 must be skipped, v8
		// applies — so exactly two SetTargets calls and never v5's target.
		for _, f := range []wire.Frame{push(7, "7.7.7.7"), push(5, "5.5.5.5"), push(8, "8.8.8.8")} {
			if err := srvWrite(ctx, c, f); err != nil {
				t.Errorf("write desired state: %v", err)
				return
			}
		}
		_, _ = srvRead(ctx, c) // hold open
	})

	runAgent(t, testOptions(srv.URL, wire.SubprotocolJSON), deps)

	waitFor(t, "v8 applied", func() bool {
		ts := fc.lastTargets()
		return len(ts) == 1 && ts[0].Target == "8.8.8.8"
	})
	if n := fc.callCount(); n != 2 {
		t.Errorf("SetTargets calls = %d, want 2 (v7 and v8; stale v5 skipped)", n)
	}
}

// TestGracefulShutdownSendsNormalClosure: cancelling the agent's context must
// complete a clean close handshake — the server reads StatusNormalClosure,
// which is what lets it mark the agent offline instantly.
func TestGracefulShutdownSendsNormalClosure(t *testing.T) {
	deps, _, _, _ := newTestDeps(t)
	helloSeen := make(chan struct{})
	statusCh := make(chan websocket.StatusCode, 1)
	srv := startServer(t, func(ctx context.Context, c *websocket.Conn) {
		f, err := srvRead(ctx, c)
		if err != nil || f.Hello == nil {
			t.Errorf("first frame: %+v, err %v; want Hello", f, err)
			return
		}
		close(helloSeen)
		for {
			if _, err := srvRead(ctx, c); err != nil {
				statusCh <- websocket.CloseStatus(err)
				return
			}
		}
	})

	cancel := runAgent(t, testOptions(srv.URL, wire.SubprotocolJSON), deps)

	select {
	case <-helloSeen:
	case <-time.After(5 * time.Second):
		t.Fatal("server never received Hello")
	}
	cancel()
	select {
	case st := <-statusCh:
		if st != websocket.StatusNormalClosure {
			t.Fatalf("server saw close status %v, want StatusNormalClosure", st)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server never observed the client close")
	}
}
