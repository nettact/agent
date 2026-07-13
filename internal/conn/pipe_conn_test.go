package conn

import (
	"context"
	"errors"
	"testing"
	"time"

	pcfg "github.com/nettact/protocol/config"
	"github.com/nettact/protocol/telemetry"
	"github.com/nettact/protocol/wire"
)

// pipeDialer returns a wire.Dialer that hands the caller one pipe end and
// invokes script with the server end on its own goroutine — the in-memory
// analogue of startServer, with no HTTP or sockets. It captures the token the
// agent dialed with so tests can assert auth parity.
func pipeDialer(t *testing.T, tokenCh chan<- string, script func(ctx context.Context, c wire.Conn)) wire.Dialer {
	t.Helper()
	return func(ctx context.Context, token string) (wire.Conn, error) {
		select {
		case tokenCh <- token:
		default:
		}
		agentEnd, serverEnd := wire.Pipe()
		go func() {
			sctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			script(sctx, serverEnd)
			_ = serverEnd.Close(wire.CloseNormalClosure, "")
		}()
		return agentEnd, nil
	}
}

// TestRunOverPipe exercises the full session — Hello handshake, a DesiredState
// push applied, and a Packet acked — over an in-memory wire.Pipe injected via
// Options.Dialer. This is the desktop transport path with no WebSocket at all.
func TestRunOverPipe(t *testing.T) {
	deps, outbox, fc, fs := newTestDeps(t)

	// Seed one batch so the session has something to drain + await an ack for.
	if _, err := outbox.Append([]telemetry.Metric{
		{TS: time.Now().UTC(), Kind: telemetry.AgentUptime, Target: "agent", Layer: telemetry.LayerLocal, Value: 1, Unit: telemetry.UnitSec},
	}, nil, nil, nil); err != nil {
		t.Fatalf("seed wal: %v", err)
	}

	acked := make(chan uint64, 1)
	tokenCh := make(chan string, 1)
	dialer := pipeDialer(t, tokenCh, func(ctx context.Context, c wire.Conn) {
		// First frame must be Hello.
		f, err := c.ReadFrame(ctx)
		if err != nil || f.Hello == nil {
			t.Errorf("first frame: %+v err=%v; want Hello", f, err)
			return
		}
		// Push DesiredState down.
		ds := pcfg.DesiredState{
			ConfigVersion: 9,
			ProbeTargets:  []pcfg.ProbeTarget{{Kind: "icmp", Target: "9.9.9.9"}},
			Intervals:     pcfg.Intervals{BaseSeconds: 5, RegularSeconds: 60},
		}
		_ = c.WriteFrame(ctx, wire.Frame{DesiredState: &ds})
		// Read the agent's telemetry packet and ack it.
		for {
			f, err := c.ReadFrame(ctx)
			if err != nil {
				return
			}
			if f.Packet != nil {
				_ = c.WriteFrame(ctx, wire.Frame{Ack: &wire.Ack{HighestSequence: f.Packet.Sequence, ServerTime: time.Now().UTC()}})
				select {
				case acked <- f.Packet.Sequence:
				default:
				}
			}
		}
	})

	opts := testOptions("", wire.SubprotocolProtobuf)
	opts.Dialer = dialer
	runAgent(t, opts, deps)

	waitFor(t, "config v9 applied", func() bool {
		ts := fc.lastTargets()
		return len(ts) == 1 && ts[0].Target == "9.9.9.9"
	})
	if base, _ := fs.intervals(); base != 5*time.Second {
		t.Errorf("base interval = %v, want 5s", base)
	}
	select {
	case <-acked:
	case <-time.After(3 * time.Second):
		t.Fatal("server never received an acked packet over the pipe")
	}
	select {
	case tok := <-tokenCh:
		if tok != "test-token" {
			t.Errorf("dialer token = %q, want test-token", tok)
		}
	default:
		t.Error("dialer was never invoked")
	}
}

// TestRunOverPipeRevoked confirms a CloseRevoked from the server end propagates
// through the pipe to the same terminal ErrRevoked classification the WebSocket
// path produces.
func TestRunOverPipeRevoked(t *testing.T) {
	deps, _, _, _ := newTestDeps(t)
	dialer := pipeDialer(t, make(chan string, 1), func(ctx context.Context, c wire.Conn) {
		if f, err := c.ReadFrame(ctx); err != nil || f.Hello == nil {
			t.Errorf("first frame: %+v err=%v; want Hello", f, err)
			return
		}
		_ = c.Close(wire.CloseRevoked, "revoked")
	})

	opts := testOptions("", wire.SubprotocolProtobuf)
	opts.Dialer = dialer

	errCh := make(chan error, 1)
	go func() { errCh <- Run(context.Background(), opts, deps) }()
	select {
	case err := <-errCh:
		if wire.CloseStatus(err) != wire.CloseRevoked && !errors.Is(err, ErrRevoked) {
			t.Fatalf("Run err = %v; want ErrRevoked", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after revoked close")
	}
}
