package conn

import (
	"context"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/nettact/agent/internal/wal"
	"github.com/nettact/protocol/telemetry"
	"github.com/nettact/protocol/wire"
)

// A revoked agent deletes its credential and re-enrolls, and without a
// console-issued reinstall token the server mints a brand-new agent_id. The
// queue is keyed by server NAME, which survives that, so the session that comes
// back must not upload what the previous identity collected: the server files
// every packet under the identity it authenticated, and the old agent's metrics,
// events, traceroutes and scenes would land on the new agent's timeline.
//
// This asserts the wiring — that Run binds its identity to the outbox before the
// first drain can claim anything. What discarding means for the store itself
// (cursor advanced, claim released, segments collected) is pinned in the wal
// package's own tests.
func TestReenrolledSessionNeverUploadsThePreviousIdentitysQueue(t *testing.T) {
	deps, outbox, _, _ := newTestDeps(t)

	// The state a revocation leaves behind: a queue collected under one identity
	// and a credential that now names a different one.
	if _, err := outbox.BindIdentity(testServer, "agent-revoked"); err != nil {
		t.Fatalf("bind previous identity: %v", err)
	}
	if _, err := outbox.Append(wal.Records{Metrics: []telemetry.Metric{
		{TS: time.Now().UTC(), Kind: telemetry.AgentUptime, Target: "agent", Value: 1, Unit: telemetry.UnitSec},
	}}, testServer); err != nil {
		t.Fatalf("wal append: %v", err)
	}

	gotCh := make(chan telemetry.Packet, 1)
	srv := startServer(t, func(ctx context.Context, c *websocket.Conn) {
		first, err := srvRead(ctx, c)
		if err != nil || first.Hello == nil {
			t.Errorf("first frame: %+v, err %v; want Hello", first, err)
			return
		}
		// Run binds the identity before it dials, so a Hello on the wire proves
		// the discard has already happened and anything appended from here on
		// belongs to the identity this session authenticated as.
		if _, err := outbox.Append(wal.Records{Metrics: []telemetry.Metric{
			{TS: time.Now().UTC(), Kind: telemetry.AgentUptime, Target: "agent", Value: 2, Unit: telemetry.UnitSec},
		}}, testServer); err != nil {
			t.Errorf("wal append: %v", err)
			return
		}
		f, err := srvRead(ctx, c)
		if err != nil || f.Packet == nil {
			t.Errorf("second frame: %+v, err %v; want Packet", f, err)
			return
		}
		if err := srvWrite(ctx, c, wire.Frame{Ack: &wire.Ack{
			HighestSequence: f.Packet.Sequence, ServerTime: time.Now().UTC(),
		}}); err != nil {
			t.Errorf("write ack: %v", err)
			return
		}
		gotCh <- *f.Packet
		_, _ = srvRead(ctx, c) // hold the connection open until the client leaves
	})

	runAgent(t, testOptions(srv.URL, wire.SubprotocolJSON), deps)

	select {
	case pkt := <-gotCh:
		if len(pkt.Metrics) != 1 || pkt.Metrics[0].Value != 2 {
			t.Fatalf("packet authenticated as %s carries %+v; the revoked identity's records must never be uploaded",
				pkt.AgentID, pkt.Metrics)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server never received a packet")
	}
	waitFor(t, "WAL drained after the discard and the ack", func() bool { return outbox.Pending(testServer) == 0 })
}
