package conn

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/nettact/protocol/wire"
)

// The clock anchor for a router's opening drain comes from the handshake
// response's Date header, so this pins the two things that has to be true of it:
// the server sends one, and the adapter surfaces it.
//
// It matters because of ordering. The session's first act is to drain the
// backlog accumulated while the server was unreachable — on a rebooted router,
// the whole outage, stamped by a clock a power cut reset. An anchor taken from
// the first acknowledgement arrives strictly after that drain has gone out.
func TestUpgradeResponseCarriesAServerDate(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := websocket.Accept(w, r, &websocket.AcceptOptions{
			Subprotocols: []string{wire.SubprotocolJSON},
		})
		if err != nil {
			return
		}
		defer c.CloseNow()
		<-r.Context().Done()
	}))
	defer srv.Close()

	dial, err := wsDialer(Options{ServerURL: srv.URL, Format: wire.SubprotocolJSON})
	if err != nil {
		t.Fatalf("build dialer: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := dial(ctx, "token")
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = c.Close(wire.CloseNormalClosure, "") }()

	sc, ok := c.(serverClock)
	if !ok {
		t.Fatal("the WebSocket adapter no longer reports a server clock")
	}
	got, have := sc.ServerDate()
	if !have {
		t.Fatal("no Date header on the upgrade response; the opening drain would go out unanchored")
	}
	// Whole-second resolution is all HTTP-date carries, which is ample against a
	// minutes-wide error — but it must at least be this machine's era.
	if d := time.Since(got); d > time.Minute || d < -time.Minute {
		t.Fatalf("server date %s is %s from now; that is not a handshake timestamp", got, d)
	}
}

// The desktop's in-process pipe connects a server reading this very clock, so it
// deliberately reports nothing and the session must cope.
func TestPipeTransportReportsNoServerClock(t *testing.T) {
	agentSide, _ := wire.Pipe()
	if _, ok := agentSide.(serverClock); ok {
		t.Fatal("the in-process pipe claims to know a server's clock; there is no skew to report")
	}
}
