// This file isolates every coder/websocket dependency of the conn package. The
// session logic in conn.go works against wire.Conn; wsConn adapts a real
// WebSocket to that interface (owning the codec fixed by the negotiated
// subprotocol and translating close codes), and wsDialer is the default
// wire.Dialer used whenever the caller injects none — i.e. every standalone
// agent. The desktop injects an in-process pipe dialer instead, so this file is
// never exercised there.
package conn

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"

	"github.com/coder/websocket"

	"github.com/nettact/protocol/wire"
)

const (
	// wsPath is the server's agent WebSocket endpoint (bearer auth on upgrade).
	wsPath = "/api/v1/agent/ws"

	// readLimit raises coder/websocket's 32 KiB default: a DesiredState push for
	// a site with many probe targets easily exceeds that.
	readLimit = 1 << 20
)

// wsConn adapts *websocket.Conn to wire.Conn. contentType is fixed by the
// subprotocol negotiated at dial time and selects the codec for every frame.
type wsConn struct {
	c           *websocket.Conn
	contentType string
}

func (w *wsConn) ReadFrame(ctx context.Context) (wire.Frame, error) {
	_, data, err := w.c.Read(ctx)
	if err != nil {
		return wire.Frame{}, translateReadErr(err)
	}
	f, err := wire.UnmarshalFrame(data, w.contentType)
	if err != nil {
		return wire.Frame{}, fmt.Errorf("decode frame: %w", err)
	}
	return f, nil
}

func (w *wsConn) WriteFrame(ctx context.Context, f wire.Frame) error {
	data, err := wire.MarshalFrame(f, w.contentType)
	if err != nil {
		return err
	}
	msgType := websocket.MessageBinary
	if w.contentType == wire.ContentTypeJSON {
		msgType = websocket.MessageText
	}
	return w.c.Write(ctx, msgType, data)
}

func (w *wsConn) Ping(ctx context.Context) error {
	return w.c.Ping(ctx)
}

func (w *wsConn) Close(code wire.CloseCode, reason string) error {
	return w.c.Close(websocket.StatusCode(code), reason)
}

// translateReadErr surfaces a peer close as a *wire.CloseError so conn.Run can
// classify terminal outcomes through wire.CloseStatus, uniformly with the pipe
// transport. Non-close errors (transport failures) pass through wrapped.
func translateReadErr(err error) error {
	if code := websocket.CloseStatus(err); code != -1 {
		return &wire.CloseError{Code: wire.CloseCode(code), Reason: err.Error()}
	}
	return fmt.Errorf("read: %w", err)
}

// wsDialer builds the default WebSocket wire.Dialer from opts. It returns an
// error for an unusable ServerURL — the same "config is broken, retrying can't
// help" contract Run previously got from deriveWSURL.
func wsDialer(opts Options) (wire.Dialer, error) {
	wsURL, err := deriveWSURL(opts.ServerURL)
	if err != nil {
		return nil, err
	}
	contentType := wire.SubprotocolContentType(opts.Format)

	tr := &http.Transport{}
	if opts.Insecure {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // opt-in for LAN self-signed
	}
	httpClient := &http.Client{Transport: tr}

	return func(ctx context.Context, token string) (wire.Conn, error) {
		c, _, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{
			HTTPHeader:   http.Header{"Authorization": {"Bearer " + token}},
			Subprotocols: []string{opts.Format},
			HTTPClient:   httpClient,
		})
		if err != nil {
			return nil, fmt.Errorf("dial: %w", err)
		}
		c.SetReadLimit(readLimit)
		return &wsConn{c: c, contentType: contentType}, nil
	}, nil
}

// deriveWSURL maps the configured server base URL onto the WebSocket endpoint.
func deriveWSURL(server string) (string, error) {
	u, err := url.Parse(server)
	if err != nil {
		return "", fmt.Errorf("parse server URL: %w", err)
	}
	switch u.Scheme {
	case "http":
		u.Scheme = "ws"
	case "https":
		u.Scheme = "wss"
	default:
		return "", fmt.Errorf("server URL scheme must be http or https, got %q", u.Scheme)
	}
	return u.JoinPath(wsPath).String(), nil
}
