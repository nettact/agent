// Package uploader batches telemetry into a Packet and POSTs it to the server
// over HTTPS with gzip (architecture §5.1). All traffic is agent-initiated
// outbound; the agent never listens. The ack carries the confirmed sequence
// watermark (and, from M2, the DesiredState config downlink).
package uploader

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/nettact/protocol/telemetry"
	"github.com/nettact/protocol/wire"
)

// Ack is the server's response to a telemetry upload. DesiredState is present
// when the server has newer monitoring config for this agent (config downlink).
// It aliases wire.Ack so the same type flows through the codec unchanged.
type Ack = wire.Ack

// Options configure an Uploader.
type Options struct {
	ServerURL    string // e.g. http://localhost:8080
	Token        string // bearer token (dev placeholder in M1)
	Hostname     string
	Platform     string
	Version      string
	Capabilities string // comma-separated; lets the server refresh caps on restart
	Insecure     bool   // skip TLS verification (LAN self-signed dev)

	// Format is the wire content-type for uploads (wire.ContentTypeProtobuf or
	// wire.ContentTypeJSON). Empty defaults to protobuf. The agent always advertises
	// Accept for both, so the server may answer in either format.
	Format string
}

type Uploader struct {
	opts   Options
	client *http.Client

	mu     sync.Mutex
	format string // active wire format; downgrades to JSON if the server rejects protobuf
}

func New(opts Options) *Uploader {
	if opts.Format == "" {
		opts.Format = wire.ContentTypeProtobuf
	}
	tr := &http.Transport{}
	if opts.Insecure {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // opt-in for LAN self-signed
	}
	return &Uploader{
		opts:   opts,
		client: &http.Client{Timeout: 30 * time.Second, Transport: tr},
		format: opts.Format,
	}
}

func (u *Uploader) currentFormat() string {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.format
}

func (u *Uploader) downgradeToJSON() {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.format = wire.ContentTypeJSON
}

// Upload encodes the packet in the active wire format (protobuf by default),
// gzip-compresses it, POSTs it, and returns the server ack decoded from whatever
// format the server replied in. If a protobuf upload is rejected by the server
// (a pre-protobuf, JSON-only server answers 400/415), the uploader permanently
// downgrades to JSON and retries once — so a rolling upgrade where the agent is
// updated before the server never stalls the WAL drain.
func (u *Uploader) Upload(ctx context.Context, pkt telemetry.Packet) (Ack, error) {
	format := u.currentFormat()
	ack, status, err := u.attempt(ctx, pkt, format)
	if err != nil && format == wire.ContentTypeProtobuf &&
		(status == http.StatusBadRequest || status == http.StatusUnsupportedMediaType) {
		// The server could not decode protobuf — treat it as JSON-only from now on.
		u.downgradeToJSON()
		ack, _, err = u.attempt(ctx, pkt, wire.ContentTypeJSON)
	}
	return ack, err
}

// attempt performs a single upload in the given format and returns the ack, the
// HTTP status code (0 on a transport-level error before a response), and any error.
func (u *Uploader) attempt(ctx context.Context, pkt telemetry.Packet, format string) (Ack, int, error) {
	raw, err := wire.MarshalPacket(pkt, format)
	if err != nil {
		return Ack{}, 0, err
	}
	var body bytes.Buffer
	gz := gzip.NewWriter(&body)
	if _, err := gz.Write(raw); err != nil {
		return Ack{}, 0, err
	}
	if err := gz.Close(); err != nil {
		return Ack{}, 0, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.opts.ServerURL+"/api/v1/telemetry", &body)
	if err != nil {
		return Ack{}, 0, err
	}
	req.Header.Set("Content-Type", format)
	req.Header.Set("Content-Encoding", "gzip")
	// Advertise both so the server may answer in protobuf (preferred) or JSON.
	req.Header.Set("Accept", wire.ContentTypeProtobuf+", "+wire.ContentTypeJSON)
	req.Header.Set("Authorization", "Bearer "+u.opts.Token)
	req.Header.Set("X-Agent-Hostname", u.opts.Hostname)
	req.Header.Set("X-Agent-Platform", u.opts.Platform)
	req.Header.Set("X-Agent-Version", u.opts.Version)
	if u.opts.Capabilities != "" {
		req.Header.Set("X-Agent-Capabilities", u.opts.Capabilities)
	}

	resp, err := u.client.Do(req)
	if err != nil {
		return Ack{}, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return Ack{}, resp.StatusCode, fmt.Errorf("server returned %s: %s", resp.Status, string(msg))
	}
	// The ack is small; read it fully so protobuf (which needs the whole buffer)
	// and JSON both decode via the codec keyed off the response Content-Type.
	rawResp, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return Ack{}, resp.StatusCode, err
	}
	ack, err := wire.UnmarshalAck(rawResp, resp.Header.Get("Content-Type"))
	return ack, resp.StatusCode, err
}
