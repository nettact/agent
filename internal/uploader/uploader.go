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
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	pcfg "github.com/nettact/protocol/config"
	"github.com/nettact/protocol/telemetry"
)

// Ack is the server's response to a telemetry upload. DesiredState is present
// when the server has newer monitoring config for this agent (config downlink).
type Ack struct {
	HighestSequence uint64             `json:"highest_sequence"`
	ServerTime      time.Time          `json:"server_time"`
	ConfigVersion   int                `json:"config_version"`
	DesiredState    *pcfg.DesiredState `json:"desired_state,omitempty"`
}

// Options configure an Uploader.
type Options struct {
	ServerURL    string // e.g. http://localhost:8080
	Token        string // bearer token (dev placeholder in M1)
	Hostname     string
	Platform     string
	Version      string
	Capabilities string // comma-separated; lets the server refresh caps on restart
	Insecure     bool   // skip TLS verification (LAN self-signed dev)
}

type Uploader struct {
	opts   Options
	client *http.Client
}

func New(opts Options) *Uploader {
	tr := &http.Transport{}
	if opts.Insecure {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // opt-in for LAN self-signed
	}
	return &Uploader{
		opts:   opts,
		client: &http.Client{Timeout: 30 * time.Second, Transport: tr},
	}
}

// Upload gzip-compresses and POSTs the packet, returning the server ack.
func (u *Uploader) Upload(ctx context.Context, pkt telemetry.Packet) (Ack, error) {
	raw, err := json.Marshal(pkt)
	if err != nil {
		return Ack{}, err
	}
	var body bytes.Buffer
	gz := gzip.NewWriter(&body)
	if _, err := gz.Write(raw); err != nil {
		return Ack{}, err
	}
	if err := gz.Close(); err != nil {
		return Ack{}, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.opts.ServerURL+"/api/v1/telemetry", &body)
	if err != nil {
		return Ack{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "gzip")
	req.Header.Set("Authorization", "Bearer "+u.opts.Token)
	req.Header.Set("X-Agent-Hostname", u.opts.Hostname)
	req.Header.Set("X-Agent-Platform", u.opts.Platform)
	req.Header.Set("X-Agent-Version", u.opts.Version)
	if u.opts.Capabilities != "" {
		req.Header.Set("X-Agent-Capabilities", u.opts.Capabilities)
	}

	resp, err := u.client.Do(req)
	if err != nil {
		return Ack{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return Ack{}, fmt.Errorf("server returned %s: %s", resp.Status, string(msg))
	}
	var ack Ack
	if err := json.NewDecoder(resp.Body).Decode(&ack); err != nil {
		return Ack{}, err
	}
	return ack, nil
}
