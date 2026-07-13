// Package enroll performs the agent-side enrollment handshake: prove key
// possession by signing a nonce, present the one-time enrollment token, and
// receive the bearer token used for telemetry (architecture §11). All outbound.
//
// The handshake is split into BuildRequest (assemble + sign, transport-free) and
// Post (the HTTP exchange). Standalone agents compose the two; the desktop keeps
// BuildRequest and hands the request to the embedded Lite server directly,
// skipping HTTP entirely.
package enroll

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/nettact/protocol"
	"github.com/nettact/protocol/capability"
	protoenroll "github.com/nettact/protocol/enroll"
)

// BuildRequest assembles and signs an enrollment request, proving possession of
// the private key by signing a fresh random nonce.
func BuildRequest(priv ed25519.PrivateKey, token, hostname, platform, version string,
	caps []capability.Capability) protoenroll.EnrollRequest {

	nonceBytes := make([]byte, 32)
	_, _ = rand.Read(nonceBytes)
	nonce := base64.StdEncoding.EncodeToString(nonceBytes)

	return protoenroll.EnrollRequest{
		SchemaVersion:   protocol.SchemaVersion,
		EnrollmentToken: token,
		PublicKey:       priv.Public().(ed25519.PublicKey),
		Nonce:           nonce,
		Signature:       ed25519.Sign(priv, []byte(nonce)),
		Hostname:        hostname,
		Platform:        platform,
		AgentVersion:    version,
		Capabilities:    caps,
	}
}

// Post performs the HTTP POST /api/v1/enroll exchange (standalone path).
func Post(ctx context.Context, serverURL string, insecure bool,
	req protoenroll.EnrollRequest) (protoenroll.EnrollResponse, error) {

	body, _ := json.Marshal(req)

	tr := &http.Transport{}
	if insecure {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // opt-in for LAN self-signed
	}
	client := &http.Client{Timeout: 30 * time.Second, Transport: tr}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, serverURL+"/api/v1/enroll", bytes.NewReader(body))
	if err != nil {
		return protoenroll.EnrollResponse{}, err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(httpReq)
	if err != nil {
		return protoenroll.EnrollResponse{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return protoenroll.EnrollResponse{}, fmt.Errorf("enroll failed (%s): %s", resp.Status, string(msg))
	}

	var er protoenroll.EnrollResponse
	if err := json.NewDecoder(resp.Body).Decode(&er); err != nil {
		return protoenroll.EnrollResponse{}, err
	}
	return er, nil
}
