// Package enroll performs the agent-side enrollment handshake: prove key
// possession by signing a nonce, present the one-time enrollment token, and
// receive the bearer token used for telemetry (architecture §11). All outbound.
//
// The handshake is split into BuildRequest (assemble + sign, transport-free) and
// Post (the HTTP exchange). Standalone agents compose the two; the desktop keeps
// BuildRequest and hands the request to the embedded server directly,
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
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/nettact/protocol"
	protoenroll "github.com/nettact/protocol/enroll"
	"github.com/nettact/protocol/permission"
)

// BuildRequest assembles and signs an enrollment request, proving possession of
// the private key by signing a fresh random nonce.
func BuildRequest(priv ed25519.PrivateKey, token, hostname, platform, version string,
	report permission.PermissionReport) protoenroll.EnrollRequest {

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
		Permissions:     report,
	}
}

// ErrRejected marks an enrollment the server ANSWERED and refused — a spent or
// expired token, a site at its agent quota, a schema it will not accept.
//
// It exists because the two ways enrollment fails call for opposite responses. A
// server that cannot be reached is a transient condition the agent retries out
// of on its own, and telling the user their token is bad would have them discard
// a token that is still perfectly good. A server that replied "no" will keep
// replying "no" until a human does something. Only a reply can distinguish them,
// so only this path can carry the distinction.
var ErrRejected = errors.New("server rejected the enrollment")

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
		err := fmt.Errorf("enroll failed (%s): %s", resp.Status, string(msg))
		// 4xx is the server having read the request and refused it. 5xx is not:
		// a server that is starting up, out of disk, or behind a proxy returning
		// 502 will accept the very same token once it recovers, so it stays in
		// the retryable class.
		if resp.StatusCode >= 400 && resp.StatusCode < 500 {
			return protoenroll.EnrollResponse{}, fmt.Errorf("%w: %v", ErrRejected, err)
		}
		return protoenroll.EnrollResponse{}, err
	}

	var er protoenroll.EnrollResponse
	if err := json.NewDecoder(resp.Body).Decode(&er); err != nil {
		return protoenroll.EnrollResponse{}, err
	}
	return er, nil
}
