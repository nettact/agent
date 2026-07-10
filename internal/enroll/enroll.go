// Package enroll performs the agent-side enrollment handshake: prove key
// possession by signing a nonce, present the one-time enrollment token, and
// receive the bearer token used for telemetry (architecture §11). All outbound.
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

	"github.com/nettact/agent/internal/identity"
	"github.com/nettact/protocol"
	"github.com/nettact/protocol/capability"
	protoenroll "github.com/nettact/protocol/enroll"
)

// Enroll registers this agent and returns its credential.
func Enroll(ctx context.Context, serverURL string, insecure bool, priv ed25519.PrivateKey,
	token, hostname, platform, version string, caps []capability.Capability) (identity.Credential, error) {

	nonceBytes := make([]byte, 32)
	_, _ = rand.Read(nonceBytes)
	nonce := base64.StdEncoding.EncodeToString(nonceBytes)

	req := protoenroll.EnrollRequest{
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
	body, _ := json.Marshal(req)

	tr := &http.Transport{}
	if insecure {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // opt-in for LAN self-signed
	}
	client := &http.Client{Timeout: 30 * time.Second, Transport: tr}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, serverURL+"/api/v1/enroll", bytes.NewReader(body))
	if err != nil {
		return identity.Credential{}, err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(httpReq)
	if err != nil {
		return identity.Credential{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return identity.Credential{}, fmt.Errorf("enroll failed (%s): %s", resp.Status, string(msg))
	}

	var er protoenroll.EnrollResponse
	if err := json.NewDecoder(resp.Body).Decode(&er); err != nil {
		return identity.Credential{}, err
	}
	return identity.Credential{AgentID: er.AgentID, SiteID: er.SiteID, AgentToken: er.AgentToken}, nil
}
