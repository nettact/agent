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
	"strings"
	"time"

	"github.com/nettact/protocol"
	protoenroll "github.com/nettact/protocol/enroll"
	"github.com/nettact/protocol/permission"
)

// PreviousSchema is the wire schema this build can still enroll under, one
// below its native one. It is written out rather than derived from the native
// version because keeping the version below speakable is a deliberate release
// decision, not an arithmetic consequence: the release that stops accepting it
// deletes this path, and a future native bump must not silently re-target it at
// a schema this binary cannot actually produce.
const PreviousSchema = 7

// BuildRequest assembles and signs an enrollment request, proving possession of
// the private key by signing a fresh random nonce.
//
// schema is the wire schema the request declares. It is a parameter rather than
// the build's native constant because a server one release behind refuses an
// enrollment whose schema it does not know, and the only way past that is to
// ask again in the schema it does know. Zero selects the native schema.
func BuildRequest(schema int, priv ed25519.PrivateKey, token, hostname, platform, version string,
	report permission.PermissionReport) protoenroll.EnrollRequest {

	if schema == 0 {
		schema = protocol.SchemaVersion
	}

	nonceBytes := make([]byte, 32)
	_, _ = rand.Read(nonceBytes)
	nonce := base64.StdEncoding.EncodeToString(nonceBytes)

	return protoenroll.EnrollRequest{
		SchemaVersion:   schema,
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

// StatusError is a non-2xx enrollment answer, kept in the shape it arrived in:
// the HTTP status and the (truncated) body. It exists so callers can decide on
// the ANSWER rather than on a formatted sentence — a downgrade retry has to
// recognise one particular refusal, and matching a substring of an error string
// that another edit could reword is not a contract.
//
// Its Error text reproduces what this package has always printed, so the status
// file and the logs read exactly as before.
type StatusError struct {
	// StatusCode/Status are the HTTP status of the answer.
	StatusCode int
	Status     string
	// Body is the response body, truncated at BodyLimit bytes. Servers answer
	// enrollment failures with a small JSON object, so the limit is never
	// reached in practice; it is there because a body is attacker-influenced
	// input on a path that runs before any credential exists.
	Body string
}

// rejected reports the 4xx class: the server read the request and refused it.
// Derived from the status rather than stored beside it, so the one rule that
// splits "a person must fix this" from "wait and try again" is written down
// once and cannot drift between the constructor and the reader.
func (e *StatusError) rejected() bool {
	return e.StatusCode >= 400 && e.StatusCode < 500
}

// BodyLimit bounds how much of a failed enrollment's response body is read and
// carried on the error.
const BodyLimit = 4096

func (e *StatusError) Error() string {
	msg := fmt.Sprintf("enroll failed (%s): %s", e.Status, e.Body)
	if e.rejected() {
		return fmt.Sprintf("%s: %s", ErrRejected, msg)
	}
	return msg
}

// Unwrap makes a 4xx answer match ErrRejected and leaves a 5xx unmatched, which
// is the split the retry policy is built on: a refusal needs a person, an
// unavailable server needs only time.
func (e *StatusError) Unwrap() error {
	if e.rejected() {
		return ErrRejected
	}
	return nil
}

// schemaRefusedMarker is the fragment a server puts in its answer when the
// enrollment declares a wire schema that build does not know. It is the
// server's own wording, produced by the shared schema check both sides link,
// and it has read the same way since that check was first written.
//
// Matching it is what makes the downgrade retry possible at all. Servers
// released before the current schema boundary answer an unknown enrollment
// schema with an HTTP 500 — enrollment has no dedicated status for "wrong
// schema", so the mismatch falls through to the generic internal-error path —
// and a 500 is otherwise indistinguishable from a proxy hiccup or a server
// still starting up. The status code alone therefore cannot be the trigger:
// keying on "any 500" would turn every transient outage into a schema
// downgrade. The body is the only part of that answer that names the cause.
const schemaRefusedMarker = "unsupported schema_version"

// SchemaRefused reports whether err is a server saying it does not know the
// wire schema the enrollment declared — the one failure a retry in the other
// schema can fix.
//
// It is deliberately narrow in both directions. A 5xx that does not name the
// mismatch keeps its existing "retry with backoff" treatment, so a misfire of
// this predicate can only cost what the agent already does today; and a 4xx is
// never a schema refusal, so the terminal "your token is bad" verdict is
// untouched.
func SchemaRefused(err error) bool {
	var se *StatusError
	if !errors.As(err, &se) {
		return false
	}
	return se.StatusCode >= 500 && strings.Contains(se.Body, schemaRefusedMarker)
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
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, BodyLimit))
		// 4xx is the server having read the request and refused it. 5xx is not:
		// a server that is starting up, out of disk, or behind a proxy returning
		// 502 will accept the very same token once it recovers, so it stays in
		// the retryable class.
		return protoenroll.EnrollResponse{}, &StatusError{
			StatusCode: resp.StatusCode,
			Status:     resp.Status,
			Body:       string(msg),
		}
	}

	var er protoenroll.EnrollResponse
	if err := json.NewDecoder(resp.Body).Decode(&er); err != nil {
		return protoenroll.EnrollResponse{}, err
	}
	return er, nil
}
