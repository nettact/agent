package identity

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// The enrollment epoch rides the v2 credential file additively. It must
// survive a SaveCredential/LoadCredentials round-trip with the rest of the
// credential intact — agentrt's rotation flow persists it together with the new
// bearer token — while a credential written without it (every pre-schema-8
// install) still loads, reading as zero rather than failing the file.
func TestCredentialEpochSurvivesRoundTrip(t *testing.T) {
	dataDir, err := os.MkdirTemp("", "nettact-identity-")
	if err != nil {
		t.Fatalf("temp dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dataDir) })

	path := filepath.Join(dataDir, credentialFile)
	in := Credential{
		AgentID:           "agent-1",
		SiteID:            "site-1",
		AgentToken:        "token-1",
		ConsumedTokenHash: "deadbeef",
		EnrollmentEpoch:   7,
	}
	if err := SaveCredential(dataDir, "alpha", in); err != nil {
		t.Fatalf("SaveCredential: %v", err)
	}
	got, err := LoadCredentials(dataDir)
	if err != nil {
		t.Fatalf("LoadCredentials: %v", err)
	}
	c, ok := got["alpha"]
	if !ok {
		t.Fatal("saved credential missing after LoadCredentials")
	}
	if c != in {
		t.Fatalf("round-tripped credential = %+v, want %+v", c, in)
	}

	// A legacy file: the epoch field is absent from disk and must read as zero.
	in.EnrollmentEpoch = 0
	if err := SaveCredential(dataDir, "alpha", in); err != nil {
		t.Fatalf("SaveCredential (legacy shape): %v", err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read credential file: %v", err)
	}
	if bytes.Contains(b, []byte("enrollment_epoch")) {
		t.Fatalf("credential file still names enrollment_epoch for a zero epoch: %s", b)
	}
	got, err = LoadCredentials(dataDir)
	if err != nil {
		t.Fatalf("LoadCredentials (legacy shape): %v", err)
	}
	if c := got["alpha"]; c.EnrollmentEpoch != 0 || c.AgentToken != "token-1" {
		t.Fatalf("legacy-shaped credential = %+v; want epoch 0 with the token intact", c)
	}
}
