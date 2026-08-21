package identity

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
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

// The negotiated wire-schema record rides the same file additively. Three
// directions have to hold at once, and each one is a way this could silently
// destroy credentials rather than merely lose a hint:
//
//  1. a save of one server's record leaves every credential and every OTHER
//     server's record byte-intact;
//  2. a file written by a build that never knew about the record still loads,
//     with no record and every credential present;
//  3. the file this build writes is still readable by a build that has no such
//     field — which is what the unchanged format number buys, and the reason
//     that number must never be bumped for an added key.
func TestNegotiatedRecordIsAdditive(t *testing.T) {
	dataDir, err := os.MkdirTemp("", "nettact-identity-neg-")
	if err != nil {
		t.Fatalf("temp dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dataDir) })

	alpha := Credential{AgentID: "agent-a", SiteID: "site-a", AgentToken: "token-a", EnrollmentEpoch: 3}
	beta := Credential{AgentID: "agent-b", SiteID: "site-b", AgentToken: "token-b"}
	if err := SaveCredential(dataDir, "alpha", alpha); err != nil {
		t.Fatalf("SaveCredential(alpha): %v", err)
	}
	if err := SaveCredential(dataDir, "beta", beta); err != nil {
		t.Fatalf("SaveCredential(beta): %v", err)
	}

	// (2) before anything is recorded, a legacy-shaped file has no records and
	// does not name the key at all.
	raw, err := os.ReadFile(filepath.Join(dataDir, credentialFile))
	if err != nil {
		t.Fatalf("read credential file: %v", err)
	}
	if bytes.Contains(raw, []byte("negotiated")) {
		t.Fatalf("a file that has learned nothing still names the record: %s", raw)
	}
	recs, err := LoadNegotiated(dataDir)
	if err != nil {
		t.Fatalf("LoadNegotiated (legacy shape): %v", err)
	}
	if len(recs) != 0 {
		t.Fatalf("LoadNegotiated on a legacy file = %+v, want empty", recs)
	}

	// (1) one server's record lands, and nothing else moves.
	decided := time.Date(2026, 8, 21, 10, 0, 0, 0, time.UTC)
	rec := Negotiated{Schema: 7, AgentVersion: "v0.4.8", DecidedAt: decided, LastProbe: decided}
	if err := SaveNegotiated(dataDir, "alpha", rec); err != nil {
		t.Fatalf("SaveNegotiated: %v", err)
	}
	creds, err := LoadCredentials(dataDir)
	if err != nil {
		t.Fatalf("LoadCredentials after SaveNegotiated: %v", err)
	}
	if creds["alpha"] != alpha || creds["beta"] != beta {
		t.Fatalf("credentials after a negotiation save = %+v; want both intact", creds)
	}
	recs, err = LoadNegotiated(dataDir)
	if err != nil {
		t.Fatalf("LoadNegotiated: %v", err)
	}
	if got := recs["alpha"]; got.Schema != 7 || got.AgentVersion != "v0.4.8" || !got.LastProbe.Equal(decided) {
		t.Fatalf("negotiation record = %+v; want schema 7 recorded for v0.4.8 at %s", got, decided)
	}
	if _, ok := recs["beta"]; ok {
		t.Fatalf("a record was invented for a server that never negotiated: %+v", recs)
	}

	// A credential save must carry the record through its own read-modify-write.
	alpha.AgentToken = "token-a2"
	if err := SaveCredential(dataDir, "alpha", alpha); err != nil {
		t.Fatalf("SaveCredential after SaveNegotiated: %v", err)
	}
	recs, err = LoadNegotiated(dataDir)
	if err != nil {
		t.Fatalf("LoadNegotiated after a credential save: %v", err)
	}
	if recs["alpha"].Schema != 7 {
		t.Fatalf("a credential save dropped the negotiation record: %+v", recs)
	}

	// Deleting a credential (the revocation path) keeps the record: the
	// enrollment that immediately follows is what needs it most.
	if err := DeleteCredential(dataDir, "alpha"); err != nil {
		t.Fatalf("DeleteCredential: %v", err)
	}
	recs, err = LoadNegotiated(dataDir)
	if err != nil {
		t.Fatalf("LoadNegotiated after DeleteCredential: %v", err)
	}
	if recs["alpha"].Schema != 7 {
		t.Fatalf("deleting a credential dropped the negotiation record the re-enrollment needs: %+v", recs)
	}

	// (3) the format number is unchanged, so an older build still reads every
	// credential out of the file this one wrote. Decoding into a struct without
	// the field is exactly what that build does.
	raw, err = os.ReadFile(filepath.Join(dataDir, credentialFile))
	if err != nil {
		t.Fatalf("read credential file: %v", err)
	}
	var legacy struct {
		V       int                   `json:"v"`
		Servers map[string]Credential `json:"servers"`
	}
	if err := json.Unmarshal(raw, &legacy); err != nil {
		t.Fatalf("a build without the field cannot parse the file: %v", err)
	}
	if legacy.V != credentialFormat {
		t.Fatalf("file format = %d, want %d — bumping it makes an older build discard every credential", legacy.V, credentialFormat)
	}
	if legacy.Servers["beta"] != beta {
		t.Fatalf("a build without the field reads beta as %+v, want %+v", legacy.Servers["beta"], beta)
	}
}

// PruneCredentials is the one path that must forget a record: the server is no
// longer configured at all, so a later entry reusing the name is a different
// server and must not inherit its conclusion.
func TestPruneForgetsNegotiatedRecords(t *testing.T) {
	dataDir, err := os.MkdirTemp("", "nettact-identity-prune-")
	if err != nil {
		t.Fatalf("temp dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dataDir) })

	if err := SaveCredential(dataDir, "keep", Credential{AgentID: "a", AgentToken: "t1"}); err != nil {
		t.Fatalf("SaveCredential(keep): %v", err)
	}
	if err := SaveNegotiated(dataDir, "keep", Negotiated{Schema: 7}); err != nil {
		t.Fatalf("SaveNegotiated(keep): %v", err)
	}
	if err := SaveNegotiated(dataDir, "gone", Negotiated{Schema: 7}); err != nil {
		t.Fatalf("SaveNegotiated(gone): %v", err)
	}
	if _, err := PruneCredentials(dataDir, []string{"keep"}); err != nil {
		t.Fatalf("PruneCredentials: %v", err)
	}
	recs, err := LoadNegotiated(dataDir)
	if err != nil {
		t.Fatalf("LoadNegotiated: %v", err)
	}
	if _, ok := recs["gone"]; ok {
		t.Fatalf("a removed server kept its negotiation record: %+v", recs)
	}
	if recs["keep"].Schema != 7 {
		t.Fatalf("a configured server lost its negotiation record: %+v", recs)
	}
}
