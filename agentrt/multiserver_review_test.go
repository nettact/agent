package agentrt

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"testing"

	"github.com/nettact/agent/internal/enroll"
	"github.com/nettact/agent/internal/identity"
	"github.com/nettact/agent/probepolicy"
	protoenroll "github.com/nettact/protocol/enroll"
	"github.com/nettact/protocol/permission"
)

// errRejectedForTest is what a server answering "no" produces.
var errRejectedForTest = fmt.Errorf("%w: enroll failed (400 Bad Request): token already used", enroll.ErrRejected)

// Regressions from the AGENT-007 review. Each of these was a real defect in the
// first cut of multi-server support.

// A server's guard has to be built from ITS policy, not the agent-wide default.
// The desktop's default is FullAccess — the trust-boundary exemption for the
// server running inside the same process — and sharing one guard handed that
// exemption to a server on someone else's network, which could then probe
// loopback, link-local and the cloud metadata endpoints.
func TestEachServerGuardUsesItsOwnPolicy(t *testing.T) {
	external := permission.Policy{
		Granted: permission.NewSet(permission.ProbeICMP),
		Source:  permission.SourceServerConfig,
	}
	cfg := Config{
		Servers: []ServerConfig{
			{Name: "local", URL: "http://127.0.0.1:1"},
			{Name: "work", URL: "https://work.example", Policy: &external},
		},
		Policy:      permission.FullAccess(),
		ProbeAccess: probepolicy.Default(),
	}
	caps := machineCaps{base: permission.Set{}, gameSupported: permission.Set{}, gameReasons: map[string]string{}}

	local, _ := viewsFor(cfg, cfg.Servers[0], true, caps)
	work, _ := viewsFor(cfg, cfg.Servers[1], false, caps)

	loopback := netip.MustParseAddr("127.0.0.1")
	metadata := netip.MustParseAddr("169.254.169.254")

	if !local.guard.CheckAddr(loopback).Allowed {
		t.Fatal("the in-process server lost its full-access bypass")
	}
	if work.guard.CheckAddr(loopback).Allowed {
		t.Fatal("an external server may probe loopback; it inherited the desktop's bypass")
	}
	if work.guard.CheckAddr(metadata).Allowed {
		t.Fatal("an external server may reach the cloud metadata endpoint")
	}
	if !work.guard.CheckAddr(netip.MustParseAddr("93.184.216.34")).Allowed {
		t.Fatal("an external server cannot reach a public address; the floor is too tight to be useful")
	}
}

// The machine floor is what an external server is held to, so a configuration
// that forgets to set one must not silently become "allow everything". A zero
// probepolicy.Policy has no mode and its address check falls through to
// denylist-default-allow, which is exactly that failure.
func TestZeroProbeAccessIsNotAFloor(t *testing.T) {
	var zero probepolicy.Policy
	if !zero.CheckAddr(netip.MustParseAddr("127.0.0.1")).Allowed {
		t.Skip("a zero policy now denies by default; this guard rail can go")
	}
	// Documented so the desktop's explicit ProbeAccess is not "tidied away": it
	// is load-bearing, not decoration.
	t.Log("a zero probe-access policy allows everything; every host that grants a non-FullAccess server must set one")
}

// Two servers enrolling at the same moment must not erase each other. The
// atomic rename makes each publish whole for a reader, which is a different
// guarantee from the one this needs: both would read the pre-enrollment map and
// the second publish would drop the first's credential.
func TestConcurrentEnrollmentsKeepBothCredentials(t *testing.T) {
	dir := agentDataDir(t)

	var wg sync.WaitGroup
	for _, name := range []string{"alpha", "beta", "gamma", "delta"} {
		wg.Add(1)
		go func(name string) {
			defer wg.Done()
			err := identity.SaveCredential(dir, name, identity.Credential{
				AgentID: "agent_" + name, SiteID: "site", AgentToken: "tok-" + name,
			})
			if err != nil {
				t.Errorf("save %q: %v", name, err)
			}
		}(name)
	}
	wg.Wait()

	creds, err := identity.LoadCredentials(dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	for _, name := range []string{"alpha", "beta", "gamma", "delta"} {
		c, ok := creds[name]
		if !ok {
			t.Fatalf("%q lost its credential to a concurrent enrollment (have %d of 4)", name, len(creds))
		}
		if c.AgentToken != "tok-"+name {
			t.Fatalf("%q holds %q", name, c.AgentToken)
		}
	}
}

// A host that owns its server list outright detaches from a server by removing
// it. Keeping the credential would let a later re-add under the same name resume
// the old identity and never spend the new token.
func TestPruneCredentialsForgetsRemovedServers(t *testing.T) {
	dir := agentDataDir(t)
	for _, name := range []string{"local", "work"} {
		if err := identity.SaveCredential(dir, name, identity.Credential{
			AgentID: "agent_" + name, SiteID: "site", AgentToken: "tok-" + name,
		}); err != nil {
			t.Fatal(err)
		}
	}

	n, err := PruneCredentials(dir, []string{"local"})
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if n != 1 {
		t.Fatalf("pruned %d credentials, want 1", n)
	}
	creds, err := identity.LoadCredentials(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := creds["work"]; ok {
		t.Fatal("the removed server kept its credential")
	}
	if _, ok := creds["local"]; !ok {
		t.Fatal("a configured server lost its credential")
	}

	// Idempotent: nothing left to forget.
	if n, err := PruneCredentials(dir, []string{"local"}); err != nil || n != 0 {
		t.Fatalf("second prune = (%d, %v)", n, err)
	}
}

// "No enrollment token configured" cannot be retried out of, and the standalone
// loaders report it through a TokenSource that exists but has nothing to hand
// out — so the runner has to recognise it through the wrapping, or a first run
// with a missing setting backs off forever instead of failing where an operator
// can see it.
func TestMissingTokenIsTerminalThroughTheLoaderCallback(t *testing.T) {
	rt := &serverRuntime{cfg: ServerConfig{
		Name: "work",
		URL:  "https://work.example",
		TokenSource: func(context.Context) (string, error) {
			return "", ErrNoEnrollmentToken
		},
	}}
	_, err := enrollServer(context.Background(), runEnv{cfg: Config{DataDir: agentDataDir(t)}}, rt)
	if !errors.Is(err, ErrNoEnrollmentToken) {
		t.Fatalf("err = %v; the runner cannot tell this from a server being down", err)
	}
	if !errors.Is(err, ErrEnroll) {
		t.Fatalf("err = %v; it must still read as an enrollment failure", err)
	}
}

// A refusal and an unreachable server call for opposite advice, so they must be
// distinguishable. Only the reply can carry the difference.
func TestRejectedEnrollmentIsDistinguishable(t *testing.T) {
	dir := agentDataDir(t)
	key, err := identity.LoadOrCreateKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	env := runEnv{cfg: Config{DataDir: dir}, key: key, hostname: "host", platformID: "linux"}

	rt := &serverRuntime{cfg: ServerConfig{
		Name:        "work",
		URL:         "https://work.example",
		TokenSource: func(context.Context) (string, error) { return "spent", nil },
		Enroller: func(context.Context, protoenroll.EnrollRequest) (protoenroll.EnrollResponse, error) {
			return protoenroll.EnrollResponse{}, errRejectedForTest
		},
	}}
	_, err = enrollServer(context.Background(), env, rt)
	if !errors.Is(err, ErrEnrollRejected) {
		t.Fatalf("err = %v; a refused token reads as a transient outage", err)
	}

	rt.cfg.Enroller = func(context.Context, protoenroll.EnrollRequest) (protoenroll.EnrollResponse, error) {
		return protoenroll.EnrollResponse{}, errors.New("dial tcp: connection refused")
	}
	_, err = enrollServer(context.Background(), env, rt)
	if errors.Is(err, ErrEnrollRejected) {
		t.Fatalf("err = %v; an unreachable server reads as a refused token", err)
	}
	if !errors.Is(err, ErrEnroll) {
		t.Fatalf("err = %v; it must still read as an enrollment failure", err)
	}
	if !strings.Contains(err.Error(), "connection refused") {
		t.Fatalf("err = %v; the cause the panel shows was lost", err)
	}
}
