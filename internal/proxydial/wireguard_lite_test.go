//go:build lite

package proxydial

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	pcfg "github.com/nettact/protocol/config"
)

// A lite agent handed an otherwise VALID WireGuard spec must still refuse it —
// and refuse it deterministically. The valid material matters: an invalid spec
// would be rejected by parsing in the full build too, so only a well-formed one
// shows that the transport itself is absent rather than the config being bad.
func TestWireGuardIsRefusedInLiteBuilds(t *testing.T) {
	m := newTestManager()
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	m.Apply([]pcfg.ProxySpec{{
		ID: "p1", Type: pcfg.ProxyTypeWireGuard, ConfigSerial: 1,
		WGPrivateKey: key, WGPeerPublicKey: key,
		WGEndpoint:   "198.51.100.9:51820",
		WGAllowedIPs: "10.7.0.0/24", WGLocalAddrs: "10.7.0.2/32",
	}})

	err := errOf(t, m, "p1")
	if !errors.Is(err, ErrProxyInit) {
		t.Fatalf("error = %v, want ErrProxyInit", err)
	}
	if !strings.Contains(err.Error(), "lite agent build") {
		t.Fatalf("error = %v, want one naming the lite build so the cause is obvious", err)
	}

	// Deterministic, so it is cached: a router must not re-attempt an egress that
	// cannot exist in this binary on every probe cycle.
	m.mu.Lock()
	cached := m.entries["p1"].buildErr != nil
	m.mu.Unlock()
	if !cached {
		t.Fatal("the refusal was not cached, so it retries every probe cycle")
	}
}

// Fail closed: the refusal must never degrade into a direct dial that would
// measure the host path instead of the tunnel.
func TestLiteWireGuardYieldsNoDialer(t *testing.T) {
	m := newTestManager()
	m.Apply([]pcfg.ProxySpec{{ID: "p1", Type: pcfg.ProxyTypeWireGuard, ConfigSerial: 1}})
	d, err := m.Dialer(context.Background(), "p1")
	if d != nil {
		t.Fatal("a dialer was returned for an unavailable transport")
	}
	if err == nil {
		t.Fatal("expected an error")
	}
}
