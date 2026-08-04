//go:build !lite

package proxydial

// Tests for the WireGuard transport's config parsing and build-error handling.
// They live apart from proxydial_test.go because everything they exercise —
// wireGuardUAPI, parseAddrList, and the transient-vs-deterministic distinction a
// real handshake attempt produces — is compiled out of the lite (router) build.

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"

	pcfg "github.com/nettact/protocol/config"
)

func TestWireGuardUAPIRendersHexKeysAndRoutes(t *testing.T) {
	priv := base64.StdEncoding.EncodeToString(bytesOf(0x01, 32))
	pub := base64.StdEncoding.EncodeToString(bytesOf(0x02, 32))
	psk := base64.StdEncoding.EncodeToString(bytesOf(0x03, 32))
	spec := pcfg.ProxySpec{
		Type: pcfg.ProxyTypeWireGuard, WGPrivateKey: priv, WGPeerPublicKey: pub, WGPresharedKey: psk,
		WGAllowedIPs: "10.7.0.0/24, 192.168.9.0/24", WGKeepaliveSeconds: 25,
	}
	uapi, err := wireGuardUAPI(spec, "198.51.100.9:51820")
	if err != nil {
		t.Fatal(err)
	}
	// The UAPI speaks hex while the console and the wire carry base64 (what wg(8)
	// prints and users paste), so the conversion is asserted explicitly.
	for _, want := range []string{
		"private_key=" + strings.Repeat("01", 32),
		"public_key=" + strings.Repeat("02", 32),
		"preshared_key=" + strings.Repeat("03", 32),
		"endpoint=198.51.100.9:51820",
		"allowed_ip=10.7.0.0/24",
		"allowed_ip=192.168.9.0/24",
		"persistent_keepalive_interval=25",
	} {
		if !strings.Contains(uapi, want) {
			t.Fatalf("UAPI missing %q:\n%s", want, uapi)
		}
	}
}

func TestWireGuardUAPIRejectsBadInput(t *testing.T) {
	goodKey := base64.StdEncoding.EncodeToString(bytesOf(0x01, 32))
	cases := []struct {
		name string
		spec pcfg.ProxySpec
		want string
	}{
		{"no private key", pcfg.ProxySpec{WGPeerPublicKey: goodKey, WGAllowedIPs: "10.0.0.0/8"}, "wg_private_key"},
		{"short key", pcfg.ProxySpec{
			WGPrivateKey:    base64.StdEncoding.EncodeToString(bytesOf(0x01, 16)),
			WGPeerPublicKey: goodKey, WGAllowedIPs: "10.0.0.0/8",
		}, "32 bytes"},
		{"no allowed ips", pcfg.ProxySpec{WGPrivateKey: goodKey, WGPeerPublicKey: goodKey}, "route nothing"},
		{"bad allowed ip", pcfg.ProxySpec{
			WGPrivateKey: goodKey, WGPeerPublicKey: goodKey, WGAllowedIPs: "10.7.0.1",
		}, "not a CIDR"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := wireGuardUAPI(c.spec, "198.51.100.9:51820")
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("error = %v, want one containing %q", err, c.want)
			}
		})
	}
}

func bytesOf(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

func TestParseAddrAndPrefixLists(t *testing.T) {
	// A tunnel-local address is conventionally written with a prefix length; the
	// address is what netstack needs, so the prefix is dropped.
	addrs, err := parseAddrList("10.7.0.2/32, 10.7.0.3 , ")
	if err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprint(addrs); got != "[10.7.0.2 10.7.0.3]" {
		t.Fatalf("parseAddrList = %s", got)
	}
	// CIDRs are masked so the installed route matches what was stored.
	pfxs, err := parsePrefixList("10.7.0.5/24")
	if err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprint(pfxs); got != "[10.7.0.0/24]" {
		t.Fatalf("parsePrefixList = %s", got)
	}
	if _, err := parseAddrList("not-an-ip"); err == nil {
		t.Fatal("expected an error for a non-address")
	}
	if _, err := parsePrefixList("10.7.0.1"); err == nil {
		t.Fatal("expected an error for a bare address in a CIDR list")
	}
}

// A build failure is cached only when it is DETERMINISTIC. Caching a transient one — the
// peer endpoint briefly unresolvable, the network down at startup — disabled the proxy
// until the server happened to change its generation, long after connectivity returned.
func TestBuildErrorStickinessDependsOnDeterminism(t *testing.T) {
	t.Run("a bad config is cached", func(t *testing.T) {
		m := newTestManager()
		// No keys, no endpoint: unparsable, so no retry can help.
		m.Apply([]pcfg.ProxySpec{{ID: "p1", Type: pcfg.ProxyTypeWireGuard, ConfigSerial: 1}})
		first := errOf(t, m, "p1")
		if !errors.Is(first, ErrProxyInit) {
			t.Fatalf("error = %v, want ErrProxyInit", first)
		}
		m.mu.Lock()
		cached := m.entries["p1"].buildErr != nil
		m.mu.Unlock()
		if !cached {
			t.Fatal("a deterministic config error was not cached, so it retries every probe cycle")
		}
	})

	t.Run("an unresolvable endpoint is retried", func(t *testing.T) {
		m := newTestManager()
		// Valid key material and routes; only the endpoint host fails to resolve. That is
		// a DNS condition that can clear on its own, so it must not disable the proxy
		// until the next config generation.
		key := base64.StdEncoding.EncodeToString(bytesOf(0x01, 32))
		m.Apply([]pcfg.ProxySpec{{
			ID: "p1", Type: pcfg.ProxyTypeWireGuard, ConfigSerial: 1,
			WGPrivateKey: key, WGPeerPublicKey: base64.StdEncoding.EncodeToString(bytesOf(0x02, 32)),
			WGEndpoint:   "peer.invalid.example.test:51820",
			WGAllowedIPs: "10.7.0.0/24", WGLocalAddrs: "10.7.0.2/32",
		}})
		if _, err := m.Dialer(context.Background(), "p1"); err == nil {
			t.Skip("peer.invalid.example.test resolved on this network; the transient case cannot be shown")
		}
		m.mu.Lock()
		cached := m.entries["p1"].buildErr != nil
		m.mu.Unlock()
		if cached {
			t.Fatal("a transient resolution failure was cached, so the proxy stays dead after DNS recovers")
		}
	})
}
