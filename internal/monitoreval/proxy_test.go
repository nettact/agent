package monitoreval

import (
	"testing"
	"time"

	"github.com/nettact/agent/internal/netguard"
	"github.com/nettact/agent/probepolicy"
	"github.com/nettact/protocol/config"
	"github.com/nettact/protocol/permission"
	"github.com/nettact/protocol/wire"
)

// fakeProxySet is a static ProxySet, so evaluation can be exercised without
// standing up real transports.
type fakeProxySet map[string]config.ProxySpec

func (f fakeProxySet) Specs() map[string]config.ProxySpec { return f }

func newTracker(t *testing.T, proxies ProxySet, policy probepolicy.Policy, bypass bool) *Tracker {
	t.Helper()
	return New(permission.All(), permission.All(), permission.All(),
		netguard.New(policy, bypass), proxies, "policy", 0, time.Second)
}

// A pinned target whose proxy is absent from the push must be reported
// un-runnable, NOT silently downgraded to a direct dial. The server deliberately
// keeps such a target in the push (rather than dropping it) so this is the status
// the operator sees.
func TestPinnedTargetWithMissingProxyIsUnsupported(t *testing.T) {
	tracker := newTracker(t, fakeProxySet{}, probepolicy.Policy{}, true)
	target := config.ProbeTarget{
		MonitorID: "m1", Kind: "http", Target: "https://example.test", ProxyID: "prx_gone",
	}
	runnable, frame := tracker.ApplyDesired(1, []config.ProbeTarget{target})
	if len(runnable) != 0 {
		t.Fatalf("runnable = %+v, want the monitor excluded (a missing proxy must not become a direct dial)", runnable)
	}
	if len(frame.Statuses) != 1 {
		t.Fatalf("statuses = %+v, want one entry", frame.Statuses)
	}
	got := frame.Statuses[0]
	if got.Status != wire.MonitorStatusUnsupported || got.Reason != ReasonProxyMissing {
		t.Fatalf("status = %q reason = %q, want unsupported/%s", got.Status, got.Reason, ReasonProxyMissing)
	}
}

// A nil ProxySet (a build or wiring without proxy support) must also fail closed.
func TestNilProxySetFailsClosed(t *testing.T) {
	tracker := newTracker(t, nil, probepolicy.Policy{}, true)
	runnable, frame := tracker.ApplyDesired(1, []config.ProbeTarget{
		{MonitorID: "m1", Kind: "http", Target: "https://example.test", ProxyID: "prx_any"},
	})
	if len(runnable) != 0 {
		t.Fatal("a pinned monitor ran with no proxy support at all")
	}
	if frame.Statuses[0].Reason != ReasonProxyMissing {
		t.Fatalf("reason = %q, want %s", frame.Statuses[0].Reason, ReasonProxyMissing)
	}
}

// The capability matrix is enforced here as well as at save time, because a proxy's
// TYPE can be changed after a target was pinned to it.
func TestPinnedTargetWithIncapableProxyIsUnsupported(t *testing.T) {
	proxies := fakeProxySet{
		"prx_socks": {ID: "prx_socks", Type: config.ProxyTypeSOCKS5},
		"prx_http":  {ID: "prx_http", Type: config.ProxyTypeHTTP},
		"prx_wg":    {ID: "prx_wg", Type: config.ProxyTypeWireGuard},
	}
	cases := []struct {
		name         string
		target       config.ProbeTarget
		wantRunnable bool
	}{
		{
			// Neither relay protocol has a command for forwarding an ICMP echo, so ping
			// stays tunnel-only even though SOCKS5 does relay UDP.
			name:   "icmp via socks5 is refused",
			target: config.ProbeTarget{MonitorID: "m1", Kind: "icmp", Target: "1.1.1.1", ProxyID: "prx_socks"},
		},
		{
			name:   "icmp via http is refused",
			target: config.ProbeTarget{MonitorID: "m1", Kind: "icmp", Target: "1.1.1.1", ProxyID: "prx_http"},
		},
		{
			name:         "icmp via wireguard runs",
			target:       config.ProbeTarget{MonitorID: "m1", Kind: "icmp", Target: "1.1.1.1", ProxyID: "prx_wg"},
			wantRunnable: true,
		},
		{
			// SOCKS5 relays UDP via UDP ASSOCIATE, so plain-UDP DNS runs — given an
			// explicit resolver endpoint (see the next two cases).
			name: "udp dns via socks5 runs",
			target: config.ProbeTarget{MonitorID: "m1", Kind: "dns", Target: "example.test", ProxyID: "prx_socks",
				Params: config.ProbeParams{ResolverProtocol: "udp", ResolverServer: "1.1.1.1"}},
			wantRunnable: true,
		},
		{
			// The SYSTEM resolver has no address a proxy could relay to. Left runnable,
			// the query would resolve off the host and the monitor would report success
			// while the pinned egress was down.
			name:   "dns without a resolver endpoint is refused on socks5",
			target: config.ProbeTarget{MonitorID: "m1", Kind: "dns", Target: "example.test", ProxyID: "prx_socks"},
		},
		{
			name:   "dns without a resolver endpoint is refused on wireguard too",
			target: config.ProbeTarget{MonitorID: "m1", Kind: "dns", Target: "example.test", ProxyID: "prx_wg"},
		},
		{
			// HTTP has only CONNECT, so datagram DNS cannot traverse it.
			name: "udp dns via http is refused",
			target: config.ProbeTarget{MonitorID: "m1", Kind: "dns", Target: "example.test", ProxyID: "prx_http",
				Params: config.ProbeParams{ResolverProtocol: "udp", ResolverServer: "1.1.1.1"}},
		},
		{
			name: "dot dns via http runs",
			target: config.ProbeTarget{MonitorID: "m1", Kind: "dns", Target: "example.test", ProxyID: "prx_http",
				Params: config.ProbeParams{ResolverProtocol: "dot", ResolverServer: "1.1.1.1"}},
			wantRunnable: true,
		},
		{
			// STUN over UDP: same split as DNS.
			name:         "udp stun via socks5 runs",
			target:       config.ProbeTarget{MonitorID: "m1", Kind: "nat", Target: "stun.example.test", ProxyID: "prx_socks"},
			wantRunnable: true,
		},
		{
			name:   "udp stun via http is refused",
			target: config.ProbeTarget{MonitorID: "m1", Kind: "nat", Target: "stun.example.test", ProxyID: "prx_http"},
		},
		{
			name:         "http via socks5 runs",
			target:       config.ProbeTarget{MonitorID: "m1", Kind: "http", Target: "https://example.test", ProxyID: "prx_socks"},
			wantRunnable: true,
		},
		{
			name:   "gateway is never proxied",
			target: config.ProbeTarget{MonitorID: "m1", Kind: "gateway", Target: "gateway", ProxyID: "prx_wg"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tracker := newTracker(t, proxies, probepolicy.Policy{}, true)
			runnable, frame := tracker.ApplyDesired(1, []config.ProbeTarget{c.target})
			if c.wantRunnable {
				if len(runnable) != 1 {
					t.Fatalf("monitor was excluded; status %+v", frame.Statuses)
				}
				return
			}
			if len(runnable) != 0 {
				t.Fatal("an incapable proxy/kind combination was scheduled")
			}
			if frame.Statuses[0].Reason != ReasonProxyUnsupported {
				t.Fatalf("reason = %q, want %s", frame.Statuses[0].Reason, ReasonProxyUnsupported)
			}
		})
	}
}

// An unpinned target is unaffected by the proxy checks.
func TestUnpinnedTargetIsUnaffected(t *testing.T) {
	tracker := newTracker(t, fakeProxySet{}, probepolicy.Policy{}, true)
	runnable, _ := tracker.ApplyDesired(1, []config.ProbeTarget{
		{MonitorID: "m1", Kind: "http", Target: "https://example.test"},
	})
	if len(runnable) != 1 {
		t.Fatal("an unpinned monitor was excluded by the proxy checks")
	}
}

// Proxy-side DNS is the one mode where the agent cannot vet the address the
// connection actually reaches. Under an allowlist policy the NAME therefore has to
// be authorized, or the probe would reach an address the policy never approved.
func TestRemoteDNSRequiresNameAuthorizationUnderAllowlist(t *testing.T) {
	remote := fakeProxySet{
		"prx": {ID: "prx", Type: config.ProxyTypeSOCKS5, DNSMode: config.ProxyDNSRemote},
	}
	local := fakeProxySet{
		"prx": {ID: "prx", Type: config.ProxyTypeSOCKS5, DNSMode: config.ProxyDNSLocal},
	}
	// An allowlist that authorizes no name at all.
	strict := probepolicy.Policy{Mode: probepolicy.ModeAllowlist}
	target := config.ProbeTarget{
		MonitorID: "m1", Kind: "http", Target: "https://internal.example.test", ProxyID: "prx",
	}

	t.Run("remote dns with an unauthorized name is refused", func(t *testing.T) {
		tracker := newTracker(t, remote, strict, false)
		runnable, frame := tracker.ApplyDesired(1, []config.ProbeTarget{target})
		if len(runnable) != 0 {
			t.Fatal("a proxy-resolved name ran under an allowlist that never authorized it")
		}
		// Either the proxy gate or the target-policy gate may claim it; both are
		// correct refusals, but it must never be scheduled.
		reason := frame.Statuses[0].Reason
		if reason != ReasonProxyRemoteDNSDenied && frame.Statuses[0].Status != wire.MonitorStatusTargetBlocked {
			t.Fatalf("reason = %q status = %q, want the remote-DNS refusal", reason, frame.Statuses[0].Status)
		}
	})

	t.Run("local dns is unaffected by name authorization", func(t *testing.T) {
		// With local DNS the agent resolves and vets the concrete address itself, so
		// the static name check is not what gates the monitor — runtime resolution is.
		tracker := newTracker(t, local, probepolicy.Policy{}, true)
		runnable, _ := tracker.ApplyDesired(1, []config.ProbeTarget{target})
		if len(runnable) != 1 {
			t.Fatal("a locally-resolved proxied monitor was excluded")
		}
	})

	t.Run("remote dns with a literal target needs no name check", func(t *testing.T) {
		tracker := newTracker(t, remote, probepolicy.Policy{}, true)
		runnable, _ := tracker.ApplyDesired(1, []config.ProbeTarget{
			{MonitorID: "m1", Kind: "tcp", Target: "203.0.113.5", ProxyID: "prx",
				Params: config.ProbeParams{Port: 443}},
		})
		if len(runnable) != 1 {
			t.Fatal("a literal-IP target was refused for remote DNS, but there is no name to resolve")
		}
	})
}

// A permission block outranks the proxy check: reporting "proxy unsupported" for a
// monitor that lacks the probe permission entirely would send the operator to fix
// the wrong thing.
func TestPermissionBlockOutranksProxyCheck(t *testing.T) {
	tracker := New(permission.NewSet(), permission.NewSet(), permission.All(),
		netguard.New(probepolicy.Policy{}, true), fakeProxySet{}, "policy", 0, time.Second)
	_, frame := tracker.ApplyDesired(1, []config.ProbeTarget{
		{MonitorID: "m1", Kind: "http", Target: "https://example.test", ProxyID: "prx_gone"},
	})
	if frame.Statuses[0].Status != wire.MonitorStatusPermissionBlocked {
		t.Fatalf("status = %q, want permission_blocked to win over the proxy check", frame.Statuses[0].Status)
	}
}
