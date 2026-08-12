package netguard

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"testing"

	"github.com/nettact/agent/probepolicy"
)

// pol builds a policy from canonical selector strings — the same spelling the
// configuration file and the environment use, so a case reads as the policy an
// operator would have written rather than as a struct literal.
func pol(t *testing.T, mode probepolicy.Mode, allow, deny []string) probepolicy.Policy {
	t.Helper()
	parse := func(ss []string) []probepolicy.Selector {
		out := make([]probepolicy.Selector, 0, len(ss))
		for _, s := range ss {
			sel, err := probepolicy.ParseSelector(s)
			if err != nil {
				t.Fatalf("ParseSelector(%q): %v", s, err)
			}
			out = append(out, sel)
		}
		return out
	}
	return probepolicy.Policy{Mode: mode, Allow: parse(allow), Deny: parse(deny)}
}

// TestNarrowIsAConjunction: a narrowed guard enforces BOTH layers, and neither
// direction leaks. A server told to reach less than the machine allows reaches
// less; a server told to reach more than the machine allows still reaches only
// what the machine allows, because there is no way to express the second.
func TestNarrowIsAConjunction(t *testing.T) {
	// The machine's floor: everything except 10/8.
	floor := pol(t, probepolicy.ModeDenylist, nil, []string{"cidr:10.0.0.0/8"})
	base := New(floor, false)
	// This server's narrowing: two addresses and nothing else — one the floor
	// allows, one the floor denies.
	narrow := pol(t, probepolicy.ModeAllowlist, []string{"ip:192.0.2.5", "ip:10.1.2.3"}, nil)
	g := base.Narrow(narrow)

	for _, tc := range []struct {
		name    string
		addr    string
		allowed bool
		matched string
	}{
		// Only a refusal names a selector: the multi-layer allow path reports the
		// conjunction's verdict, not whichever layer's allow happened to match.
		{name: "both layers allow", addr: "192.0.2.5", allowed: true, matched: ""},
		// Allowed by the floor, outside this server's allowlist.
		{name: "narrowing refuses", addr: "203.0.113.7", allowed: false, matched: ""},
		// And the other way round: naming an address the machine forbids does not
		// reach it, and the refusal reports the floor's selector — the layer that
		// actually blocked the dial.
		{name: "floor refuses", addr: "10.1.2.3", allowed: false, matched: "cidr:10.0.0.0/8"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := g.CheckAddr(netip.MustParseAddr(tc.addr))
			if got.Allowed != tc.allowed || got.Matched != tc.matched {
				t.Fatalf("CheckAddr(%s) = %+v, want allowed=%v matched=%q", tc.addr, got, tc.allowed, tc.matched)
			}
		})
	}

	// The receiver is untouched, so one machine-wide guard can spawn a tightened
	// view per server without any of them affecting each other.
	if got := base.CheckAddr(netip.MustParseAddr("203.0.113.7")); !got.Allowed {
		t.Fatalf("base.CheckAddr after Narrow = %+v, want the floor unchanged", got)
	}
}

// TestNarrowBypassEnforcesTheNarrowing: bypass is "the floor allows everything",
// so a conjunction with it is the narrowing alone. Keeping the bypass flag would
// silently discard the narrowing, which is the one outcome that must not be
// possible.
func TestNarrowBypassEnforcesTheNarrowing(t *testing.T) {
	base := New(probepolicy.Policy{}, true)
	g := base.Narrow(pol(t, probepolicy.ModeAllowlist, []string{"ip:192.0.2.5"}, nil))

	if got := g.CheckAddr(netip.MustParseAddr("192.0.2.5")); !got.Allowed {
		t.Errorf("narrowed bypass CheckAddr(192.0.2.5) = %+v, want allowed", got)
	}
	if got := g.CheckAddr(netip.MustParseAddr("203.0.113.7")); got.Allowed {
		t.Errorf("narrowed bypass CheckAddr(203.0.113.7) = %+v, want refused", got)
	}
	// A hostname is no longer authorized by default either: the narrowing is an
	// allowlist naming no host, so the name has to survive the full address check.
	if got := g.CheckHost("api.example.com"); got.NameAuthorized {
		t.Errorf("narrowed bypass CheckHost = %+v, want the name unauthorized", got)
	}
	// The bypass guard itself still allows everything.
	if got := base.CheckAddr(netip.MustParseAddr("203.0.113.7")); !got.Allowed {
		t.Errorf("bypass guard after Narrow = %+v, want unchanged", got)
	}
	if got := base.CheckHost("api.example.com"); !got.NameAuthorized {
		t.Errorf("bypass guard CheckHost after Narrow = %+v, want authorized", got)
	}
}

// TestCheckGatewayDenyOverrideAppliesAcrossLayers: the OS-default-gateway
// exception survives a scope deny in any layer (so a scope:link-local deny does
// not break fe80:: gateways), while an explicit ip:/cidr: deny still wins — and
// a server-level narrowing that names the gateway means it just as much as the
// machine-wide policy does.
func TestCheckGatewayDenyOverrideAppliesAcrossLayers(t *testing.T) {
	floor := pol(t, probepolicy.ModeDenylist, nil, []string{"scope:link-local", "cidr:10.0.0.0/8"})
	narrow := pol(t, probepolicy.ModeDenylist, nil, []string{"ip:192.168.1.1"})
	g := New(floor, false).Narrow(narrow)

	gateways := []netip.Addr{
		netip.MustParseAddr("192.168.1.1"),
		netip.MustParseAddr("fe80::1"),
		netip.MustParseAddr("10.0.0.1"),
	}
	for _, tc := range []struct {
		name    string
		addr    string
		allowed bool
		matched string
	}{
		// The whole point of the exception: a link-local gateway stays reachable
		// even though the floor denies that scope outright.
		{name: "scope deny does not override", addr: "fe80::1", allowed: true},
		// An explicit ip: deny in the NARROWING layer overrides it.
		{name: "narrowing ip deny wins", addr: "192.168.1.1", allowed: false, matched: "ip:192.168.1.1"},
		// And a cidr: deny in the floor layer does too.
		{name: "floor cidr deny wins", addr: "10.0.0.1", allowed: false, matched: "cidr:10.0.0.0/8"},
		// Not a current OS gateway: refused before any layer is consulted.
		{name: "not a gateway", addr: "192.168.1.2", allowed: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := g.CheckGateway(netip.MustParseAddr(tc.addr), gateways)
			if got.Allowed != tc.allowed || got.Matched != tc.matched {
				t.Fatalf("CheckGateway(%s) = %+v, want allowed=%v matched=%q", tc.addr, got, tc.allowed, tc.matched)
			}
		})
	}
}

// TestCheckHostAcrossLayers: a conclusive deny in ANY layer denies, and the name
// counts as authorized only when EVERY layer authorizes it.
//
// The conjunction has to run that way round. A name allowed by one layer's host:
// selector but not by another's still has to have its resolved addresses checked
// in full against that other layer — otherwise the narrower policy would be
// satisfied by a name it never mentioned.
func TestCheckHostAcrossLayers(t *testing.T) {
	floor := pol(t, probepolicy.ModeAllowlist, []string{"host:*.example.com"}, nil)
	base := New(floor, false)

	// Both layers authorize the name: an empty denylist authorizes by default.
	both := base.Narrow(pol(t, probepolicy.ModeDenylist, nil, nil))
	if got := both.CheckHost("api.example.com"); !got.NameAuthorized || got.Denied {
		t.Errorf("both-authorize CheckHost = %+v, want authorized and undenied", got)
	}

	// The narrowing is an allowlist naming addresses only, so it never authorizes
	// a name — and the conjunction must not inherit the floor's authorization.
	addrsOnly := base.Narrow(pol(t, probepolicy.ModeAllowlist, []string{"ip:192.0.2.5"}, nil))
	if got := addrsOnly.CheckHost("api.example.com"); got.NameAuthorized || got.Denied {
		t.Errorf("address-only narrowing CheckHost = %+v, want unauthorized but undenied", got)
	}
	// The floor on its own still authorizes it — the AND is what changed, not the
	// floor.
	if got := base.CheckHost("api.example.com"); !got.NameAuthorized {
		t.Errorf("floor CheckHost = %+v, want authorized", got)
	}

	// A conclusive deny in the narrowing layer denies outright, even though the
	// floor's wildcard allow matches the same name.
	denied := base.Narrow(pol(t, probepolicy.ModeDenylist, nil, []string{"host:evil.example.com"}))
	if got := denied.CheckHost("evil.example.com"); !got.Denied || got.Matched != "host:evil.example.com" {
		t.Fatalf("narrowing deny CheckHost = %+v, want denied by host:evil.example.com", got)
	}
}

// A hostname the layers authorize by DIFFERENT means still has to reach its
// destination. The floor may allow it by name while a server's narrowing allows
// the resolved address by CIDR: both are satisfied, but collapsing the two into
// one "was the name authorized" flag forces the full address check onto the
// floor as well, where the resolved IP has no allow of its own and the probe is
// silently refused.
func TestPerLayerNameAuthorization(t *testing.T) {
	floor := pol(t, probepolicy.ModeAllowlist, []string{"host:api.example.com"}, nil)
	narrow := pol(t, probepolicy.ModeAllowlist, []string{"cidr:203.0.113.0/24"}, nil)
	g := New(floor, false).Narrow(narrow)

	resolved := netip.MustParseAddr("203.0.113.10")
	auth := g.hostAuth("api.example.com")
	if len(auth) != 2 {
		t.Fatalf("hostAuth returned %d layers, want 2", len(auth))
	}
	if !auth[0] {
		t.Fatal("the floor's host: allow did not authorize the name")
	}
	if auth[1] {
		t.Fatal("the narrowing has no host: allow, so it must not authorize the name")
	}
	if dec := g.checkAddr(auth, resolved); !dec.Allowed {
		t.Fatalf("a target both layers allow was refused (%s); the layers were collapsed into one flag", dec.Matched)
	}

	// The narrowing still binds: an address outside its CIDR is refused even
	// though the floor authorized the name.
	if dec := g.checkAddr(auth, netip.MustParseAddr("198.51.100.7")); dec.Allowed {
		t.Fatal("the narrowing was skipped for a name the floor authorized")
	}
	// And a deny in either layer still wins over a name authorization.
	denied := New(floor, false).Narrow(pol(t, probepolicy.ModeDenylist, nil, []string{"cidr:203.0.113.0/24"}))
	if dec := denied.checkAddr(denied.hostAuth("api.example.com"), resolved); dec.Allowed {
		t.Fatal("a deny in the narrowing was overridden by the floor's name authorization")
	}
}

// TestDialSourcePortPinsLocalPort proves DialSourcePort binds the requested local
// source port instead of an ephemeral one — the property the TCP fan-out's
// reproducible five-tuple is built on. The guard is a bypass, so the only thing
// under test is the pinning.
func TestDialSourcePortPinsLocalPort(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	go func() {
		for {
			conn, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			conn.Close()
		}
	}()

	// Grab a local source port that is free right now, then hand it to the dialer.
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("probe listen: %v", err)
	}
	src := probe.Addr().(*net.TCPAddr).Port
	probe.Close()

	g := New(probepolicy.Policy{}, true) // bypass: CheckAddr and the Control backstop allow everything
	conn, err := g.DialSourcePort(context.Background(), "tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), src)
	if err != nil {
		t.Fatalf("DialSourcePort: %v", err)
	}
	defer conn.Close()
	local, ok := conn.LocalAddr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("LocalAddr = %T, want *net.TCPAddr", conn.LocalAddr())
	}
	if local.Port != src {
		t.Fatalf("bound source port = %d, want %d (an ephemeral port would not be pinned)", local.Port, src)
	}
}

// TestDialSourcePortRejectsHostname pins the literal-only contract: a fan-out
// deliberately dials ONE vetted address, so a hostname is refused with a
// *BlockedError rather than resolved — no DNS ever happens.
func TestDialSourcePortRejectsHostname(t *testing.T) {
	g := New(probepolicy.Policy{}, true)
	_, err := g.DialSourcePort(context.Background(), "tcp", "localhost:80", 12345)
	var be *BlockedError
	if !errors.As(err, &be) {
		t.Fatalf("DialSourcePort(localhost:80) = %v, want a *BlockedError", err)
	}
	if be.Matched != "literal address required" {
		t.Fatalf("BlockedError.Matched = %q, want %q", be.Matched, "literal address required")
	}
}

// TestDialSourcePortEnforcesPolicy: a literal dial must clear the SAME full
// CheckAddr a plain literal dial gets, before any bind. The default policy denies
// loopback, so a 127.0.0.1 dial is refused outright.
func TestDialSourcePortEnforcesPolicy(t *testing.T) {
	g := New(probepolicy.Default(), false)
	_, err := g.DialSourcePort(context.Background(), "tcp", "127.0.0.1:80", 12345)
	var be *BlockedError
	if !errors.As(err, &be) {
		t.Fatalf("DialSourcePort(127.0.0.1:80) = %v, want a *BlockedError", err)
	}
	if be.Target != "127.0.0.1" {
		t.Fatalf("BlockedError.Target = %q, want 127.0.0.1 (a literal may be named)", be.Target)
	}
}

// TestDialSourcePortAllowsVettedLiteral: a literal the policy DOES allow dials
// through — the CheckAddr gate and the Control backstop both pass it. This pins
// that the enforcement test above is a real check, not an always-block.
func TestDialSourcePortAllowsVettedLiteral(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	go func() {
		for {
			conn, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			conn.Close()
		}
	}()

	g := New(pol(t, probepolicy.ModeAllowlist, []string{"ip:127.0.0.1"}, nil), false)

	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("probe listen: %v", err)
	}
	src := probe.Addr().(*net.TCPAddr).Port
	probe.Close()

	conn, err := g.DialSourcePort(context.Background(), "tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), src)
	if err != nil {
		t.Fatalf("DialSourcePort(allowlisted 127.0.0.1) = %v, want success", err)
	}
	conn.Close()
}
