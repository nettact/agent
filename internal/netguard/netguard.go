// Package netguard enforces the probe target-access policy at the point of dial.
// It is the single mechanical choke point every probe collector routes outbound
// connections through: literal IPs are checked directly, hostnames are resolved
// exactly once and the vetted literal IP is pinned to the dial (the DNS-rebinding
// defense — no second resolution can occur). A Guard constructed with bypass
// (desktop FullAccess) short-circuits every check to "allow".
package netguard

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"syscall"

	"github.com/nettact/agent/probepolicy"
)

// Guard evaluates and enforces one or more immutable probe-access policies.
//
// More than one because an agent may report to several servers and each may be
// given a tighter target-access policy than the machine's (AGENT-007 phase 2).
// The layers are a conjunction, not a merge: a destination must satisfy EVERY
// layer, so the agent-wide policy is a floor the machine owner sets and a server
// entry can only ever narrow it. There is deliberately no way to express the
// other direction — a per-server policy that widened the floor would let a
// configured server reach somewhere the owner of the machine said it may not.
type Guard struct {
	layers []probepolicy.Policy
	bypass bool
}

// New builds a Guard. bypass=true (desktop FullAccess) allows everything.
func New(policy probepolicy.Policy, bypass bool) *Guard {
	return &Guard{layers: []probepolicy.Policy{policy}, bypass: bypass}
}

// Narrow returns a Guard enforcing everything the receiver does AND p. The
// receiver is unchanged, so one machine-wide guard can spawn a tightened view
// per server without any of them affecting each other.
//
// Narrowing a bypass guard yields a guard over p alone. Bypass is "the floor
// allows everything", so a conjunction with it is just p — and keeping the
// bypass flag instead would silently discard the narrowing, which is the one
// outcome that must not be possible.
func (g *Guard) Narrow(p probepolicy.Policy) *Guard {
	if g.bypass {
		return &Guard{layers: []probepolicy.Policy{p}}
	}
	layers := make([]probepolicy.Policy, 0, len(g.layers)+1)
	layers = append(layers, g.layers...)
	layers = append(layers, p)
	return &Guard{layers: layers}
}

// checkAddr runs the address check against every layer and returns the first
// refusal, so the reported selector is the one that actually blocked the dial.
//
// auth carries, per layer, whether that layer already authorized the hostname
// being dialed (nil for a literal IP, where no name was involved). A layer that
// did gets the deny-only check, exactly as a single-policy guard always has; the
// rest get the full check.
//
// Per layer, and not one flag for the whole guard, because the layers can
// authorize the same target by different means: a machine floor may allow
// `host:api.example.com` while a server's narrowing allows `cidr:10.0.0.0/8`.
// Both are satisfied, but a single flag has to pick one interpretation for
// everyone — and "not every layer authorized the name" forces the full check
// onto the floor too, where the resolved address has no allow of its own and the
// probe is refused. That is a legitimate configuration silently failing.
func (g *Guard) checkAddr(auth []bool, a netip.Addr) probepolicy.Decision {
	for i := range g.layers {
		if auth != nil && auth[i] {
			if denied, m := g.layers[i].DeniedAddr(a); denied {
				return probepolicy.Decision{Allowed: false, Matched: m}
			}
			continue
		}
		if dec := g.layers[i].CheckAddr(a); !dec.Allowed {
			return dec
		}
	}
	return probepolicy.Decision{Allowed: true}
}

// hostAuth is the per-layer name authorization for one hostname.
func (g *Guard) hostAuth(host string) []bool {
	out := make([]bool, len(g.layers))
	for i := range g.layers {
		out[i] = g.layers[i].CheckHost(host).NameAuthorized
	}
	return out
}

// BlockedError reports a destination refused by policy. FromResolve marks a block
// on an address discovered by resolving a hostname: callers must then report only
// the matched selector, never the resolved address (spec privacy). Literal-IP
// targets may name the address (the server supplied it).
type BlockedError struct {
	Target      string
	Matched     string
	FromResolve bool
}

func (e *BlockedError) Error() string {
	if e.FromResolve {
		return fmt.Sprintf("probe target %q blocked by policy (%s)", e.Target, e.Matched)
	}
	if e.Matched != "" {
		return fmt.Sprintf("probe target %q blocked by policy selector %s", e.Target, e.Matched)
	}
	return fmt.Sprintf("probe target %q blocked by policy", e.Target)
}

// CheckAddr runs the full address check (deny wins; allowlist requires an allow).
func (g *Guard) CheckAddr(a netip.Addr) probepolicy.Decision {
	if g.bypass {
		return probepolicy.Decision{Allowed: true}
	}
	return g.checkAddr(nil, a)
}

// CheckAddrString parses a literal IP and checks it. A non-IP string is treated
// as a policy error (callers should route hostnames through DialContext).
func (g *Guard) CheckAddrString(s string) (probepolicy.Decision, error) {
	a, err := netip.ParseAddr(s)
	if err != nil {
		return probepolicy.Decision{}, err
	}
	return g.CheckAddr(a.Unmap()), nil
}

// CheckGateway allows only an address currently present in the OS gateway list.
// OS-default-gateway probes bypass scope denies (so a default scope:link-local
// deny does not break fe80:: gateways), but an explicit ip:/cidr: deny still wins.
func (g *Guard) CheckGateway(a netip.Addr, osGateways []netip.Addr) probepolicy.Decision {
	if g.bypass {
		return probepolicy.Decision{Allowed: true}
	}
	a = a.Unmap()
	present := false
	for _, gw := range osGateways {
		if gw.Unmap() == a {
			present = true
			break
		}
	}
	if !present {
		return probepolicy.Decision{Allowed: false}
	}
	// Only an explicit ip:/cidr: deny overrides the gateway exception — in any
	// layer, since a server-level narrowing that names the gateway means it just
	// as much as the machine-wide policy does.
	for i := range g.layers {
		for _, s := range g.layers[i].Deny {
			switch s.Kind {
			case probepolicy.KindIP:
				if s.Addr.Unmap() == a {
					return probepolicy.Decision{Allowed: false, Matched: s.String()}
				}
			case probepolicy.KindCIDR:
				if s.Prefix.Contains(a) {
					return probepolicy.Decision{Allowed: false, Matched: s.String()}
				}
			}
		}
	}
	return probepolicy.Decision{Allowed: true}
}

// ResolveVetted resolves host once and returns the addresses that survive the
// policy: per layer, deny-only where that layer already authorized the name (a
// host:/name allow matched, or denylist mode) and the full CheckAddr where it
// did not. An empty result is a *BlockedError with FromResolve set.
//
// nameAuthorized is the caller's aggregate answer from CheckHost. It is accepted
// but not used to decide: the authorization is re-derived per layer from host,
// which is the only form that stays correct when the layers authorize by
// different means (see checkAddr). A single-policy guard — every standalone
// agent — behaves exactly as before either way.
func (g *Guard) ResolveVetted(ctx context.Context, host string, nameAuthorized bool) ([]netip.Addr, error) {
	_ = nameAuthorized
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	if g.bypass {
		out := make([]netip.Addr, len(addrs))
		for i, a := range addrs {
			out[i] = a.Unmap()
		}
		return out, nil
	}
	auth := g.hostAuth(host)
	var out []netip.Addr
	var lastMatched string
	for _, a := range addrs {
		a = a.Unmap()
		if dec := g.checkAddr(auth, a); dec.Allowed {
			out = append(out, a)
		} else {
			lastMatched = dec.Matched
		}
	}
	if len(out) == 0 {
		return nil, &BlockedError{Target: host, Matched: lastMatched, FromResolve: true}
	}
	return out, nil
}

// DialContext is THE choke point every probe transport/dialer uses. A literal-IP
// address is checked directly; a hostname is classified (denied before any DNS
// query), then resolved once and the vetted literal IPs are dialed directly —
// the hostname is never handed back to the stdlib, so no second resolution can
// occur. The inner Dialer.Control re-checks the final syscall address as a
// belt-and-suspenders backstop.
func (g *Guard) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}

	if a, perr := netip.ParseAddr(host); perr == nil {
		dec := g.CheckAddr(a.Unmap())
		if !dec.Allowed {
			return nil, &BlockedError{Target: host, Matched: dec.Matched}
		}
		// A literal IP is authorized by the full check; the backstop re-runs the
		// same full check on the settled address.
		d := &net.Dialer{Control: g.control(nil)}
		return d.DialContext(ctx, network, address)
	}

	hd := g.checkHost(host)
	if hd.Denied {
		return nil, &BlockedError{Target: host, Matched: hd.Matched}
	}
	vetted, err := g.ResolveVetted(ctx, host, hd.NameAuthorized)
	if err != nil {
		return nil, err
	}
	// The backstop must apply the same semantics that vetted the addresses:
	// per layer, deny-only where that layer authorized the name (a host:/name
	// allow, or denylist mode) and full CheckAddr where it did not — otherwise a
	// name-authorized address that legitimately lacks an independent ip:/scope:
	// allow is rejected at syscall time in allowlist mode.
	d := &net.Dialer{Control: g.control(g.hostAuth(host))}
	var lastErr error
	for _, a := range vetted {
		conn, derr := d.DialContext(ctx, network, net.JoinHostPort(a.String(), port))
		if derr == nil {
			return conn, nil
		}
		lastErr = derr
	}
	if lastErr == nil {
		lastErr = &BlockedError{Target: host, FromResolve: true}
	}
	return nil, lastErr
}

// DialVettedAddrs dials already-vetted addresses in order and returns the first
// successful connection, applying the SAME syscall backstop the resolution used:
// per layer, deny-only where that layer authorized the hostname (a host:/name
// allow, or denylist mode) and full CheckAddr where it did not. It exists for
// probes that resolve a hostname separately — e.g. to time DNS apart from the
// connect — yet must keep everything DialContext gives a hostname dial: the
// per-address fallback AND the name-authorization contract (so a host:-only
// allowlist entry is not rejected when the resolved IP lacks an independent
// ip:/cidr: allow). addrs must already be policy-vetted (from ResolveVetted);
// only the literal IPs are dialed, never the raw name.
//
// host is the name those addresses were resolved from, and it is what the
// backstop re-derives the per-layer authorization from — a bool could not, since
// different layers may authorize the same target by different means.
func (g *Guard) DialVettedAddrs(ctx context.Context, network string, addrs []netip.Addr, port, host string) (net.Conn, error) {
	d := &net.Dialer{Control: g.control(g.hostAuth(host))}
	var lastErr error
	for _, a := range addrs {
		conn, err := d.DialContext(ctx, network, net.JoinHostPort(a.String(), port))
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = &BlockedError{FromResolve: true}
	}
	return nil, lastErr
}

// DialSourcePort dials a literal ip:port address from a pinned local source port
// — the TCP source-port fan-out path. It exists because a fan-out's five-tuple
// must be reproducible across cycles: ECMP/LAG hashing keys on the full tuple, so
// a deterministic source port is what keeps each flow hitting the same member
// every cycle, which is the entire basis for telling a stable bad subset apart
// from uniform loss. No ephemeral-port dialer can give that, and re-dialing
// through DialContext would both lose the pin and re-run the hostname path.
//
// It keeps the SAME fail-closed semantics every other guard dial has:
//   - address MUST be a literal IP (the vetted destination a fan-out dials); a
//     hostname is refused with a *BlockedError rather than resolved, because a
//     fan-out deliberately dials ONE vetted address and has no business
//     re-resolving a name that was vetted upstream.
//   - the literal is checked via the per-layer authorization carried by host —
//     the hostname the address was vetted under, so a host: allowlist grant
//     covers its resolved IPs exactly as DialVettedAddrs does. A literal-IP
//     target passes its own address as host, which is detected as a literal and
//     given NIL authorization: host selectors accept numeric LDH labels, so
//     hostAuth would otherwise let a host:203.0.113.7 selector authorize a
//     literal that matches no ip:/cidr:/scope: selector — a weaker check than a
//     plain literal dial gets. The literal path therefore stays on the full
//     address check.
//   - the connection tears down with an RST instead of a FIN (SO_LINGER {1,0}),
//     so no TIME_WAIT tuple parks the source port. A fan-out's ports must repeat
//     every cycle; a FIN close would leave each in TIME_WAIT (120s on Windows)
//     where a pinned port refuses to rebind (WSAEADDRINUSE), and the flow count
//     would silently shrink after the first cycle. The probe sends no data, so
//     an aborted teardown costs nothing.
//
// Only the source PORT is pinned: LocalAddr.IP stays unspecified so the OS picks
// a local interface. Binding the destination address as the local address would
// fail with address-not-available for any target that is not itself a local
// interface — the fan-out dials remote targets, so the pin must be port-only.
//
// A bind failure (the source port is locally in use) is returned as-is; callers
// skip that flow rather than treating it as a verdict about the target.
func (g *Guard) DialSourcePort(ctx context.Context, network, address string, sourcePort int, host string) (net.Conn, error) {
	addrHost, _, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	a, perr := netip.ParseAddr(addrHost)
	if perr != nil {
		return nil, &BlockedError{Target: addrHost, Matched: "literal address required"}
	}
	a = a.Unmap()
	// The destination is a VETTED literal: a hostname target's resolved address
	// was already policy-approved upstream, so the dial carries the same per-layer
	// name authorization DialVettedAddrs uses (a host: allowlist grants its
	// resolved IPs). A LITERAL target (host == its own address) carries none: host
	// selectors accept numeric LDH labels, so a selector like host:203.0.113.7
	// would authorize that literal string and skip the ip:/cidr:/scope: allow
	// check a literal is supposed to face. nil restores the full address check.
	auth := g.hostAuth(host)
	if _, perr := netip.ParseAddr(host); perr == nil {
		auth = nil
	}
	// checkAddr has no bypass short-circuit (that lives in CheckAddr): a
	// FullAccess guard must allow a pinned fan-out dial to loopback/link-local
	// exactly as an ordinary guarded dial would, so the bypass is honored here.
	if !g.bypass {
		if dec := g.checkAddr(auth, a); !dec.Allowed {
			return nil, &BlockedError{Target: addrHost, Matched: dec.Matched}
		}
	}
	d := &net.Dialer{
		LocalAddr: &net.TCPAddr{Port: sourcePort},
		Control:   g.controlSourcePort(auth),
	}
	return d.DialContext(ctx, network, address)
}

// controlSourcePort returns the Dialer.Control for a pinned-source-port dial: the
// same policy backstop a literal dial gets, plus SO_LINGER {1,0} so the connection
// tears down with an RST instead of a FIN — see DialSourcePort for why.
func (g *Guard) controlSourcePort(auth []bool) func(network, address string, c syscall.RawConn) error {
	backstop := g.control(auth)
	return func(network, address string, c syscall.RawConn) error {
		if err := backstop(network, address, c); err != nil {
			return err
		}
		var serr error
		if err := c.Control(func(fd uintptr) { serr = setLingerRST(fd) }); err != nil {
			return err
		}
		return serr
	}
}

// checkHost applies the hostname pre-resolution check (bypass authorizes all).
//
// Across layers: a conclusive deny in ANY layer denies, and the name counts as
// authorized only when EVERY layer authorizes it. The conjunction has to run
// that way round — a name allowed by one layer's host: selector but not by
// another's still has to have its resolved addresses checked in full against
// that other layer, or the narrower policy would be satisfied by a name it never
// mentioned.
func (g *Guard) checkHost(host string) probepolicy.HostDecision {
	if g.bypass {
		return probepolicy.HostDecision{NameAuthorized: true}
	}
	out := probepolicy.HostDecision{NameAuthorized: true}
	for i := range g.layers {
		d := g.layers[i].CheckHost(host)
		if d.Denied {
			return d
		}
		if !d.NameAuthorized {
			out.NameAuthorized = false
		}
	}
	return out
}

// control returns a Dialer.Control backstop that re-checks the concrete address
// the dialer settled on, so even a path that slipped past cannot dial a denied
// address. It mirrors the semantics that vetted the address: per layer,
// deny-only where that layer authorized the name, full CheckAddr where it did
// not. auth is nil for a literal-IP dial, where no name was involved.
func (g *Guard) control(auth []bool) func(network, address string, c syscall.RawConn) error {
	return func(network, address string, c syscall.RawConn) error {
		if g.bypass {
			return nil
		}
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return nil
		}
		a, err := netip.ParseAddr(host)
		if err != nil {
			return nil
		}
		if dec := g.checkAddr(auth, a.Unmap()); !dec.Allowed {
			return &BlockedError{Target: host, Matched: dec.Matched}
		}
		return nil
	}
}

// CheckHost exposes the hostname pre-resolution decision for monitor evaluation.
func (g *Guard) CheckHost(host string) probepolicy.HostDecision {
	return g.checkHost(host)
}

// VetUDPAddr resolves a host:port UDP destination (a STUN server, a second STUN
// server, or a server-supplied/derived STUN address) and returns the first
// policy-vetted UDP address. It applies the same contract as DialContext for the
// unconnected-socket probes that cannot use a Dialer: literal IPs get the full
// CheckAddr; hostnames get the pre-resolution CheckHost (a conclusive deny wins
// before any DNS query) then vetted resolution (deny-only when the name is
// authorized, full otherwise) with the returned address pinned. Both IPv4 and
// IPv6 are supported. A denied destination yields a *BlockedError (FromResolve
// set for a resolved-address block, so the caller reports only the matched
// selector, never the newly resolved private address). Bypass authorizes all.
func (g *Guard) VetUDPAddr(ctx context.Context, hostport string) (*net.UDPAddr, error) {
	host, portStr, err := net.SplitHostPort(hostport)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, err
	}
	if a, perr := netip.ParseAddr(host); perr == nil {
		a = a.Unmap()
		if dec := g.CheckAddr(a); !dec.Allowed {
			return nil, &BlockedError{Target: host, Matched: dec.Matched}
		}
		return net.UDPAddrFromAddrPort(netip.AddrPortFrom(a, uint16(port))), nil
	}
	hd := g.checkHost(host)
	if hd.Denied {
		return nil, &BlockedError{Target: host, Matched: hd.Matched}
	}
	vetted, err := g.ResolveVetted(ctx, host, hd.NameAuthorized)
	if err != nil {
		return nil, err
	}
	return net.UDPAddrFromAddrPort(netip.AddrPortFrom(vetted[0], uint16(port))), nil
}

// IPToAddr converts a net.IP to a netip.Addr (unmapped).
func IPToAddr(ip net.IP) (netip.Addr, bool) {
	a, ok := netip.AddrFromSlice(ip)
	if !ok {
		return netip.Addr{}, false
	}
	return a.Unmap(), true
}
