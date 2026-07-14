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

// Guard evaluates and enforces one immutable probe-access policy.
type Guard struct {
	policy probepolicy.Policy
	bypass bool
}

// New builds a Guard. bypass=true (desktop FullAccess) allows everything.
func New(policy probepolicy.Policy, bypass bool) *Guard {
	return &Guard{policy: policy, bypass: bypass}
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
	return g.policy.CheckAddr(a)
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
	// Only an explicit ip:/cidr: deny overrides the gateway exception.
	for _, s := range g.policy.Deny {
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
	return probepolicy.Decision{Allowed: true}
}

// ResolveVetted resolves host once and returns the addresses that survive the
// policy: deny-only when the name is already authorized (a host:/name allow
// matched, or denylist mode), full CheckAddr otherwise. An empty result is a
// *BlockedError with FromResolve set.
func (g *Guard) ResolveVetted(ctx context.Context, host string, nameAuthorized bool) ([]netip.Addr, error) {
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
	var out []netip.Addr
	var lastMatched string
	for _, a := range addrs {
		a = a.Unmap()
		if nameAuthorized {
			if denied, m := g.policy.DeniedAddr(a); denied {
				lastMatched = m
				continue
			}
			out = append(out, a)
		} else {
			dec := g.policy.CheckAddr(a)
			if dec.Allowed {
				out = append(out, a)
			} else {
				lastMatched = dec.Matched
			}
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
		d := &net.Dialer{Control: g.control(false)}
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
	// deny-only when the name was authorized (a host:/name allow, or denylist
	// mode), full CheckAddr otherwise — otherwise a name-authorized address that
	// legitimately lacks an independent ip:/scope: allow is rejected at syscall
	// time in allowlist mode.
	d := &net.Dialer{Control: g.control(hd.NameAuthorized)}
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
// deny-only when the hostname was authorized (a host:/name allow, or denylist
// mode), full CheckAddr otherwise. It exists for probes that resolve a hostname
// separately — e.g. to time DNS apart from the connect — yet must keep everything
// DialContext gives a hostname dial: the per-address fallback AND the
// name-authorization contract (so a host:-only allowlist entry is not rejected
// when the resolved IP lacks an independent ip:/cidr: allow). addrs must already
// be policy-vetted (from ResolveVetted); only the literal IPs are dialed, never
// the raw name.
func (g *Guard) DialVettedAddrs(ctx context.Context, network string, addrs []netip.Addr, port string, nameAuthorized bool) (net.Conn, error) {
	d := &net.Dialer{Control: g.control(nameAuthorized)}
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

// checkHost applies the hostname pre-resolution check (bypass authorizes all).
func (g *Guard) checkHost(host string) probepolicy.HostDecision {
	if g.bypass {
		return probepolicy.HostDecision{NameAuthorized: true}
	}
	return g.policy.CheckHost(host)
}

// control returns a Dialer.Control backstop that re-checks the concrete address
// the dialer settled on, so even a path that slipped past cannot dial a denied
// address. It mirrors the semantics that vetted the address: deny-only when the
// name was authorized, full CheckAddr otherwise.
func (g *Guard) control(nameAuthorized bool) func(network, address string, c syscall.RawConn) error {
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
		a = a.Unmap()
		if nameAuthorized {
			if denied, m := g.policy.DeniedAddr(a); denied {
				return &BlockedError{Target: host, Matched: m}
			}
			return nil
		}
		if dec := g.policy.CheckAddr(a); !dec.Allowed {
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
