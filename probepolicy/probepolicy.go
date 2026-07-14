// Package probepolicy is the agent's probe target-access policy: an
// allowlist/denylist of selectors evaluated against every outbound probe
// destination (literal IPs, resolved DNS results, custom resolver/STUN
// endpoints, and HTTP redirect hops). Deny always wins. It governs probe
// traffic only — never the agent's own server/control connection.
//
// The package is exported (imported by agentrt for Config and by
// internal/netguard for enforcement) and depends only on the stdlib.
package probepolicy

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

// Mode is the policy evaluation mode.
type Mode string

const (
	ModeAllowlist Mode = "allowlist" // default deny; a non-empty allowlist is required
	ModeDenylist  Mode = "denylist"  // default allow; a non-empty denylist or explicit none
)

// SelectorKind identifies the selector family.
type SelectorKind string

const (
	KindScope SelectorKind = "scope"
	KindCIDR  SelectorKind = "cidr"
	KindIP    SelectorKind = "ip"
	KindHost  SelectorKind = "host"
)

// Scope is a built-in address class.
type Scope string

const (
	ScopeLoopback  Scope = "loopback"
	ScopeLAN       Scope = "lan"
	ScopeLinkLocal Scope = "link-local"
	ScopePublic    Scope = "public"
	ScopeMetadata  Scope = "metadata"
	ScopeAny       Scope = "any"
)

// Selector is one allow/deny rule.
type Selector struct {
	Kind   SelectorKind
	Scope  Scope        // KindScope
	Prefix netip.Prefix // KindCIDR
	Addr   netip.Addr   // KindIP
	Host   string       // KindHost (lowercased; may be "*.example.com")
}

// ParseSelector parses one selector string. Invalid selectors are startup-fatal.
func ParseSelector(s string) (Selector, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return Selector{}, fmt.Errorf("empty selector")
	}
	kind, rest, ok := strings.Cut(s, ":")
	if !ok {
		return Selector{}, fmt.Errorf("selector %q missing kind prefix (scope:/cidr:/ip:/host:)", s)
	}
	rest = strings.TrimSpace(rest)
	switch SelectorKind(strings.ToLower(kind)) {
	case KindScope:
		sc := Scope(strings.ToLower(rest))
		switch sc {
		case ScopeLoopback, ScopeLAN, ScopeLinkLocal, ScopePublic, ScopeMetadata, ScopeAny:
			return Selector{Kind: KindScope, Scope: sc}, nil
		default:
			return Selector{}, fmt.Errorf("unknown scope %q", rest)
		}
	case KindCIDR:
		p, err := netip.ParsePrefix(rest)
		if err != nil {
			return Selector{}, fmt.Errorf("invalid cidr %q: %v", rest, err)
		}
		if p.Addr().Zone() != "" {
			return Selector{}, fmt.Errorf("cidr %q must not carry a zone", rest)
		}
		if p != p.Masked() {
			return Selector{}, fmt.Errorf("cidr %q has host bits set (use %s)", rest, p.Masked())
		}
		return Selector{Kind: KindCIDR, Prefix: p.Masked()}, nil
	case KindIP:
		a, err := netip.ParseAddr(rest)
		if err != nil {
			return Selector{}, fmt.Errorf("invalid ip %q: %v", rest, err)
		}
		if a.Zone() != "" {
			return Selector{}, fmt.Errorf("ip %q must not carry a zone", rest)
		}
		return Selector{Kind: KindIP, Addr: a.Unmap()}, nil
	case KindHost:
		h, err := parseHostSelector(rest)
		if err != nil {
			return Selector{}, err
		}
		return Selector{Kind: KindHost, Host: h}, nil
	default:
		return Selector{}, fmt.Errorf("unknown selector kind %q", kind)
	}
}

// parseHostSelector validates an LDH hostname, allowing a single leading "*."
// wildcard label (matches subdomains at any depth, not the apex).
func parseHostSelector(h string) (string, error) {
	h = strings.ToLower(strings.TrimSpace(h))
	if h == "" {
		return "", fmt.Errorf("empty host selector")
	}
	check := h
	if strings.HasPrefix(h, "*.") {
		check = h[2:]
		if check == "" {
			return "", fmt.Errorf("host selector %q has empty base domain", h)
		}
	}
	for _, label := range strings.Split(check, ".") {
		if label == "" {
			return "", fmt.Errorf("host selector %q has an empty label", h)
		}
		for i := 0; i < len(label); i++ {
			ch := label[i]
			isLDH := (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '-'
			if !isLDH {
				return "", fmt.Errorf("host selector %q has an invalid label %q", h, label)
			}
		}
	}
	return h, nil
}

// String returns the canonical form for hashing and issue payloads.
func (s Selector) String() string {
	switch s.Kind {
	case KindScope:
		return "scope:" + string(s.Scope)
	case KindCIDR:
		return "cidr:" + s.Prefix.Masked().String()
	case KindIP:
		return "ip:" + s.Addr.Unmap().String()
	case KindHost:
		return "host:" + s.Host
	default:
		return string(s.Kind)
	}
}

// Policy is the evaluated target-access policy.
type Policy struct {
	Mode  Mode
	Allow []Selector
	Deny  []Selector
}

// Default is the policy used when all probe access variables are absent.
func Default() Policy {
	return Policy{
		Mode: ModeAllowlist,
		Allow: []Selector{
			{Kind: KindScope, Scope: ScopeLAN},
			{Kind: KindScope, Scope: ScopePublic},
		},
		Deny: []Selector{
			{Kind: KindScope, Scope: ScopeLoopback},
			{Kind: KindScope, Scope: ScopeLinkLocal},
			{Kind: KindScope, Scope: ScopeMetadata},
		},
	}
}

// metadataV4/V6 are the well-known cloud metadata destinations (spec §17.2).
var (
	metadataAddrs = mustAddrs(
		"169.254.169.254", // AWS/GCP/Azure/Oracle/OpenStack IMDS
		"169.254.170.2",   // AWS ECS task/credentials
		"100.100.100.200", // Alibaba (inside CGNAT)
		"192.0.0.192",     // Oracle legacy
		"fd00:ec2::254",   // AWS v6 IMDS
	)
	metadataHosts = map[string]struct{}{
		"metadata.google.internal": {},
		"metadata.goog":            {},
	}
	cgnatPrefix = netip.MustParsePrefix("100.64.0.0/10")
)

func mustAddrs(ss ...string) []netip.Addr {
	out := make([]netip.Addr, 0, len(ss))
	for _, s := range ss {
		out = append(out, netip.MustParseAddr(s).Unmap())
	}
	return out
}

// Classification predicates. One address can match several classes; deny
// precedence and default scope denies resolve overlaps (e.g. Alibaba metadata
// inside CGNAT). All checks operate on the unmapped address.

func isLoopback(a netip.Addr) bool  { return a.IsLoopback() }
func isLinkLocal(a netip.Addr) bool { return a.IsLinkLocalUnicast() }

func isLAN(a netip.Addr) bool {
	if a.IsPrivate() { // RFC1918 + ULA fc00::/7
		return true
	}
	return a.Is4() && cgnatPrefix.Contains(a) // CGNAT 100.64.0.0/10
}

func isMetadata(a netip.Addr) bool {
	for _, m := range metadataAddrs {
		if m == a {
			return true
		}
	}
	return false
}

func isPublic(a netip.Addr) bool {
	if !a.IsGlobalUnicast() {
		return false
	}
	if isLoopback(a) || isLinkLocal(a) || isLAN(a) || a.IsMulticast() || a.IsUnspecified() {
		return false
	}
	return true
}

// scopeMatchesAddr reports whether an address falls in the given scope.
func scopeMatchesAddr(sc Scope, a netip.Addr) bool {
	switch sc {
	case ScopeLoopback:
		return isLoopback(a)
	case ScopeLinkLocal:
		return isLinkLocal(a)
	case ScopeLAN:
		return isLAN(a)
	case ScopeMetadata:
		return isMetadata(a)
	case ScopePublic:
		return isPublic(a)
	case ScopeAny:
		return true
	default:
		return false
	}
}

// selectorMatchesAddr reports whether an address-capable selector matches a.
// host selectors never match a raw address.
func selectorMatchesAddr(s Selector, a netip.Addr) bool {
	a = a.Unmap()
	switch s.Kind {
	case KindScope:
		return scopeMatchesAddr(s.Scope, a)
	case KindCIDR:
		return s.Prefix.Contains(a)
	case KindIP:
		return s.Addr.Unmap() == a
	default:
		return false
	}
}

// hostMatchesSelector reports whether a name matches a host: selector.
func hostMatchesSelector(s Selector, host string) bool {
	if s.Kind != KindHost {
		return false
	}
	host = strings.ToLower(strings.TrimSpace(host))
	if strings.HasPrefix(s.Host, "*.") {
		base := s.Host[1:] // ".example.com"
		return strings.HasSuffix(host, base) && host != s.Host[2:]
	}
	return host == s.Host
}

// scopeMatchesName reports whether a scope can classify a hostname before
// resolution. Only metadata hostnames and localhost, plus scope:any, apply.
func scopeMatchesName(sc Scope, host string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	switch sc {
	case ScopeAny:
		return true
	case ScopeMetadata:
		_, ok := metadataHosts[host]
		return ok
	case ScopeLoopback:
		return host == "localhost"
	default:
		return false
	}
}

// Decision is the outcome of an address check.
type Decision struct {
	Allowed bool
	Matched string // deciding selector, or "" for the mode default
}

// CheckAddr is the full address check: deny wins; allowlist requires an allow;
// denylist defaults to allow.
func (p Policy) CheckAddr(a netip.Addr) Decision {
	a = a.Unmap()
	if sel, ok := p.firstDenyMatch(a); ok {
		return Decision{Allowed: false, Matched: sel}
	}
	if p.Mode == ModeAllowlist {
		if sel, ok := p.firstAllowMatch(a); ok {
			return Decision{Allowed: true, Matched: sel}
		}
		return Decision{Allowed: false, Matched: ""}
	}
	// denylist: default allow.
	return Decision{Allowed: true, Matched: ""}
}

// DeniedAddr is the deny-only check for an address already authorized by name.
func (p Policy) DeniedAddr(a netip.Addr) (bool, string) {
	sel, ok := p.firstDenyMatch(a.Unmap())
	return ok, sel
}

func (p Policy) firstDenyMatch(a netip.Addr) (string, bool) {
	for _, s := range p.Deny {
		if selectorMatchesAddr(s, a) {
			return s.String(), true
		}
	}
	return "", false
}

func (p Policy) firstAllowMatch(a netip.Addr) (string, bool) {
	for _, s := range p.Allow {
		if selectorMatchesAddr(s, a) {
			return s.String(), true
		}
	}
	return "", false
}

// HostDecision is the outcome of a hostname check (pre-resolution).
type HostDecision struct {
	Denied         bool
	Matched        string
	NameAuthorized bool // a host/name allow matched, or denylist mode
}

// CheckHost evaluates a hostname before resolution. Deny wins conclusively; an
// allowlist host/name allow authorizes the name (its resolved IPs then need only
// survive the deny list); denylist authorizes by default.
func (p Policy) CheckHost(host string) HostDecision {
	host = strings.ToLower(strings.TrimSpace(host))
	// (1) conclusive deny by name.
	for _, s := range p.Deny {
		if s.Kind == KindHost && hostMatchesSelector(s, host) {
			return HostDecision{Denied: true, Matched: s.String()}
		}
		if s.Kind == KindScope && scopeMatchesName(s.Scope, host) {
			return HostDecision{Denied: true, Matched: s.String()}
		}
	}
	// (2) allowlist: a matching host/name-capable scope allow authorizes the name.
	if p.Mode == ModeAllowlist {
		for _, s := range p.Allow {
			if s.Kind == KindHost && hostMatchesSelector(s, host) {
				return HostDecision{NameAuthorized: true, Matched: s.String()}
			}
			if s.Kind == KindScope && scopeMatchesName(s.Scope, host) {
				return HostDecision{NameAuthorized: true, Matched: s.String()}
			}
		}
		return HostDecision{NameAuthorized: false}
	}
	// (3) denylist: authorized unless denied above.
	return HostDecision{NameAuthorized: true}
}

// canonicalSelectors returns the sorted canonical String() forms (for hashing).
func canonicalSelectors(sels []Selector) []string {
	out := make([]string, len(sels))
	for i, s := range sels {
		out[i] = s.String()
	}
	sort.Strings(out)
	return out
}

// AllowStrings / DenyStrings return sorted canonical selector strings, used by
// the policy-hash preimage.
func (p Policy) AllowStrings() []string { return canonicalSelectors(p.Allow) }
func (p Policy) DenyStrings() []string  { return canonicalSelectors(p.Deny) }
