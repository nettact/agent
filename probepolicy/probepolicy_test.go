package probepolicy

import (
	"net/netip"
	"testing"
)

func TestDefaultPolicyAddressClasses(t *testing.T) {
	p := Default()
	tests := []struct {
		addr    string
		allowed bool
		matched string
	}{
		{addr: "192.168.1.20", allowed: true, matched: "scope:lan"},
		{addr: "100.64.0.10", allowed: true, matched: "scope:lan"},
		{addr: "fd12::1", allowed: true, matched: "scope:lan"},
		{addr: "1.1.1.1", allowed: true, matched: "scope:public"},
		{addr: "2606:4700:4700::1111", allowed: true, matched: "scope:public"},
		{addr: "127.0.0.1", allowed: false, matched: "scope:loopback"},
		{addr: "169.254.10.20", allowed: false, matched: "scope:link-local"},
		// Metadata denial wins even though this address is also in CGNAT/LAN.
		{addr: "100.100.100.200", allowed: false, matched: "scope:metadata"},
		{addr: "fd00:ec2::254", allowed: false, matched: "scope:metadata"},
	}
	for _, tt := range tests {
		t.Run(tt.addr, func(t *testing.T) {
			got := p.CheckAddr(netip.MustParseAddr(tt.addr))
			if got.Allowed != tt.allowed || got.Matched != tt.matched {
				t.Fatalf("CheckAddr(%s) = %+v, want allowed=%v matched=%q", tt.addr, got, tt.allowed, tt.matched)
			}
		})
	}
}

func TestDenyAlwaysWinsAndHostWildcardDoesNotMatchApex(t *testing.T) {
	any, _ := ParseSelector("scope:any")
	deny, _ := ParseSelector("cidr:10.0.0.0/8")
	p := Policy{Mode: ModeAllowlist, Allow: []Selector{any}, Deny: []Selector{deny}}
	if got := p.CheckAddr(netip.MustParseAddr("10.1.2.3")); got.Allowed || got.Matched != "cidr:10.0.0.0/8" {
		t.Fatalf("deny precedence decision = %+v", got)
	}

	host, _ := ParseSelector("host:*.example.com")
	p = Policy{Mode: ModeAllowlist, Allow: []Selector{host}}
	if got := p.CheckHost("api.dev.example.com"); !got.NameAuthorized || got.Denied {
		t.Fatalf("wildcard subdomain decision = %+v", got)
	}
	if got := p.CheckHost("example.com"); got.NameAuthorized || got.Denied {
		t.Fatalf("wildcard apex decision = %+v, want allowlist default deny", got)
	}
}
