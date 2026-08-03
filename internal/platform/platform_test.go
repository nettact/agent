package platform

import "testing"

func ipv4Default(gateway string, metric int) *IPv4Default {
	return &IPv4Default{Gateway: gateway, Metric: &metric}
}

// Default egress is the interface the OS prefers, not the one it happened to
// enumerate first. A host with two connected wired NICs carries a default route
// on each; naming the costlier one points the gateway probe, the path card and
// the incident scene at a gateway the host's traffic never uses.
func TestResolveIPv4GatewayPrefersTheLowestMetric(t *testing.T) {
	ifaces := []IfaceInfo{
		{ID: "lo", Name: "lo", Up: true, IsLoopback: true, IPv4Default: ipv4Default("127.0.0.1", 1)},
		{ID: "tun", Name: "tailscale0", Up: true}, // best interface metric, but no default route
		{ID: "eth2", Name: "eth2", Up: true, IPv4Default: ipv4Default("172.16.66.1", 20)},
		{ID: "eth1", Name: "eth1", Up: true, IPv4Default: ipv4Default("192.168.66.1", 10)},
		{ID: "wlan", Name: "wlan0", IsWireless: true, IPv4Default: ipv4Default("192.168.66.1", 1)}, // down
	}
	gw, name := ResolveIPv4Gateway(ifaces, "")
	if gw != "192.168.66.1" || name != "eth1" {
		t.Fatalf("ResolveIPv4Gateway = %q via %q, want 192.168.66.1 via eth1", gw, name)
	}

	// An explicit NIC selection still wins over the metric: the monitor asked for
	// that interface's gateway, not for default egress.
	if gw, name = ResolveIPv4Gateway(ifaces, "eth2"); gw != "172.16.66.1" || name != "eth2" {
		t.Fatalf("pinned interface = %q via %q, want 172.16.66.1 via eth2", gw, name)
	}
	if gw, _ = ResolveIPv4Gateway(ifaces, "wlan0"); gw != "" {
		t.Fatalf("down interface resolved a gateway: %q", gw)
	}
}

// The gateway comes from the same route as the metric that won. An interface
// whose gateway addresses are known but whose default route is not (nil
// IPv4Default) is not a candidate: those addresses may be a disconnected
// adapter's leftovers, and none of them is known to be reachable.
func TestResolveIPv4GatewayIgnoresUnroutedGateways(t *testing.T) {
	ifaces := []IfaceInfo{
		{ID: "eth0", Name: "eth0", Up: true, Gateways: []string{"10.0.0.1"}},
		{ID: "eth1", Name: "eth1", Up: true, Gateways: []string{"fe80::1", "192.168.66.1"},
			IPv4Default: ipv4Default("192.168.66.1", 100)},
	}
	if gw, name := ResolveIPv4Gateway(ifaces, ""); gw != "192.168.66.1" || name != "eth1" {
		t.Fatalf("ResolveIPv4Gateway = %q via %q, want the routed eth1", gw, name)
	}
	if gw, _ := ResolveIPv4Gateway(ifaces, "eth0"); gw != "" {
		t.Fatalf("an interface with no default route resolved a gateway: %q", gw)
	}
}

// A platform that cannot rank its routes must not outrank one that can, and with
// no metrics at all the enumeration order is all there is to go on.
func TestResolveIPv4GatewayWithoutMetrics(t *testing.T) {
	unranked := []IfaceInfo{
		{ID: "a", Name: "eth0", Up: true, IPv4Default: &IPv4Default{Gateway: "10.0.0.1"}},
		{ID: "b", Name: "eth1", Up: true, IPv4Default: &IPv4Default{Gateway: "10.0.1.1"}},
	}
	if gw, name := ResolveIPv4Gateway(unranked, ""); gw != "10.0.0.1" || name != "eth0" {
		t.Fatalf("unranked = %q via %q, want 10.0.0.1 via eth0", gw, name)
	}

	mixed := []IfaceInfo{
		{ID: "a", Name: "eth0", Up: true, IPv4Default: &IPv4Default{Gateway: "10.0.0.1"}},
		{ID: "b", Name: "eth1", Up: true, IPv4Default: ipv4Default("10.0.1.1", 600)},
	}
	if gw, name := ResolveIPv4Gateway(mixed, ""); gw != "10.0.1.1" || name != "eth1" {
		t.Fatalf("mixed = %q via %q, want the ranked eth1", gw, name)
	}
}
