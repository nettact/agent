//go:build !lite

package incidentscene

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/nettact/agent/internal/netguard"
	"github.com/nettact/agent/internal/platform"
	"github.com/nettact/agent/probepolicy"
	"github.com/nettact/protocol/permission"
	"github.com/nettact/protocol/telemetry"
)

// fakePlatform serves a fixed interface table (or a read error) so the gateway
// tests exercise the routing-table path without touching the host's real NICs.
type fakePlatform struct {
	ifaces []platform.IfaceInfo
	err    error
}

func (f fakePlatform) Interfaces(platform.IfaceQuery) ([]platform.IfaceInfo, error) {
	return f.ifaces, f.err
}
func (fakePlatform) Ping(context.Context, string, platform.PingOptions) (platform.PingResult, error) {
	return platform.PingResult{}, errors.New("not used")
}
func (fakePlatform) Neighbors() ([]platform.Neighbor, error) { return nil, errors.New("not used") }
func (fakePlatform) WiFi(bool) platform.WiFiResult           { return platform.WiFiResult{State: "ok"} }
func (fakePlatform) Supports() permission.Set                { return permission.NewSet() }

// gatewayDeps builds Deps whose platform serves ifaces and whose effective
// permissions grant the gateway probe.
func gatewayDeps(ifaces []platform.IfaceInfo, err error) Deps {
	return Deps{
		Platform:  fakePlatform{ifaces: ifaces, err: err},
		Guard:     netguard.New(probepolicy.Default(), false),
		Effective: permission.NewSet(permission.NetworkGatewayProbe),
	}
}

// defaultVia is one interface's preferred IPv4 default route, as the OS's route
// table would report it.
func defaultVia(gateway string, metric int) *platform.IPv4Default {
	return &platform.IPv4Default{Gateway: gateway, Metric: &metric}
}

// lanIfaces is a two-NIC host: an up Wi-Fi NIC owning default egress and an up
// Ethernet NIC with its own costlier default route, plus a loopback that must
// never be chosen.
func lanIfaces() []platform.IfaceInfo {
	return []platform.IfaceInfo{
		{ID: "lo", Name: "Loopback", Up: true, IsLoopback: true, Gateways: []string{"127.0.0.1"},
			IPv4Default: defaultVia("127.0.0.1", 1)},
		{ID: "wifi0", Name: "Wi-Fi", Up: true, IsWireless: true, Gateways: []string{"192.168.1.1"},
			IPv4Default: defaultVia("192.168.1.1", 10)},
		{ID: "eth0", Name: "以太网", Up: true, Gateways: []string{"10.0.0.1"},
			IPv4Default: defaultVia("10.0.0.1", 20)},
	}
}

// A gateway monitor's target is the server-normalized sentinel "gateway", which
// no resolver can answer. Handing it to DNS reported "dns_error" on the incident
// detail page for a plain LAN outage — pointing the reader at a layer that was
// working fine. It must resolve from the routing table instead.
func TestGatewayTargetResolvesFromRoutingTableNotDNS(t *testing.T) {
	refs := []TargetRef{{MonitorID: "mon_gw", Kind: "gateway", Target: "gateway"}}
	tg := Collect(context.Background(), gatewayDeps(lanIfaces(), nil), refs).Targets[0]

	if tg.ErrorClass != "" {
		t.Errorf("error class = %q, want empty (the gateway resolved)", tg.ErrorClass)
	}
	// Default NIC selection: the first up, non-loopback IPv4 gateway.
	if len(tg.ResolvedIPs) != 1 || tg.ResolvedIPs[0] != "192.168.1.1" {
		t.Errorf("resolved = %v, want [192.168.1.1]", tg.ResolvedIPs)
	}
	// A gateway monitor pings; it has no port, so it must claim no endpoint.
	if len(tg.Endpoints) != 0 {
		t.Errorf("endpoints = %v, want none", tg.Endpoints)
	}
}

// The monitor's NIC selection has to reach the snapshot, or a multi-NIC host
// reports one NIC's gateway for an incident raised on another's.
func TestGatewayTargetHonoursInterfaceSelection(t *testing.T) {
	refs := []TargetRef{
		{MonitorID: "mon_gw", Kind: "gateway", Target: "gateway", Iface: "以太网"},
		// A NIC that no longer exists must not silently fall back to the default.
		{MonitorID: "mon_gone", Kind: "gateway", Target: "gateway", Iface: "does-not-exist"},
	}
	got := Collect(context.Background(), gatewayDeps(lanIfaces(), nil), refs).Targets

	if len(got[0].ResolvedIPs) != 1 || got[0].ResolvedIPs[0] != "10.0.0.1" {
		t.Errorf("named NIC resolved = %v, want [10.0.0.1]", got[0].ResolvedIPs)
	}
	if got[1].ErrorClass != errClassNoGateway {
		t.Errorf("missing NIC error class = %q, want %q", got[1].ErrorClass, errClassNoGateway)
	}
	if len(got[1].ResolvedIPs) != 0 {
		t.Errorf("missing NIC resolved %v, want nothing", got[1].ResolvedIPs)
	}
}

// Each way the gateway lookup can fail gets its own class. Collapsing them (or
// borrowing dns_error) is the bug this whole path exists to avoid.
func TestGatewayFailuresAreClassifiedDistinctly(t *testing.T) {
	refs := []TargetRef{{MonitorID: "mon_gw", Kind: "gateway", Target: "gateway"}}
	noGateway := []platform.IfaceInfo{{ID: "eth0", Name: "以太网", Up: true}}
	// An IPv6-only gateway is not an IPv4 default route: the probe would not use
	// it, so the snapshot must not name it either.
	v6Only := []platform.IfaceInfo{{ID: "eth0", Name: "以太网", Up: true, Gateways: []string{"fe80::1"}}}
	// A down NIC's stale route must not be reported as the live default route.
	downNIC := []platform.IfaceInfo{{ID: "eth0", Name: "以太网", Up: false,
		Gateways: []string{"10.0.0.1"}, IPv4Default: defaultVia("10.0.0.1", 10)}}

	for _, tc := range []struct {
		name   string
		deps   Deps
		want   string
		target TargetRef
	}{
		{name: "no ipv4 gateway", deps: gatewayDeps(noGateway, nil), want: errClassNoGateway},
		{name: "ipv6 only", deps: gatewayDeps(v6Only, nil), want: errClassNoGateway},
		{name: "nic down", deps: gatewayDeps(downNIC, nil), want: errClassNoGateway},
		// The platform reports an unreadable routing table alongside a populated
		// interface list; the gateway is UNKNOWN, which is not "there is none".
		{name: "routing table unreadable", deps: gatewayDeps(lanIfaces(), platform.ErrRoutesUnreadable), want: errClassRouteUnreadable},
		{name: "interfaces unreadable", deps: gatewayDeps(nil, errors.New("boom")), want: errClassRouteUnreadable},
		{name: "no permission at all", deps: Deps{
			Platform: fakePlatform{ifaces: lanIfaces()},
			Guard:    netguard.New(probepolicy.Default(), false),
		}, want: errClassPermissionDenied},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tg := Collect(context.Background(), tc.deps, refs).Targets[0]
			if tg.ErrorClass != tc.want {
				t.Errorf("error class = %q, want %q", tg.ErrorClass, tc.want)
			}
			if tg.ErrorClass == errClassDNS {
				t.Error("a gateway monitor must never report a DNS failure")
			}
		})
	}
}

// Address-read alone authorizes gateway disclosure — collectNetwork already
// publishes the default route under it. Demanding the probe permission here made
// one snapshot print the default route in its network group while the gateway
// target next to it claimed permission was denied for the same address.
func TestGatewayResolutionAcceptsAddressReadPermission(t *testing.T) {
	refs := []TargetRef{{MonitorID: "mon_gw", Kind: "gateway", Target: "gateway"}}
	for _, tc := range []struct {
		name string
		set  permission.Set
	}{
		{name: "address read only", set: permission.NewSet(permission.NetIfaceAddressRead)},
		{name: "gateway probe only", set: permission.NewSet(permission.NetworkGatewayProbe)},
		{name: "both", set: permission.NewSet(permission.NetIfaceAddressRead, permission.NetworkGatewayProbe)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			deps := Deps{
				Platform:  fakePlatform{ifaces: lanIfaces()},
				Guard:     netguard.New(probepolicy.Default(), false),
				Effective: tc.set,
			}
			tg := Collect(context.Background(), deps, refs).Targets[0]
			if tg.ErrorClass != "" {
				t.Errorf("error class = %q, want empty", tg.ErrorClass)
			}
			if len(tg.ResolvedIPs) != 1 || tg.ResolvedIPs[0] != "192.168.1.1" {
				t.Errorf("resolved = %v, want [192.168.1.1]", tg.ResolvedIPs)
			}
		})
	}
}

// An unreadable routing table must not cost the caller the interface evidence it
// did get. The network group stays collected with its interfaces; only the
// default route is absent.
func TestRoutesUnreadableKeepsNetworkGroupCollected(t *testing.T) {
	deps := Deps{
		Platform:  fakePlatform{ifaces: lanIfaces(), err: platform.ErrRoutesUnreadable},
		Guard:     netguard.New(probepolicy.Default(), false),
		Effective: permission.NewSet(permission.NetIfaceStatusRead, permission.NetIfaceAddressRead),
	}
	snap := Collect(context.Background(), deps, nil)

	var status string
	for _, g := range snap.Groups {
		if g.Group == telemetry.SnapshotGroupNetwork {
			status = g.Status
		}
	}
	if status != telemetry.ScopeCollected {
		t.Errorf("network group = %q, want %q", status, telemetry.ScopeCollected)
	}
	if snap.Network == nil || len(snap.Network.Interfaces) != len(lanIfaces()) {
		t.Fatalf("interfaces were dropped: %+v", snap.Network)
	}
	if snap.Network.DefaultRoute != nil {
		t.Errorf("default route = %+v, want absent when the routing table is unreadable", snap.Network.DefaultRoute)
	}
}

// The network group's default route and a gateway target's resolution are two
// readings of one fact and must never disagree inside a single snapshot. Taking
// "first non-loopback interface carrying any gateway" for the group made them
// disagree on exactly the hosts where it matters: a disconnected adapter keeps a
// stale route, and a dual-stack NIC can list its IPv6 gateway first, while the
// target resolves through ResolveIPv4Gateway (up, non-loopback, IPv4).
func TestDefaultRouteAgreesWithGatewayTarget(t *testing.T) {
	ifaces := []platform.IfaceInfo{
		{ID: "lo", Name: "Loopback", Up: true, IsLoopback: true, Gateways: []string{"127.0.0.1"},
			IPv4Default: defaultVia("127.0.0.1", 1)},
		// Unplugged, and its stale route is the cheapest on the host: down beats
		// cheap, so it must still lose.
		{ID: "eth1", Name: "Dock", Up: false, Gateways: []string{"10.9.9.1"},
			IPv4Default: defaultVia("10.9.9.1", 5)},
		{ID: "wifi0", Name: "Wi-Fi", Up: true, Gateways: []string{"fe80::1", "192.168.1.1"}, // IPv6 first
			IPv4Default: defaultVia("192.168.1.1", 50)},
	}
	deps := Deps{
		Platform:  fakePlatform{ifaces: ifaces},
		Guard:     netguard.New(probepolicy.Default(), false),
		Effective: permission.NewSet(permission.NetIfaceStatusRead, permission.NetworkGatewayProbe),
	}
	refs := []TargetRef{{MonitorID: "mon_gw", Kind: "gateway", Target: "gateway"}}
	snap := Collect(context.Background(), deps, refs)

	if snap.Network == nil || snap.Network.DefaultRoute == nil {
		t.Fatalf("no default route in %+v", snap.Network)
	}
	if got := snap.Network.DefaultRoute.Gateway; got != "192.168.1.1" {
		t.Errorf("default route gateway = %q, want 192.168.1.1 (up, IPv4)", got)
	}
	if got := snap.Network.DefaultRoute.Interface; got != "Wi-Fi" {
		t.Errorf("default route interface = %q, want Wi-Fi", got)
	}
	if ips := snap.Targets[0].ResolvedIPs; len(ips) != 1 || ips[0] != snap.Network.DefaultRoute.Gateway {
		t.Errorf("gateway target resolved %v, want the same address the group reports (%s)",
			ips, snap.Network.DefaultRoute.Gateway)
	}
}

// A spent budget must not turn a gateway lookup into a timeout either: the
// routing table is a local read with no resolver and no network round trip, so
// it still answers.
func TestGatewayResolvesWithSpentBudget(t *testing.T) {
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	refs := []TargetRef{{MonitorID: "mon_gw", Kind: "gateway", Target: "gateway"}}
	tg := Collect(ctx, gatewayDeps(lanIfaces(), nil), refs).Targets[0]

	if tg.ErrorClass != "" || len(tg.ResolvedIPs) != 1 || tg.ResolvedIPs[0] != "192.168.1.1" {
		t.Errorf("class = %q resolved = %v, want empty class and [192.168.1.1]", tg.ErrorClass, tg.ResolvedIPs)
	}
}

// A spent collection budget must be reported as a timeout on every target, never
// as a DNS failure. The stdlib resolver wraps a dead context in a *net.DNSError,
// so classifying every resolve error as dns_error made an agent-side budget
// expiry (historically: a request deadline minted on a skewed server clock) look
// like the monitored target's name had stopped resolving.
func TestExpiredBudgetReportsTimeoutNotDNSError(t *testing.T) {
	guard := netguard.New(probepolicy.Default(), false)
	deps := Deps{Guard: guard, Identity: Identity{AgentID: "agent_1"}}
	refs := []TargetRef{
		{MonitorID: "mon_http", Kind: "http", Target: "http://connect.rom.miui.com/generate_204"},
		{MonitorID: "mon_icmp", Kind: "icmp", Target: "example.invalid"},
	}

	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	snap := Collect(ctx, deps, refs)

	if len(snap.Targets) != len(refs) {
		t.Fatalf("targets = %d, want %d", len(snap.Targets), len(refs))
	}
	for _, tg := range snap.Targets {
		if tg.ErrorClass != errClassTimeout {
			t.Errorf("target %s error class = %q, want %q", tg.MonitorID, tg.ErrorClass, errClassTimeout)
		}
		if len(tg.ResolvedIPs) != 0 {
			t.Errorf("target %s resolved %v with a spent budget", tg.MonitorID, tg.ResolvedIPs)
		}
	}

	// The HTTP target still reports the endpoint it would have probed (host:port
	// from the URL), so the scene shows what was attempted even with no answer.
	if got := snap.Targets[0].Endpoints; len(got) != 1 || got[0] != "connect.rom.miui.com:80" {
		t.Errorf("http endpoints = %v, want [connect.rom.miui.com:80]", got)
	}

	// A session teardown is a distinct class from budget exhaustion.
	cctx, ccancel := context.WithCancel(context.Background())
	ccancel()
	if got := Collect(cctx, deps, refs).Targets[0].ErrorClass; got != errClassCanceled {
		t.Errorf("canceled error class = %q, want %q", got, errClassCanceled)
	}
}

// A literal-IP target needs no resolver, so a spent budget must not stop it from
// reporting the address and endpoint the probe would have used.
func TestLiteralIPTargetResolvesWithoutBudget(t *testing.T) {
	deps := Deps{Guard: netguard.New(probepolicy.Default(), false)}
	refs := []TargetRef{{MonitorID: "mon_tcp", Kind: "tcp", Target: "192.0.2.10", Port: 443}}

	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	tg := Collect(ctx, deps, refs).Targets[0]

	if tg.ErrorClass != "" {
		t.Errorf("error class = %q, want empty", tg.ErrorClass)
	}
	if len(tg.ResolvedIPs) != 1 || tg.ResolvedIPs[0] != "192.0.2.10" {
		t.Errorf("resolved = %v, want [192.0.2.10]", tg.ResolvedIPs)
	}
	if len(tg.Endpoints) != 1 || tg.Endpoints[0] != "192.0.2.10:443" {
		t.Errorf("endpoints = %v, want [192.0.2.10:443]", tg.Endpoints)
	}
}

// Every attempted group is classified even when the budget is spent and no
// permission is granted, so the server always gets a complete, terminal scene.
//
// The target group is the one exception, and its absence is a statement: a scene
// collected on the disconnect edge has no target in question — the probes were
// fine and only the uplink was not — so reporting an empty "targets: collected"
// would answer a question nobody asked. A scene with refs must still carry it.
func TestGroupsAlwaysReported(t *testing.T) {
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	deps := Deps{Guard: netguard.New(probepolicy.Default(), false)}
	snap := Collect(ctx, deps, nil)

	got := map[string]string{}
	for _, g := range snap.Groups {
		got[g.Group] = g.Status
	}
	for _, group := range []string{
		telemetry.SnapshotGroupNetwork, telemetry.SnapshotGroupAgent,
		telemetry.SnapshotGroupResources,
	} {
		if got[group] == "" {
			t.Errorf("group %s missing from %v", group, got)
		}
	}
	if _, ok := got[telemetry.SnapshotGroupTargets]; ok {
		t.Errorf("a scene with no target in question reported a targets group: %v", got)
	}
	if got[telemetry.SnapshotGroupAgent] != telemetry.ScopeCollected {
		t.Errorf("agent group = %q, want %q", got[telemetry.SnapshotGroupAgent], telemetry.ScopeCollected)
	}

	withRefs := Collect(ctx, deps, []TargetRef{{MonitorID: "mon_icmp", Kind: "icmp", Target: "192.0.2.10"}})
	var seen bool
	for _, g := range withRefs.Groups {
		if g.Group == telemetry.SnapshotGroupTargets {
			seen = true
		}
	}
	if !seen {
		t.Errorf("a scene with a failing target dropped its targets group: %+v", withRefs.Groups)
	}
}
