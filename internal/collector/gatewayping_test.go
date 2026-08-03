package collector

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/nettact/agent/internal/netguard"
	"github.com/nettact/agent/internal/platform"
	"github.com/nettact/agent/probepolicy"
	pcfg "github.com/nettact/protocol/config"
	"github.com/nettact/protocol/permission"
	"github.com/nettact/protocol/telemetry"
)

// gwTestPlatform is a fake HAL for the gateway collector: it serves a fixed
// interface set and records ping calls. recv, when set, decides per-echo whether
// the reply is received (echo index is 0-based); nil means every echo answers.
type gwTestPlatform struct {
	ifaces   []platform.IfaceInfo
	ifaceErr error
	pinged   string
	pings    int
	recv     func(seq int) bool
}

func (p *gwTestPlatform) Interfaces(platform.IfaceQuery) ([]platform.IfaceInfo, error) {
	return p.ifaces, p.ifaceErr
}
func (p *gwTestPlatform) Ping(_ context.Context, target string, _ platform.PingOptions) (platform.PingResult, error) {
	seq := p.pings
	p.pings++
	p.pinged = target
	received := p.recv == nil || p.recv(seq)
	return platform.PingResult{Target: target, RTT: 3 * time.Millisecond, Received: received}, nil
}
func (p *gwTestPlatform) Neighbors() ([]platform.Neighbor, error) { return nil, nil }
func (p *gwTestPlatform) WiFi(includeSSID bool) platform.WiFiResult {
	return platform.WiFiResult{State: "ok"}
}
func (p *gwTestPlatform) Supports() permission.Set { return nil }

// defaultVia is one interface's preferred IPv4 default route, as the OS's route
// table would report it.
func defaultVia(gateway string, metric int) *platform.IPv4Default {
	return &platform.IPv4Default{Gateway: gateway, Metric: &metric}
}

func gwTestIfaces() []platform.IfaceInfo {
	return []platform.IfaceInfo{
		{ID: "lo", Name: "lo", IsLoopback: true, Up: true, Gateways: []string{"127.0.0.1"},
			IPv4Default: defaultVia("127.0.0.1", 1)},
		{ID: "eth-id", Name: "eth0", Up: true, Gateways: []string{"192.168.1.1"},
			IPv4Default: defaultVia("192.168.1.1", 10)},
		{ID: "wifi-id", Name: "wlan0", Up: true, IsWireless: true, Gateways: []string{"10.0.0.1"},
			IPv4Default: defaultVia("10.0.0.1", 50)},
	}
}

// lossPct extracts the ICMPLoss metric value (or -1 when absent).
func lossPct(res Result) float64 {
	for _, m := range res.Metrics {
		if m.Kind == telemetry.ICMPLoss {
			return m.Value
		}
	}
	return -1
}

func TestGatewayCollectorNamedInterface(t *testing.T) {
	p := &gwTestPlatform{ifaces: gwTestIfaces()}
	c := NewGatewayPingCollector(p, netguard.New(probepolicy.Policy{}, true))
	c.SetTargets([]pcfg.ProbeTarget{
		{MonitorID: "gw1", Kind: "gateway", Target: "gateway", Params: pcfg.ProbeParams{Interface: "wlan0"}},
	})
	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	// wlan0's gateway is 10.0.0.1 — selection must not fall through to eth0.
	if p.pinged != "10.0.0.1" {
		t.Fatalf("pinged=%q want 10.0.0.1", p.pinged)
	}
	if got := lossPct(res); got != 0 {
		t.Fatalf("loss=%v want 0 (gateway answered)", got)
	}
	for _, m := range res.Metrics {
		if m.MonitorID != "gw1" {
			t.Fatalf("metric missing MonitorID: %+v", m)
		}
		if m.Layer != telemetry.LayerLAN {
			t.Fatalf("metric layer=%q want LAN", m.Layer)
		}
	}
}

// An unreadable routing table means the agent could not look, not that the LAN
// is dead. Reporting it as 100% loss plus a gateway-unreachable event blamed the
// network for a restriction on the agent — and that fabricated outage replays
// from the WAL long after the restriction is gone.
func TestGatewayCollectorSkipsUnreadableRoutes(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"routes unreadable", fmt.Errorf("%w: seccomp", platform.ErrRoutesUnreadable)},
		{"enumeration failed", errors.New("interface enumeration failed")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := &gwTestPlatform{ifaces: gwTestIfaces(), ifaceErr: tc.err}
			c := NewGatewayPingCollector(p, netguard.New(probepolicy.Policy{}, true))
			c.SetTargets([]pcfg.ProbeTarget{{MonitorID: "gw1", Kind: "gateway", Target: "gateway"}})
			res, err := c.Collect(context.Background())
			if err != nil {
				t.Fatalf("Collect: %v", err)
			}
			if len(res.Metrics) != 0 || len(res.Events) != 0 {
				t.Fatalf("unreadable routes fabricated telemetry: metrics=%+v events=%+v", res.Metrics, res.Events)
			}
			if p.pings != 0 {
				t.Fatalf("pinged %d times with no known gateway", p.pings)
			}
		})
	}
}

// A readable table that genuinely holds no default route IS a LAN-layer fault,
// and must still be reported as one.
func TestGatewayCollectorReportsGenuinelyMissingGateway(t *testing.T) {
	p := &gwTestPlatform{ifaces: []platform.IfaceInfo{{ID: "eth-id", Name: "eth0", Up: true}}}
	c := NewGatewayPingCollector(p, netguard.New(probepolicy.Policy{}, true))
	c.SetTargets([]pcfg.ProbeTarget{{MonitorID: "gw1", Kind: "gateway", Target: "gateway"}})
	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if got := lossPct(res); got != 100 {
		t.Fatalf("loss=%v want 100 (no gateway on a readable table)", got)
	}
	if len(res.Events) != 1 || res.Events[0].Type != telemetry.EventGatewayUnreachable {
		t.Fatalf("events=%+v want one gateway.unreachable", res.Events)
	}
}

func TestGatewayCollectorDefaultInterface(t *testing.T) {
	p := &gwTestPlatform{ifaces: gwTestIfaces()}
	c := NewGatewayPingCollector(p, netguard.New(probepolicy.Policy{}, true))
	c.SetTargets([]pcfg.ProbeTarget{
		{MonitorID: "gw1", Kind: "gateway", Target: "gateway"},
	})
	if _, err := c.Collect(context.Background()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	// Empty interface = default: first up, non-loopback IPv4 gateway (eth0).
	if p.pinged != "192.168.1.1" {
		t.Fatalf("pinged=%q want 192.168.1.1 (default NIC)", p.pinged)
	}
}

func TestGatewayCollectorUnknownInterface(t *testing.T) {
	p := &gwTestPlatform{ifaces: gwTestIfaces()}
	c := NewGatewayPingCollector(p, netguard.New(probepolicy.Policy{}, true))
	c.SetTargets([]pcfg.ProbeTarget{
		{MonitorID: "gw1", Kind: "gateway", Target: "gateway", Params: pcfg.ProbeParams{Interface: "does-not-exist"}},
	})
	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if p.pinged != "" {
		t.Fatalf("pinged=%q want no ping (interface not found)", p.pinged)
	}
	if got := lossPct(res); got != 100 {
		t.Fatalf("loss=%v want 100 (unreachable)", got)
	}
	if len(res.Events) != 1 || res.Events[0].Type != telemetry.EventGatewayUnreachable {
		t.Fatalf("events=%+v want one gateway-unreachable", res.Events)
	}
}

func TestGatewayCollectorDefaultPacketCount(t *testing.T) {
	// No PacketCount/Retries set → the collector must send the default burst of 5
	// echoes (not a single one), so the RTT distribution + jitter are produced.
	p := &gwTestPlatform{ifaces: gwTestIfaces()}
	c := NewGatewayPingCollector(p, netguard.New(probepolicy.Policy{}, true))
	c.SetTargets([]pcfg.ProbeTarget{
		{MonitorID: "gw1", Kind: "gateway", Target: "gateway", Params: pcfg.ProbeParams{Interface: "eth0"}},
	})
	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if p.pings != 5 {
		t.Fatalf("pings=%d want 5 (default burst)", p.pings)
	}
	got := map[telemetry.MetricKind]bool{}
	for _, m := range res.Metrics {
		got[m.Kind] = true
	}
	for _, want := range []telemetry.MetricKind{
		telemetry.ICMPLoss, telemetry.ICMPSamples, telemetry.ICMPRTTms,
		telemetry.ICMPRTTMin, telemetry.ICMPRTTMax, telemetry.ICMPJitter,
	} {
		if !got[want] {
			t.Fatalf("missing metric %s (have %v)", want, got)
		}
	}
}

func TestGatewayCollectorHonorsPacketCount(t *testing.T) {
	// 4 echoes, every other one lost → 2/4 received → 50% loss.
	p := &gwTestPlatform{ifaces: gwTestIfaces(), recv: func(seq int) bool { return seq%2 == 0 }}
	c := NewGatewayPingCollector(p, netguard.New(probepolicy.Policy{}, true))
	c.SetTargets([]pcfg.ProbeTarget{
		{MonitorID: "gw1", Kind: "gateway", Target: "gateway", Params: pcfg.ProbeParams{Interface: "eth0", PacketCount: 4}},
	})
	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if p.pings != 4 {
		t.Fatalf("pings=%d want 4 (packet_count honored)", p.pings)
	}
	if got := lossPct(res); got != 50 {
		t.Fatalf("loss=%v want 50", got)
	}
}

func TestGatewayCollectorIgnoresNonGatewayKinds(t *testing.T) {
	p := &gwTestPlatform{ifaces: gwTestIfaces()}
	c := NewGatewayPingCollector(p, netguard.New(probepolicy.Policy{}, true))
	c.SetTargets([]pcfg.ProbeTarget{
		{MonitorID: "p1", Kind: "icmp", Target: "1.1.1.1"},
	})
	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(res.Metrics) != 0 || p.pinged != "" {
		t.Fatalf("collected non-gateway target: metrics=%+v pinged=%q", res.Metrics, p.pinged)
	}
}
