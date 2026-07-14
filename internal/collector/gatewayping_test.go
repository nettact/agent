package collector

import (
	"context"
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
	ifaces []platform.IfaceInfo
	pinged string
	pings  int
	recv   func(seq int) bool
}

func (p *gwTestPlatform) Interfaces(platform.IfaceQuery) ([]platform.IfaceInfo, error) {
	return p.ifaces, nil
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

func gwTestIfaces() []platform.IfaceInfo {
	return []platform.IfaceInfo{
		{ID: "lo", Name: "lo", IsLoopback: true, Up: true, Gateways: []string{"127.0.0.1"}},
		{ID: "eth-id", Name: "eth0", Up: true, Gateways: []string{"192.168.1.1"}},
		{ID: "wifi-id", Name: "wlan0", Up: true, IsWireless: true, Gateways: []string{"10.0.0.1"}},
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
