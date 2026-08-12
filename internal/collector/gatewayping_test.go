package collector

import (
	"context"
	"errors"
	"fmt"
	"sync"
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
//
// clk+rtt make an echo cost time on the synthetic clock, the way a real link
// does. Left unset, echoes are instantaneous — fine for tests about counts and
// classification, useless for tests about pacing under a real round trip. An rtt
// at or beyond the per-echo timeout is reported as a timeout, as a real pinger
// would.
//
// The counters are mutex-guarded because cycles now run on their own goroutines
// (see probeRunner), so several targets can be pinging this fake at once.
type gwTestPlatform struct {
	ifaces   []platform.IfaceInfo
	ifaceErr error
	recv     func(seq int) bool
	clk      *fakeCycleClock
	rtt      time.Duration

	mu     sync.Mutex
	pinged string
	pings  int
	sizes  []int // payload size of each echo, in send order
}

func (p *gwTestPlatform) Interfaces(platform.IfaceQuery) ([]platform.IfaceInfo, error) {
	return p.ifaces, p.ifaceErr
}
func (p *gwTestPlatform) Ping(_ context.Context, target string, opts platform.PingOptions) (platform.PingResult, error) {
	p.mu.Lock()
	seq := p.pings
	p.pings++
	p.pinged = target
	p.sizes = append(p.sizes, opts.PayloadSize)
	p.mu.Unlock()

	rtt := 3 * time.Millisecond
	if p.clk != nil && p.rtt > 0 {
		rtt = p.rtt
		if rtt >= opts.Timeout {
			// The echo outlives its budget: the pinger waits out the timeout and
			// reports nothing back.
			p.clk.spend(opts.Timeout)
			return platform.PingResult{Target: target, Reason: telemetry.ProbeReasonTimeout}, nil
		}
		p.clk.spend(rtt)
	}
	received := p.recv == nil || p.recv(seq)
	return platform.PingResult{Target: target, RTT: rtt, Received: received}, nil
}
func (p *gwTestPlatform) Neighbors() ([]platform.Neighbor, error) { return nil, nil }
func (p *gwTestPlatform) WiFi(includeSSID bool) platform.WiFiResult {
	return platform.WiFiResult{State: "ok"}
}
func (p *gwTestPlatform) Supports() permission.Set { return nil }

// pingCount is how many echoes this fake has been asked for.
func (p *gwTestPlatform) pingCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.pings
}

// lastPinged is the destination of the most recent echo ("" if never pinged).
func (p *gwTestPlatform) lastPinged() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.pinged
}

// payloadSizes is the payload size of each echo in send order.
func (p *gwTestPlatform) payloadSizes() []int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]int(nil), p.sizes...)
}

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
	stubCycleClock(t)
	p := &gwTestPlatform{ifaces: gwTestIfaces()}
	c := NewGatewayPingCollector(p, netguard.New(probepolicy.Policy{}, true), nil)
	c.SetTargets([]pcfg.ProbeTarget{
		{MonitorID: "gw1", Kind: "gateway", Target: "gateway", Params: pcfg.ProbeParams{Interface: "wlan0"}},
	})
	res := collectSettled(t, context.Background(), c)
	// wlan0's gateway is 10.0.0.1 — selection must not fall through to eth0.
	if got := p.lastPinged(); got != "10.0.0.1" {
		t.Fatalf("pinged=%q want 10.0.0.1", got)
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
			stubCycleClock(t)
			p := &gwTestPlatform{ifaces: gwTestIfaces(), ifaceErr: tc.err}
			c := NewGatewayPingCollector(p, netguard.New(probepolicy.Policy{}, true), nil)
			c.SetTargets([]pcfg.ProbeTarget{{MonitorID: "gw1", Kind: "gateway", Target: "gateway"}})
			res := collectSettled(t, context.Background(), c)
			if len(res.Metrics) != 0 || len(res.Events) != 0 {
				t.Fatalf("unreadable routes fabricated telemetry: metrics=%+v events=%+v", res.Metrics, res.Events)
			}
			if got := p.pingCount(); got != 0 {
				t.Fatalf("pinged %d times with no known gateway", got)
			}
		})
	}
}

// A readable table that genuinely holds no default route IS a LAN-layer fault,
// and must still be reported as one.
func TestGatewayCollectorReportsGenuinelyMissingGateway(t *testing.T) {
	stubCycleClock(t)
	p := &gwTestPlatform{ifaces: []platform.IfaceInfo{{ID: "eth-id", Name: "eth0", Up: true}}}
	c := NewGatewayPingCollector(p, netguard.New(probepolicy.Policy{}, true), nil)
	c.SetTargets([]pcfg.ProbeTarget{{MonitorID: "gw1", Kind: "gateway", Target: "gateway"}})
	res := collectSettled(t, context.Background(), c)
	if got := lossPct(res); got != 100 {
		t.Fatalf("loss=%v want 100 (no gateway on a readable table)", got)
	}
	if len(res.Events) != 1 || res.Events[0].Type != telemetry.EventGatewayUnreachable {
		t.Fatalf("events=%+v want one gateway.unreachable", res.Events)
	}
}

func TestGatewayCollectorDefaultInterface(t *testing.T) {
	stubCycleClock(t)
	p := &gwTestPlatform{ifaces: gwTestIfaces()}
	c := NewGatewayPingCollector(p, netguard.New(probepolicy.Policy{}, true), nil)
	c.SetTargets([]pcfg.ProbeTarget{
		{MonitorID: "gw1", Kind: "gateway", Target: "gateway"},
	})
	collectSettled(t, context.Background(), c)
	// Empty interface = default: first up, non-loopback IPv4 gateway (eth0).
	if got := p.lastPinged(); got != "192.168.1.1" {
		t.Fatalf("pinged=%q want 192.168.1.1 (default NIC)", got)
	}
}

func TestGatewayCollectorUnknownInterface(t *testing.T) {
	stubCycleClock(t)
	p := &gwTestPlatform{ifaces: gwTestIfaces()}
	c := NewGatewayPingCollector(p, netguard.New(probepolicy.Policy{}, true), nil)
	c.SetTargets([]pcfg.ProbeTarget{
		{MonitorID: "gw1", Kind: "gateway", Target: "gateway", Params: pcfg.ProbeParams{Interface: "does-not-exist"}},
	})
	res := collectSettled(t, context.Background(), c)
	if got := p.lastPinged(); got != "" {
		t.Fatalf("pinged=%q want no ping (interface not found)", got)
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
	stubCycleClock(t)
	p := &gwTestPlatform{ifaces: gwTestIfaces()}
	c := NewGatewayPingCollector(p, netguard.New(probepolicy.Policy{}, true), nil)
	c.SetTargets([]pcfg.ProbeTarget{
		{MonitorID: "gw1", Kind: "gateway", Target: "gateway", Params: pcfg.ProbeParams{Interface: "eth0"}},
	})
	res := collectSettled(t, context.Background(), c)
	if got := p.pingCount(); got != 5 {
		t.Fatalf("pings=%d want 5 (default burst)", got)
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
	stubCycleClock(t)
	p := &gwTestPlatform{ifaces: gwTestIfaces(), recv: func(seq int) bool { return seq%2 == 0 }}
	c := NewGatewayPingCollector(p, netguard.New(probepolicy.Policy{}, true), nil)
	c.SetTargets([]pcfg.ProbeTarget{
		{MonitorID: "gw1", Kind: "gateway", Target: "gateway", Params: pcfg.ProbeParams{Interface: "eth0", PacketCount: 4}},
	})
	res := collectSettled(t, context.Background(), c)
	if got := p.pingCount(); got != 4 {
		t.Fatalf("pings=%d want 4 (packet_count honored)", got)
	}
	if got := lossPct(res); got != 50 {
		t.Fatalf("loss=%v want 50", got)
	}
}

func TestGatewayCollectorIgnoresNonGatewayKinds(t *testing.T) {
	stubCycleClock(t)
	p := &gwTestPlatform{ifaces: gwTestIfaces()}
	c := NewGatewayPingCollector(p, netguard.New(probepolicy.Policy{}, true), nil)
	c.SetTargets([]pcfg.ProbeTarget{
		{MonitorID: "p1", Kind: "icmp", Target: "1.1.1.1"},
	})
	res := collectSettled(t, context.Background(), c)
	if len(res.Metrics) != 0 || p.lastPinged() != "" {
		t.Fatalf("collected non-gateway target: metrics=%+v pinged=%q", res.Metrics, p.lastPinged())
	}
}
