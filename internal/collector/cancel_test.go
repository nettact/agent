package collector

import (
	"context"
	"testing"
	"time"

	"github.com/nettact/agent/internal/netguard"
	"github.com/nettact/agent/internal/platform"
	"github.com/nettact/agent/probepolicy"
	pcfg "github.com/nettact/protocol/config"
	"github.com/nettact/protocol/telemetry"
)

// These tests pin the shutdown contract: a probe pass aborted by run
// cancellation must not fabricate failure samples/events. Such samples would be
// appended to the WAL after the session closed and replayed on the next start,
// raising a false outage alert for every in-flight target (the desktop
// restart-storm bug).

// cancelPingPlatform answers echoes like gwTestPlatform but cancels the run
// context once cancelAfter echoes have been sent — simulating shutdown landing
// in the middle of a ping cycle.
type cancelPingPlatform struct {
	gwTestPlatform
	cancel      context.CancelFunc
	cancelAfter int
}

func (p *cancelPingPlatform) Ping(ctx context.Context, target string, opts platform.PingOptions) (platform.PingResult, error) {
	r, err := p.gwTestPlatform.Ping(ctx, target, opts)
	if p.pings >= p.cancelAfter {
		p.cancel()
	}
	return r, err
}

// assertNoSamples fails when a cancelled pass produced any metric or event.
func assertNoSamples(t *testing.T, res Result) {
	t.Helper()
	if len(res.Metrics) != 0 || len(res.Events) != 0 || len(res.Blocked) != 0 {
		t.Fatalf("cancelled pass emitted data: metrics=%+v events=%+v blocked=%+v",
			res.Metrics, res.Events, res.Blocked)
	}
}

func cancelledCtx() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

func TestPublicPingCancelledRunEmitsNothing(t *testing.T) {
	p := &gwTestPlatform{}
	c := NewPublicPingCollector(p, netguard.New(probepolicy.Policy{}, true))
	c.SetTargets([]pcfg.ProbeTarget{
		{MonitorID: "m1", Kind: "icmp", Target: "1.1.1.1"},
		{MonitorID: "m2", Kind: "icmp", Target: "8.8.8.8"},
	})
	res, err := c.Collect(cancelledCtx())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	assertNoSamples(t, res)
	if p.pings != 0 {
		t.Fatalf("pings=%d want 0 under a cancelled run", p.pings)
	}
}

func TestPublicPingMidCycleAbortEmitsNothing(t *testing.T) {
	// Cancel fires after the first echo of the first target: without the guard the
	// cut cycle would read as 2/3 lost (66%) and the second target as 100% loss.
	ctx, cancel := context.WithCancel(context.Background())
	p := &cancelPingPlatform{cancel: cancel, cancelAfter: 1}
	c := NewPublicPingCollector(p, netguard.New(probepolicy.Policy{}, true))
	c.SetTargets([]pcfg.ProbeTarget{
		{MonitorID: "m1", Kind: "icmp", Target: "1.1.1.1", Params: pcfg.ProbeParams{PacketCount: 3}},
		{MonitorID: "m2", Kind: "icmp", Target: "8.8.8.8", Params: pcfg.ProbeParams{PacketCount: 3}},
	})
	res, err := c.Collect(ctx)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	assertNoSamples(t, res)
}

func TestGatewayPingCancelledRunEmitsNothing(t *testing.T) {
	p := &gwTestPlatform{ifaces: gwTestIfaces()}
	c := NewGatewayPingCollector(p, netguard.New(probepolicy.Policy{}, true))
	c.SetTargets([]pcfg.ProbeTarget{
		{MonitorID: "gw1", Kind: "gateway", Target: "gateway"},
	})
	res, err := c.Collect(cancelledCtx())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	assertNoSamples(t, res)
	if p.pings != 0 {
		t.Fatalf("pings=%d want 0 under a cancelled run", p.pings)
	}
}

func TestGatewayPingMidCycleAbortEmitsNothing(t *testing.T) {
	// Every echo is lost AND the run is cancelled after the first: without the
	// guard this would emit loss=100 plus a gateway-unreachable event.
	ctx, cancel := context.WithCancel(context.Background())
	p := &cancelPingPlatform{
		gwTestPlatform: gwTestPlatform{ifaces: gwTestIfaces(), recv: func(int) bool { return false }},
		cancel:         cancel,
		cancelAfter:    1,
	}
	c := NewGatewayPingCollector(p, netguard.New(probepolicy.Policy{}, true))
	c.SetTargets([]pcfg.ProbeTarget{
		{MonitorID: "gw1", Kind: "gateway", Target: "gateway", Params: pcfg.ProbeParams{Interface: "eth0", PacketCount: 3}},
	})
	res, err := c.Collect(ctx)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	assertNoSamples(t, res)
}

func TestDNSCancelledRunEmitsNothing(t *testing.T) {
	c := NewDNSCollector(netguard.New(probepolicy.Policy{}, true))
	c.SetTargets([]pcfg.ProbeTarget{
		{MonitorID: "d1", Kind: "dns", Target: "example.com"},
	})
	res, err := c.Collect(cancelledCtx())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	assertNoSamples(t, res)
}

func TestHTTPCancelledRunEmitsNothing(t *testing.T) {
	c := NewHTTPCollector(netguard.New(probepolicy.Policy{}, true), true)
	c.SetTargets([]pcfg.ProbeTarget{
		{MonitorID: "h1", Kind: "http", Target: "http://192.0.2.1/"},
	})
	res, err := c.Collect(cancelledCtx())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	assertNoSamples(t, res)
}

func TestTCPCancelledRunEmitsNothing(t *testing.T) {
	c := NewTCPCollector(netguard.New(probepolicy.Policy{}, true))
	c.SetTargets([]pcfg.ProbeTarget{
		{MonitorID: "t1", Kind: "tcp", Target: "192.0.2.1", Params: pcfg.ProbeParams{Port: 443}},
	})
	res, err := c.Collect(cancelledCtx())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	assertNoSamples(t, res)
}

func TestTCPProbeAbortedResultDropped(t *testing.T) {
	// Drive probe directly (bypassing Collect's pass guard) so the in-probe
	// guards are exercised: a dial/resolution "failure" under a cancelled run
	// must not become a tcp.ok=0 sample. Both the literal-IP path (dial) and the
	// hostname path (resolution) are covered; neither touches the network under a
	// cancelled context.
	c := NewTCPCollector(netguard.New(probepolicy.Policy{}, true))
	ctx := cancelledCtx()
	var res Result
	c.probe(ctx, time.Now().UTC(), pcfg.ProbeTarget{
		MonitorID: "t1", Kind: "tcp", Target: "192.0.2.1", Params: pcfg.ProbeParams{Port: 443},
	}, &res)
	c.probe(ctx, time.Now().UTC(), pcfg.ProbeTarget{
		MonitorID: "t2", Kind: "tcp", Target: "tcp-cancel.example", Params: pcfg.ProbeParams{Port: 443},
	}, &res)
	assertNoSamples(t, res)
}

func TestNATCancelledRunEmitsNothing(t *testing.T) {
	c := NewNATCollector(netguard.New(probepolicy.Policy{}, true))
	c.SetTargets([]pcfg.ProbeTarget{
		{MonitorID: "n1", Kind: "nat", Target: "stun.example"},
	})
	res, err := c.Collect(cancelledCtx())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	assertNoSamples(t, res)
}

func TestNATEmitBindingAbortedFailureDropped(t *testing.T) {
	c := NewNATCollector(netguard.New(probepolicy.Policy{}, true))
	target := pcfg.ProbeTarget{MonitorID: "n1", Kind: "nat", Target: "stun.example"}
	base := map[string]string{"transport": "udp", "server": "stun.example:3478"}

	// Cancelled run: the failed exchange is dropped, no nat.ok=0 and no event.
	var res Result
	c.emitBinding(cancelledCtx(), time.Now().UTC(), target, &res, base, "", 0, errTimeout)
	assertNoSamples(t, res)

	// Live run: the same failure is still recorded (no behavior regression).
	var live Result
	c.emitBinding(context.Background(), time.Now().UTC(), target, &live, base, "", 0, errTimeout)
	foundOK := false
	for _, m := range live.Metrics {
		if m.Kind == telemetry.NATOK && m.Value == 0 {
			foundOK = true
		}
	}
	if !foundOK || len(live.Events) != 1 {
		t.Fatalf("live failure not recorded: metrics=%+v events=%+v", live.Metrics, live.Events)
	}
}
