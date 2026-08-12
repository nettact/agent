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
	if p.pingCount() >= p.cancelAfter {
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

// assertProbesEmitNothing drives a collector through a full async round trip and
// fails if either pass produced anything. Every probe now runs on its own
// goroutine, so the check has to cover both the pass that starts them and the
// pass that would have drained them.
func assertProbesEmitNothing(t *testing.T, ctx context.Context, c settledCollector) {
	t.Helper()
	started, err := c.Collect(ctx)
	if err != nil {
		t.Fatalf("Collect (start): %v", err)
	}
	assertNoSamples(t, started)
	c.WaitIdle()
	drained, err := c.Collect(ctx)
	if err != nil {
		t.Fatalf("Collect (drain): %v", err)
	}
	assertNoSamples(t, drained)
}

func cancelledCtx() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

func TestPublicPingCancelledRunEmitsNothing(t *testing.T) {
	stubCycleClock(t)
	p := &gwTestPlatform{}
	c := NewPublicPingCollector(p, netguard.New(probepolicy.Policy{}, true), nil, nil)
	c.SetTargets([]pcfg.ProbeTarget{
		{MonitorID: "m1", Kind: "icmp", Target: "1.1.1.1"},
		{MonitorID: "m2", Kind: "icmp", Target: "8.8.8.8"},
	})
	assertProbesEmitNothing(t, cancelledCtx(), c)
	if got := p.pingCount(); got != 0 {
		t.Fatalf("pings=%d want 0 under a cancelled run", got)
	}
}

func TestPublicPingMidCycleAbortEmitsNothing(t *testing.T) {
	// Cancel fires after the first echo lands: without the guard the cut cycle
	// would read as 2/3 lost (66%) and any target that never started as 100%
	// loss. Both targets' cycles run concurrently, so which one sent that echo is
	// not fixed — only the "no samples at all" outcome is.
	stubCycleClock(t)
	ctx, cancel := context.WithCancel(context.Background())
	p := &cancelPingPlatform{cancel: cancel, cancelAfter: 1}
	c := NewPublicPingCollector(p, netguard.New(probepolicy.Policy{}, true), nil, nil)
	c.SetTargets([]pcfg.ProbeTarget{
		{MonitorID: "m1", Kind: "icmp", Target: "1.1.1.1", Params: pcfg.ProbeParams{PacketCount: 3}},
		{MonitorID: "m2", Kind: "icmp", Target: "8.8.8.8", Params: pcfg.ProbeParams{PacketCount: 3}},
	})
	assertProbesEmitNothing(t, ctx, c)
}

func TestGatewayPingCancelledRunEmitsNothing(t *testing.T) {
	stubCycleClock(t)
	p := &gwTestPlatform{ifaces: gwTestIfaces()}
	c := NewGatewayPingCollector(p, netguard.New(probepolicy.Policy{}, true), nil)
	c.SetTargets([]pcfg.ProbeTarget{
		{MonitorID: "gw1", Kind: "gateway", Target: "gateway"},
	})
	assertProbesEmitNothing(t, cancelledCtx(), c)
	if got := p.pingCount(); got != 0 {
		t.Fatalf("pings=%d want 0 under a cancelled run", got)
	}
}

func TestGatewayPingMidCycleAbortEmitsNothing(t *testing.T) {
	// Every echo is lost AND the run is cancelled after the first: without the
	// guard this would emit loss=100 plus a gateway-unreachable event.
	stubCycleClock(t)
	ctx, cancel := context.WithCancel(context.Background())
	p := &cancelPingPlatform{
		gwTestPlatform: gwTestPlatform{ifaces: gwTestIfaces(), recv: func(int) bool { return false }},
		cancel:         cancel,
		cancelAfter:    1,
	}
	c := NewGatewayPingCollector(p, netguard.New(probepolicy.Policy{}, true), nil)
	c.SetTargets([]pcfg.ProbeTarget{
		{MonitorID: "gw1", Kind: "gateway", Target: "gateway", Params: pcfg.ProbeParams{Interface: "eth0", PacketCount: 3}},
	})
	assertProbesEmitNothing(t, ctx, c)
}

func TestDNSCancelledRunEmitsNothing(t *testing.T) {
	c := NewDNSCollector(netguard.New(probepolicy.Policy{}, true), nil, nil, nil)
	c.SetTargets([]pcfg.ProbeTarget{
		{MonitorID: "d1", Kind: "dns", Target: "example.com"},
	})
	assertProbesEmitNothing(t, cancelledCtx(), c)
}

func TestHTTPCancelledRunEmitsNothing(t *testing.T) {
	c := NewHTTPCollector(netguard.New(probepolicy.Policy{}, true), nil, true, nil)
	c.SetTargets([]pcfg.ProbeTarget{
		{MonitorID: "h1", Kind: "http", Target: "http://192.0.2.1/"},
	})
	assertProbesEmitNothing(t, cancelledCtx(), c)
}

func TestTCPCancelledRunEmitsNothing(t *testing.T) {
	c := NewTCPCollector(netguard.New(probepolicy.Policy{}, true), nil, nil)
	c.SetTargets([]pcfg.ProbeTarget{
		{MonitorID: "t1", Kind: "tcp", Target: "192.0.2.1", Params: pcfg.ProbeParams{Port: 443}},
	})
	assertProbesEmitNothing(t, cancelledCtx(), c)
}

func TestTCPProbeAbortedResultDropped(t *testing.T) {
	// Drive probe directly (bypassing runTarget's guards) so the in-probe guards
	// are exercised: a dial/resolution "failure" under a cancelled run must not
	// become a tcp.ok=0 sample. Both the literal-IP path (dial) and the hostname
	// path (resolution) are covered; neither touches the network under a
	// cancelled context.
	c := NewTCPCollector(netguard.New(probepolicy.Policy{}, true), nil, nil)
	ctx := cancelledCtx()
	var res Result
	c.probe(ctx, time.Now().UTC(), pcfg.ProbeTarget{
		MonitorID: "t1", Kind: "tcp", Target: "192.0.2.1", Params: pcfg.ProbeParams{Port: 443},
	}, time.Now().Add(time.Minute), &res)
	c.probe(ctx, time.Now().UTC(), pcfg.ProbeTarget{
		MonitorID: "t2", Kind: "tcp", Target: "tcp-cancel.example", Params: pcfg.ProbeParams{Port: 443},
	}, time.Now().Add(time.Minute), &res)
	assertNoSamples(t, res)
}

func TestNATCancelledRunEmitsNothing(t *testing.T) {
	c := NewNATCollector(netguard.New(probepolicy.Policy{}, true), nil, nil)
	c.SetTargets([]pcfg.ProbeTarget{
		{MonitorID: "n1", Kind: "nat", Target: "stun.example"},
	})
	assertProbesEmitNothing(t, cancelledCtx(), c)
}

func TestNATEmitBindingAbortedFailureDropped(t *testing.T) {
	c := NewNATCollector(netguard.New(probepolicy.Policy{}, true), nil, nil)
	target := pcfg.ProbeTarget{MonitorID: "n1", Kind: "nat", Target: "stun.example"}
	base := map[string]string{"transport": "udp", "server": "stun.example:3478"}

	// Cancelled run: the failed exchange is dropped, no nat.ok=0 and no event.
	var res Result
	var obs mappedObservation
	c.emitBinding(cancelledCtx(), time.Now().UTC(), target, &res, &obs, base, "", 0, errTimeout)
	assertNoSamples(t, res)

	// Live run: the same failure is still recorded (no behavior regression).
	var live Result
	c.emitBinding(context.Background(), time.Now().UTC(), target, &live, &obs, base, "", 0, errTimeout)
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
