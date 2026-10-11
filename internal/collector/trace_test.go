package collector

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/nettact/agent/internal/netguard"
	"github.com/nettact/agent/internal/traceroute"
	"github.com/nettact/agent/probepolicy"
	pcfg "github.com/nettact/protocol/config"
	"github.com/nettact/protocol/permission"
	"github.com/nettact/protocol/telemetry"
)

func TestTraceRequestDefaults(t *testing.T) {
	req := traceRequest(pcfg.ProbeTarget{MonitorID: "m1", Kind: "trace", Target: "192.0.2.1"}, "trace_x")
	want := traceroute.Request{
		ReportID: "trace_x", Mode: pcfg.TraceModeICMP, DestKey: "ip:192.0.2.1", DestHost: "192.0.2.1",
		SubjectKind: telemetry.TraceSubjectTarget, TriggerReason: telemetry.TraceTriggerScheduled,
		MaxHops: pcfg.DefaultTraceMaxHops, AttemptsPerHop: pcfg.DefaultTraceAttemptsPerHop,
		TotalTimeoutMs:      int(pcfg.DefaultTraceCycleDeadline / time.Millisecond),
		ResolveHopHostnames: true,
	}
	if req != want {
		t.Fatalf("request =\n%+v\nwant\n%+v", req, want)
	}
	if !req.FirstFailedAt.IsZero() || req.TriggerStreak != 0 || req.EgressProxyID != "" {
		t.Fatalf("scheduled request carries diagnosis fields: %+v", req)
	}

	// TCP without a port takes the default; an ICMP request never carries one.
	tcp := traceRequest(pcfg.ProbeTarget{Kind: "trace", Target: "Example.COM",
		Params: pcfg.ProbeParams{TraceMode: pcfg.TraceModeTCP}}, "r")
	if tcp.Mode != pcfg.TraceModeTCP || tcp.Port != pcfg.DefaultTraceTCPPort {
		t.Fatalf("tcp mode/port = %s/%d, want tcp/%d", tcp.Mode, tcp.Port, pcfg.DefaultTraceTCPPort)
	}
	if tcp.DestKey != "host:example.com" || tcp.DestHost != "example.com" {
		t.Fatalf("dest = %s %s, want the canonical host key", tcp.DestKey, tcp.DestHost)
	}
	icmp := traceRequest(pcfg.ProbeTarget{Kind: "trace", Target: "192.0.2.1", Params: pcfg.ProbeParams{Port: 80}}, "r")
	if icmp.Port != 0 {
		t.Fatalf("icmp request port = %d, want 0", icmp.Port)
	}
}

func TestTraceRequestExplicitParams(t *testing.T) {
	req := traceRequest(pcfg.ProbeTarget{Kind: "trace", Target: "192.0.2.1", Params: pcfg.ProbeParams{
		TraceMode: pcfg.TraceModeTCP, Port: 8443, MaxHops: 12, AttemptsPerHop: 2,
		TimeoutMs: 700, GlobalTimeoutMs: 45_000,
	}}, "r")
	if req.Port != 8443 || req.MaxHops != 12 || req.AttemptsPerHop != 2 ||
		req.PerHopTimeoutMs != 700 || req.TotalTimeoutMs != 45_000 {
		t.Fatalf("request = %+v, want the pushed params", req)
	}
	// An unknown mode is passed through for the engine to refuse, never
	// silently run as ICMP.
	odd := traceRequest(pcfg.ProbeTarget{Kind: "trace", Target: "192.0.2.1", Params: pcfg.ProbeParams{TraceMode: "udp"}}, "r")
	if odd.Mode != "udp" {
		t.Fatalf("unknown mode = %q, want it passed through", odd.Mode)
	}
}

// fakeTracer records requests and answers from a script.
type fakeTracer struct {
	mu   sync.Mutex
	reqs []traceroute.Request
	res  telemetry.TraceResult
	ok   bool
}

func (f *fakeTracer) run(_ context.Context, req traceroute.Request, _ time.Time) (telemetry.TraceResult, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reqs = append(f.reqs, req)
	r := f.res
	r.ReportID, r.Mode, r.DestKey, r.DestHost = req.ReportID, req.Mode, req.DestKey, req.DestHost
	r.TriggerReason, r.SubjectKind = req.TriggerReason, req.SubjectKind
	return r, f.ok
}

func runOnce(t *testing.T, c *TraceCollector) Result {
	t.Helper()
	if _, err := c.Collect(context.Background()); err != nil {
		t.Fatal(err)
	}
	c.WaitIdle()
	res, _ := c.Collect(context.Background())
	return res
}

func reachedResult() telemetry.TraceResult {
	return telemetry.TraceResult{
		Status: telemetry.TraceStatusSucceeded, DestinationIP: "192.0.2.1",
		Reached: true, ReachedTTL: 3, StartedAt: time.Now().UTC(),
		Hops: []telemetry.TraceHop{
			{TTL: 1, Attempts: []telemetry.TraceAttempt{{ResponderAddr: "10.0.0.1", RTTMs: 1}}},
			{TTL: 2, Attempts: []telemetry.TraceAttempt{{Timeout: true}}},
			{TTL: 3, Attempts: []telemetry.TraceAttempt{
				{ResponderAddr: "192.0.2.1", RTTMs: 10},
				{ResponderAddr: "192.0.2.1", RTTMs: 20},
				{Timeout: true},
			}},
		},
	}
}

func TestTraceCollectorStampsScheduledResult(t *testing.T) {
	f := &fakeTracer{res: reachedResult(), ok: true}
	c := newTraceCollector(f.run)
	c.SetTargets([]pcfg.ProbeTarget{
		{MonitorID: "m1", ConfigSerial: 7, Kind: "trace", Target: "192.0.2.1"},
		{MonitorID: "m2", Kind: "icmp", Target: "192.0.2.1"},                  // not ours
		{MonitorID: "m3", Kind: "trace", Target: "192.0.2.1", ProxyID: "prx"}, // pinned: never run
		{MonitorID: "m4", Kind: "trace", Target: ""},                          // no destination
	})
	res := runOnce(t, c)
	if len(f.reqs) != 1 {
		t.Fatalf("ran %d sweeps, want 1 (only the unpinned trace target)", len(f.reqs))
	}
	if len(res.TraceResults) != 1 {
		t.Fatalf("trace results = %d, want 1", len(res.TraceResults))
	}
	tr := res.TraceResults[0]
	if tr.MonitorID != "m1" || tr.ConfigSerial != 7 || tr.TriggerReason != telemetry.TraceTriggerScheduled ||
		tr.SubjectKind != telemetry.TraceSubjectTarget {
		t.Fatalf("result stamp = monitor %q serial %d trigger %q subject %q", tr.MonitorID, tr.ConfigSerial, tr.TriggerReason, tr.SubjectKind)
	}
	if len(tr.ReportID) < len("trace_")+1 || tr.ReportID[:6] != "trace_" {
		t.Fatalf("report id = %q, want a fresh trace_ id", tr.ReportID)
	}

	got := map[telemetry.MetricKind]telemetry.Metric{}
	for _, m := range res.Metrics {
		if m.MonitorID != "m1" || m.ConfigSerial != 7 {
			t.Fatalf("metric %s stamped %q/%d, want m1/7", m.Kind, m.MonitorID, m.ConfigSerial)
		}
		got[m.Kind] = m
	}
	if got[TraceReached].Value != 1 || got[TraceHopCount].Value != 3 || got[TraceDestRTT].Value != 15 {
		t.Fatalf("metrics = %+v, want reached=1 hops=3 rtt=15", got)
	}
	if len(got) != 3 {
		t.Fatalf("metric kinds = %d, want 3", len(got))
	}
}

func TestTraceMetricsUnreached(t *testing.T) {
	tr := telemetry.TraceResult{Status: telemetry.TraceStatusPartial, Hops: []telemetry.TraceHop{
		{TTL: 1, Attempts: []telemetry.TraceAttempt{{ResponderAddr: "10.0.0.1", RTTMs: 1}}},
		{TTL: 2, Attempts: []telemetry.TraceAttempt{{ResponderAddr: "10.0.1.1", RTTMs: 4}}},
		{TTL: 3, Attempts: []telemetry.TraceAttempt{{Timeout: true}}},
	}}
	ms := traceMetrics(pcfg.ProbeTarget{MonitorID: "m"}, tr)
	if len(ms) != 2 || ms[0].Kind != TraceReached || ms[0].Value != 0 || ms[1].Kind != TraceHopCount || ms[1].Value != 2 {
		t.Fatalf("unreached metrics = %+v, want reached=0 hop_count=2 and no rtt", ms)
	}
	// A refusal that measured nothing produces no samples at all.
	for _, tr := range []telemetry.TraceResult{
		{Status: telemetry.TraceStatusUnsupported, Reason: "raw_socket_unavailable"},
		{Status: telemetry.TraceStatusFailed, Reason: "probe_failed"},
		{Status: telemetry.TraceStatusCanceled, Reason: "canceled"},
	} {
		if ms := traceMetrics(pcfg.ProbeTarget{}, tr); len(ms) != 0 {
			t.Fatalf("%s/%s produced metrics %+v", tr.Status, tr.Reason, ms)
		}
	}
	// No route from this host is the path's own answer.
	if ms := traceMetrics(pcfg.ProbeTarget{}, telemetry.TraceResult{Status: telemetry.TraceStatusFailed, Reason: traceroute.ReasonLocalNoRoute}); len(ms) != 2 {
		t.Fatalf("local_no_route metrics = %+v, want reached=0 and hop_count", ms)
	}
}

// A sweep the engine refused for a missing mode is reported, but carries no
// samples that would chart as an outage.
func TestTraceCollectorReportsUnsupportedWithoutMetrics(t *testing.T) {
	f := &fakeTracer{res: telemetry.TraceResult{Status: telemetry.TraceStatusUnsupported, Reason: "raw_socket_unavailable"}, ok: true}
	c := newTraceCollector(f.run)
	c.SetTargets([]pcfg.ProbeTarget{{MonitorID: "m1", Kind: "trace", Target: "192.0.2.1"}})
	res := runOnce(t, c)
	if len(res.TraceResults) != 1 || len(res.Metrics) != 0 {
		t.Fatalf("results=%d metrics=%d, want 1 report and no metrics", len(res.TraceResults), len(res.Metrics))
	}
}

func TestTraceCollectorPolicyDenialIsABlock(t *testing.T) {
	f := &fakeTracer{res: telemetry.TraceResult{Status: telemetry.TraceStatusFailed, Reason: traceroute.ReasonPolicyDenied}, ok: true}
	c := newTraceCollector(f.run)
	c.SetTargets([]pcfg.ProbeTarget{{MonitorID: "m1", ConfigSerial: 2, Kind: "trace", Target: "denied.example"}})
	res := runOnce(t, c)
	if len(res.TraceResults) != 0 || len(res.Metrics) != 0 {
		t.Fatalf("a policy-refused sweep was reported as a route sample: %+v", res)
	}
	if len(res.Blocked) != 1 || res.Blocked[0].MonitorID != "m1" || res.Blocked[0].ConfigSerial != 2 ||
		res.Blocked[0].Reason != "resolved_denied" {
		t.Fatalf("blocked = %+v, want one resolved_denied block for m1/2", res.Blocked)
	}
}

// A sweep that found the trace budget busy reports nothing and is retried
// soon, not a whole interval later; it also keeps its first-run status.
func TestTraceCollectorDefersWhenBudgetBusy(t *testing.T) {
	f := &fakeTracer{ok: false}
	c := newTraceCollector(f.run)
	tg := pcfg.ProbeTarget{MonitorID: "m1", Kind: "trace", Target: "192.0.2.1"}
	c.SetTargets([]pcfg.ProbeTarget{tg})
	before := time.Now()
	res := runOnce(t, c)
	if !resultEmpty(res) {
		t.Fatalf("a deferred sweep produced %+v", res)
	}
	k := schedKey(tg)
	c.runner.sched.mu.Lock()
	next := c.runner.sched.nextDue[k]
	first := !c.runner.sched.reported[k]
	c.runner.sched.mu.Unlock()
	if next.Before(before.Add(traceBusyRetry)) || next.After(time.Now().Add(traceBusyRetry)) {
		t.Fatalf("next due in %v, want about %v", next.Sub(before), traceBusyRetry)
	}
	if !first {
		t.Fatal("a deferred sweep spent the target's first-run status")
	}
}

// The interval is the target's own (default 10m), floored at the route-monitor
// minimum whatever the agent-local floor or the push says.
func TestTraceCollectorIntervalFloor(t *testing.T) {
	c := newTraceCollector((&fakeTracer{ok: true}).run)
	c.SetMinInterval(10 * time.Second) // the agent-wide probe floor is far lower
	c.SetTargets([]pcfg.ProbeTarget{
		{MonitorID: "fast", Kind: "trace", Target: "192.0.2.1", Params: pcfg.ProbeParams{IntervalSeconds: 60}},
		{MonitorID: "dflt", Kind: "trace", Target: "192.0.2.2"},
		{MonitorID: "slow", Kind: "trace", Target: "192.0.2.3", Params: pcfg.ProbeParams{IntervalSeconds: 1800}},
	})
	now := time.Now()
	got := map[string]time.Duration{}
	for _, sp := range c.runner.sched.claim(now) {
		got[sp.Target.MonitorID] = sp.NextDue.Sub(now)
	}
	want := map[string]time.Duration{"fast": pcfg.MinTraceInterval, "dflt": pcfg.DefaultTraceInterval, "slow": 30 * time.Minute}
	for id, w := range want {
		if got[id] != w {
			t.Fatalf("%s interval = %v, want %v", id, got[id], w)
		}
	}
	// A raised agent floor still applies above the route minimum.
	c.SetMinInterval(20 * time.Minute)
	c.runner.sched.mu.Lock()
	floor := c.runner.sched.minInterval
	c.runner.sched.mu.Unlock()
	if floor != 20*time.Minute {
		t.Fatalf("floor = %v, want the higher agent floor", floor)
	}
}

func TestScheduledTraceViews(t *testing.T) {
	icmpOnly := permission.NewSet(permission.DiagnosticTracerouteICMP, permission.ProbeTraceroute)
	eff, gr, _ := scheduledTraceViews(permission.NewSet(permission.ProbeTraceroute), icmpOnly)
	if !eff.Has(permission.DiagnosticTracerouteICMP) || eff.Has(permission.DiagnosticTracerouteTCP) {
		t.Fatalf("effective = %v, want ICMP only", eff.Sorted())
	}
	if !gr.Has(permission.DiagnosticTracerouteTCP) {
		t.Fatal("probe.traceroute must authorize both modes, so a TCP gap reads as capability, not policy")
	}
	// The diagnostic grant alone does not authorize a standing sweep.
	both := permission.NewSet(permission.DiagnosticTracerouteICMP, permission.DiagnosticTracerouteTCP)
	if eff, _, _ := scheduledTraceViews(both, both); len(eff) != 0 {
		t.Fatalf("effective without probe.traceroute = %v, want empty", eff.Sorted())
	}
}

// End to end through the real engine: a TCP route monitor on a machine that
// can only trace ICMP is answered unsupported, never silently run as ICMP.
func TestTraceCollectorTCPWithoutCapabilityIsUnsupported(t *testing.T) {
	guard := netguard.New(probepolicy.Policy{}, true)
	c := NewTraceCollector(guard, permission.NewSet(permission.ProbeTraceroute),
		permission.NewSet(permission.ProbeTraceroute, permission.DiagnosticTracerouteICMP), traceroute.NewLimiter(0))
	tr, ok := c.run(context.Background(), traceRequest(pcfg.ProbeTarget{Kind: "trace", Target: "192.0.2.1",
		Params: pcfg.ProbeParams{TraceMode: pcfg.TraceModeTCP}}, "r"), time.Now())
	if !ok || tr.Status != telemetry.TraceStatusUnsupported || tr.Mode != pcfg.TraceModeTCP {
		t.Fatalf("tcp on icmp-only = ok %v %s/%s mode %s, want unsupported in tcp mode", ok, tr.Status, tr.Reason, tr.Mode)
	}
	if tr.TriggerReason != telemetry.TraceTriggerScheduled || tr.PathScope != telemetry.TracePathDirect {
		t.Fatalf("trigger/scope = %q/%q", tr.TriggerReason, tr.PathScope)
	}
}
