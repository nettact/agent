package collector

import (
	"context"
	"net"
	"strconv"
	"testing"
	"time"

	pcfg "github.com/nettact/protocol/config"
	"github.com/nettact/protocol/telemetry"
)

// TestClassifyFlowFanout exercises the pure fan-out classifier. Codes:
// 4 insufficient (fewer than two flows ran), 3 all flows failed (stable), 2 a
// deterministic bad subset (the member fault the fan-out exists to find), 1
// uniform (no stable bad subset).
func TestClassifyFlowFanout(t *testing.T) {
	cases := []struct {
		name                    string
		flows, badStable, badNew int
		want                    int
	}{
		{"no flow ran", 0, 0, 0, 4},
		{"one flow ran", 1, 0, 0, 4},
		{"every flow failed and stable", 3, 3, 0, 3},
		{"one stable bad member", 4, 1, 0, 2},
		{"stable member plus flapping", 4, 1, 1, 2},
		{"all flows clean", 3, 0, 0, 1},
		{"bad subset but flapping", 4, 0, 2, 1},
		{"every flow failed but flapping", 3, 0, 3, 1},
		{"some clean, some new", 3, 0, 1, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyFlowFanout(tc.flows, tc.badStable, tc.badNew); got != tc.want {
				t.Fatalf("classifyFlowFanout(%d, %d, %d) = %d, want %d",
					tc.flows, tc.badStable, tc.badNew, got, tc.want)
			}
		})
	}
}

// TestFlowPortsPinsDerivedSet pins flowPorts' whole contract against concrete
// derived values: deterministic in the target/monitor/serial, a consecutive
// base..base+n-1 window inside the source-port range, and re-derived when the
// config serial or the monitor changes (so a material config edit starts a fresh,
// unrelated port set and never folds into the old one's history).
func TestFlowPortsPinsDerivedSet(t *testing.T) {
	got := flowPorts("1.1.1.1", 443, "m1", 5, 4)
	want := []int{26875, 26876, 26877, 26878}
	if len(got) != len(want) {
		t.Fatalf("flowPorts returned %d ports, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("flowPorts = %v, want %v", got, want)
		}
	}
	if got[0] < 10000 || got[len(got)-1] > 65535 {
		t.Fatalf("flowPorts out of the source-port range: %v", got)
	}
	// Determinism: the same inputs yield the same set every call.
	again := flowPorts("1.1.1.1", 443, "m1", 5, 4)
	for i := range again {
		if again[i] != got[i] {
			t.Fatalf("flowPorts not deterministic: %v vs %v", got, again)
		}
	}
	// A config-serial edit re-derives an unrelated base.
	if b := flowPorts("1.1.1.1", 443, "m1", 6, 4); b[0] == got[0] {
		t.Fatalf("flowPorts ignored the config serial: %v vs %v", got, b)
	}
	// A different monitor on the same target gets its own set.
	if d := flowPorts("1.1.1.1", 443, "m2", 5, 4); d[0] == got[0] {
		t.Fatalf("flowPorts ignored the monitor id: %v vs %v", got, d)
	}
}

// TestFlowOutcomeFoldsHistory drives flowOutcome across consecutive cycles and
// pins the history folding: a failing flow is bad_new on first sight, becomes
// bad_stable when the SAME flow fails again, and the ok count rises for flows
// that are clean now (a flow that did not run this cycle carries no verdict, and
// a clean flow that was not measured last cycle reads as clean). A config-serial
// change resets the history outright.
func TestFlowOutcomeFoldsHistory(t *testing.T) {
	c := NewTCPCollector(testGuard(), nil, nil)
	attempted := []bool{true, true, true, true}
	bad1 := []bool{false, false, true, false}

	// Cycle 1: one new bad flow among clean ones — uniform, not yet a verdict.
	code, flows, badStable, badNew, ok := c.flowOutcome("m1", 5, attempted, bad1)
	if code != 1 || flows != 4 || badStable != 0 || badNew != 1 || ok != 3 {
		t.Fatalf("cycle 1 = code %d flows %d badStable %d badNew %d ok %d; want 1/4/0/1/3",
			code, flows, badStable, badNew, ok)
	}
	// Cycle 2: the SAME flow fails again — now a stable bad member (the member
	// fault the fan-out exists to find).
	code, flows, badStable, badNew, ok = c.flowOutcome("m1", 5, attempted, bad1)
	if code != 2 || flows != 4 || badStable != 1 || badNew != 0 || ok != 3 {
		t.Fatalf("cycle 2 (same bad flow) = code %d flows %d badStable %d badNew %d ok %d; want 2/4/1/0/3",
			code, flows, badStable, badNew, ok)
	}
	// Cycle 3: the member recovered. It is no longer a bad flow, but recovery is
	// not ok yet either — the ok count needs a second clean read.
	clean := []bool{false, false, false, false}
	code, flows, badStable, badNew, ok = c.flowOutcome("m1", 5, attempted, clean)
	if code != 1 || flows != 4 || badStable != 0 || badNew != 0 || ok != 3 {
		t.Fatalf("cycle 3 (recovery) = code %d flows %d badStable %d badNew %d ok %d; want 1/4/0/0/3",
			code, flows, badStable, badNew, ok)
	}
	// Cycle 4: flows 0 and 3 skip the round — a flow that did not run carries no
	// verdict and is absent from every count. The two that ran stay clean.
	partial := []bool{false, true, true, false}
	code, flows, badStable, badNew, ok = c.flowOutcome("m1", 5, partial, clean)
	if code != 1 || flows != 2 || badStable != 0 || badNew != 0 || ok != 2 {
		t.Fatalf("partial cycle = code %d flows %d badStable %d badNew %d ok %d; want 1/2/0/0/2",
			code, flows, badStable, badNew, ok)
	}
	// A config-serial edit discards the old history: the flow that was stable for
	// two cycles is new again under the new serial.
	code, flows, badStable, badNew, ok = c.flowOutcome("m1", 6, attempted, bad1)
	if code != 1 || flows != 4 || badStable != 0 || badNew != 1 || ok != 3 {
		t.Fatalf("post-serial-change = code %d flows %d badStable %d badNew %d ok %d; want 1/4/0/1/3",
			code, flows, badStable, badNew, ok)
	}
}

// TestTCPFanOutAllFlowsSucceed runs a real 3-flow fan-out against a live local
// listener and pins the aggregate semantics: ok=1 only when every flow succeeded,
// connect_ms as the mean over successful flows, error_class None, and a flow
// fan-out classification of uniform-all-clean with all three flows ok. A second
// cycle must read the first as clean history (no bad_stable).
func TestTCPFanOutAllFlowsSucceed(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	go func() {
		for {
			conn, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			conn.Close()
		}
	}()

	c := NewTCPCollector(testGuard(), nil, nil)
	target := pcfg.ProbeTarget{MonitorID: "t1", Kind: "tcp", Target: "127.0.0.1",
		Params: pcfg.ProbeParams{Port: port, FlowFanout: 3, TimeoutMs: 3000}}

	now := time.Now().UTC()
	var res Result
	c.probe(context.Background(), now, target, time.Now().Add(time.Minute), &res)

	ok := metricByKind(res, telemetry.TCPOK)
	if ok == nil || ok.Value != 1 {
		t.Fatalf("tcp.ok = %+v, want 1 (every flow succeeded)", ok)
	}
	ff := metricByKind(res, telemetry.TCPFlowFanout)
	if ff == nil {
		t.Fatal("no probe.tcp.flow_fanout sample for a fan-out target")
	}
	if ff.Value != 1 {
		t.Fatalf("flow_fanout = %v, want 1 (uniform, all clean)", ff.Value)
	}
	for label, want := range map[string]string{
		telemetry.FlowFanoutFlowsLabel:     "3",
		telemetry.FlowFanoutBadStableLabel: "0",
		telemetry.FlowFanoutBadNewLabel:    "0",
		telemetry.FlowFanoutOKLabel:        "3",
		"port":                             strconv.Itoa(port),
	} {
		if ff.Labels[label] != want {
			t.Fatalf("flow_fanout label %s = %q, want %q (%+v)", label, ff.Labels[label], want, ff.Labels)
		}
	}
	cm := metricByKind(res, telemetry.TCPConnectMs)
	if cm == nil || cm.Value < 0 {
		t.Fatalf("connect_ms = %+v, want a non-negative mean over successful flows", cm)
	}
	ec := metricByKind(res, telemetry.TCPErrorClass)
	if ec == nil || ec.Value != float64(telemetry.ProbeReasonNone) {
		t.Fatalf("error_class = %+v, want None", ec)
	}
	// No TLS configured: the TLS segment must be absent, not a zero sample.
	if m := metricByKind(res, telemetry.TCPTLSms); m != nil {
		t.Fatalf("tls_ms = %+v, want absent (TLS off)", m)
	}

	// Cycle 2 under the same config: the first cycle's history is all-clean, so
	// the verdict and counts repeat.
	var res2 Result
	c.probe(context.Background(), time.Now().UTC(), target, time.Now().Add(time.Minute), &res2)
	ff2 := metricByKind(res2, telemetry.TCPFlowFanout)
	if ff2.Value != 1 || ff2.Labels[telemetry.FlowFanoutBadStableLabel] != "0" ||
		ff2.Labels[telemetry.FlowFanoutBadNewLabel] != "0" || ff2.Labels[telemetry.FlowFanoutOKLabel] != "3" {
		t.Fatalf("cycle 2 flow_fanout = %v (%+v), want 1 with 3 ok and no bad flows", ff2.Value, ff2.Labels)
	}
}
