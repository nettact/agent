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

	var res Result
	c.probe(context.Background(), target, time.Now().Add(time.Minute), &res)

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
	c.probe(context.Background(), target, time.Now().Add(time.Minute), &res2)
	ff2 := metricByKind(res2, telemetry.TCPFlowFanout)
	if ff2.Value != 1 || ff2.Labels[telemetry.FlowFanoutBadStableLabel] != "0" ||
		ff2.Labels[telemetry.FlowFanoutBadNewLabel] != "0" || ff2.Labels[telemetry.FlowFanoutOKLabel] != "3" {
		t.Fatalf("cycle 2 flow_fanout = %v (%+v), want 1 with 3 ok and no bad flows", ff2.Value, ff2.Labels)
	}
}
