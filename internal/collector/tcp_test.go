package collector

import (
	"context"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/nettact/agent/internal/netguard"
	"github.com/nettact/agent/probepolicy"
	pcfg "github.com/nettact/protocol/config"
	"github.com/nettact/protocol/telemetry"
)

// metricByKind returns the first metric of the given kind (nil when absent).
func metricByKind(res Result, kind telemetry.MetricKind) *telemetry.Metric {
	for i := range res.Metrics {
		if res.Metrics[i].Kind == kind {
			return &res.Metrics[i]
		}
	}
	return nil
}

func TestTCPProbeErrorClassDetail(t *testing.T) {
	// A live local listener, then the same port after close: success must emit
	// error_class None with NO detail label; the refused connect must carry the
	// raw dial error as the detail — on the error_class sample only, never on the
	// metrics aliasing the shared label map.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
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

	c := NewTCPCollector(netguard.New(probepolicy.Policy{}, true), nil)
	target := pcfg.ProbeTarget{MonitorID: "t1", Kind: "tcp", Target: "127.0.0.1",
		Params: pcfg.ProbeParams{Port: port, TimeoutMs: 3000}}

	var okRes Result
	c.probe(context.Background(), time.Now().UTC(), target, &okRes)
	ec := metricByKind(okRes, telemetry.TCPErrorClass)
	if ec == nil || ec.Value != float64(telemetry.ProbeReasonNone) {
		t.Fatalf("success error_class = %+v, want None", ec)
	}
	if _, has := ec.Labels[telemetry.ProbeReasonDetailLabel]; has {
		t.Fatalf("success error_class must not carry a detail label: %+v", ec.Labels)
	}

	ln.Close()
	var failRes Result
	c.probe(context.Background(), time.Now().UTC(), target, &failRes)
	ec = metricByKind(failRes, telemetry.TCPErrorClass)
	if ec == nil || ec.Value != float64(telemetry.ProbeReasonRefused) {
		t.Fatalf("refused error_class = %+v, want Refused", ec)
	}
	if ec.Labels[telemetry.ProbeReasonDetailLabel] == "" {
		t.Fatalf("refused error_class missing detail label: %+v", ec.Labels)
	}
	if ec.Labels["port"] != strconv.Itoa(port) {
		t.Fatalf("error_class labels lost the port: %+v", ec.Labels)
	}
	okm := metricByKind(failRes, telemetry.TCPOK)
	if okm == nil || okm.Value != 0 {
		t.Fatalf("tcp.ok = %+v, want 0", okm)
	}
	if _, has := okm.Labels[telemetry.ProbeReasonDetailLabel]; has {
		t.Fatalf("detail leaked onto the shared label map: %+v", okm.Labels)
	}
}
