package collector

import (
	"context"
	"crypto/tls"
	"net"
	"strconv"
	"time"

	"github.com/nettact/protocol/capability"
	pcfg "github.com/nettact/protocol/config"
	"github.com/nettact/protocol/telemetry"
)

// TCPCollector performs a TCP connect (optionally followed by a TLS handshake)
// against a server-configured host:port set (a TCP port monitor).
// Each target carries its own per-protocol params (port, tls, timeout, interval)
// and is probed on its own schedule via schedState.
type TCPCollector struct {
	sched *schedState
}

func NewTCPCollector() *TCPCollector {
	return &TCPCollector{sched: newSchedState(30 * time.Second)}
}

func (c *TCPCollector) SetTargets(targets []pcfg.ProbeTarget) {
	var tcp []pcfg.ProbeTarget
	for _, t := range targets {
		if t.Kind == "tcp" && t.Target != "" && t.Params.Port > 0 {
			tcp = append(tcp, t)
		}
	}
	c.sched.set(tcp)
}

func (c *TCPCollector) Name() string { return "tcp" }

func (c *TCPCollector) Capabilities() []capability.Capability {
	return []capability.Capability{capability.ProbeTCP}
}

func (c *TCPCollector) Tier() Tier { return TierRegular }

func (c *TCPCollector) Collect(ctx context.Context) (Result, error) {
	targets := c.sched.due(time.Now())
	if len(targets) == 0 {
		return Result{}, nil
	}

	now := time.Now().UTC()
	var res Result
	for _, t := range targets {
		timeout := time.Duration(t.Params.TimeoutMs) * time.Millisecond
		if timeout <= 0 {
			timeout = 5 * time.Second
		}
		addr := net.JoinHostPort(t.Target, strconv.Itoa(t.Params.Port))

		cctx, cancel := context.WithTimeout(ctx, timeout)
		t0 := time.Now()
		var dialer net.Dialer
		conn, err := dialer.DialContext(cctx, "tcp", addr)
		if err == nil && t.Params.TLS {
			// Wrap the live connection in a TLS handshake so a mismatched cert or
			// non-TLS port is reported as down (optional SSL/TLS check).
			tconn := tls.Client(conn, &tls.Config{
				ServerName:         t.Target,
				InsecureSkipVerify: t.Params.IgnoreTLS,
			})
			err = tconn.HandshakeContext(cctx)
			conn = tconn
		}
		lat := float64(time.Since(t0).Microseconds()) / 1000.0
		cancel()
		if conn != nil {
			_ = conn.Close()
		}

		ok := 0.0
		if err == nil {
			ok = 1.0
		}
		res.Metrics = append(res.Metrics, telemetry.Metric{
			TS: now, Kind: telemetry.TCPOK, Target: t.Target, Layer: telemetry.LayerService,
			Value: ok, Unit: telemetry.UnitBool, Labels: map[string]string{"port": strconv.Itoa(t.Params.Port)},
			MonitorID: t.MonitorID,
		})
		if err == nil {
			res.Metrics = append(res.Metrics, telemetry.Metric{
				TS: now, Kind: telemetry.TCPConnectMs, Target: t.Target, Layer: telemetry.LayerService,
				Value: lat, Unit: telemetry.UnitMs, Labels: map[string]string{"port": strconv.Itoa(t.Params.Port)},
				MonitorID: t.MonitorID,
			})
		} else {
			res.Events = append(res.Events, telemetry.Event{
				ID: newID(), TS: now, Type: telemetry.EventProbeFailed, Layer: telemetry.LayerService,
				Severity: telemetry.SeverityWarn, Message: "TCP connect failed: " + addr,
			})
		}
	}
	return res, nil
}
