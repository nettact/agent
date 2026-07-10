package collector

import (
	"context"
	"net/http"
	"time"

	"github.com/nettact/protocol/capability"
	pcfg "github.com/nettact/protocol/config"
	"github.com/nettact/protocol/telemetry"
)

// HTTPCollector performs HTTP/HTTPS availability checks against a
// server-configured URL set (architecture §4 service layer). Each URL carries
// its own per-target params (timeout, interval, method, expected status) and is
// probed on its own schedule via schedState.
type HTTPCollector struct {
	client *http.Client
	sched  *schedState
}

func NewHTTPCollector() *HTTPCollector {
	// No client-level Timeout: each request is bounded by its own per-target
	// context timeout, so a configured TimeoutMs above 10s is honored instead of
	// being silently capped by a fixed client timeout.
	return &HTTPCollector{
		client: &http.Client{},
		sched:  newSchedState(30 * time.Second),
	}
}

func (c *HTTPCollector) SetTargets(targets []pcfg.ProbeTarget) {
	var urls []pcfg.ProbeTarget
	for _, t := range targets {
		if t.Kind == "http" && t.Target != "" {
			urls = append(urls, t)
		}
	}
	c.sched.set(urls)
}

func (c *HTTPCollector) Name() string { return "http" }

func (c *HTTPCollector) Capabilities() []capability.Capability {
	return []capability.Capability{capability.ProbeHTTP}
}

func (c *HTTPCollector) Tier() Tier { return TierRegular }

func (c *HTTPCollector) Collect(ctx context.Context) (Result, error) {
	targets := c.sched.due(time.Now())
	if len(targets) == 0 {
		return Result{}, nil
	}

	now := time.Now().UTC()
	var res Result
	for _, t := range targets {
		timeout := time.Duration(t.Params.TimeoutMs) * time.Millisecond
		if timeout <= 0 {
			timeout = 10 * time.Second
		}
		method := t.Params.Method
		if method == "" {
			method = http.MethodGet
		}

		cctx, cancel := context.WithTimeout(ctx, timeout)
		req, err := http.NewRequestWithContext(cctx, method, t.Target, nil)
		if err != nil {
			cancel()
			continue
		}
		t0 := time.Now()
		resp, err := c.client.Do(req)
		lat := float64(time.Since(t0).Microseconds()) / 1000.0
		if err != nil {
			cancel()
			res.Metrics = append(res.Metrics, telemetry.Metric{
				TS: now, Kind: telemetry.HTTPOK, Target: t.Target, Layer: telemetry.LayerService, Value: 0, Unit: telemetry.UnitBool,
			})
			res.Events = append(res.Events, telemetry.Event{
				ID: newID(), TS: now, Type: telemetry.EventProbeFailed, Layer: telemetry.LayerService,
				Severity: telemetry.SeverityWarn, Message: "HTTP request failed: " + t.Target,
			})
			continue
		}
		status := resp.StatusCode
		resp.Body.Close()
		cancel()

		ok := 0.0
		if t.Params.ExpectedStatus > 0 {
			if status == t.Params.ExpectedStatus {
				ok = 1.0
			}
		} else if status >= 200 && status < 400 {
			ok = 1.0
		}
		res.Metrics = append(res.Metrics,
			telemetry.Metric{TS: now, Kind: telemetry.HTTPStatus, Target: t.Target, Layer: telemetry.LayerService, Value: float64(status), Unit: telemetry.UnitCode},
			telemetry.Metric{TS: now, Kind: telemetry.HTTPLat, Target: t.Target, Layer: telemetry.LayerService, Value: lat, Unit: telemetry.UnitMs},
			telemetry.Metric{TS: now, Kind: telemetry.HTTPOK, Target: t.Target, Layer: telemetry.LayerService, Value: ok, Unit: telemetry.UnitBool},
		)
	}
	return res, nil
}
