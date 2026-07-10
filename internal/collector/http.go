package collector

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/nettact/protocol/capability"
	pcfg "github.com/nettact/protocol/config"
	"github.com/nettact/protocol/telemetry"
)

// HTTPCollector performs HTTP/HTTPS availability checks against a
// server-configured URL set (architecture §4 service layer).
type HTTPCollector struct {
	mu      sync.RWMutex
	urls    []string
	client  *http.Client
	timeout time.Duration
}

func NewHTTPCollector() *HTTPCollector {
	return &HTTPCollector{
		client:  &http.Client{Timeout: 10 * time.Second},
		timeout: 10 * time.Second,
	}
}

func (c *HTTPCollector) SetTargets(targets []pcfg.ProbeTarget) {
	var urls []string
	for _, t := range targets {
		if t.Kind == "http" && t.Target != "" {
			urls = append(urls, t.Target)
		}
	}
	c.mu.Lock()
	c.urls = urls
	c.mu.Unlock()
}

func (c *HTTPCollector) Name() string { return "http" }

func (c *HTTPCollector) Capabilities() []capability.Capability {
	return []capability.Capability{capability.ProbeHTTP}
}

func (c *HTTPCollector) Tier() Tier { return TierRegular }

func (c *HTTPCollector) Collect(ctx context.Context) (Result, error) {
	c.mu.RLock()
	urls := append([]string(nil), c.urls...)
	c.mu.RUnlock()

	now := time.Now().UTC()
	var res Result
	for _, url := range urls {
		cctx, cancel := context.WithTimeout(ctx, c.timeout)
		req, err := http.NewRequestWithContext(cctx, http.MethodGet, url, nil)
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
				TS: now, Kind: telemetry.HTTPOK, Target: url, Layer: telemetry.LayerService, Value: 0, Unit: telemetry.UnitBool,
			})
			res.Events = append(res.Events, telemetry.Event{
				ID: newID(), TS: now, Type: telemetry.EventProbeFailed, Layer: telemetry.LayerService,
				Severity: telemetry.SeverityWarn, Message: "HTTP request failed: " + url,
			})
			continue
		}
		status := resp.StatusCode
		resp.Body.Close()
		cancel()

		ok := 0.0
		if status >= 200 && status < 400 {
			ok = 1.0
		}
		res.Metrics = append(res.Metrics,
			telemetry.Metric{TS: now, Kind: telemetry.HTTPStatus, Target: url, Layer: telemetry.LayerService, Value: float64(status), Unit: telemetry.UnitCode},
			telemetry.Metric{TS: now, Kind: telemetry.HTTPLat, Target: url, Layer: telemetry.LayerService, Value: lat, Unit: telemetry.UnitMs},
			telemetry.Metric{TS: now, Kind: telemetry.HTTPOK, Target: url, Layer: telemetry.LayerService, Value: ok, Unit: telemetry.UnitBool},
		)
	}
	return res, nil
}
