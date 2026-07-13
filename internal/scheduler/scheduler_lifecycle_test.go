package scheduler

import (
	"context"
	"testing"
	"time"

	"github.com/nettact/agent/internal/collector"
	"github.com/nettact/protocol/capability"
)

type blockingCollector struct {
	entered chan struct{}
	release chan struct{}
}

func (c *blockingCollector) Name() string                          { return "blocking" }
func (c *blockingCollector) Capabilities() []capability.Capability { return nil }
func (c *blockingCollector) Tier() collector.Tier                  { return collector.TierBase }
func (c *blockingCollector) Collect(context.Context) (collector.Result, error) {
	select {
	case <-c.entered:
	default:
		close(c.entered)
	}
	<-c.release
	return collector.Result{}, nil
}

func TestWaitJoinsInFlightCollector(t *testing.T) {
	c := &blockingCollector{entered: make(chan struct{}), release: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	s := New([]collector.Collector{c}, nil, func(collector.Result) {})
	s.Run(ctx)

	select {
	case <-c.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("collector did not start")
	}

	cancel()
	waited := make(chan struct{})
	go func() {
		s.Wait()
		close(waited)
	}()

	select {
	case <-waited:
		t.Fatal("Wait returned while Collect was still in flight")
	case <-time.After(30 * time.Millisecond):
	}

	close(c.release)
	select {
	case <-waited:
	case <-time.After(2 * time.Second):
		t.Fatal("Wait did not return after the collector drained")
	}
}
