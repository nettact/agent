package scheduler

import (
	"context"
	"testing"
	"time"

	"github.com/nettact/agent/internal/collector"
)

type blockingCollector struct {
	entered chan struct{}
	release chan struct{}
}

type fixedCollector struct{ result collector.Result }

func (c fixedCollector) Name() string         { return "fixed" }
func (c fixedCollector) Tier() collector.Tier { return collector.TierRegular }
func (c fixedCollector) Collect(context.Context) (collector.Result, error) {
	return c.result, nil
}

func (c *blockingCollector) Name() string         { return "blocking" }
func (c *blockingCollector) Tier() collector.Tier { return collector.TierBase }
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

func TestSelfScheduledBlockedOnlyResultReachesSink(t *testing.T) {
	want := collector.BlockedProbe{MonitorID: "mon-1", Matched: "scope:metadata", Reason: "resolved_denied"}
	c := fixedCollector{result: collector.Result{Blocked: []collector.BlockedProbe{want}}}
	got := make(chan collector.Result, 1)
	ctx, cancel := context.WithCancel(context.Background())
	s := New(nil, []collector.Collector{c}, func(r collector.Result) { got <- r })
	s.Run(ctx)

	select {
	case res := <-got:
		if len(res.Blocked) != 1 || res.Blocked[0] != want {
			t.Fatalf("sink result = %+v, want blocked-only %+v", res, want)
		}
		if len(res.Metrics) != 0 || len(res.Events) != 0 {
			t.Fatalf("blocked result synthesized outage telemetry: %+v", res)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("blocked-only self-scheduled result was dropped")
	}
	cancel()
	s.Wait()
}
