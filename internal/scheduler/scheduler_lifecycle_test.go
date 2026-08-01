package scheduler

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/nettact/agent/internal/collector"
	"github.com/nettact/protocol/telemetry"
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

// A collector with nothing to report must not reach the sink. Appending is not
// free — it opens a transaction and consumes a group id whatever it is handed —
// so a collector that is legitimately silent most of the time (the game sensor
// while no game runs) would otherwise write to durable storage on every tick.
func TestEmptyTieredResultNeverReachesSink(t *testing.T) {
	empties := fixedCollector{result: collector.Result{}}
	var mu sync.Mutex
	var calls int
	ctx, cancel := context.WithCancel(context.Background())
	s := New([]collector.Collector{empties}, nil, func(collector.Result) {
		mu.Lock()
		calls++
		mu.Unlock()
	})
	s.Run(ctx)
	time.Sleep(150 * time.Millisecond)
	cancel()
	s.Wait()

	mu.Lock()
	defer mu.Unlock()
	if calls != 0 {
		t.Fatalf("sink called %d times for an empty result, want 0", calls)
	}
}

// The emptiness test must not swallow a result whose only content is a snapshot:
// the interface collector reports that way, and dropping it would lose the
// authoritative interface set.
func TestTieredSnapshotOnlyResultReachesSink(t *testing.T) {
	snap := &telemetry.InterfaceSnapshot{}
	c := fixedCollector{result: collector.Result{InterfaceSnapshot: snap}}
	got := make(chan collector.Result, 1)
	ctx, cancel := context.WithCancel(context.Background())
	s := New([]collector.Collector{c}, nil, func(r collector.Result) {
		select {
		case got <- r:
		default:
		}
	})
	s.Run(ctx)
	select {
	case res := <-got:
		if res.InterfaceSnapshot == nil {
			t.Fatal("snapshot-only result reached the sink stripped of its snapshot")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("snapshot-only result was dropped as empty")
	}
	cancel()
	s.Wait()
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
