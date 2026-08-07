// Package scheduler runs collectors at three frequency tiers (architecture
// §3.2): base (fast — interface/ARP snapshots), regular (slower), and a burst
// mode that temporarily speeds up the base tier when a fault is detected, to
// capture more evidence during an incident. Target-driven probes (gateway /
// public ping / DNS / HTTP / TCP / NAT) are self-scheduled instead: polled on a
// fine tick, each gates its own targets by their per-target interval and runs
// them on their own goroutines, and their 100% loss still arms burst mode via
// selfLoop.
package scheduler

import (
	"context"
	"sync"
	"time"

	"github.com/nettact/agent/internal/collector"
	"github.com/nettact/protocol/telemetry"
)

// Sink receives each collector Result (the agent appends it to the WAL).
type Sink func(collector.Result)

// selfTick is how often self-scheduling collectors are polled; each such
// collector then gates its own targets by their per-target interval.
const selfTick = 1 * time.Second

type Scheduler struct {
	base      []collector.Collector
	regular   []collector.Collector
	selfSched []collector.Collector
	sink      Sink

	wg sync.WaitGroup

	mu              sync.Mutex
	baseInterval    time.Duration
	regularInterval time.Duration
	burstInterval   time.Duration
	burstWindow     time.Duration
	burstUntil      time.Time
}

// New builds a scheduler. tiered collectors run on the base/regular/burst tier
// loops; selfSched collectors are polled on a fine tick (selfTick) and gate
// their own targets by each target's configured interval.
func New(tiered []collector.Collector, selfSched []collector.Collector, sink Sink) *Scheduler {
	s := &Scheduler{
		sink:            sink,
		selfSched:       selfSched,
		baseInterval:    10 * time.Second,
		regularInterval: 30 * time.Second,
		burstInterval:   3 * time.Second,
		burstWindow:     60 * time.Second,
	}
	for _, c := range tiered {
		if c.Tier() == collector.TierRegular {
			s.regular = append(s.regular, c)
		} else {
			s.base = append(s.base, c)
		}
	}
	return s
}

// SetIntervals updates tier intervals from pushed DesiredState (0 = unchanged).
func (s *Scheduler) SetIntervals(base, regular time.Duration) {
	s.mu.Lock()
	if base > 0 {
		s.baseInterval = base
	}
	if regular > 0 {
		s.regularInterval = regular
	}
	s.mu.Unlock()
}

// Run starts the tier loops and the self-scheduled poll loop until ctx is
// cancelled. The loops are tracked so the caller can Wait for them to exit
// before tearing down shared state (e.g. closing the WAL the sink writes to).
func (s *Scheduler) Run(ctx context.Context) {
	s.wg.Add(3)
	go func() { defer s.wg.Done(); s.tierLoop(ctx, s.base, true) }()
	go func() { defer s.wg.Done(); s.tierLoop(ctx, s.regular, false) }()
	go func() { defer s.wg.Done(); s.selfLoop(ctx); s.waitSelfIdle() }()
}

// Wait blocks until every loop started by Run has returned. It only returns once
// the Run ctx is cancelled and all in-flight collects/sinks have drained.
func (s *Scheduler) Wait() { s.wg.Wait() }

// waitSelfIdle joins the work a self-scheduled collector left running past its
// Collect. Every probe runs on its own goroutine, which outlives the poll loop;
// joining here is what keeps Wait's contract intact — once Wait returns, nothing
// Run started is still touching the platform HAL or the proxy manager, so the
// runtime can tear them down in its usual order. After cancellation a run
// unwinds within one operation timeout.
func (s *Scheduler) waitSelfIdle() {
	for _, c := range s.selfSched {
		if w, ok := c.(interface{ WaitIdle() }); ok {
			w.WaitIdle()
		}
	}
}

// selfLoop polls self-scheduling collectors on a fine tick; each returns only
// the targets due by their own interval (empty Result otherwise).
//
// The poll must stay quick, and now that is a contract every self-scheduled
// collector keeps rather than a hope. All of them run their probes on their own
// goroutines (see collector.probeRunner) and use Collect only to hand back what
// finished since the previous tick and to start what has come due — so a probe
// that takes its whole timeout, or an ICMP cycle spread across its entire check
// interval, costs this loop nothing.
//
// It used to be otherwise, and the asymmetry was the reason to change it: the
// single-shot probes ran inline, so one unreachable HTTP target held this
// goroutine for its full 10s timeout and a NAT discovery for 25s, delaying every
// other probe on the agent — including the ping cycles — by exactly that. The
// moment that hurt most was the moment a fault was unfolding, which is when the
// probes queued behind it were the ones someone was waiting on.
func (s *Scheduler) selfLoop(ctx context.Context) {
	if len(s.selfSched) == 0 {
		return
	}
	t := time.NewTicker(selfTick)
	defer t.Stop()
	for {
		for _, c := range s.selfSched {
			res, err := c.Collect(ctx)
			if err != nil {
				continue
			}
			if empty(res) {
				continue
			}
			// A self-scheduled probe reporting 100% loss is still a burst signal
			// (public-ping moved off the base tier, so this is now the only place
			// its faults would trigger burst diagnostics). For a ping target that
			// is the tick after its cycle ended, not the tick that started it.
			if faultDetected(res) {
				s.mu.Lock()
				s.burstUntil = time.Now().Add(s.burstWindow)
				s.mu.Unlock()
			}
			s.sink(res)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// empty reports whether a Result carries nothing at all. Passing one to the
// sink is not free: an Append opens a transaction and consumes a group id
// whatever it is given, so a collector that legitimately has nothing to say —
// a probe whose targets are all still waiting out their own intervals — would
// otherwise write to durable storage on every tick, forever.
func empty(res collector.Result) bool {
	return len(res.Metrics) == 0 && len(res.Events) == 0 && len(res.Inventory) == 0 &&
		len(res.Blocked) == 0 && res.InterfaceSnapshot == nil
}

func (s *Scheduler) tierLoop(ctx context.Context, cols []collector.Collector, isBase bool) {
	if len(cols) == 0 {
		return
	}
	for {
		faulted := false
		for _, c := range cols {
			res, err := c.Collect(ctx)
			if err != nil {
				continue
			}
			if isBase && faultDetected(res) {
				faulted = true
			}
			if empty(res) {
				continue
			}
			s.sink(res)
		}
		if isBase && faulted {
			s.mu.Lock()
			s.burstUntil = time.Now().Add(s.burstWindow)
			s.mu.Unlock()
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(s.nextSleep(isBase)):
		}
	}
}

func (s *Scheduler) nextSleep(isBase bool) time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	if isBase && time.Now().Before(s.burstUntil) {
		return s.burstInterval
	}
	if isBase {
		return s.baseInterval
	}
	return s.regularInterval
}

// InBurst reports whether the base tier is currently in burst mode.
func (s *Scheduler) InBurst() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return time.Now().Before(s.burstUntil)
}

// faultDetected flags 100% loss on the LAN/internet layers (gateway or public
// target down), which triggers burst diagnostics.
func faultDetected(res collector.Result) bool {
	for _, m := range res.Metrics {
		if m.Kind == telemetry.ICMPLoss && m.Value >= 100 {
			return true
		}
	}
	return false
}
