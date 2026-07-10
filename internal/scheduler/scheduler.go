// Package scheduler runs collectors at three frequency tiers (architecture
// §3.2): base (fast — gateway/public ping), regular (slower — DNS/HTTP/ARP/
// interface), and a burst mode that temporarily speeds up the base tier when a
// fault is detected, to capture more evidence during an incident.
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
// cancelled.
func (s *Scheduler) Run(ctx context.Context) {
	go s.tierLoop(ctx, s.base, true)
	go s.tierLoop(ctx, s.regular, false)
	go s.selfLoop(ctx)
}

// selfLoop polls self-scheduling collectors on a fine tick; each returns only
// the targets due by their own interval (empty Result otherwise).
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
			if len(res.Metrics) == 0 && len(res.Events) == 0 && len(res.Inventory) == 0 {
				continue
			}
			// A self-scheduled probe reporting 100% loss is still a burst signal
			// (public-ping moved off the base tier, so this is now the only place
			// its faults would trigger burst diagnostics).
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
