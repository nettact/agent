// Package collector implements the agent's monitoring probes. Each capability
// is an independent Collector emitting the normalized protocol types
// (architecture §3.1). The scheduler runs collectors at one of three frequency
// tiers; M1 ships two collectors (interface + gateway ping).
package collector

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/nettact/protocol/capability"
	pcfg "github.com/nettact/protocol/config"
	"github.com/nettact/protocol/telemetry"
)

// Tier is the scheduling frequency band (architecture §3.2).
type Tier string

const (
	TierBase    Tier = "base"    // 5–30s: gateway/public ping, iface up/down
	TierRegular Tier = "regular" // 30–120s: DNS, HTTP, interface snapshot, ARP
	TierBurst   Tier = "burst"   // event-driven diagnostic escalation
)

// Result is what one Collect run produces.
type Result struct {
	Metrics   []telemetry.Metric
	Events    []telemetry.Event
	Inventory []telemetry.InventoryItem
	// InterfaceSnapshot is the authoritative full interface set for this round
	// (interface collector only; nil for other collectors). It replaces the old
	// per-interface inventory delta.
	InterfaceSnapshot *telemetry.InterfaceSnapshot
}

// Collector is a single monitoring probe.
type Collector interface {
	Name() string
	Capabilities() []capability.Capability
	Tier() Tier
	Collect(ctx context.Context) (Result, error)
}

// schedState tracks per-target next-due times so a collector can probe each of
// its targets on that target's own interval (falling back to a default when the
// target sets no interval_seconds). Used by the self-scheduling collectors
// (public ping / DNS / HTTP) which the agent drives on a fine-grained tick.
type schedState struct {
	mu       sync.Mutex
	targets  []pcfg.ProbeTarget
	nextDue  map[string]time.Time
	fallback time.Duration
}

func newSchedState(fallback time.Duration) *schedState {
	return &schedState{nextDue: map[string]time.Time{}, fallback: fallback}
}

// schedKey uniquely identifies a probe within a collector. The monitor id leads:
// two user-created monitors may share the same kind, target AND params, and each
// must keep its own due-time slot so both run every interval. The kind/target/
// params tail keeps distinct probes apart when ids are absent (older fixtures).
func schedKey(t pcfg.ProbeTarget) string {
	b, _ := json.Marshal(t.Params)
	return t.MonitorID + "|" + t.Kind + "|" + t.Target + "|" + string(b)
}

// set replaces the target list (from a DesiredState push) and prunes due-times
// for probes that are no longer present.
func (s *schedState) set(targets []pcfg.ProbeTarget) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.targets = targets
	live := make(map[string]bool, len(targets))
	for _, t := range targets {
		live[schedKey(t)] = true
	}
	for k := range s.nextDue {
		if !live[k] {
			delete(s.nextDue, k)
		}
	}
}

// due returns the probes whose interval has elapsed by now, advancing each
// returned probe's next-due time. A probe with no recorded due-time is due
// immediately (so a freshly-pushed probe runs on the next tick).
func (s *schedState) due(now time.Time) []pcfg.ProbeTarget {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []pcfg.ProbeTarget
	for _, t := range s.targets {
		k := schedKey(t)
		nd, ok := s.nextDue[k]
		if ok && now.Before(nd) {
			continue
		}
		out = append(out, t)
		iv := s.fallback
		if t.Params.IntervalSeconds > 0 {
			iv = time.Duration(t.Params.IntervalSeconds) * time.Second
		}
		s.nextDue[k] = now.Add(iv)
	}
	return out
}
