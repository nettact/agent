// Package collector implements the agent's monitoring probes. Each capability
// is an independent Collector emitting the normalized protocol types
// (architecture §3.1). The scheduler runs collectors at one of three frequency
// tiers; M1 ships two collectors (interface + gateway ping).
package collector

import (
	"context"
	"encoding/json"
	"strconv"
	"sync"
	"time"

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

// BlockedProbe is one monitor whose probe was refused at runtime by the target-
// access policy (e.g. a hostname that resolved to a denied address, a denied
// redirect hop). It carries no metric/event — the runtime routes it to the
// monitor-status tracker so the block surfaces as an operational issue, not a
// synthetic probe failure.
type BlockedProbe struct {
	MonitorID string
	// ConfigSerial is the originating ProbeTarget's material config generation. It
	// travels with the block so the runtime tracker can ignore an obsolete in-flight
	// result: a block produced by a superseded generation must never override, clear,
	// or relabel the current generation's status.
	ConfigSerial int
	Matched      string // matched selector (never a newly-resolved private address)
	Reason       string // resolved_denied | redirect_denied | literal_denied
}

// Result is what one Collect run produces.
type Result struct {
	Metrics   []telemetry.Metric
	Events    []telemetry.Event
	Inventory []telemetry.InventoryItem
	// InterfaceSnapshot is the authoritative full interface set for this round
	// (interface collector only; nil for other collectors). It replaces the old
	// per-interface inventory delta.
	InterfaceSnapshot *telemetry.InterfaceSnapshot
	// Blocked lists monitors refused by target-access policy this round.
	Blocked []BlockedProbe
}

// Collector is a single monitoring probe.
type Collector interface {
	Name() string
	Tier() Tier
	Collect(ctx context.Context) (Result, error)
}

// schedState tracks per-target next-due times so a collector can probe each of
// its targets on that target's own interval (falling back to a default when the
// target sets no interval_seconds). Used by the self-scheduling collectors
// (public ping / DNS / HTTP) which the agent drives on a fine-grained tick.
//
// The ping collectors additionally run each cycle asynchronously (a spread ICMP
// cycle spans most of its interval), so schedState also tracks which probes are
// in flight: claim marks them, finish releases them, and a claimed probe is
// never handed out twice. The synchronous collectors use due and never mark
// anything, since their cycle is over before Collect returns.
type schedState struct {
	mu          sync.Mutex
	targets     []pcfg.ProbeTarget
	nextDue     map[string]time.Time
	inflight    map[string]bool
	reported    map[string]bool
	fallback    time.Duration
	minInterval time.Duration // per-target interval floor (stability limit); 0 = no floor
}

func newSchedState(fallback time.Duration) *schedState {
	return &schedState{
		nextDue:  map[string]time.Time{},
		inflight: map[string]bool{},
		reported: map[string]bool{},
		fallback: fallback,
	}
}

// SetMinInterval sets the per-target interval floor (a local stability limit).
func (s *schedState) SetMinInterval(d time.Duration) {
	s.mu.Lock()
	s.minInterval = d
	s.mu.Unlock()
}

// schedKey uniquely identifies a probe generation within a collector. The monitor
// id leads: two user-created monitors may share the same kind, target AND params,
// and each must keep its own due-time slot so both run every interval. The material
// ConfigSerial is part of the key so every new target generation is a fresh slot
// with no recorded due-time — it probes on the next collector tick instead of
// inheriting the previous generation's schedule, including an edit-then-restore that
// reproduces an earlier generation's kind/target/params. The kind/target/params tail
// keeps distinct probes apart when ids are absent (older fixtures).
func schedKey(t pcfg.ProbeTarget) string {
	b, _ := json.Marshal(t.Params)
	return t.MonitorID + "|" + strconv.Itoa(t.ConfigSerial) + "|" + t.Kind + "|" + t.Target + "|" + string(b)
}

// set replaces the target list (from a DesiredState push) and prunes due-times
// for probes that are no longer present. In-flight marks are pruned the same
// way: a superseded generation must never keep its replacement from being
// claimed, so the new generation probes on the next tick while the old one is
// still mid-cycle. That briefly leaves two cycles running for one monitor, which
// is harmless — the old one carries its own ConfigSerial, so its samples land in
// the generation's own series and the monitor-status tracker ignores it — and
// when it finishes it finds nothing to release.
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
	for k := range s.inflight {
		if !live[k] {
			delete(s.inflight, k)
		}
	}
	for k := range s.reported {
		if !live[k] {
			delete(s.reported, k)
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
	for _, sp := range s.dueLocked(now, false) {
		out = append(out, sp.Target)
	}
	return out
}

// scheduledProbe is one probe claimed for an asynchronous run: the target, the
// schedState key its runner releases with finish, and the instant the target is
// next due — which a spread ping cycle paces its echoes against, so the last
// echo lands before the next cycle starts.
type scheduledProbe struct {
	Target  pcfg.ProbeTarget
	Key     string
	NextDue time.Time
	// First marks a probe that has never reported anything yet — a target just
	// pushed down, just edited into a new generation, or running for the first
	// time since the agent started. Its cycle has no cadence to blend into yet
	// and nothing has ever been reported for it, so a pacing budget of one whole
	// interval would leave a freshly created monitor blank for that interval
	// (five minutes, for a five-minute target). The ping collectors pace a first
	// cycle against its own worst case instead, and settle into the interval
	// from the first cycle that actually reports something.
	First bool
}

// claim is the asynchronous variant of due: it returns the due probes together
// with their next-due instants and marks each in flight, so a cycle that spans
// most of its interval can never be started a second time while it is still
// running. The caller must finish every returned Key.
//
// next-due still advances from the claim instant, not from the run's end, so a
// cycle that overruns its interval makes its target due again on the first tick
// after it finishes — the same degenerate cadence the synchronous collectors
// fall into, rather than an ever-growing skew.
func (s *schedState) claim(now time.Time) []scheduledProbe {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.dueLocked(now, true)
}

// finish releases an in-flight claim. reported says whether the cycle actually
// produced telemetry: a cycle that produced nothing (routes momentarily
// unreadable, a run cancelled by shutdown) leaves the probe still marked as
// never having reported, so its next cycle is still a First one. Without that,
// a single empty cycle would spend the target's one fast first cycle and the
// first REAL measurement would be spread over a whole interval — a five-minute
// monitor blank for ten minutes instead of five.
//
// Unknown keys (a generation superseded while its cycle ran) are a no-op.
func (s *schedState) finish(key string, reported bool) {
	s.mu.Lock()
	delete(s.inflight, key)
	if reported {
		s.reported[key] = true
	}
	s.mu.Unlock()
}

// dueLocked selects the probes due at now and advances their next-due times.
// With mark set, in-flight probes are skipped and the returned ones are marked.
func (s *schedState) dueLocked(now time.Time, mark bool) []scheduledProbe {
	var out []scheduledProbe
	for _, t := range s.targets {
		k := schedKey(t)
		if mark && s.inflight[k] {
			continue
		}
		nd, ok := s.nextDue[k]
		if ok && now.Before(nd) {
			continue
		}
		iv := s.fallback
		if t.Params.IntervalSeconds > 0 {
			iv = time.Duration(t.Params.IntervalSeconds) * time.Second
		}
		if s.minInterval > 0 && iv < s.minInterval {
			iv = s.minInterval
		}
		next := now.Add(iv)
		s.nextDue[k] = next
		if mark {
			s.inflight[k] = true
		}
		out = append(out, scheduledProbe{Target: t, Key: k, NextDue: next, First: !s.reported[k]})
	}
	return out
}
