// Package collector implements the agent's monitoring probes. Each capability
// is an independent Collector emitting the normalized protocol types
// (architecture §3.1). The scheduler runs collectors at one of three frequency
// tiers; M1 ships two collectors (interface + gateway ping).
package collector

import (
	"context"

	"github.com/nettact/protocol/capability"
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
}

// Collector is a single monitoring probe.
type Collector interface {
	Name() string
	Capabilities() []capability.Capability
	Tier() Tier
	Collect(ctx context.Context) (Result, error)
}
