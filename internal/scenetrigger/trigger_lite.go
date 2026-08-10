//go:build lite

// Package scenetrigger is a no-op in the lite build: this device collects no
// incident scenes.
//
// The exclusion is about the outbox, not the collection. Gathering a scene costs
// a few local reads even on a router, but the report is large next to a lite
// agent's whole telemetry budget — 5000 rows of memory, spilled to flash only
// while a server is unreachable, which is precisely when the disconnect trigger
// would be firing. A device with that budget should spend it on measurements,
// and whoever is looking at a connectivity incident on an OpenWrt box is one SSH
// away from the same interface table a scene would have carried.
//
// The type keeps the full surface so the runtime wiring stays identical between
// builds. A caller cannot tell the difference, which is the point: there is no
// `if lite` anywhere in the pipeline.
package scenetrigger

import (
	"context"
	"time"

	"github.com/nettact/agent/internal/tracetrigger"
	"github.com/nettact/protocol/telemetry"
)

// Trigger collects nothing.
type Trigger struct{}

// New returns the no-op trigger. The arguments are accepted and discarded so the
// call site is identical in both builds.
func New(string, Deps, time.Duration, func(telemetry.SceneReport)) *Trigger {
	return &Trigger{}
}

func (t *Trigger) Start(context.Context)              {}
func (t *Trigger) Wait()                              {}
func (t *Trigger) SetAgentID(string)                  {}
func (t *Trigger) OnFaultEdge(tracetrigger.FaultEdge) {}
func (t *Trigger) SessionUp()                         {}
func (t *Trigger) Disarm()                            {}
func (t *Trigger) SessionLost(string, time.Time)      {}
