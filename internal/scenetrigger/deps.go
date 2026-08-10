package scenetrigger

import (
	"github.com/nettact/agent/internal/netguard"
	"github.com/nettact/agent/internal/platform"
	"github.com/nettact/protocol/permission"
)

// Deps are the agent-side capabilities a scene collection reuses — the same
// platform HAL, target-access guard, and permission views this server's probes
// run under. No new capability surface is introduced.
//
// The type lives here rather than in incidentscene, and carries the identity
// fields flat rather than the collector's own struct, so this file can be built
// in BOTH configurations. The lite build excludes the collector entirely; if the
// wiring had to name one of its types, every construction site would need a
// build tag of its own and the pipeline would grow an `if lite` where it
// currently has none.
type Deps struct {
	Platform  platform.Platform
	Guard     *netguard.Guard
	Effective permission.Set
	Granted   permission.Set
	Supported permission.Set

	// The detecting agent's own identity, fixed into each scene at collection
	// time so later renames never rewrite history. AgentID arrives separately
	// (SetAgentID) because it is only known once this server has enrolled.
	Hostname string
	OS       string // runtime.GOOS
	Version  string
}
