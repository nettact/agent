//go:build !windows

package gamesense

import (
	"context"
	"errors"
)

// Frame presentation is read from the Windows graphics event stream, and the
// sensor component that reads it is a Windows executable. On every other
// platform this package is a precise-unsupported stub: discovery reports no
// sensor, so the game.* permissions never enter the supported set and nothing
// below is ever reached. It exists so the agent cross-compiles unchanged.

// platformSupported gates discovery: there is no sensor to find here.
const platformSupported = false

// errUnsupported is returned by paths that only exist to satisfy the compiler.
var errUnsupported = errors.New("gamesense: unsupported platform")

// Probe reports no capability. Locate never returns a path off Windows, so the
// agent has nothing to pass here in the first place.
func Probe(_ context.Context, _ string) ProbeResult {
	return ProbeResult{Reason: ReasonUnsupportedOS}
}

func (s *Supervisor) runOnce(_ context.Context) error { return errUnsupported }
