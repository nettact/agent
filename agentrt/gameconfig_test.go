package agentrt

import (
	"testing"

	pcfg "github.com/nettact/protocol/config"
	gs "github.com/nettact/protocol/gamesense"
)

// The tracking mode is the site's record-unmatched setting under another name,
// and deriving it is the agent's only piece of game-configuration policy — so it
// is worth pinning on its own, without a sensor in the way.
func TestSensorConfigDerivesTheTrackingMode(t *testing.T) {
	profiles := []pcfg.GameProfile{{ID: "p1", Name: "CS2", Exe: []string{"cs2.exe"}, Tier: "diag"}}

	tests := []struct {
		name            string
		recordUnmatched bool
		profiles        []pcfg.GameProfile
		want            string
	}{
		// Out of the box: nothing named, everything recorded.
		{"no profiles, recording everything", true, nil, gs.ModeAll},
		// Profiles exist but unmatched processes are still wanted, so the sensor
		// keeps watching everything — the profiles only decide what gets stamped.
		{"profiles, recording everything", true, profiles, gs.ModeAll},
		{"profiles, strict", false, profiles, gs.ModeProfiles},
		// The case the profile count must not decide: the setting says no unmatched
		// process may be recorded, and with no profiles nothing matches, so nothing
		// is recorded. Falling back to ModeAll here would record every window on the
		// machine precisely because the user asked for the opposite.
		{"no profiles, strict", false, nil, gs.ModeProfiles},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sensorConfig(pcfg.GameConfig{
				Version: 1, RecordUnmatched: tt.recordUnmatched, Profiles: tt.profiles,
			}, false)
			if got.Mode != tt.want {
				t.Fatalf("mode = %q, want %q", got.Mode, tt.want)
			}
		})
	}
}

// The sensor is given what changes its behaviour and nothing else. A profile's
// display name and linked monitors are read only by the console, and a field the
// sensor carries without reading is a field that can drift.
func TestSensorConfigCarriesOnlyWhatTheSensorActsOn(t *testing.T) {
	got := sensorConfig(pcfg.GameConfig{
		Version: 4,
		Profiles: []pcfg.GameProfile{
			{ID: "p1", Name: "CS2", Exe: []string{"cs2.exe", "cs2_win64.exe"}, TargetFPS: 240, Tier: gs.TierDiag},
			{ID: "p2", Name: "Deep Rock", Exe: []string{"FSD-Win64-Shipping.exe"}, Tier: gs.TierBase},
		},
	}, false)

	if len(got.Profiles) != 2 {
		t.Fatalf("profiles = %+v, want both", got.Profiles)
	}
	first := got.Profiles[0]
	if first.ID != "p1" || first.TargetFPS != 240 || first.Tier != gs.TierDiag {
		t.Errorf("profile = %+v, want the pushed id, target and tier", first)
	}
	if len(first.Exe) != 2 || first.Exe[0] != "cs2.exe" || first.Exe[1] != "cs2_win64.exe" {
		t.Errorf("profile executables = %v, want both as pushed", first.Exe)
	}
	if got.Profiles[1].ID != "p2" || got.Profiles[1].Tier != gs.TierBase {
		t.Errorf("profile = %+v, want the second as pushed", got.Profiles[1])
	}
	// The matching rule the sensor will apply is the protocol's own, so the
	// mapping has to survive it.
	if p, ok := got.Match("CS2.EXE"); !ok || p.ID != "p1" {
		t.Errorf("Match(CS2.EXE) = %+v, %v; want the first profile", p, ok)
	}
}

// The GPU flag is the one field of the sensor's configuration the site does not
// choose: it is the effective game.gpu.read decision, and no push may raise or
// lower it. A site editing its profiles must not be able to switch adapter
// telemetry on for a machine whose permission set excludes it, nor off for one
// that has it.
func TestSensorConfigTakesTheGPUFlagFromThePermissionNotThePush(t *testing.T) {
	pushed := pcfg.GameConfig{
		Version:         7,
		RecordUnmatched: true,
		Profiles:        []pcfg.GameProfile{{ID: "p1", Name: "CS2", Exe: []string{"cs2.exe"}, Tier: gs.TierDiag}},
	}
	for _, gpu := range []bool{true, false} {
		if got := sensorConfig(pushed, gpu); got.GPU != gpu {
			t.Errorf("sensorConfig(..., %v).GPU = %v, want the effective permission", gpu, got.GPU)
		}
	}
}
