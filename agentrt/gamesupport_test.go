package agentrt

import (
	"slices"
	"strings"
	"testing"

	"github.com/nettact/agent/internal/gamesense"
	gs "github.com/nettact/protocol/gamesense"
	"github.com/nettact/protocol/permission"
)

// The permission report has to carry the reason the probe already knows.
//
// Every one of the rows below leaves at least one game permission unsupported,
// and in the three sets alone they are indistinguishable — which is how an
// operator running a perfectly healthy PresentMon was sent to install it. The
// third row is that operator: a stale sensor speaking a protocol this agent no
// longer implements, correctly diagnosed and then thrown away.
//
// The platform is an axis of the table rather than an assumption, because the
// two silent rows are the easiest pair to get wrong: a machine where the sensor
// could exist and does not is a finding, while a platform where it could not is
// a property of the build, and only the first is the agent's to report. The last
// two rows are that same distinction one level down, for the adapter question
// nobody asked.
func TestGameSupportExplainsWhatItLeavesUnsupported(t *testing.T) {
	// Both grants that reach the sensor, and the same policy with the adapter read
	// deliberately withheld. Closure is what a real policy is validated against, so
	// the parents come along.
	withGPU := permission.Closure(permission.NewSet(permission.GameGPURead))
	withoutGPU := permission.Closure(permission.NewSet(permission.GamePerformanceRead))

	detect, perf, gpu := string(permission.GameProcessDetect),
		string(permission.GamePerformanceRead), string(permission.GameGPURead)

	tests := []struct {
		name string
		// platformSupported is whether a sensor component could exist here at all.
		// Stated per row rather than taken from the build, so the non-Windows answer
		// is exercised on every platform — including the one where it can never
		// happen for real.
		platformSupported bool
		granted           permission.Set
		found             bool
		probe             gamesense.ProbeResult
		wantSupport       []permission.ID
		wantReasons       map[string]string
	}{{
		// The platform where the component is not a thing. Everything is granted, so
		// the silence belongs to the platform rather than to the policy — and silence
		// is the whole point: which platforms can host a sensor is a property of the
		// build that a console already knows and renders correctly on its own, so a
		// reason here would replace a right answer with a wrong one and send someone
		// after a build carrying the component for a machine where game capture does
		// not exist.
		name:    "platform has no sensor component at all",
		granted: withGPU,
	}, {
		// A platform that could host one, and none beside the agent. That IS a fact
		// about this install, so it is reported — and reporting it only here is what
		// keeps sensor_missing meaning what it says.
		name:              "no sensor component installed",
		platformSupported: true,
		granted:           withGPU,
		wantReasons: map[string]string{
			detect: gs.ReasonSensorMissing,
			perf:   gs.ReasonSensorMissing,
			gpu:    gs.ReasonSensorMissing,
		},
	}, {
		// The case that shipped broken. The agent diagnosed it exactly and had
		// nowhere to say so, so the console offered the one remedy it knew.
		name:              "sensor speaking an older protocol",
		platformSupported: true,
		granted:           withGPU,
		found:             true,
		probe:             gamesense.ProbeResult{Proto: 2, Reason: gamesense.ReasonProtoMismatch},
		wantReasons: map[string]string{
			detect: gamesense.ReasonProtoMismatch,
			perf:   gamesense.ReasonProtoMismatch,
			gpu:    gamesense.ReasonProtoMismatch,
		},
	}, {
		// The failure the console's single guess was actually written for — and
		// under a policy that never asked about the adapter, so that question stays
		// unanswered rather than being answered with this cause.
		name:              "middleware missing, adapter read never granted",
		platformSupported: true,
		granted:           withoutGPU,
		found:             true,
		probe:             gamesense.ProbeResult{Reason: gamesense.ReasonPresentMonMissing},
		wantReasons: map[string]string{
			detect: gamesense.ReasonPresentMonMissing,
			perf:   gamesense.ReasonPresentMonMissing,
		},
	}, {
		name:              "everything verified",
		platformSupported: true,
		granted:           withGPU,
		found:             true,
		probe:             gamesense.ProbeResult{OK: true, GPUOK: true},
		wantSupport: []permission.ID{
			permission.GameProcessDetect, permission.GamePerformanceRead, permission.GameGPURead,
		},
	}, {
		// Frames capture, the adapter publishes nothing. The two reads that worked
		// are supported, and only the third is explained — an ordinary machine,
		// which is a thing the console can only say if it is told.
		name:              "capture works, adapter publishes no telemetry",
		platformSupported: true,
		granted:           withGPU,
		found:             true,
		probe:             gamesense.ProbeResult{OK: true},
		wantSupport:       []permission.ID{permission.GameProcessDetect, permission.GamePerformanceRead},
		wantReasons:       map[string]string{gpu: gs.ReasonGPUTelemetryUnavailable},
	}, {
		// The same machine under a policy that withheld the adapter read: --gpu
		// never went out, so the sensor was never asked and there is no answer to
		// report. It looks like an omission and is the contract — an absent key is
		// how "never asked" is written down, and inventing a code here would report
		// a failure that never happened.
		name:              "adapter read never granted, so never asked",
		platformSupported: true,
		granted:           withoutGPU,
		found:             true,
		probe:             gamesense.ProbeResult{OK: true},
		wantSupport:       []permission.ID{permission.GameProcessDetect, permission.GamePerformanceRead},
	}, {
		// The standalone baseline grants no game permission at all, so nothing was
		// located, probed or asked, and all three are unprobed rather than failed.
		// The platform could have answered, which is what makes this the policy's
		// doing and not the build's.
		name:              "no game permission granted",
		platformSupported: true,
		granted:           permission.DefaultStandalone(),
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotSupport, gotReasons := gameSupport(tt.granted, tt.platformSupported, tt.found, tt.probe)

			want := permission.NewSet(tt.wantSupport...)
			if got, want := join(gotSupport), join(want); got != want {
				t.Errorf("supported = [%s], want [%s]", got, want)
			}
			for id, want := range tt.wantReasons {
				if got := gotReasons[id]; got != want {
					t.Errorf("reason for %s = %q, want %q", id, got, want)
				}
			}
			// The other direction is the half that carries the contract: a key the
			// table does not list is a question this agent answered without being
			// asked it.
			for id, got := range gotReasons {
				if _, ok := tt.wantReasons[id]; !ok {
					t.Errorf("reason for %s = %q, want no entry at all", id, got)
				}
			}
			// The invariant across every row: the map explains what is missing, so a
			// reason for something supported would describe a failure that did not
			// happen.
			for id := range gotReasons {
				if gotSupport.Has(permission.ID(id)) {
					t.Errorf("%s is supported and carries the reason %q", id, gotReasons[id])
				}
			}
		})
	}
}

// join renders a set for comparison and for a failure message. Strings is in
// canonical order, so two equal sets always render identically.
func join(s permission.Set) string { return strings.Join(s.Strings(), " ") }

// Frame capture belongs to exactly one server, so what gameSupport settled for
// the machine reaches only that server's view — and every other server is told
// why, not just that it cannot have it.
//
// Without the reason a console would render a machine that plainly can capture
// frames as one that cannot, and send the operator after a sensor that is
// installed and working. The other direction is the half that carries the
// contract: a server that granted no game permission asked nothing, and gets no
// entry at all rather than one explaining a capability it never wanted.
func TestViewsForGivesGameCaptureToTheOwnerAlone(t *testing.T) {
	gameIDs := []permission.ID{
		permission.GameProcessDetect, permission.GamePerformanceRead, permission.GameGPURead,
	}
	// A machine whose sensor probe verified all three: the interesting case,
	// because every difference below is then the ownership rule and nothing else.
	caps := machineCaps{
		base:          platformIndependentSupported(),
		gameSupported: permission.NewSet(gameIDs...),
		gameReasons:   map[string]string{},
	}
	withGame := permission.Policy{
		Granted: permission.Closure(permission.NewSet(permission.GameGPURead)),
		Source:  permission.SourceEnvironment,
	}
	noGame := permission.Policy{
		Granted: permission.NewSet(permission.ProbeDNS),
		Source:  permission.SourceServerConfig,
	}

	cfg := Config{
		Servers: []ServerConfig{
			{Name: "home", URL: "https://home.example"},
			{Name: "work", URL: "https://work.example"},
		},
		Policy: withGame,
	}

	for _, tt := range []struct {
		name string
		sc   ServerConfig
		owns bool
		// wantGame is whether the three game permissions are supported (and, since
		// all three are granted here, effective).
		wantGame bool
		// wantReason is the UnsupportedReasons entry expected for each GRANTED game
		// permission; "" means the map must carry none at all.
		wantReason string
	}{{
		// Servers[0] owns the sensor, so it gets what the probe verified.
		name:     "owner",
		sc:       cfg.Servers[0],
		owns:     true,
		wantGame: true,
	}, {
		// The same grant at a server that does not own capture. Genuinely
		// unsupported — and said so with the cause, because "unsupported" alone is
		// indistinguishable from a missing sensor.
		name:       "non-owner that granted capture",
		sc:         cfg.Servers[1],
		wantReason: gs.ReasonOwnedByAnotherServer,
	}, {
		// A non-owner that never asked. Nothing was withheld from it, so there is
		// nothing to explain.
		name: "non-owner that granted no game permission",
		sc:   ServerConfig{Name: "work", URL: "https://work.example", Policy: &noGame},
	}} {
		t.Run(tt.name, func(t *testing.T) {
			v, report := viewsFor(cfg, tt.sc, tt.owns, caps)

			for _, id := range gameIDs {
				if got := v.supported.Has(id); got != tt.wantGame {
					t.Errorf("supported.Has(%s) = %v, want %v (supported = [%s])", id, got, tt.wantGame, join(v.supported))
				}
				if got := v.effective.Has(id); got != tt.wantGame {
					t.Errorf("effective.Has(%s) = %v, want %v (effective = [%s])", id, got, tt.wantGame, join(v.effective))
				}
			}
			// The report is what the server is actually told, so it has to agree
			// with the views rather than merely be derived from them.
			for _, id := range gameIDs {
				if slices.Contains(report.Supported, string(id)) != tt.wantGame {
					t.Errorf("report.Supported = %v, want %s present=%v", report.Supported, id, tt.wantGame)
				}
			}

			if tt.wantReason == "" {
				if len(report.UnsupportedReasons) != 0 {
					t.Fatalf("UnsupportedReasons = %v, want no entry at all", report.UnsupportedReasons)
				}
				return
			}
			for _, id := range gameIDs {
				if got := report.UnsupportedReasons[string(id)]; got != tt.wantReason {
					t.Errorf("reason for %s = %q, want %q", id, got, tt.wantReason)
				}
			}
			// And nothing beyond the three: the map explains what was asked about
			// and withheld, not whatever else happens to be unsupported.
			if len(report.UnsupportedReasons) != len(gameIDs) {
				t.Errorf("UnsupportedReasons = %v, want exactly the %d game permissions",
					report.UnsupportedReasons, len(gameIDs))
			}
		})
	}
}
