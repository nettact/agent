package agentrt

import (
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
