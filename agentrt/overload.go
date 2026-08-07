package agentrt

import (
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/nettact/protocol/telemetry"
)

// probeOverloadWindow is how often at most the agent reports that its probe
// budget refused work.
//
// It is deliberately much longer than the heartbeat's own 30s tick. The
// condition it reports is not transient and not per-round: an agent configured
// with more probing than max_probe_concurrency can serve stays overloaded until
// someone changes one of the two. Emitting on every heartbeat would put 120
// events an hour, per server, behind a single fact the operator has already
// either acted on or decided to live with — and would bury the events that do
// need attention.
//
// Five minutes also gives the count something to say. "37 probes refused in the
// last 5 minutes" is a magnitude someone can size a limit against; "1 refused in
// the last 30 seconds" is noise with a number attached.
const probeOverloadWindow = 5 * time.Minute

// probeOverloadEvent reports that the machine's probe budget turned work away.
//
// It explains rather than detects. A probe that never ran leaves no sample, so
// the monitor goes stale on its own and the server says so; what nothing else
// can say is that the cause was this agent running out of probe budget rather
// than the network going away. The attributes carry the magnitude, the window it
// covers, and the limit it was competing for — the three things needed to decide
// whether to raise max_probe_concurrency or to probe less.
func probeOverloadEvent(now time.Time, refused int, window time.Duration, limit int) telemetry.Event {
	return telemetry.Event{
		ID:       uuid.NewString(),
		TS:       now,
		Type:     telemetry.EventProbeOverload,
		Layer:    telemetry.LayerLocal,
		Severity: telemetry.SeverityWarn,
		Message:  "probe concurrency limit reached: " + strconv.Itoa(refused) + " probes were skipped",
		Attrs: map[string]string{
			telemetry.ProbeOverloadAbandonedLabel: strconv.Itoa(refused),
			telemetry.ProbeOverloadWindowLabel:    strconv.Itoa(int(window.Round(time.Second).Seconds())),
			telemetry.ProbeOverloadLimitLabel:     strconv.Itoa(limit),
		},
	}
}
