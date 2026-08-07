package agentrt

import (
	"strconv"
	"testing"
	"time"

	"github.com/nettact/protocol/telemetry"
)

// The overload event's whole job is to explain a silence, so the figures a user
// needs to act on it — how many probes were skipped, over what window, against
// what limit — are a wire contract, not decoration.
func TestProbeOverloadEventCarriesActionableAttributes(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	ev := probeOverloadEvent(now, 37, 5*time.Minute, 16)

	if ev.Type != telemetry.EventProbeOverload {
		t.Fatalf("type = %q, want %q", ev.Type, telemetry.EventProbeOverload)
	}
	if ev.ID == "" {
		t.Error("event has no id — the server dedups on (agent, id)")
	}
	if !ev.TS.Equal(now) {
		t.Errorf("ts = %v, want %v", ev.TS, now)
	}
	if ev.Severity != telemetry.SeverityWarn {
		t.Errorf("severity = %q, want warn", ev.Severity)
	}
	if ev.Layer != telemetry.LayerLocal {
		t.Errorf("layer = %q, want local — the exhausted budget is this host's", ev.Layer)
	}
	for label, want := range map[string]string{
		telemetry.ProbeOverloadAbandonedLabel: "37",
		telemetry.ProbeOverloadWindowLabel:    "300",
		telemetry.ProbeOverloadLimitLabel:     "16",
	} {
		if got := ev.Attrs[label]; got != want {
			t.Errorf("attr %q = %q, want %q", label, got, want)
		}
	}
	// The count belongs in the message too: a console that renders only messages
	// must still convey the magnitude.
	if ev.Message == "" || !containsCount(ev.Message, 37) {
		t.Errorf("message %q does not state how many probes were skipped", ev.Message)
	}
}

func containsCount(msg string, n int) bool {
	needle := strconv.Itoa(n)
	for i := 0; i+len(needle) <= len(msg); i++ {
		if msg[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}

// The aggregation window has to be well clear of the heartbeat's own tick, or
// sustained overload puts an event on every heartbeat to repeat one fact.
func TestProbeOverloadWindowIsCoarserThanTheHeartbeat(t *testing.T) {
	if probeOverloadWindow <= 30*time.Second {
		t.Fatalf("probeOverloadWindow = %v, want well above the 30s heartbeat tick", probeOverloadWindow)
	}
}
