package collector

import (
	"context"
	"testing"
	"time"

	"github.com/nettact/agent/internal/netguard"
	"github.com/nettact/agent/probepolicy"
	pcfg "github.com/nettact/protocol/config"
)

func newTestNATCollector() *NATCollector {
	return NewNATCollector(netguard.New(probepolicy.Policy{}, true), nil, nil)
}

// observe is one completed discovery of addr, as commitMapped receives it.
func observe(addr string) mappedObservation {
	return mappedObservation{seen: true, transport: "udp", addr: addr, ts: time.Unix(1000, 0).UTC()}
}

// Two rounds for one monitor overlap whenever a target leaves and re-enters the
// runnable set, and a NAT round is long enough (a 25s deadline) that the earlier
// one can finish last. Letting it write would rewind the change gate to an
// address the newer run has already superseded, so the next round reports a WAN
// IP change that never happened.
//
// Note the tokens, not config serials: the case that produces the overlap is
// precisely the one where both rounds carry the SAME generation, because
// schedKey includes the serial — a differing serial is a different key.
func TestNATChangeGateIgnoresALateEarlierRun(t *testing.T) {
	c := newTestNATCollector()

	if !c.commitMapped("n1", "stun.example", 1, observe("203.0.113.10:1234")) {
		t.Fatal("the first sighting should report a change")
	}
	if c.commitMapped("n1", "stun.example", 2, observe("203.0.113.10:1234")) {
		t.Fatal("an unchanged address reported a change")
	}
	// A run that STARTED earlier finishes last, carrying its older observation.
	if c.commitMapped("n1", "stun.example", 1, observe("198.51.100.7:5678")) {
		t.Fatal("an earlier run reported a WAN IP change out of order")
	}
	// The state must still hold the newer run's address, so a genuine change is
	// still detected — and a repeat of it is still not.
	if !c.commitMapped("n1", "stun.example", 3, observe("198.51.100.7:5678")) {
		t.Fatal("a real address change after an out-of-order write was missed")
	}
	if c.commitMapped("n1", "stun.example", 4, observe("198.51.100.7:5678")) {
		t.Fatal("the new address was not recorded")
	}
}

// The run token must NOT be part of the map key — keyed by it, every round would
// be a first sighting, and a first sighting emits, so a stable address would
// announce a change every round.
func TestNATChangeGateIsStableAcrossRuns(t *testing.T) {
	c := newTestNATCollector()

	c.commitMapped("n1", "stun.example", 1, observe("203.0.113.10:1234"))
	for token := int64(2); token < 6; token++ {
		if c.commitMapped("n1", "stun.example", token, observe("203.0.113.10:1234")) {
			t.Fatalf("token %d reported a change on an unchanged address", token)
		}
	}
	if !c.commitMapped("n1", "stun.example", 6, observe("198.51.100.7:5678")) {
		t.Fatal("a real address change was missed after several stable rounds")
	}
}

// Two monitors probing the same STUN server keep independent gates, and so do
// two transports of one monitor.
func TestNATChangeGateIsPerMonitorAndTransport(t *testing.T) {
	c := newTestNATCollector()

	if !c.commitMapped("n1", "stun.example", 1, observe("203.0.113.10:1234")) {
		t.Fatal("monitor a's first sighting should report a change")
	}
	if !c.commitMapped("n2", "stun.example", 2, observe("203.0.113.10:1234")) {
		t.Fatal("monitor b's first sighting must not be masked by monitor a")
	}
	tcp := observe("203.0.113.10:1234")
	tcp.transport = "tcp"
	if !c.commitMapped("n1", "stun.example", 3, tcp) {
		t.Fatal("a second transport's first sighting must not be masked by the first")
	}
}

// A round that produced no reflexive address never reports a change — there is
// nothing to have changed to.
func TestNATChangeGateIgnoresAnEmptyAddress(t *testing.T) {
	c := newTestNATCollector()

	if c.commitMapped("n1", "stun.example", 1, observe("")) {
		t.Fatal("an empty mapped address reported a change")
	}
	if !c.commitMapped("n1", "stun.example", 2, observe("203.0.113.10:1234")) {
		t.Fatal("the first real address after an empty one should report a change")
	}
}

// The gate must only advance for a round that is actually published: the runner
// discards the Result of a cancelled run, so a commit made INSIDE the discovery
// would advance the gate past an event that went in the bin — and the next
// round, seeing no difference, would never report the change at all.
//
// The structural half of that guarantee is testable without a STUN server:
// probeNAT must not write the gate at all. It only records into the observation,
// and runTarget commits after it has decided to keep the round.
func TestProbeNATDoesNotAdvanceTheChangeGate(t *testing.T) {
	c := newTestNATCollector()
	target := pcfg.ProbeTarget{MonitorID: "n1", Kind: "nat", Target: "192.0.2.1",
		Params: pcfg.ProbeParams{NATTransport: "udp", TimeoutMs: 50, GlobalTimeoutMs: 150}}

	var res Result
	var obs mappedObservation
	c.probeNAT(context.Background(), time.Now().UTC(), target, &res, &obs)

	c.mu.Lock()
	n := len(c.lastMapped)
	c.mu.Unlock()
	if n != 0 {
		t.Fatalf("probeNAT wrote the change gate directly (%d entries) — a discarded round would advance it", n)
	}
}
