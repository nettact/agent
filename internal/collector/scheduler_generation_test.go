package collector

import (
	"testing"
	"time"

	pcfg "github.com/nettact/protocol/config"
)

func TestSchedStateTreatsNewGenerationAsImmediatelyDue(t *testing.T) {
	s := newSchedState(30 * time.Minute)
	now := time.Unix(1000, 0)
	target := pcfg.ProbeTarget{
		MonitorID: "monitor-a", Kind: "nat", Target: "stun.example.test", ConfigSerial: 7,
	}
	s.set([]pcfg.ProbeTarget{target})
	if got := s.due(now); len(got) != 1 || got[0].ConfigSerial != 7 {
		t.Fatalf("first due = %+v, want generation 7", got)
	}
	if got := s.due(now.Add(time.Second)); len(got) != 0 {
		t.Fatalf("same generation became due early: %+v", got)
	}

	target.ConfigSerial = 8
	s.set([]pcfg.ProbeTarget{target})
	if got := s.due(now.Add(2 * time.Second)); len(got) != 1 || got[0].ConfigSerial != 8 {
		t.Fatalf("new generation due = %+v, want immediate generation 8", got)
	}
}
