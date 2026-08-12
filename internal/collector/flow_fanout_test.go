package collector

import "testing"

func TestClassifyFlowFanout(t *testing.T) {
	tests := []struct {
		name                    string
		flows, badStable, badNew int
		want                    int
	}{
		{name: "no flow ran", want: 4},
		{name: "one flow ran", flows: 1, want: 4},
		{name: "every flow failed and stable", flows: 3, badStable: 3, want: 3},
		{name: "one stable bad member", flows: 4, badStable: 1, want: 2},
		{name: "stable member plus flapping", flows: 4, badStable: 1, badNew: 1, want: 2},
		{name: "all flows clean", flows: 3, want: 1},
		{name: "bad subset but flapping", flows: 4, badNew: 2, want: 1},
		{name: "every flow failed but flapping", flows: 3, badNew: 3, want: 1},
		{name: "some clean, some new", flows: 3, badNew: 1, want: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := classifyFlowFanout(tt.flows, tt.badStable, tt.badNew); got != tt.want {
				t.Fatalf("classifyFlowFanout(%d, %d, %d) = %d, want %d",
					tt.flows, tt.badStable, tt.badNew, got, tt.want)
			}
		})
	}
}

func TestFlowPortsPinsDerivedSet(t *testing.T) {
	got := flowPorts("1.1.1.1", 443, "m1", 5, 4)
	want := []int{26875, 26876, 26877, 26878}
	if len(got) != len(want) {
		t.Fatalf("flowPorts returned %d ports, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("flowPorts = %v, want %v", got, want)
		}
	}
	if got[0] < 10000 || got[len(got)-1] > 65535 {
		t.Fatalf("flowPorts out of the source-port range: %v", got)
	}
	again := flowPorts("1.1.1.1", 443, "m1", 5, 4)
	for i := range again {
		if again[i] != got[i] {
			t.Fatalf("flowPorts not deterministic: %v vs %v", got, again)
		}
	}
	if changed := flowPorts("1.1.1.1", 443, "m1", 6, 4); changed[0] == got[0] {
		t.Fatalf("flowPorts ignored the config serial: %v vs %v", got, changed)
	}
	if other := flowPorts("1.1.1.1", 443, "m2", 5, 4); other[0] == got[0] {
		t.Fatalf("flowPorts ignored the monitor id: %v vs %v", got, other)
	}
}

func TestFlowHistoryOutcome(t *testing.T) {
	history := newFlowHistory()
	all := []bool{true, true, true, true}
	partial := []bool{false, true, true, false}
	bad := []bool{false, false, true, false}
	clean := []bool{false, false, false, false}
	tests := []struct {
		name                 string
		serial               int
		attempted, bad        []bool
		code, flows           int
		badStable, badNew, ok int
	}{
		{name: "new bad branch", serial: 5, attempted: all, bad: bad, code: 1, flows: 4, badNew: 1, ok: 3},
		{name: "stable bad branch", serial: 5, attempted: all, bad: bad, code: 2, flows: 4, badStable: 1, ok: 3},
		{name: "first clean read after recovery", serial: 5, attempted: all, bad: clean, code: 1, flows: 4, ok: 3},
		{name: "unattempted branches carry no verdict", serial: 5, attempted: partial, bad: clean, code: 1, flows: 2, ok: 2},
		{name: "config serial resets history", serial: 6, attempted: all, bad: bad, code: 1, flows: 4, badNew: 1, ok: 3},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, flows, badStable, badNew, ok := history.outcome("m1", tt.serial, tt.attempted, tt.bad)
			if code != tt.code || flows != tt.flows || badStable != tt.badStable || badNew != tt.badNew || ok != tt.ok {
				t.Fatalf("outcome = %d/%d/%d/%d/%d, want %d/%d/%d/%d/%d",
					code, flows, badStable, badNew, ok, tt.code, tt.flows, tt.badStable, tt.badNew, tt.ok)
			}
		})
	}
}
