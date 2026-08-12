package collector

import (
	"fmt"
	"hash/fnv"
	"sync"
)

// flowHistory keeps each monitor's previous fan-out outcomes. TCP and HTTP
// collectors own separate instances, so equal monitor ids cannot share state:
// a TCP connection outcome and a complete HTTP acceptance outcome are different
// evidence even when both probes happen to use the same monitor id.
type flowHistory struct {
	mu   sync.Mutex
	prev map[string]flowPrevState
}

type flowPrevState struct {
	serial int
	bad    []bool
}

func newFlowHistory() *flowHistory {
	return &flowHistory{prev: map[string]flowPrevState{}}
}

// flowPorts derives a stable consecutive source-port set. Including the config
// serial gives a materially edited target a fresh set and fresh history.
func flowPorts(targetIP string, port int, monitorID string, configSerial, n int) []int {
	h := fnv.New32a()
	_, _ = h.Write([]byte(fmt.Sprintf("%s:%d:%s:%d", targetIP, port, monitorID, configSerial)))
	base := 10000 + int(h.Sum32()%22000)
	out := make([]int, n)
	for i := range out {
		out[i] = base + i
	}
	return out
}

func classifyFlowFanout(flows, badStable, badNew int) int {
	switch {
	case flows < 2:
		return 4
	case badStable == flows && badNew == 0:
		return 3
	case badStable > 0 && badStable+badNew < flows:
		return 2
	default:
		return 1
	}
}

// outcome folds one cycle into the classifier labels and advances history.
// Unattempted branches are absent from all counts because they are not evidence.
func (h *flowHistory) outcome(monitorID string, configSerial int, attempted, bad []bool) (code, flows, badStable, badNew, okCount int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	prev, have := h.prev[monitorID]
	if !have || prev.serial != configSerial {
		prev = flowPrevState{}
	}
	next := make([]bool, len(attempted))
	for i := range attempted {
		if !attempted[i] {
			continue
		}
		flows++
		prevBad := i < len(prev.bad) && prev.bad[i]
		next[i] = bad[i]
		switch {
		case bad[i] && prevBad:
			badStable++
		case bad[i]:
			badNew++
		case !prevBad:
			okCount++
		}
	}
	h.prev[monitorID] = flowPrevState{serial: configSerial, bad: next}
	return classifyFlowFanout(flows, badStable, badNew), flows, badStable, badNew, okCount
}
