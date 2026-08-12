package collector

import (
	"context"
	"math"
	"slices"
	"testing"
	"time"

	pcfg "github.com/nettact/protocol/config"
	"github.com/nettact/protocol/telemetry"
)

// TestClassifySizeSweep exercises the pure size-correlation classifier: whether
// ICMP loss rises with payload size (the physical-layer fingerprint), stays flat
// across sizes (the congestion signature), or the cycle collected too little
// evidence to say. The rule is deliberately conservative: correlation needs the
// large size to lose at least twice the small's rate, OR at least 25 points more,
// AND at least 20% on its own.
func TestClassifySizeSweep(t *testing.T) {
	cases := []struct {
		name                  string
		lossSmall, lossLarge  float64
		countSmall, countLarge int
		want                  int
	}{
		{"flat, both clean", 0, 0, 2, 2, 0},
		{"flat, both losing equally", 10, 10, 2, 2, 0},
		{"correlated: large is 2x small", 40, 90, 2, 2, 1},
		{"correlated: large exactly 2x small", 50, 100, 2, 2, 1},
		{"correlated: 2x small counts even when +25 does not", 20, 40, 2, 2, 1},
		{"correlated: large exceeds small by 25", 0, 26, 2, 2, 1},
		{"below both bars", 30, 40, 2, 2, 0}, // 40 < 2×30=60 and 40 < 30+25=55
		{"large under 20% is never correlated", 0, 19, 2, 2, 0},
		{"one echo per size is not evidence", 0, 100, 1, 1, 2},
		{"missing small count", 0, 100, 1, 2, 2},
		{"missing large count", 0, 100, 2, 1, 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifySizeSweep(tc.lossSmall, tc.lossLarge, tc.countSmall, tc.countLarge); got != tc.want {
				t.Fatalf("classifySizeSweep(%v, %v, %d, %d) = %d, want %d",
					tc.lossSmall, tc.lossLarge, tc.countSmall, tc.countLarge, got, tc.want)
			}
		})
	}
}

// TestPingCountSweepMultiplies pins the cycle-length contract a size sweep is
// built on: PingCount counts per-size echoes, so a sweeping cycle is PacketCount
// x len(SweepSizes) long — the length both the agent's pacing and the server's
// round-completeness check read from the same function.
func TestPingCountSweepMultiplies(t *testing.T) {
	base := pcfg.ProbeParams{PacketCount: 4}
	if got, want := pcfg.PingCount(base), 4; got != want {
		t.Fatalf("PingCount with sweep off = %d, want %d", got, want)
	}
	sweep := pcfg.ProbeParams{PacketCount: 4, SizeSweep: true}
	if got, want := pcfg.PingCount(sweep), 4*len(pcfg.DefaultSweepSizes); got != want {
		t.Fatalf("PingCount swept = %d, want %d (PacketCount x len(DefaultSweepSizes))", got, want)
	}
	custom := pcfg.ProbeParams{PacketCount: 4, SizeSweep: true, PayloadSizes: []int{100, 1500}}
	if got, want := pcfg.PingCount(custom), 8; got != want {
		t.Fatalf("PingCount custom sizes = %d, want %d (PacketCount x len(PayloadSizes))", got, want)
	}
}

// TestPingCycleSizeSweepRoundRobinsPayloads drives a whole sweeping cycle through
// the shared pingLoop and pins three things at once: the count is the multiplied
// PingCount, the echoes round-robin across the swept sizes, and the per-size
// tally agrees with what the platform was actually asked to send.
func TestPingCycleSizeSweepRoundRobinsPayloads(t *testing.T) {
	stubCycleClock(t)
	p := &gwTestPlatform{}
	params := pcfg.ProbeParams{SizeSweep: true, PacketCount: 2}
	r := pingCycle(context.Background(), p, "1.1.1.1", params, time.Now().Add(30*time.Second), nil)
	if want := pcfg.PingCount(params); r.Sent != want || r.Received != want {
		t.Fatalf("cycle sent %d/%d, want %d echoes (PacketCount x len(sizes))", r.Sent, r.Received, want)
	}
	wantSizes := []int{64, 512, 1232, 64, 512, 1232}
	if got := p.payloadSizes(); !slices.Equal(got, wantSizes) {
		t.Fatalf("payload sizes = %v, want %v (round-robin across the sweep)", got, wantSizes)
	}
	if len(r.Sweep) != 3 {
		t.Fatalf("cycle tallied %d sizes, want 3", len(r.Sweep))
	}
	for i, f := range r.Sweep {
		want := sizeSweepFact{Size: pcfg.DefaultSweepSizes[i], Sent: 2, Received: 2}
		if f != want {
			t.Fatalf("size %d tally = %+v, want %+v", i, f, want)
		}
	}
}

// TestPingCycleSizeSweepLossPerSize drops exactly the echoes carrying the largest
// swept size: the sweep's whole point is that the large size loses while the
// small ones stay clean — and the aggregate metrics stay over ALL echoes, exactly
// as a normal cycle's do.
func TestPingCycleSizeSweepLossPerSize(t *testing.T) {
	stubCycleClock(t)
	// recv drops echo indices 2 and 5, which are the two 1232B echoes.
	p := &gwTestPlatform{recv: func(seq int) bool { return seq%3 != 2 }}
	params := pcfg.ProbeParams{SizeSweep: true, PacketCount: 2}
	r := pingCycle(context.Background(), p, "1.1.1.1", params, time.Now().Add(30*time.Second), nil)
	if r.Sent != 6 || r.Received != 4 {
		t.Fatalf("cycle = sent %d received %d, want 6/4", r.Sent, r.Received)
	}
	if math.Abs(r.Loss-(100.0*2/6)) > 1e-9 {
		t.Fatalf("aggregate loss = %v, want %.1f (loss stays over ALL echoes)", r.Loss, 100.0*2/6)
	}
	want := []sizeSweepFact{
		{Size: 64, Sent: 2, Received: 2},
		{Size: 512, Sent: 2, Received: 2},
		{Size: 1232, Sent: 2, Received: 0},
	}
	for i := range want {
		if r.Sweep[i] != want[i] {
			t.Fatalf("size %d tally = %+v, want %+v", i, r.Sweep[i], want[i])
		}
	}
	// And the tally reduces to a size-correlated verdict: 100% at 1232B vs 0% at
	// 64B.
	code, _, ok := sizeSweepSample(r.Sweep)
	if !ok || code != 1 {
		t.Fatalf("sizeSweepSample = %d (ok=%v), want 1 (size-correlated)", code, ok)
	}
}

// TestAppendICMPMetricsSizeSweepEvidence pins the emitted sample: the value is
// the classifier code and the labels carry the compared sizes' evidence, merged
// onto the shared labels — while the sibling cycle metrics that ALIAS the shared
// map must never pick the size facts up.
func TestAppendICMPMetricsSizeSweepEvidence(t *testing.T) {
	var res Result
	now := time.Unix(1000, 0).UTC()
	r := pingCycleResult{
		Loss: 100.0 * 2 / 6, Sent: 6, Received: 4,
		Sweep: []sizeSweepFact{
			{Size: 64, Sent: 2, Received: 2},
			{Size: 512, Sent: 2, Received: 2},
			{Size: 1232, Sent: 2, Received: 0},
		},
	}
	appendICMPMetrics(&res, now, "m1", 3, "1.1.1.1", telemetry.LayerInternet,
		map[string]string{"ip": "1.1.1.1"}, r)
	ss := metricByKind(res, telemetry.ICMPSizeSweep)
	if ss == nil {
		t.Fatal("a sweeping cycle emitted no probe.icmp.size_sweep sample")
	}
	if ss.Value != 1 {
		t.Fatalf("size_sweep = %v, want 1 (1232B lost 100%%, small sizes 0%%)", ss.Value)
	}
	want := map[string]string{
		telemetry.SizeSmallLabel:  "64",
		telemetry.SizeLargeLabel:  "1232",
		telemetry.LossSmallLabel:  "0.0",
		telemetry.LossLargeLabel:  "100.0",
		telemetry.CountSmallLabel: "2",
		telemetry.CountLargeLabel: "2",
		"ip":                      "1.1.1.1",
	}
	if len(ss.Labels) != len(want) {
		t.Fatalf("size_sweep labels = %+v, want %d labels", ss.Labels, len(want))
	}
	for k, v := range want {
		if ss.Labels[k] != v {
			t.Fatalf("size_sweep label %s = %q, want %q (%+v)", k, ss.Labels[k], v, ss.Labels)
		}
	}
	for _, m := range res.Metrics {
		if m.Kind != telemetry.ICMPSizeSweep {
			if _, has := m.Labels[telemetry.LossLargeLabel]; has {
				t.Fatalf("size facts leaked onto %s's labels: %+v", m.Kind, m.Labels)
			}
		}
	}
}

// TestAppendICMPMetricsSizeSweepNoneWithoutSweep: a non-sweeping cycle must never
// emit a size_sweep sample — there is no per-size evidence to classify.
func TestAppendICMPMetricsSizeSweepNoneWithoutSweep(t *testing.T) {
	var res Result
	appendICMPMetrics(&res, time.Unix(1000, 0).UTC(), "m1", 3, "1.1.1.1", telemetry.LayerInternet, nil,
		pingCycleResult{Sent: 5, Received: 5})
	if m := metricByKind(res, telemetry.ICMPSizeSweep); m != nil {
		t.Fatalf("a non-sweeping cycle emitted a size_sweep sample: %+v", m)
	}
}

// TestSizeSweepSampleInsufficientEvidence: the reducer must refuse to fabricate a
// verdict when the cycle holds no usable evidence — a budget-truncated round that
// sent too few echoes per size, or one that sent nothing at all.
func TestSizeSweepSampleInsufficientEvidence(t *testing.T) {
	// One echo per compared size is code 2 (insufficient), not a size verdict.
	code, _, ok := sizeSweepSample([]sizeSweepFact{
		{Size: 64, Sent: 1, Received: 0},
		{Size: 1232, Sent: 1, Received: 0},
	})
	if !ok || code != 2 {
		t.Fatalf("sizeSweepSample over one-echo sizes = %d (ok=%v), want 2", code, ok)
	}
	// A size that was never attempted is not evidence at all.
	if _, _, ok := sizeSweepSample([]sizeSweepFact{
		{Size: 64, Sent: 0}, {Size: 512, Sent: 0}, {Size: 1232, Sent: 0},
	}); ok {
		t.Fatal("a cycle that sent no swept echo must not produce a sample")
	}
	if _, _, ok := sizeSweepSample(nil); ok {
		t.Fatal("an empty sweep must not produce a sample")
	}
}
