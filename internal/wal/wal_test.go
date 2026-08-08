//go:build !lite

package wal

import (
	"math"
	"path/filepath"
	"testing"
	"time"

	"github.com/nettact/protocol/telemetry"
)

func TestNextBatchKeepsCollectorResultWhole(t *testing.T) {
	s, err := Open(filepath.Join(tempWALDir(t), "wal"), []string{srvA}, Options{})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	now := time.Now().UTC()
	metrics := []telemetry.Metric{
		{TS: now, Kind: telemetry.IfaceUp, Target: "wlan0", Value: 1},
		{TS: now, Kind: telemetry.WiFiSignalDBm, Target: "wlan0", Value: -55},
	}
	snaps := []telemetry.InterfaceSnapshot{{
		SampledAt: now, WiFiState: telemetry.WiFiCollectionOK,
		Interfaces: []telemetry.InterfaceState{{Name: "wlan0", IsWireless: true, WiFi: &telemetry.WiFiInfo{State: telemetry.WiFiConnected, SSID: "home"}}},
	}}
	if _, err := s.Append(Records{Metrics: metrics, Snapshots: snaps}, srvA); err != nil {
		t.Fatalf("Append: %v", err)
	}

	b, ok, err := s.NextBatch(srvA, 1) // boundary falls inside the three-row result
	if err != nil || !ok {
		t.Fatalf("NextBatch: ok=%v err=%v", ok, err)
	}
	if len(b.Metrics) != 2 || len(b.Snapshots) != 1 || !b.Snapshots[0].SampledAt.Equal(now) {
		t.Fatalf("collector result split: %+v", b)
	}
	b2, ok, err := s.NextBatch(srvA, 1)
	if err != nil || !ok || b2.Sequence != b.Sequence {
		// The unacked batch must be returned again with the same sequence.
		t.Fatalf("pending NextBatch: first=%d second=%d ok=%v err=%v", b.Sequence, b2.Sequence, ok, err)
	}
	if err := s.Ack(srvA, b.Sequence); err != nil {
		t.Fatalf("Ack: %v", err)
	}
	if _, ok, err := s.NextBatch(srvA, 1); err != nil || ok {
		t.Fatalf("after Ack: ok=%v err=%v", ok, err)
	}
}

func TestFastForwardPreservesInflightAndAdvancesNewBatches(t *testing.T) {
	s, err := Open(filepath.Join(tempWALDir(t), "wal"), []string{srvA}, Options{})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	metric := func(v float64) []telemetry.Metric {
		return []telemetry.Metric{{TS: time.Now().UTC(), Kind: telemetry.AgentUptime, Target: "agent", Value: v}}
	}

	if _, err := s.Append(Records{Metrics: metric(1)}, srvA); err != nil {
		t.Fatal(err)
	}
	first, ok, err := s.NextBatch(srvA, 10)
	if err != nil || !ok || first.Sequence != 1 {
		t.Fatalf("first batch=%+v ok=%v err=%v", first, ok, err)
	}
	if err := s.FastForward(33711); err != nil {
		t.Fatalf("FastForward: %v", err)
	}
	// Fast-forwarding only changes the allocator. The already-tagged batch must
	// remain sequence 1 until it is acknowledged.
	retry, ok, err := s.NextBatch(srvA, 10)
	if err != nil || !ok || retry.Sequence != first.Sequence {
		t.Fatalf("in-flight batch renumbered: first=%d retry=%d ok=%v err=%v", first.Sequence, retry.Sequence, ok, err)
	}
	if err := s.Ack(srvA, first.Sequence); err != nil {
		t.Fatal(err)
	}

	if _, err := s.Append(Records{Metrics: metric(2)}, srvA); err != nil {
		t.Fatal(err)
	}
	advanced, ok, err := s.NextBatch(srvA, 10)
	if err != nil || !ok || advanced.Sequence != 33712 {
		t.Fatalf("advanced batch=%+v ok=%v err=%v", advanced, ok, err)
	}
	if err := s.Ack(srvA, advanced.Sequence); err != nil {
		t.Fatal(err)
	}

	// A lower watermark is a no-op; the allocator continues monotonically.
	if err := s.FastForward(50); err != nil {
		t.Fatalf("lower FastForward: %v", err)
	}
	if _, err := s.Append(Records{Metrics: metric(3)}, srvA); err != nil {
		t.Fatal(err)
	}
	next, ok, err := s.NextBatch(srvA, 10)
	if err != nil || !ok || next.Sequence != 33713 {
		t.Fatalf("next batch=%+v ok=%v err=%v", next, ok, err)
	}

	if err := s.FastForward(math.MaxUint64); err == nil {
		t.Fatal("FastForward(MaxUint64) succeeded; want explicit overflow error")
	}
}
