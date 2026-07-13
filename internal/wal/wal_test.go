package wal

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/nettact/protocol/telemetry"
)

func TestNextBatchKeepsCollectorResultWhole(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "wal.db"))
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
	if _, err := s.Append(metrics, nil, nil, snaps); err != nil {
		t.Fatalf("Append: %v", err)
	}

	b, ok, err := s.NextBatch(1) // boundary falls inside the three-row result
	if err != nil || !ok {
		t.Fatalf("NextBatch: ok=%v err=%v", ok, err)
	}
	if len(b.Metrics) != 2 || len(b.Snapshots) != 1 || !b.Snapshots[0].SampledAt.Equal(now) {
		t.Fatalf("collector result split: %+v", b)
	}
	b2, ok, err := s.NextBatch(1)
	if err != nil || !ok || b2.Sequence != b.Sequence {
		// The unacked batch must be returned again with the same sequence.
		t.Fatalf("pending NextBatch: first=%d second=%d ok=%v err=%v", b.Sequence, b2.Sequence, ok, err)
	}
	if err := s.Ack(b.Sequence); err != nil {
		t.Fatalf("Ack: %v", err)
	}
	if _, ok, err := s.NextBatch(1); err != nil || ok {
		t.Fatalf("after Ack: ok=%v err=%v", ok, err)
	}
}
