package collector

import (
	"context"
	"testing"

	"github.com/nettact/agent/internal/platform"
	"github.com/nettact/protocol/permission"
	"github.com/nettact/protocol/telemetry"
)

type ifaceTestPlatform struct {
	ifaces []platform.IfaceInfo
	wifi   platform.WiFiResult
	err    error
}

func (p ifaceTestPlatform) Interfaces(platform.IfaceQuery) ([]platform.IfaceInfo, error) {
	return p.ifaces, p.err
}
func (p ifaceTestPlatform) WiFi(includeSSID bool) platform.WiFiResult { return p.wifi }
func (p ifaceTestPlatform) Ping(context.Context, string, platform.PingOptions) (platform.PingResult, error) {
	return platform.PingResult{}, nil
}
func (p ifaceTestPlatform) Neighbors() ([]platform.Neighbor, error) { return nil, nil }
func (p ifaceTestPlatform) Supports() permission.Set                { return nil }

func intPtr(v int) *int           { return &v }
func floatPtr(v float64) *float64 { return &v }

func TestInterfaceCollectorAuthoritativeWiFiSnapshot(t *testing.T) {
	p := ifaceTestPlatform{
		ifaces: []platform.IfaceInfo{
			{ID: "lo", Name: "lo", IsLoopback: true, Up: true},
			{ID: "eth", Name: "eth0", Up: true, Gateways: []string{"192.168.1.1"}},
			{ID: "wifi-id", Name: "wlan0", Up: true, IsWireless: true, Addrs: []string{"192.168.1.2/24"}, Gateways: []string{"10.0.0.1"}},
		},
		wifi: platform.WiFiResult{State: "ok", Adapters: []platform.WiFiStatus{{
			ID: "wifi-id", Name: "wlan0", State: "connected", SSID: "home", Band: "5", Channel: 36,
			SignalDBm: intPtr(-55), Quality: intPtr(90), RxMbps: floatPtr(432.1), TxMbps: floatPtr(866.7),
		}}},
	}
	res, err := NewInterfaceCollector(p, true, true, true, true).Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if res.InterfaceSnapshot == nil || len(res.InterfaceSnapshot.Interfaces) != 2 {
		t.Fatalf("snapshot=%+v", res.InterfaceSnapshot)
	}
	if route := res.InterfaceSnapshot.DefaultRoute; route == nil || route.Gateway != "192.168.1.1" || route.Interface != "eth0" {
		t.Fatalf("default route=%+v, want eth0 via 192.168.1.1", route)
	}
	if len(res.Inventory) != 0 {
		t.Fatalf("interface collector emitted obsolete inventory deltas: %+v", res.Inventory)
	}
	var wifi *telemetry.InterfaceState
	for i := range res.InterfaceSnapshot.Interfaces {
		if res.InterfaceSnapshot.Interfaces[i].Name == "wlan0" {
			wifi = &res.InterfaceSnapshot.Interfaces[i]
		}
	}
	if wifi == nil || wifi.WiFi == nil || wifi.WiFi.State != telemetry.WiFiConnected || wifi.WiFi.SSID != "home" {
		t.Fatalf("wireless row=%+v", wifi)
	}
	want := map[telemetry.MetricKind]float64{
		telemetry.WiFiUp: 1, telemetry.WiFiSignalDBm: -55, telemetry.WiFiQualityPct: 90,
		telemetry.WiFiLinkRxMbps: 432.1, telemetry.WiFiLinkTxMbps: 866.7,
	}
	for _, m := range res.Metrics {
		if m.Target != "wlan0" || m.Kind == telemetry.IfaceUp {
			continue
		}
		if m.Layer != telemetry.LayerWireless || want[m.Kind] != m.Value || !m.TS.Equal(res.InterfaceSnapshot.SampledAt) {
			t.Errorf("Wi-Fi metric=%+v", m)
		}
		delete(want, m.Kind)
	}
	if len(want) != 0 {
		t.Fatalf("missing Wi-Fi metrics: %+v", want)
	}
}

func TestInterfaceCollectorMissingAdapterAndDisconnectedMetrics(t *testing.T) {
	missing := ifaceTestPlatform{
		ifaces: []platform.IfaceInfo{{ID: "w", Name: "wlan0", IsWireless: true}},
		wifi:   platform.WiFiResult{State: "ok"},
	}
	res, err := NewInterfaceCollector(missing, true, true, true, true).Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	w := res.InterfaceSnapshot.Interfaces[0].WiFi
	if w == nil || w.State != telemetry.WiFiUnreadable || w.Reason != telemetry.WiFiReasonDriver {
		t.Fatalf("missing adapter status=%+v", w)
	}
	for _, m := range res.Metrics {
		if m.Kind == telemetry.WiFiUp {
			t.Fatal("unreadable adapter emitted wifi.up")
		}
	}

	disconnected := missing
	disconnected.wifi.Adapters = []platform.WiFiStatus{{ID: "w", Name: "wlan0", State: "disconnected", SSID: "stale", Band: "5", Channel: 36}}
	res, err = NewInterfaceCollector(disconnected, true, true, true, true).Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	w = res.InterfaceSnapshot.Interfaces[0].WiFi
	if w.State != telemetry.WiFiDisconnected || w.SSID != "" || w.Band != "" || w.Channel != 0 {
		t.Fatalf("disconnect retained categorical details: %+v", w)
	}
	foundDown := false
	for _, m := range res.Metrics {
		if m.Kind == telemetry.WiFiUp && m.Value == 0 {
			foundDown = true
		}
	}
	if !foundDown {
		t.Fatal("disconnected adapter did not emit wifi.up=0")
	}
}
