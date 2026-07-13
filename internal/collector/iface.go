package collector

import (
	"context"
	"time"

	"github.com/nettact/agent/internal/platform"
	"github.com/nettact/protocol/capability"
	"github.com/nettact/protocol/telemetry"
)

// InterfaceCollector reports NIC/IP/gateway/DNS state plus per-adapter Wi-Fi
// status (architecture §2.1 local layer / §4 wireless layer). Each round it
// emits an iface.up metric per interface, the Wi-Fi numeric metrics per wireless
// adapter, and one authoritative InterfaceSnapshot — the full interface set plus
// the collection-level Wi-Fi verdict. The snapshot replaces the old per-interface
// inventory delta: the server reconciles the complete set every round, so adapter
// removal, agent restarts and the zero-interface case all converge by
// construction (no process-local previous-set).
type InterfaceCollector struct {
	p platform.Platform
}

func NewInterfaceCollector(p platform.Platform) *InterfaceCollector {
	return &InterfaceCollector{p: p}
}

func (c *InterfaceCollector) Name() string { return "interface" }

func (c *InterfaceCollector) Capabilities() []capability.Capability {
	return []capability.Capability{capability.NetIfaceRead, capability.NetRouteRead}
}

func (c *InterfaceCollector) Tier() Tier { return TierRegular }

func (c *InterfaceCollector) Collect(ctx context.Context) (Result, error) {
	ifaces, err := c.p.Interfaces()
	if err != nil {
		// Total enumeration failure is the only error path — the scheduler skips
		// the round. Wi-Fi classification never blocks interface reporting.
		return Result{}, err
	}
	wr := c.p.WiFi()
	now := time.Now().UTC()

	// Index adapters by stable ID (GUID on Windows, name elsewhere). Adapters not
	// matching any interface row this round are dropped (transient enumeration
	// race, consistent next round).
	adapterByID := make(map[string]platform.WiFiStatus, len(wr.Adapters))
	for _, a := range wr.Adapters {
		adapterByID[a.ID] = a
	}

	var res Result
	snap := &telemetry.InterfaceSnapshot{
		SampledAt:  now,
		WiFiState:  telemetry.WiFiCollectionState(wr.State),
		WiFiReason: telemetry.WiFiReason(wr.Reason),
		Interfaces: []telemetry.InterfaceState{}, // explicit empty: a zero-interface round still clears server rows
	}

	for _, ifc := range ifaces {
		if ifc.IsLoopback {
			continue
		}
		up := 0.0
		if ifc.Up {
			up = 1.0
		}
		res.Metrics = append(res.Metrics, telemetry.Metric{
			TS:     now,
			Kind:   telemetry.IfaceUp,
			Target: ifc.Name,
			Layer:  telemetry.LayerLocal,
			Value:  up,
			Unit:   telemetry.UnitBool,
		})

		st := telemetry.InterfaceState{
			Name:       ifc.Name,
			Addrs:      ifc.Addrs,
			Gateway:    firstOr(ifc.Gateways),
			DNS:        ifc.DNS,
			Up:         ifc.Up,
			IsWireless: ifc.IsWireless,
		}

		if a, ok := adapterByID[ifc.ID]; ok {
			st.IsWireless = true // a matched Wi-Fi adapter always marks the row wireless (covers macOS)
			st.WiFi = wifiInfoFromStatus(a)
			res.Metrics = append(res.Metrics, wifiMetrics(now, ifc.Name, a)...)
		} else if ifc.IsWireless && wr.State == "ok" {
			// Known wireless hardware with no adapter entry while collection
			// succeeded ⇒ this specific adapter was unreadable.
			st.WiFi = &telemetry.WiFiInfo{State: telemetry.WiFiUnreadable, Reason: telemetry.WiFiReasonDriver}
		}
		// Wired rows keep WiFi == nil.

		snap.Interfaces = append(snap.Interfaces, st)
	}

	res.InterfaceSnapshot = snap
	return res, nil
}

// wifiInfoFromStatus builds the categorical WiFiInfo for a snapshot row. SSID/
// band/channel are carried only when connected (disconnected/unreadable samples
// carry them empty by construction — this clears stale details).
func wifiInfoFromStatus(a platform.WiFiStatus) *telemetry.WiFiInfo {
	info := &telemetry.WiFiInfo{
		State:  telemetry.WiFiLinkState(a.State),
		Reason: telemetry.WiFiReason(a.Reason),
	}
	if a.State == string(telemetry.WiFiConnected) {
		info.SSID = a.SSID
		info.Band = telemetry.WiFiBand(a.Band)
		info.Channel = a.Channel
	}
	return info
}

// wifiMetrics emits the numeric Wi-Fi time series for one adapter. wifi.up is
// emitted only when the adapter is readable (an unreadable adapter yields NO
// sample — an honest chart gap). The link numerics are emitted only when
// connected AND the driver reported them (never inferred zeros).
func wifiMetrics(now time.Time, iface string, a platform.WiFiStatus) []telemetry.Metric {
	base := func(kind telemetry.MetricKind, value float64, unit string) telemetry.Metric {
		return telemetry.Metric{TS: now, Kind: kind, Target: iface, Layer: telemetry.LayerWireless, Value: value, Unit: unit}
	}
	var out []telemetry.Metric
	switch a.State {
	case string(telemetry.WiFiConnected):
		out = append(out, base(telemetry.WiFiUp, 1, telemetry.UnitBool))
		if a.SignalDBm != nil {
			out = append(out, base(telemetry.WiFiSignalDBm, float64(*a.SignalDBm), telemetry.UnitDBm))
		}
		if a.Quality != nil {
			out = append(out, base(telemetry.WiFiQualityPct, float64(*a.Quality), telemetry.UnitPct))
		}
		if a.RxMbps != nil {
			out = append(out, base(telemetry.WiFiLinkRxMbps, *a.RxMbps, telemetry.UnitMbps))
		}
		if a.TxMbps != nil {
			out = append(out, base(telemetry.WiFiLinkTxMbps, *a.TxMbps, telemetry.UnitMbps))
		}
	case string(telemetry.WiFiDisconnected):
		out = append(out, base(telemetry.WiFiUp, 0, telemetry.UnitBool))
	}
	// Unreadable: no wifi.up sample at all.
	return out
}

func firstOr(s []string) string {
	if len(s) > 0 {
		return s[0]
	}
	return ""
}
