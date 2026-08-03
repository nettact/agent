package collector

import (
	"context"
	"errors"
	"time"

	"github.com/nettact/agent/internal/platform"
	"github.com/nettact/protocol/telemetry"
)

// InterfaceCollector reports NIC/IP/gateway/DNS state plus per-adapter Wi-Fi
// status (architecture §2.1 local layer / §4 wireless layer). Each round it
// emits an iface.up metric per interface, the Wi-Fi numeric metrics per wireless
// adapter, and one authoritative InterfaceSnapshot — the full interface set plus
// the collection-level Wi-Fi verdict.
//
// Field disclosure is permission-gated: addresses/gateway/DNS are populated only
// under network.interface.address.read; Wi-Fi status is read from the OS only
// under network.wifi.status.read; and the SSID is disclosed only under
// network.wifi.ssid.read. Registration itself requires
// network.interface.status.read.
type InterfaceCollector struct {
	p             platform.Platform
	reportAddr    bool
	reportGateway bool
	reportWiFi    bool
	reportSSID    bool
}

func NewInterfaceCollector(p platform.Platform, reportAddr, reportGateway, reportWiFi, reportSSID bool) *InterfaceCollector {
	return &InterfaceCollector{
		p: p, reportAddr: reportAddr, reportGateway: reportGateway,
		reportWiFi: reportWiFi, reportSSID: reportSSID,
	}
}

func (c *InterfaceCollector) Name() string { return "interface" }

func (c *InterfaceCollector) Tier() Tier { return TierRegular }

func (c *InterfaceCollector) Collect(ctx context.Context) (Result, error) {
	// Address/gateway/DNS are read from the OS only under the address-read
	// permission; when denied, the platform never reads them (no read-then-redact).
	ifaces, err := c.p.Interfaces(platform.IfaceQuery{
		Addrs:    c.reportAddr,
		Gateways: c.reportGateway,
		DNS:      c.reportAddr,
	})
	if err != nil && !errors.Is(err, platform.ErrRoutesUnreadable) {
		// Total enumeration failure — the scheduler skips the round. Wi-Fi
		// classification never blocks interface reporting.
		return Result{}, err
	}
	// An unreadable routing table is partial, not fatal: every interface row is
	// still populated and worth reporting; only the default route is unknown, and
	// resolveIPv4Gateway finds nothing below, so DefaultRoute stays absent.
	// Wi-Fi status is read from the OS only when granted; otherwise the subsystem
	// is never queried and every row stays wired-shaped.
	var wr platform.WiFiResult
	if c.reportWiFi {
		wr = c.p.WiFi(c.reportSSID)
	} else {
		wr = platform.WiFiResult{State: "ok"}
	}
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
	if c.reportGateway {
		if gateway, interfaceName := platform.ResolveIPv4Gateway(ifaces, ""); gateway != "" {
			snap.DefaultRoute = &telemetry.SnapshotRoute{Gateway: gateway, Interface: interfaceName}
		}
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
			Up:         ifc.Up,
			IsWireless: ifc.IsWireless,
		}
		// Addresses/DNS require address-read. Gateway disclosure is also allowed
		// by the gateway-probe permission because that collector already resolves
		// and probes the same OS route.
		if c.reportAddr {
			st.Addrs = ifc.Addrs
			st.DNS = ifc.DNS
		}
		if c.reportGateway && ifc.IPv4Default != nil {
			// The next hop of this NIC's preferred IPv4 default route — the same fact
			// the snapshot's DefaultRoute names, from the same routing table entry.
			// Reporting "the first gateway the OS listed" instead put the IPv6 gateway
			// of a dual-stack NIC in this field, and the console could no longer match
			// the row against the IPv4 default route beside it.
			st.Gateway = ifc.IPv4Default.Gateway
		}

		if a, ok := adapterByID[ifc.ID]; ok {
			st.IsWireless = true // a matched Wi-Fi adapter always marks the row wireless (covers macOS)
			st.WiFi = c.wifiInfoFromStatus(a)
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

// wifiInfoFromStatus builds the categorical WiFiInfo for a snapshot row. SSID is
// disclosed only under the ssid-read permission (band/channel are carried when
// connected). Disconnected/unreadable samples carry these empty by construction.
func (c *InterfaceCollector) wifiInfoFromStatus(a platform.WiFiStatus) *telemetry.WiFiInfo {
	info := &telemetry.WiFiInfo{
		State:  telemetry.WiFiLinkState(a.State),
		Reason: telemetry.WiFiReason(a.Reason),
	}
	if a.State == string(telemetry.WiFiConnected) {
		if c.reportSSID {
			info.SSID = a.SSID
		}
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
