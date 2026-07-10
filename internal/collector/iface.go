package collector

import (
	"context"
	"time"

	"github.com/nettact/agent/internal/platform"
	"github.com/nettact/protocol/capability"
	"github.com/nettact/protocol/telemetry"
)

// InterfaceCollector reports NIC/IP/gateway/DNS state: an iface.up metric per
// interface plus an interface inventory delta (architecture §2.1 local layer).
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
		return Result{}, err
	}
	now := time.Now().UTC()
	var res Result
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
		res.Inventory = append(res.Inventory, telemetry.InventoryItem{
			Kind:    telemetry.InventoryInterface,
			Op:      telemetry.OpUpsert,
			ID:      ifc.Name,
			Name:    ifc.Name,
			Addrs:   ifc.Addrs,
			Gateway: firstOr(ifc.Gateways),
			DNS:     ifc.DNS,
			Up:      ifc.Up,
		})
	}
	return res, nil
}

func firstOr(s []string) string {
	if len(s) > 0 {
		return s[0]
	}
	return ""
}
