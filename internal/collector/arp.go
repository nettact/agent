package collector

import (
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/nettact/agent/internal/platform"
	"github.com/nettact/protocol/capability"
	"github.com/nettact/protocol/telemetry"
)

// ARPCollector performs passive LAN device discovery from the ARP/neighbor
// table (architecture §3.1). No packet capture — just reading the OS table.
type ARPCollector struct {
	p platform.Platform
}

func NewARPCollector(p platform.Platform) *ARPCollector { return &ARPCollector{p: p} }

func (c *ARPCollector) Name() string { return "arp" }

func (c *ARPCollector) Capabilities() []capability.Capability {
	return []capability.Capability{capability.InventoryARP}
}

func (c *ARPCollector) Tier() Tier { return TierRegular }

func (c *ARPCollector) Collect(ctx context.Context) (Result, error) {
	neighbors, err := c.p.Neighbors()
	if err != nil {
		return Result{}, err
	}
	now := time.Now().UTC()
	var res Result
	for _, n := range neighbors {
		if !usableMAC(n.MAC) {
			continue
		}
		res.Inventory = append(res.Inventory, telemetry.InventoryItem{
			Kind:     telemetry.InventoryDevice,
			Op:       telemetry.OpUpsert,
			ID:       n.MAC,
			MAC:      n.MAC,
			IP:       n.IP,
			LastSeen: now,
		})
	}
	return res, nil
}

// usableMAC skips broadcast, multicast and all-zero addresses.
func usableMAC(mac string) bool {
	mac = strings.ToLower(strings.TrimSpace(mac))
	if mac == "" || mac == "ff:ff:ff:ff:ff:ff" || mac == "00:00:00:00:00:00" || len(mac) < 2 {
		return false
	}
	// multicast: least-significant bit of the first octet is set
	if first, err := strconv.ParseUint(mac[:2], 16, 8); err == nil && first&1 == 1 {
		return false
	}
	return true
}
