package collector

import (
	"context"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/nettact/agent/internal/platform"
	"github.com/nettact/protocol/capability"
	"github.com/nettact/protocol/telemetry"
)

// Reverse-DNS resolution tuning. LAN device sets are small, so a short per-lookup
// timeout with modest concurrency keeps a collection cycle snappy even when many
// neighbors lack a PTR record. Results (including misses) are cached for dnsTTL so
// we don't re-query every cycle.
const (
	dnsTTL         = 10 * time.Minute
	dnsLookupTO    = 400 * time.Millisecond
	dnsConcurrency = 8
)

// ARPCollector performs passive LAN device discovery from the ARP/neighbor
// table (architecture §3.1). No packet capture — just reading the OS table, then
// enriching each device with a reverse-DNS hostname where one is available.
type ARPCollector struct {
	p platform.Platform

	// lookup resolves an IP to PTR names; seam for tests. Defaults to the
	// system resolver.
	lookup func(ctx context.Context, addr string) ([]string, error)

	mu    sync.Mutex
	cache map[string]hostEntry // ip -> resolved hostname (empty = negative cache)
}

type hostEntry struct {
	name string
	at   time.Time
}

func NewARPCollector(p platform.Platform) *ARPCollector {
	return &ARPCollector{
		p:      p,
		lookup: net.DefaultResolver.LookupAddr,
		cache:  make(map[string]hostEntry),
	}
}

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

	// Keep only usable neighbors, then resolve their hostnames in one batch.
	usable := make([]platform.Neighbor, 0, len(neighbors))
	ips := make([]string, 0, len(neighbors))
	for _, n := range neighbors {
		if !usableMAC(n.MAC) {
			continue
		}
		usable = append(usable, n)
		ips = append(ips, n.IP)
	}
	hosts := c.resolveHostnames(ctx, ips)

	var res Result
	for _, n := range usable {
		res.Inventory = append(res.Inventory, telemetry.InventoryItem{
			Kind:     telemetry.InventoryDevice,
			Op:       telemetry.OpUpsert,
			ID:       n.MAC,
			MAC:      n.MAC,
			IP:       n.IP,
			Hostname: hosts[n.IP],
			LastSeen: now,
		})
	}
	return res, nil
}

// resolveHostnames returns ip -> hostname for the given IPs, serving fresh cache
// entries directly and resolving the rest concurrently (bounded). A failed or
// empty lookup is cached as an empty string (negative cache) so unnamed devices
// don't trigger a query every cycle.
func (c *ARPCollector) resolveHostnames(ctx context.Context, ips []string) map[string]string {
	out := make(map[string]string, len(ips))
	var misses []string
	now := time.Now()

	c.mu.Lock()
	for _, ip := range ips {
		if ip == "" {
			continue
		}
		if _, seen := out[ip]; seen {
			continue // duplicate IP in the neighbor table
		}
		if e, ok := c.cache[ip]; ok && now.Sub(e.at) < dnsTTL {
			out[ip] = e.name
			continue
		}
		out[ip] = "" // resolved below; keeps the IP de-duplicated meanwhile
		misses = append(misses, ip)
	}
	c.mu.Unlock()

	if len(misses) == 0 {
		return out
	}

	sem := make(chan struct{}, dnsConcurrency)
	var wg sync.WaitGroup
	var mu sync.Mutex
	for _, ip := range misses {
		wg.Add(1)
		sem <- struct{}{}
		go func(ip string) {
			defer wg.Done()
			defer func() { <-sem }()
			name := c.reverseLookup(ctx, ip)
			mu.Lock()
			out[ip] = name
			mu.Unlock()
			c.mu.Lock()
			c.cache[ip] = hostEntry{name: name, at: time.Now()}
			c.mu.Unlock()
		}(ip)
	}
	wg.Wait()
	return out
}

// reverseLookup returns the first PTR name for ip (trailing dot stripped), or ""
// on error / no record / timeout.
func (c *ARPCollector) reverseLookup(ctx context.Context, ip string) string {
	lctx, cancel := context.WithTimeout(ctx, dnsLookupTO)
	defer cancel()
	names, err := c.lookup(lctx, ip)
	if err != nil || len(names) == 0 {
		return ""
	}
	return strings.TrimSuffix(strings.TrimSpace(names[0]), ".")
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
