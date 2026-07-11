package collector

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/nettact/agent/internal/platform"
	"github.com/nettact/protocol/capability"
)

// fakePlatform implements platform.Platform; only Neighbors is exercised here.
type fakePlatform struct {
	neighbors []platform.Neighbor
	err       error
}

func (f fakePlatform) Interfaces() ([]platform.IfaceInfo, error) { return nil, nil }
func (f fakePlatform) Ping(context.Context, string, platform.PingOptions) (platform.PingResult, error) {
	return platform.PingResult{}, nil
}
func (f fakePlatform) Neighbors() ([]platform.Neighbor, error) { return f.neighbors, f.err }
func (f fakePlatform) Supports() []capability.Capability       { return nil }

func TestARPCollectorResolvesHostnames(t *testing.T) {
	p := fakePlatform{neighbors: []platform.Neighbor{
		{IP: "192.168.1.10", MAC: "aa:bb:cc:dd:ee:01"},
		{IP: "192.168.1.11", MAC: "aa:bb:cc:dd:ee:02"}, // no PTR
		{IP: "192.168.1.10", MAC: "aa:bb:cc:dd:ee:01"}, // duplicate IP
		{IP: "192.168.1.1", MAC: "ff:ff:ff:ff:ff:ff"},  // filtered (broadcast)
	}}

	var calls int32
	c := NewARPCollector(p)
	c.lookup = func(_ context.Context, addr string) ([]string, error) {
		atomic.AddInt32(&calls, 1)
		if addr == "192.168.1.10" {
			return []string{"host-a.lan."}, nil // trailing dot must be stripped
		}
		return nil, errors.New("no PTR record")
	}

	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}

	got := map[string]string{}
	for _, it := range res.Inventory {
		got[it.MAC] = it.Hostname
	}
	if _, ok := got["ff:ff:ff:ff:ff:ff"]; ok {
		t.Errorf("broadcast MAC should be filtered out")
	}
	if got["aa:bb:cc:dd:ee:01"] != "host-a.lan" {
		t.Errorf("hostname = %q, want %q (trailing dot stripped)", got["aa:bb:cc:dd:ee:01"], "host-a.lan")
	}
	if got["aa:bb:cc:dd:ee:02"] != "" {
		t.Errorf("no-PTR device hostname = %q, want empty", got["aa:bb:cc:dd:ee:02"])
	}
	// Two unique IPs → exactly two lookups (the duplicate .10 is de-duped).
	if n := atomic.LoadInt32(&calls); n != 2 {
		t.Errorf("lookups = %d, want 2 (unique IPs only)", n)
	}

	// A second cycle should be served entirely from cache — including the
	// negative-cached miss — so no further lookups happen.
	before := atomic.LoadInt32(&calls)
	if _, err := c.Collect(context.Background()); err != nil {
		t.Fatalf("Collect (2nd): %v", err)
	}
	if extra := atomic.LoadInt32(&calls) - before; extra != 0 {
		t.Errorf("cache miss on 2nd cycle: %d extra lookups", extra)
	}
}
