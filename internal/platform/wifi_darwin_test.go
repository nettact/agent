//go:build darwin

package platform

import (
	"errors"
	"testing"
)

// fakeCWClient drives darwinWiFiTick without CoreWLAN, counting the gated
// ssid() reads — the number this whole design exists to minimize.
type fakeCWClient struct {
	ads         []cwAdapter
	adaptersErr error
	ssids       map[string]string
	withheld    bool // CoreWLAN returns nil SSID (location policy)
	ssidCalls   int
}

func (f *fakeCWClient) adapters() ([]cwAdapter, error) { return f.ads, f.adaptersErr }

func (f *fakeCWClient) ssid(ifname string) (string, bool, error) {
	f.ssidCalls++
	if f.withheld {
		return "", false, nil
	}
	s, ok := f.ssids[ifname]
	return s, ok, nil
}

func connectedEn0() cwAdapter {
	return cwAdapter{
		Name: "en0", PoweredOn: true, HasChannel: true, Band: "5", Channel: 44,
		RSSI: -65, HasRSSI: true, TxRateMbps: 866.66, HasTxRate: true,
	}
}

func TestDarwinTickSteadyStateReadsSSIDOnce(t *testing.T) {
	clk := newWiFiClock()
	cache := newWiFiCache(macCacheCfg(), clk.now)
	cl := &fakeCWClient{ads: []cwAdapter{connectedEn0()}, ssids: map[string]string{"en0": "home"}}

	res := darwinWiFiTick(cl, cache, true)
	if res.State != "ok" || len(res.Adapters) != 1 {
		t.Fatalf("res=%+v", res)
	}
	r := res.Adapters[0]
	if r.State != "connected" || r.SSID != "home" || r.Reason != "" {
		t.Fatalf("row=%+v", r)
	}
	// Ungated fields flow per tick exactly as the old direct read reported them.
	if r.Band != "5" || r.Channel != 44 ||
		r.SignalDBm == nil || *r.SignalDBm != -65 || r.Quality == nil || *r.Quality != 70 {
		t.Fatalf("row=%+v", r)
	}
	if r.TxMbps == nil || *r.TxMbps != 866.7 || r.RxMbps != nil {
		t.Fatalf("link rates=%+v", r)
	}
	if cl.ssidCalls != 1 {
		t.Fatalf("ssid calls=%d want 1", cl.ssidCalls)
	}

	// Ten steady-state ticks: zero further gated reads, SSID still served.
	for i := 0; i < 10; i++ {
		clk.advance(30e9)
		res = darwinWiFiTick(cl, cache, true)
	}
	if cl.ssidCalls != 1 {
		t.Fatalf("steady state performed %d extra gated reads", cl.ssidCalls-1)
	}
	if res.Adapters[0].SSID != "home" {
		t.Fatalf("cached SSID lost: %+v", res.Adapters[0])
	}
}

func TestDarwinTickSSIDWithheldByPolicy(t *testing.T) {
	clk := newWiFiClock()
	cache := newWiFiCache(macCacheCfg(), clk.now)
	cl := &fakeCWClient{ads: []cwAdapter{connectedEn0()}, withheld: true}

	res := darwinWiFiTick(cl, cache, true)
	r := res.Adapters[0]
	if r.State != "connected" || r.Reason != "permission" || r.SSID != "" {
		t.Fatalf("row=%+v", r)
	}
	if r.SignalDBm == nil || *r.SignalDBm != -65 {
		t.Fatalf("ungated fields lost: %+v", r)
	}
	// A policy denial must not be retried per tick.
	for i := 0; i < 5; i++ {
		clk.advance(30e9)
		darwinWiFiTick(cl, cache, true)
	}
	if cl.ssidCalls != 1 {
		t.Fatalf("policy denial retried eagerly: %d calls", cl.ssidCalls)
	}
}

func TestDarwinTickSSIDDemandWindow(t *testing.T) {
	clk := newWiFiClock()
	cache := newWiFiCache(macCacheCfg(), clk.now)
	cl := &fakeCWClient{ads: []cwAdapter{connectedEn0()}, ssids: map[string]string{"en0": "home"}}

	// No caller wants the SSID: the gated read never happens, and the row says
	// so via the historical reason=permission semantics.
	res := darwinWiFiTick(cl, cache, false)
	if cl.ssidCalls != 0 {
		t.Fatalf("ssid read without demand: %d", cl.ssidCalls)
	}
	if r := res.Adapters[0]; r.State != "connected" || r.Reason != "permission" || r.SSID != "" {
		t.Fatalf("row=%+v", r)
	}

	// A caller with the grant appears → exactly one gated read.
	clk.advance(30e9)
	res = darwinWiFiTick(cl, cache, true)
	if cl.ssidCalls != 1 || res.Adapters[0].SSID != "home" {
		t.Fatalf("calls=%d row=%+v", cl.ssidCalls, res.Adapters[0])
	}

	// Every grant revoked: after the demand window the cached SSID is dropped
	// and no further reads happen.
	clk.advance(120e9)
	res = darwinWiFiTick(cl, cache, false)
	if res.Adapters[0].SSID != "" {
		t.Fatalf("stale SSID outlived demand: %+v", res.Adapters[0])
	}
	if cl.ssidCalls != 1 {
		t.Fatalf("read without demand: %d", cl.ssidCalls)
	}
}

func TestDarwinTickTransitionFallbackRefreshes(t *testing.T) {
	// No delegate events (fake client): the ungated transition reconcile must
	// still refresh the SSID on link bounce and channel change.
	clk := newWiFiClock()
	cache := newWiFiCache(macCacheCfg(), clk.now)
	cl := &fakeCWClient{ads: []cwAdapter{connectedEn0()}, ssids: map[string]string{"en0": "home"}}
	darwinWiFiTick(cl, cache, true)

	// Roam to another network on a different channel, no event delivered.
	clk.advance(30e9)
	a := connectedEn0()
	a.Channel, a.Band = 6, "2.4"
	cl.ads = []cwAdapter{a}
	cl.ssids["en0"] = "attic"
	res := darwinWiFiTick(cl, cache, true)
	if r := res.Adapters[0]; r.SSID != "attic" || r.Channel != 6 || r.Band != "2.4" {
		t.Fatalf("row=%+v", r)
	}
	if cl.ssidCalls != 2 {
		t.Fatalf("calls=%d want 2", cl.ssidCalls)
	}

	// Link down then up again: down needs no read, up re-reads.
	clk.advance(30e9)
	down := a
	down.HasChannel = false
	cl.ads = []cwAdapter{down}
	res = darwinWiFiTick(cl, cache, true)
	if res.Adapters[0].State != "disconnected" || cl.ssidCalls != 2 {
		t.Fatalf("row=%+v calls=%d", res.Adapters[0], cl.ssidCalls)
	}
	clk.advance(30e9)
	cl.ads = []cwAdapter{a}
	res = darwinWiFiTick(cl, cache, true)
	if res.Adapters[0].SSID != "attic" || cl.ssidCalls != 3 {
		t.Fatalf("row=%+v calls=%d", res.Adapters[0], cl.ssidCalls)
	}
}

func TestDarwinTickUnreadable(t *testing.T) {
	clk := newWiFiClock()
	cache := newWiFiCache(macCacheCfg(), clk.now)
	cl := &fakeCWClient{adaptersErr: errors.New("xpc gone")}
	res := darwinWiFiTick(cl, cache, true)
	if res.State != "unreadable" || res.Reason != "driver" {
		t.Fatalf("res=%+v", res)
	}
}

func TestCWBand(t *testing.T) {
	for in, want := range map[int]string{0: "", 1: "2.4", 2: "5", 3: "6", 4: ""} {
		if got := cwBand(in); got != want {
			t.Errorf("cwBand(%d)=%q want %q", in, got, want)
		}
	}
}
