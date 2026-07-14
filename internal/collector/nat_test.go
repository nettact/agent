package collector

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/nettact/agent/internal/netguard"
	"github.com/nettact/agent/probepolicy"
	pcfg "github.com/nettact/protocol/config"
	"github.com/nettact/protocol/telemetry"
)

func TestClassify(t *testing.T) {
	cases := []struct {
		name            string
		reflexive       string
		mapping, filter int
		want            int
	}{
		{"full cone", "203.0.113.5:40000", natEndpointIndependent, natEndpointIndependent, natTypeFullCone},
		{"restricted cone", "203.0.113.5:40000", natEndpointIndependent, natAddressDependent, natTypeRestrictedCone},
		{"port restricted", "203.0.113.5:40000", natEndpointIndependent, natAddressAndPortDependent, natTypePortRestrictedCone},
		{"symmetric (addr mapping)", "203.0.113.5:40000", natAddressDependent, natEndpointIndependent, natTypeSymmetric},
		{"symmetric (addr+port mapping)", "203.0.113.5:40000", natAddressAndPortDependent, natAddressAndPortDependent, natTypeSymmetric},
		{"unknown", "203.0.113.5:40000", natUnknown, natUnknown, natTypeUnknown},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := classify(c.reflexive, c.mapping, c.filter); got != c.want {
				t.Fatalf("classify(%q,%d,%d) = %d, want %d", c.reflexive, c.mapping, c.filter, got, c.want)
			}
		})
	}
}

func TestStunHostPort(t *testing.T) {
	cases := []struct {
		target string
		port   int
		def    int
		want   string
	}{
		{"stun.example.com", 0, defaultSTUNPort, "stun.example.com:3478"},
		{"stun.example.com", 0, defaultSTUNSPort, "stun.example.com:5349"}, // tls/dtls default
		{"stun.example.com", 5349, defaultSTUNPort, "stun.example.com:5349"},
		{"stun.example.com:19302", 0, defaultSTUNPort, "stun.example.com:19302"},
		{"1.2.3.4:3478", 3478, defaultSTUNPort, "1.2.3.4:3478"},
	}
	for _, c := range cases {
		if got := stunHostPort(c.target, c.port, c.def); got != c.want {
			t.Errorf("stunHostPort(%q,%d,%d) = %q, want %q", c.target, c.port, c.def, got, c.want)
		}
	}
}

func TestStunDefaultPort(t *testing.T) {
	for _, c := range []struct {
		transport string
		want      int
	}{{"", 3478}, {"udp", 3478}, {"tcp", 3478}, {"tls", 5349}, {"dtls", 5349}} {
		if got := stunDefaultPort(c.transport); got != c.want {
			t.Errorf("stunDefaultPort(%q) = %d, want %d", c.transport, got, c.want)
		}
	}
}

func TestBehaviorLabels(t *testing.T) {
	if mappingLabel(natEndpointIndependent) != "endpoint-independent" {
		t.Error("mapping label mismatch")
	}
	if natTypeLabel(natTypeSymmetric) != "symmetric" {
		t.Error("type label mismatch")
	}
	if natTypeLabel(99) != "unknown" {
		t.Error("out-of-range type should be unknown")
	}
}

// TestNATBindingSmoke exercises the real UDP binding path against a public STUN
// server (reflexive address only — public servers rarely return OTHER-ADDRESS).
// It needs DNS + outbound UDP to a third-party server, so it only runs when
// NETTACT_STUN_IT is set; a plain `go test ./...` (offline/CI) skips it.
func TestNATBindingSmoke(t *testing.T) {
	if os.Getenv("NETTACT_STUN_IT") == "" {
		t.Skip("set NETTACT_STUN_IT=1 to run the public-STUN integration test")
	}
	c := NewNATCollector(netguard.New(probepolicy.Policy{}, true))
	c.SetTargets([]pcfg.ProbeTarget{{Kind: "nat", Target: "stun.l.google.com:19302", Params: pcfg.ProbeParams{NATTransport: "udp", TimeoutMs: 3000, GlobalTimeoutMs: 8000}}})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	res, err := c.Collect(ctx)
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	var ok bool
	for _, m := range res.Metrics {
		if m.Kind == telemetry.NATOK {
			ok = m.Value == 1
		}
	}
	if !ok {
		t.Fatalf("expected NATOK=1 from public STUN, metrics=%+v", res.Metrics)
	}
}
