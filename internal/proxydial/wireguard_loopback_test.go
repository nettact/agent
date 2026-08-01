package proxydial

// End-to-end tests over a REAL WireGuard tunnel, both ends in this process.
//
// The unit tests in tracemux_test.go drive the mux against a fake tun device;
// these drive the production wiring instead — Manager.Apply builds the dialer
// through newWireGuard, so netstack, the mux and wireguard-go are assembled
// exactly as they are on an agent, and probes cross a genuine Noise handshake,
// ChaCha20-Poly1305 transport and UDP socket to reach the far side.
//
// The far side is a second wireguard-go device whose tun device is wgLab: it
// answers the decrypted IP packets the agent really sent, standing in for the
// peer's whole LAN. Only the network BEYOND the peer is simulated, and that is
// deliberate — a scripted topology is the only way to assert hop-by-hop
// behaviour (a router that answers, one that stays silent, one that answers
// from an address WireGuard will refuse) without needing real routers.
//
// Everything runs on loopback with ephemeral keys and needs no privileges.

import (
	"bytes"
	"context"
	crand "crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"

	"github.com/nettact/agent/internal/traceroute"
	pcfg "github.com/nettact/protocol/config"
	"github.com/nettact/protocol/permission"
	"github.com/nettact/protocol/telemetry"
)

// The lab's address plan. AllowedIPs is 10.9.0.0/24, so labOutside is reachable
// by nothing and exists only to prove what WireGuard refuses to deliver.
var (
	labLocal   = netip.MustParseAddr("10.9.0.2")  // the agent's own in-tunnel address
	labDest    = netip.MustParseAddr("10.9.0.10") // the monitored target inside the tunnel
	labHop1    = netip.MustParseAddr("10.9.0.1")
	labHop2    = netip.MustParseAddr("10.9.0.5")
	labOutside = netip.MustParseAddr("172.31.5.1") // outside the peer's AllowedIPs
)

const labAllowedIPs = "10.9.0.0/24"

// labRouter is one simulated hop. A silent router answers nothing, the way a
// real one with ICMP rate limiting or a firewall does; its hop renders as `*`.
type labRouter struct {
	addr   netip.Addr
	silent bool
}

// wgLab is the far end of the tunnel: a tun.Device behind a second wireguard-go
// device. Write receives the decrypted packets the agent sent; Read hands back
// the responses the simulated topology produces.
type wgLab struct {
	// routers[i] answers TTL i+1. A packet whose TTL outlives the list has
	// reached the destination and is answered by an echo reply.
	routers []labRouter

	out    chan []byte
	done   chan struct{}
	events chan tun.Event

	mu       sync.Mutex
	closed   bool
	received int
}

func newWGLab(routers []labRouter) *wgLab {
	return &wgLab{
		routers: routers,
		out:     make(chan []byte, 32),
		done:    make(chan struct{}),
		events:  make(chan tun.Event, 4),
	}
}

func (l *wgLab) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	select {
	case pkt := <-l.out:
		sizes[0] = copy(bufs[0][offset:], pkt)
		return 1, nil
	case <-l.done:
		return 0, os.ErrClosed
	}
}

func (l *wgLab) Write(bufs [][]byte, offset int) (int, error) {
	for _, b := range bufs {
		l.handle(b[offset:])
	}
	return len(bufs), nil
}

// handle applies the topology to one echo request. Anything else the tunnel
// carries is counted and ignored — the lab is a responder, not a stack.
func (l *wgLab) handle(pkt []byte) {
	if len(pkt) < ipv4HeaderLen+icmpEchoLen || pkt[0]>>4 != 4 || pkt[9] != 1 {
		return
	}
	ihl := int(pkt[0]&0x0f) * 4
	if len(pkt) < ihl+icmpEchoLen || pkt[ihl] != 8 {
		return
	}
	l.mu.Lock()
	l.received++
	l.mu.Unlock()

	if ttl := int(pkt[8]); ttl <= len(l.routers) {
		r := l.routers[ttl-1]
		if r.silent {
			return
		}
		l.emit(labTimeExceeded(pkt, r.addr))
		return
	}
	l.emit(labEchoReply(pkt))
}

func (l *wgLab) emit(pkt []byte) {
	select {
	case l.out <- pkt:
	case <-l.done:
	}
}

// echoesSeen is how many echo requests actually crossed the tunnel — the proof
// a fail-closed refusal never sent anything.
func (l *wgLab) echoesSeen() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.received
}

func (l *wgLab) File() *os.File           { return nil }
func (l *wgLab) MTU() (int, error)        { return 1420, nil }
func (l *wgLab) Name() (string, error)    { return "wglab", nil }
func (l *wgLab) Events() <-chan tun.Event { return l.events }
func (l *wgLab) BatchSize() int           { return 1 }

func (l *wgLab) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.closed {
		l.closed = true
		close(l.done)
		close(l.events)
	}
	return nil
}

// labPacket wraps an already-marshaled ICMP body in an IPv4 header. The
// checksums must be real: everything the lab sends is also injected into the
// agent's netstack, which validates them (the mux's own sniffer does not).
func labPacket(src, dst netip.Addr, body []byte) []byte {
	pkt := make([]byte, ipv4HeaderLen+len(body))
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	pkt[8] = 64
	pkt[9] = 1
	s, d := src.As4(), dst.As4()
	copy(pkt[12:16], s[:])
	copy(pkt[16:20], d[:])
	binary.BigEndian.PutUint16(pkt[10:12], ipv4HeaderChecksum(pkt[:ipv4HeaderLen]))
	copy(pkt[ipv4HeaderLen:], body)
	return pkt
}

// labEchoReply answers an echo request from the address it was sent to,
// mirroring id, sequence and payload the way a real host does.
func labEchoReply(req []byte) []byte {
	ihl := int(req[0]&0x0f) * 4
	b := req[ihl:]
	msg := icmp.Message{Type: ipv4.ICMPTypeEchoReply, Body: &icmp.Echo{
		ID:   int(binary.BigEndian.Uint16(b[4:6])),
		Seq:  int(binary.BigEndian.Uint16(b[6:8])),
		Data: append([]byte(nil), b[icmpEchoLen:]...),
	}}
	body, err := msg.Marshal(nil)
	if err != nil {
		return nil
	}
	src, _ := netip.AddrFromSlice(req[16:20])
	dst, _ := netip.AddrFromSlice(req[12:16])
	return labPacket(src, dst, body)
}

// labTimeExceeded is the TTL-expiry answer of an intermediate router, quoting
// the original header plus 8 bytes — the quote the mux correlates on.
func labTimeExceeded(req []byte, from netip.Addr) []byte {
	ihl := int(req[0]&0x0f) * 4
	msg := icmp.Message{Type: ipv4.ICMPTypeTimeExceeded, Body: &icmp.TimeExceeded{
		Data: append([]byte(nil), req[:ihl+icmpEchoLen]...),
	}}
	body, err := msg.Marshal(nil)
	if err != nil {
		return nil
	}
	dst, _ := netip.AddrFromSlice(req[12:16])
	return labPacket(from, dst, body)
}

// wgKeypair is a Curve25519 keypair. Generated per run rather than fixtured:
// the handshake must work for arbitrary valid keys, not one lucky pair.
type wgKeypair struct{ priv, pub [32]byte }

func newWGKeypair(t *testing.T) wgKeypair {
	t.Helper()
	var kp wgKeypair
	if _, err := crand.Read(kp.priv[:]); err != nil {
		t.Fatalf("generate private key: %v", err)
	}
	kp.priv[0] &= 248
	kp.priv[31] = (kp.priv[31] & 127) | 64
	curve25519.ScalarBaseMult(&kp.pub, &kp.priv)
	return kp
}

// startWGLab brings up the far end and returns the spec an agent would be
// pushed to reach it. Both devices are torn down with the test.
func startWGLab(t *testing.T, routers ...labRouter) (*wgLab, pcfg.ProxySpec) {
	t.Helper()
	agentKeys, peerKeys := newWGKeypair(t), newWGKeypair(t)

	lab := newWGLab(routers)
	dev := device.NewDevice(lab, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, "wglab "))
	// listen_port=0 takes any free port; the peer learns the agent's endpoint
	// from the handshake, so it needs no endpoint of its own.
	cfg := "private_key=" + hex.EncodeToString(peerKeys.priv[:]) + "\n" +
		"listen_port=0\n" +
		"public_key=" + hex.EncodeToString(agentKeys.pub[:]) + "\n" +
		"allowed_ip=" + labLocal.String() + "/32\n"
	if err := dev.IpcSet(cfg); err != nil {
		t.Fatalf("configure lab peer: %v", err)
	}
	if err := dev.Up(); err != nil {
		t.Fatalf("bring lab peer up: %v", err)
	}
	t.Cleanup(func() { dev.Close() })

	spec := pcfg.ProxySpec{
		ID:              "prx_wg_lab",
		Name:            "loopback lab",
		Type:            pcfg.ProxyTypeWireGuard,
		ConfigSerial:    4,
		WGPrivateKey:    base64.StdEncoding.EncodeToString(agentKeys.priv[:]),
		WGPeerPublicKey: base64.StdEncoding.EncodeToString(peerKeys.pub[:]),
		WGEndpoint:      "127.0.0.1:" + strconv.Itoa(labListenPort(t, dev)),
		WGAllowedIPs:    labAllowedIPs,
		WGLocalAddrs:    labLocal.String() + "/32",
	}
	return lab, spec
}

func labListenPort(t *testing.T, dev *device.Device) int {
	t.Helper()
	cfg, err := dev.IpcGet()
	if err != nil {
		t.Fatalf("read lab peer config: %v", err)
	}
	for _, line := range strings.Split(cfg, "\n") {
		v, ok := strings.CutPrefix(strings.TrimSpace(line), "listen_port=")
		if !ok {
			continue
		}
		port, perr := strconv.Atoi(v)
		if perr != nil {
			t.Fatalf("parse listen_port %q: %v", v, perr)
		}
		return port
	}
	t.Fatal("lab peer reported no listen_port")
	return 0
}

// labManager builds the dialer the way an agent does: through Apply +
// DialerForGeneration, so the generation pin is exercised too.
func labManager(t *testing.T, spec pcfg.ProxySpec) (*Manager, *Dialer) {
	t.Helper()
	m := newTestManager()
	t.Cleanup(m.Close)
	m.Apply([]pcfg.ProxySpec{spec})
	d, err := m.DialerForGeneration(context.Background(), spec.ID, spec.ConfigSerial)
	if err != nil {
		t.Fatalf("build tunnel dialer: %v", err)
	}
	return m, d
}

// waitTunnelUp probes until the far side answers, absorbing the handshake. It
// doubles as the assertion that the tunnel came up at all.
func waitTunnelUp(t *testing.T, d *Dialer) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		r, err := d.TraceProbe(context.Background(), labDest, 64, 500*time.Millisecond)
		if err != nil {
			t.Fatalf("probe while handshaking: %v", err)
		}
		if r.Reached {
			return
		}
	}
	t.Fatal("tunnel never completed a handshake")
}

func TestWireGuardLoopbackTracesHopByHopInsideTheTunnel(t *testing.T) {
	lab, spec := startWGLab(t, labRouter{addr: labHop1}, labRouter{addr: labHop2})
	_, d := labManager(t, spec)
	waitTunnelUp(t, d)

	for _, tc := range []struct {
		ttl       int
		responder netip.Addr
		reached   bool
	}{
		{1, labHop1, false}, // Time Exceeded from the first router
		{2, labHop2, false}, // ...and the second
		{3, labDest, true},  // the destination's own echo reply
	} {
		r, err := d.TraceProbe(context.Background(), labDest, tc.ttl, 3*time.Second)
		if err != nil {
			t.Fatalf("ttl %d: %v", tc.ttl, err)
		}
		if r.Timeout {
			t.Fatalf("ttl %d timed out, want a responder", tc.ttl)
		}
		if r.Responder != tc.responder || r.Reached != tc.reached {
			t.Fatalf("ttl %d = %v (reached=%v), want %v (reached=%v)",
				tc.ttl, r.Responder, r.Reached, tc.responder, tc.reached)
		}
	}
	if lab.echoesSeen() == 0 {
		t.Fatal("no echo crossed the tunnel")
	}
}

func TestWireGuardLoopbackSilentHopTimesOutWithoutWedgingTheTunnel(t *testing.T) {
	_, spec := startWGLab(t, labRouter{addr: labHop1, silent: true})
	_, d := labManager(t, spec)
	waitTunnelUp(t, d)

	r, err := d.TraceProbe(context.Background(), labDest, 1, 400*time.Millisecond)
	if err != nil {
		t.Fatalf("silent hop: %v", err)
	}
	if !r.Timeout {
		t.Fatalf("silent hop = %+v, want a timeout", r)
	}
	// The mux must recover: an unanswered probe leaves no registration behind
	// and the next TTL still gets through.
	r, err = d.TraceProbe(context.Background(), labDest, 2, 3*time.Second)
	if err != nil {
		t.Fatalf("probe after silent hop: %v", err)
	}
	if !r.Reached || r.Responder != labDest {
		t.Fatalf("probe after silent hop = %+v, want the destination", r)
	}
}

func TestWireGuardLoopbackDropsRepliesSourcedOutsideAllowedIPs(t *testing.T) {
	// The documented limitation of DIAG-004: WireGuard's crypt-key routing
	// refuses an inbound packet whose source is outside the peer's AllowedIPs,
	// so a router answering from such an address is invisible — the hop can only
	// render as `*`, and no amount of work in the mux can change that.
	lab, spec := startWGLab(t, labRouter{addr: labOutside})
	_, d := labManager(t, spec)
	waitTunnelUp(t, d)

	before := lab.echoesSeen()
	r, err := d.TraceProbe(context.Background(), labDest, 1, 500*time.Millisecond)
	if err != nil {
		t.Fatalf("out-of-range responder: %v", err)
	}
	if !r.Timeout {
		t.Fatalf("out-of-range responder = %+v, want a timeout (the reply must be dropped)", r)
	}
	// Without this the test would also pass on a dead tunnel. The probe DID
	// reach the far side and the router DID answer — the answer is what
	// WireGuard refused, which is the whole point.
	if after := lab.echoesSeen(); after == before {
		t.Fatal("the probe never reached the far side, so this proves nothing about AllowedIPs")
	}
}

func TestWireGuardLoopbackProbesCoexistWithNetstackTraffic(t *testing.T) {
	// The mux copies inbound packets to its probe registry and forwards every
	// one of them to netstack. Both consumers must work at once: a tunnel ping
	// (the pingtunnel collector's path, owned by gVisor) and a raw probe (ours)
	// in flight together, neither stealing the other's reply.
	_, spec := startWGLab(t, labRouter{addr: labHop1})
	_, d := labManager(t, spec)
	waitTunnelUp(t, d)

	type probeResult struct {
		r   TraceProbeReply
		err error
	}
	probeCh := make(chan probeResult, 1)
	pingCh := make(chan error, 1)
	go func() {
		r, err := d.TraceProbe(context.Background(), labDest, 1, 5*time.Second)
		probeCh <- probeResult{r, err}
	}()
	go func() { pingCh <- labTunnelPing(d, 7) }()

	if err := <-pingCh; err != nil {
		t.Fatalf("netstack ping through the mux: %v", err)
	}
	got := <-probeCh
	if got.err != nil {
		t.Fatalf("concurrent probe: %v", got.err)
	}
	if got.r.Timeout || got.r.Responder != labHop1 {
		t.Fatalf("concurrent probe = %+v, want the first router", got.r)
	}
}

// labTunnelPing sends one echo through netstack's own ping socket, exactly as
// collector.tunnelPingOnce does, and matches the reply on sequence + payload
// (the stack owns the ICMP id).
func labTunnelPing(d *Dialer, seq int) error {
	c, err := d.DialPing(context.Background(), "ping4", labDest.String())
	if err != nil {
		return fmt.Errorf("dial ping: %w", err)
	}
	defer c.Close()

	payload := []byte("nettact-probe")
	req := icmp.Message{Type: ipv4.ICMPTypeEcho, Body: &icmp.Echo{Seq: seq, Data: payload}}
	wire, err := req.Marshal(nil)
	if err != nil {
		return err
	}
	if err := c.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return err
	}
	if _, err := c.Write(wire); err != nil {
		return fmt.Errorf("write echo: %w", err)
	}
	buf := make([]byte, len(wire)+512)
	for {
		n, rerr := c.Read(buf)
		if rerr != nil {
			return fmt.Errorf("read echo reply: %w", rerr)
		}
		msg, perr := icmp.ParseMessage(1, buf[:n])
		if perr != nil {
			continue
		}
		echo, ok := msg.Body.(*icmp.Echo)
		if ok && echo.Seq == seq && bytes.Equal(echo.Data, payload) {
			return nil
		}
	}
}

// labEgressResolver mirrors the runtime bridge in agentrt: it is what turns a
// pinned {id, generation} into an in-tunnel probe, and its error mapping IS the
// fail-closed contract. Mirrored rather than imported because agentrt depends
// on this package; the engine tests below drive the real Manager through it.
func labEgressResolver(m *Manager) traceroute.EgressResolver {
	return func(ctx context.Context, proxyID string, serial int) (traceroute.EgressProbeFunc, error) {
		d, err := m.DialerForGeneration(ctx, proxyID, serial)
		switch {
		case errors.Is(err, ErrProxyGeneration):
			return nil, fmt.Errorf("%w: %v", traceroute.ErrEgressGenerationMismatch, err)
		case err != nil:
			return nil, fmt.Errorf("%w: %v", traceroute.ErrEgressNotAvailable, err)
		case d.Spec.Type != pcfg.ProxyTypeWireGuard:
			return nil, fmt.Errorf("%w: %s cannot carry in-tunnel probes", traceroute.ErrEgressNotAvailable, d.Spec.Type)
		}
		return func(ctx context.Context, dest netip.Addr, ttl int, timeout time.Duration) (traceroute.EgressReply, error) {
			r, perr := d.TraceProbe(ctx, dest, ttl, timeout)
			if perr != nil {
				return traceroute.EgressReply{}, perr
			}
			return traceroute.EgressReply{
				Responder: r.Responder,
				Reached:   r.Reached,
				Timeout:   r.Timeout,
				RTTMs:     float64(r.RTT.Microseconds()) / 1000,
			}, nil
		}, nil
	}
}

func labTraceRequest(spec pcfg.ProxySpec, serial int) pcfg.TraceRequest {
	return pcfg.TraceRequest{
		ReportID: "trace-lab", Mode: pcfg.TraceModeICMP, DestinationHost: labDest.String(),
		// The budget divided by the hop ceiling is the per-attempt wait, so keep it
		// at the engine's 500ms floor: reachable hops answer in microseconds over
		// loopback and only the silent one actually spends it.
		MaxHops: 6, AttemptsPerHop: 1, TotalTimeoutMs: 3_000, BudgetMs: 30_000,
		EgressProxyID: spec.ID, EgressConfigSerial: serial,
	}
}

func TestWireGuardLoopbackEngineProducesAnAttestedInTunnelTrace(t *testing.T) {
	// The whole stack: server-shaped TraceRequest → Engine → egress resolver →
	// Manager → tunnel → lab, and back as a TraceResult the server would ingest.
	lab, spec := startWGLab(t, labRouter{addr: labHop1}, labRouter{addr: labHop2, silent: true})
	m, d := labManager(t, spec)
	waitTunnelUp(t, d)

	granted := permission.FromStrings([]string{string(permission.DiagnosticTracerouteICMP)})
	// supported is EMPTY on purpose: this host cannot raw-socket its way to a
	// host-stack traceroute, and the in-tunnel path must not care.
	e := traceroute.New(bypassGuard(), permission.Set{}, granted, permission.Set{}, 2, labEgressResolver(m))

	res := e.Run(context.Background(), labTraceRequest(spec, spec.ConfigSerial), time.Now())
	if res.Status != telemetry.TraceStatusSucceeded {
		t.Fatalf("result = %s/%s, want succeeded", res.Status, res.Reason)
	}
	if !res.Reached || res.ReachedTTL != 3 || len(res.Hops) != 3 {
		t.Fatalf("reached=%v ttl=%d hops=%d, want a 3-hop reach", res.Reached, res.ReachedTTL, len(res.Hops))
	}
	if got := res.Hops[0].Attempts[0].ResponderAddr; got != labHop1.String() {
		t.Fatalf("hop 1 responder = %q, want %v", got, labHop1)
	}
	if !res.Hops[1].Attempts[0].Timeout {
		t.Fatalf("hop 2 = %+v, want the silent router's `*`", res.Hops[1].Attempts[0])
	}
	if got := res.Hops[2].Attempts[0].ResponderAddr; got != labDest.String() {
		t.Fatalf("hop 3 responder = %q, want %v", got, labDest)
	}
	if res.DestinationIP != labDest.String() {
		t.Fatalf("destination = %q, want %v", res.DestinationIP, labDest)
	}
	// The attestation the server validates the report against.
	if res.PathScope != telemetry.TracePathWireGuardInner ||
		res.EgressProxyID != spec.ID || res.EgressConfigSerial != spec.ConfigSerial {
		t.Fatalf("attestation = %s/%s/%d, want wireguard_inner/%s/%d",
			res.PathScope, res.EgressProxyID, res.EgressConfigSerial, spec.ID, spec.ConfigSerial)
	}
	if lab.echoesSeen() == 0 {
		t.Fatal("the engine reported hops but nothing crossed the tunnel")
	}
}

func TestWireGuardLoopbackEngineFailsClosedOnRotatedGeneration(t *testing.T) {
	lab, spec := startWGLab(t, labRouter{addr: labHop1})
	m, d := labManager(t, spec)
	waitTunnelUp(t, d)

	// The operator re-keys the proxy between the fault and the diagnostic. The
	// pushed generation moves; the request still names the old one.
	rotated := spec
	rotated.ConfigSerial = spec.ConfigSerial + 1
	m.Apply([]pcfg.ProxySpec{rotated})
	before := lab.echoesSeen()

	granted := permission.FromStrings([]string{string(permission.DiagnosticTracerouteICMP)})
	e := traceroute.New(bypassGuard(), granted, granted, granted, 2, labEgressResolver(m))

	res := e.Run(context.Background(), labTraceRequest(spec, spec.ConfigSerial), time.Now())
	if res.Status != telemetry.TraceStatusFailed || res.Reason != "egress_generation_mismatch" {
		t.Fatalf("result = %s/%s, want failed/egress_generation_mismatch", res.Status, res.Reason)
	}
	if len(res.Hops) != 0 {
		t.Fatalf("refused trace reported %d hops, want none", len(res.Hops))
	}
	// Fail-closed means nothing was sent — not over the new generation, not
	// direct. The refusal still attests the plan it declined.
	if after := lab.echoesSeen(); after != before {
		t.Fatalf("%d echoes crossed the tunnel after the refusal, want 0", after-before)
	}
	if res.PathScope != telemetry.TracePathWireGuardInner || res.EgressProxyID != spec.ID {
		t.Fatalf("attestation = %s/%s, want wireguard_inner/%s", res.PathScope, res.EgressProxyID, spec.ID)
	}
}
