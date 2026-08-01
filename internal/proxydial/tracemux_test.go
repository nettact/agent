package proxydial

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tun"
)

// fakeInner is a scripted netstack stand-in: Read blocks on packets the test
// feeds, Write records copies of everything forwarded to "gVisor".
type fakeInner struct {
	feed   chan []byte
	events chan tun.Event

	mu      sync.Mutex
	written [][]byte
	wrote   chan struct{} // signaled once per Write call
	closed  bool
}

func newFakeInner() *fakeInner {
	return &fakeInner{
		feed:   make(chan []byte, 16),
		events: make(chan tun.Event, 1),
		wrote:  make(chan struct{}, 64),
	}
}

func (f *fakeInner) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	pkt, ok := <-f.feed
	if !ok {
		return 0, os.ErrClosed
	}
	sizes[0] = copy(bufs[0][offset:], pkt)
	return 1, nil
}

func (f *fakeInner) Write(bufs [][]byte, offset int) (int, error) {
	f.mu.Lock()
	for _, b := range bufs {
		f.written = append(f.written, append([]byte(nil), b[offset:]...))
	}
	f.mu.Unlock()
	f.wrote <- struct{}{}
	return len(bufs), nil
}

func (f *fakeInner) writtenPackets() [][]byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([][]byte, len(f.written))
	copy(out, f.written)
	return out
}

func (f *fakeInner) File() *os.File           { return nil }
func (f *fakeInner) MTU() (int, error)        { return 1420, nil }
func (f *fakeInner) Name() (string, error)    { return "fake", nil }
func (f *fakeInner) Events() <-chan tun.Event { return f.events }
func (f *fakeInner) BatchSize() int           { return 1 }

func (f *fakeInner) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.closed {
		f.closed = true
		close(f.feed)
		close(f.events)
	}
	return nil
}

var (
	muxLocal = netip.MustParseAddr("10.7.0.2")
	muxDest  = netip.MustParseAddr("10.7.0.10")
)

// muxRead performs one device-side Read at a nonzero offset (wireguard-go
// always passes one) and returns the packet.
func muxRead(t *testing.T, m *traceMux) []byte {
	t.Helper()
	const offset = 16
	buf := make([]byte, 2048)
	sizes := make([]int, 1)
	n, err := m.Read([][]byte{buf}, sizes, offset)
	if err != nil {
		t.Fatalf("mux.Read: %v", err)
	}
	if n != 1 {
		t.Fatalf("mux.Read returned %d packets, want 1", n)
	}
	return buf[offset : offset+sizes[0]]
}

// startProbe launches traceProbe and returns the channel its outcome lands on.
func startProbe(m *traceMux, ttl int, timeout time.Duration) chan struct {
	r   TraceProbeReply
	err error
} {
	out := make(chan struct {
		r   TraceProbeReply
		err error
	}, 1)
	go func() {
		r, err := m.traceProbe(context.Background(), muxDest, ttl, timeout)
		out <- struct {
			r   TraceProbeReply
			err error
		}{r, err}
	}()
	return out
}

// echoReplyFor reverses a captured probe into the destination's echo reply,
// optionally corrupting the payload token.
func echoReplyFor(t *testing.T, probe []byte, from netip.Addr, corruptToken bool) []byte {
	t.Helper()
	if len(probe) < ipv4HeaderLen+icmpEchoLen {
		t.Fatalf("captured probe too short: %d bytes", len(probe))
	}
	reply := append([]byte(nil), probe...)
	src4 := from.As4()
	local4 := muxLocal.As4()
	copy(reply[12:16], src4[:])
	copy(reply[16:20], local4[:])
	reply[icmpEchoLen] = 64 // TTL of the reply; irrelevant to matching
	body := reply[ipv4HeaderLen:]
	body[0] = 0 // Echo Reply
	if corruptToken {
		body[len(body)-1] ^= 0xff
	}
	// The mux never verifies inbound checksums (the tunnel's crypto already
	// authenticated the packet), so leaving them stale is deliberate.
	return reply
}

// icmpErrorFor wraps a captured probe in a Time Exceeded / Destination
// Unreachable error from a router, quoting the inner header + 8 bytes.
func icmpErrorFor(t *testing.T, probe []byte, icmpType byte, router netip.Addr, mangle func(quote []byte)) []byte {
	t.Helper()
	quote := append([]byte(nil), probe[:ipv4HeaderLen+icmpEchoLen]...)
	if mangle != nil {
		mangle(quote)
	}
	pkt := make([]byte, ipv4HeaderLen+icmpEchoLen+len(quote))
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	pkt[8] = 64
	pkt[9] = 1
	r4 := router.As4()
	local4 := muxLocal.As4()
	copy(pkt[12:16], r4[:])
	copy(pkt[16:20], local4[:])
	pkt[ipv4HeaderLen] = icmpType
	copy(pkt[ipv4HeaderLen+icmpEchoLen:], quote)
	return pkt
}

func feedInbound(t *testing.T, m *traceMux, pkt []byte) {
	t.Helper()
	if _, err := m.Write([][]byte{append(make([]byte, 4), pkt...)}, 4); err != nil {
		t.Fatalf("mux.Write: %v", err)
	}
}

func TestTraceMuxInjectAndChecksums(t *testing.T) {
	inner := newFakeInner()
	m := newTraceMux(inner, muxLocal)
	defer m.Close()

	done := startProbe(m, 7, 200*time.Millisecond)
	pkt := muxRead(t, m)

	if got := pkt[0] >> 4; got != 4 {
		t.Fatalf("version = %d, want 4", got)
	}
	if pkt[8] != 7 {
		t.Fatalf("TTL = %d, want 7", pkt[8])
	}
	if pkt[9] != 1 {
		t.Fatalf("protocol = %d, want 1 (ICMP)", pkt[9])
	}
	local4, dest4 := muxLocal.As4(), muxDest.As4()
	if !bytes.Equal(pkt[12:16], local4[:]) || !bytes.Equal(pkt[16:20], dest4[:]) {
		t.Fatalf("src/dst = %v/%v, want %v/%v", pkt[12:16], pkt[16:20], local4, dest4)
	}
	if int(binary.BigEndian.Uint16(pkt[2:4])) != len(pkt) {
		t.Fatalf("total length field %d != packet length %d", binary.BigEndian.Uint16(pkt[2:4]), len(pkt))
	}
	// Both checksums must verify: the header sums to 0xffff complemented, and
	// the ICMP body checksums to zero when summed whole.
	hdr := append([]byte(nil), pkt[:ipv4HeaderLen]...)
	want := binary.BigEndian.Uint16(hdr[10:12])
	if got := ipv4HeaderChecksum(hdr); got != want {
		t.Fatalf("IPv4 header checksum = %#x, want %#x", want, got)
	}
	var sum uint32
	body := pkt[ipv4HeaderLen:]
	for i := 0; i+1 < len(body); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(body[i : i+2]))
	}
	if len(body)%2 == 1 {
		sum += uint32(body[len(body)-1]) << 8 // RFC 1071: odd trailing byte pads with zero
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	if uint16(sum) != 0xffff {
		t.Fatalf("ICMP checksum does not verify (folded sum %#x)", sum)
	}
	if body[0] != 8 || body[1] != 0 {
		t.Fatalf("ICMP type/code = %d/%d, want 8/0", body[0], body[1])
	}
	if !bytes.HasPrefix(body[icmpEchoLen:], echoPayloadPrefix) {
		t.Fatalf("payload missing %q prefix", echoPayloadPrefix)
	}

	res := <-done
	if res.err != nil {
		t.Fatalf("probe error: %v", res.err)
	}
	if !res.r.Timeout {
		t.Fatalf("probe with no reply = %+v, want Timeout", res.r)
	}
}

func TestTraceMuxPassThroughCoexistence(t *testing.T) {
	inner := newFakeInner()
	m := newTraceMux(inner, muxLocal)
	defer m.Close()

	gvisorPkt := []byte{0x45, 0, 0, 20, 1, 2, 3, 4, 64, 17, 0, 0, 10, 7, 0, 2, 10, 7, 0, 9}
	inner.feed <- gvisorPkt
	done := startProbe(m, 1, 500*time.Millisecond)

	// Both the netstack packet and the injected probe must come out of Read;
	// order is select-random, so collect two and classify.
	var sawGvisor, sawProbe bool
	for i := 0; i < 2; i++ {
		pkt := muxRead(t, m)
		switch {
		case bytes.Equal(pkt, gvisorPkt):
			sawGvisor = true
		case pkt[9] == 1 && pkt[ipv4HeaderLen] == 8:
			sawProbe = true
		default:
			t.Fatalf("unexpected packet from Read: %v", pkt)
		}
	}
	if !sawGvisor || !sawProbe {
		t.Fatalf("saw gvisor=%v probe=%v, want both", sawGvisor, sawProbe)
	}

	// Inbound non-ICMP traffic passes through untouched.
	feedInbound(t, m, gvisorPkt)
	got := inner.writtenPackets()
	if len(got) != 1 || !bytes.Equal(got[0], gvisorPkt) {
		t.Fatalf("forwarded = %v, want the exact inbound packet", got)
	}
	<-done
}

func TestTraceMuxEchoReplyCorrelation(t *testing.T) {
	inner := newFakeInner()
	m := newTraceMux(inner, muxLocal)
	defer m.Close()

	done := startProbe(m, 30, time.Second)
	probe := muxRead(t, m)

	// A measurable delay before the reply: Windows' clock granularity would
	// otherwise round a same-instant RTT down to zero.
	time.Sleep(5 * time.Millisecond)
	feedInbound(t, m, echoReplyFor(t, probe, muxDest, false))

	res := <-done
	if res.err != nil {
		t.Fatalf("probe error: %v", res.err)
	}
	if !res.r.Reached || res.r.Timeout {
		t.Fatalf("reply outcome = %+v, want Reached", res.r)
	}
	if res.r.Responder != muxDest {
		t.Fatalf("responder = %v, want %v", res.r.Responder, muxDest)
	}
	if res.r.RTT <= 0 {
		t.Fatalf("RTT = %v, want > 0", res.r.RTT)
	}
	// The reply itself was still forwarded to netstack.
	if got := inner.writtenPackets(); len(got) != 1 {
		t.Fatalf("forwarded %d packets, want 1 (the reply, sniffed AND passed through)", len(got))
	}
}

func TestTraceMuxICMPErrorCorrelation(t *testing.T) {
	router := netip.MustParseAddr("10.7.0.1")

	cases := []struct {
		name     string
		icmpType byte
	}{
		{"time_exceeded", 11},
		{"dest_unreachable", 3},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			inner := newFakeInner()
			m := newTraceMux(inner, muxLocal)
			defer m.Close()

			done := startProbe(m, 2, time.Second)
			probe := muxRead(t, m)
			feedInbound(t, m, icmpErrorFor(t, probe, tc.icmpType, router, nil))

			res := <-done
			if res.err != nil {
				t.Fatalf("probe error: %v", res.err)
			}
			if res.r.Reached || res.r.Timeout {
				t.Fatalf("outcome = %+v, want intermediate responder", res.r)
			}
			if res.r.Responder != router {
				t.Fatalf("responder = %v, want %v", res.r.Responder, router)
			}
		})
	}
}

func TestTraceMuxMismatchedRepliesIgnored(t *testing.T) {
	router := netip.MustParseAddr("10.7.0.1")
	inner := newFakeInner()
	m := newTraceMux(inner, muxLocal)
	defer m.Close()

	done := startProbe(m, 3, 300*time.Millisecond)
	probe := muxRead(t, m)

	// Wrong quoted {id,seq}: not ours.
	feedInbound(t, m, icmpErrorFor(t, probe, 11, router, func(q []byte) {
		binary.BigEndian.PutUint16(q[ipv4HeaderLen+4:], binary.BigEndian.Uint16(q[ipv4HeaderLen+4:])+1)
	}))
	// Wrong quoted destination: stale key from another probe's world.
	feedInbound(t, m, icmpErrorFor(t, probe, 11, router, func(q []byte) {
		q[19] ^= 0xff
	}))
	// Right {id,seq} on an echo reply but wrong token.
	feedInbound(t, m, echoReplyFor(t, probe, muxDest, true))

	res := <-done
	if res.err != nil {
		t.Fatalf("probe error: %v", res.err)
	}
	if !res.r.Timeout {
		t.Fatalf("outcome = %+v, want Timeout (every reply must have been rejected)", res.r)
	}
	// All three packets were still forwarded.
	if got := inner.writtenPackets(); len(got) != 3 {
		t.Fatalf("forwarded %d packets, want 3", len(got))
	}
}

func TestTraceMuxMalformedInboundIsForwardedNotParsed(t *testing.T) {
	inner := newFakeInner()
	m := newTraceMux(inner, muxLocal)
	defer m.Close()

	valid := buildEchoPacket(muxDest, muxLocal, 64, probeKey{id: 1, seq: 1}, []byte("x"))
	malformed := [][]byte{
		{},                      // empty
		{0x45},                  // one byte
		valid[:19],              // truncated IPv4 header
		valid[:ipv4HeaderLen+7], // truncated ICMP header
		{0x60, 0, 0, 0},         // IPv6
		func() []byte { p := append([]byte(nil), valid...); p[9] = 17; return p }(), // UDP
		func() []byte { // fragmented: nonzero offset, ICMP header absent
			p := append([]byte(nil), valid...)
			binary.BigEndian.PutUint16(p[6:8], 0x00b9)
			return p
		}(),
		func() []byte { // ICMP error whose quote is truncated
			p := icmpErrorFor(t, valid, 11, muxDest, nil)
			return p[:len(p)-icmpEchoLen-1]
		}(),
	}
	for i, pkt := range malformed {
		feedInbound(t, m, pkt) // must not panic
		_ = i
	}
	// Everything nonempty reached netstack (the fake counts post-offset bytes).
	if got := inner.writtenPackets(); len(got) != len(malformed) {
		t.Fatalf("forwarded %d packets, want %d", len(got), len(malformed))
	}
}

func TestTraceMuxLateReplyIgnoredAfterTimeout(t *testing.T) {
	inner := newFakeInner()
	m := newTraceMux(inner, muxLocal)
	defer m.Close()

	done := startProbe(m, 4, 50*time.Millisecond)
	probe := muxRead(t, m)

	res := <-done
	if res.err != nil || !res.r.Timeout {
		t.Fatalf("outcome = %+v/%v, want Timeout", res.r, res.err)
	}
	// The registration died with the call; a late reply finds nothing.
	feedInbound(t, m, echoReplyFor(t, probe, muxDest, false))
	m.mu.Lock()
	pendingLen := len(m.pending)
	m.mu.Unlock()
	if pendingLen != 0 {
		t.Fatalf("pending registry has %d entries after timeout, want 0", pendingLen)
	}
}

func TestTraceMuxCloseUnblocksEverything(t *testing.T) {
	inner := newFakeInner()
	m := newTraceMux(inner, muxLocal)

	readDone := make(chan error, 1)
	go func() {
		buf := make([]byte, 2048)
		sizes := make([]int, 1)
		_, err := m.Read([][]byte{buf}, sizes, 0)
		readDone <- err
	}()
	probeDone := startProbe(m, 5, 10*time.Second)
	<-m.inject // steal the injected packet so the probe is parked waiting

	if err := m.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	select {
	case err := <-readDone:
		if !errors.Is(err, os.ErrClosed) {
			t.Fatalf("blocked Read returned %v, want os.ErrClosed", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("blocked Read did not unblock after Close")
	}
	select {
	case res := <-probeDone:
		if res.err == nil {
			t.Fatalf("waiting probe returned %+v, want hard error", res.r)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("waiting probe did not unblock after Close")
	}

	// New work after close fails immediately, and Close is idempotent.
	if _, err := m.traceProbe(context.Background(), muxDest, 1, time.Second); err == nil {
		t.Fatal("traceProbe after Close succeeded, want error")
	}
	if err := m.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

func TestTraceMuxInFlightCap(t *testing.T) {
	inner := newFakeInner()
	m := newTraceMux(inner, muxLocal)
	defer m.Close()

	for i := 0; i < maxPendingProbes; i++ {
		if _, _, err := m.register(muxDest); err != nil {
			t.Fatalf("register %d: %v", i, err)
		}
	}
	if _, _, err := m.register(muxDest); err == nil {
		t.Fatalf("registration %d succeeded, want hard error", maxPendingProbes+1)
	}
}

func TestTraceMuxNoIPv4RefusesProbes(t *testing.T) {
	inner := newFakeInner()
	m := newTraceMux(inner, netip.Addr{})
	defer m.Close()

	if fn := traceProbeFor(m, netip.Addr{}); fn != nil {
		t.Fatal("traceProbeFor with no IPv4 returned a func, want nil (Dialer fails closed)")
	}
	if _, err := m.traceProbe(context.Background(), muxDest, 1, time.Second); err == nil {
		t.Fatal("traceProbe without local IPv4 succeeded, want error")
	}
}
