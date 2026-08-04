//go:build !lite

package proxydial

import (
	"bytes"
	"context"
	crand "crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"sync"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.zx2c4.com/wireguard/tun"
)

// traceMux is a tun.Device wrapper inserted between netstack.CreateNetTUN and
// device.NewDevice. It is what makes an in-tunnel traceroute possible at all:
// the netstack above it exposes no TTL control and drops ICMP Time-Exceeded in
// its IP layer, while the device below it will happily encrypt any IP packet it
// is handed. So the mux speaks raw IPv4/ICMP directly to the device:
//
//   - Read (wireguard-go pulling outbound): netstack's packets flow through
//     unchanged, interleaved with self-built TTL'd ICMP echoes from traceProbe.
//   - Write (wireguard-go pushing decrypted inbound): every packet is forwarded
//     to netstack unchanged; Echo Reply, Time Exceeded and Destination
//     Unreachable are additionally COPIED to the matching in-flight probe.
//
// The copy-never-consume rule is what keeps the tunnel's normal traffic (TCP,
// UDP, netstack's own pings) completely unaffected: gVisor drops what it does
// not own (foreign-id echo replies in its ICMP endpoint, Time-Exceeded in its
// IPv4 layer), which for once works in our favor.
//
// v1 scope is deliberately IPv4 + ICMP echo only.
type traceMux struct {
	inner tun.Device

	// innerOut carries netstack's outbound packets from the pump goroutine to
	// Read. Buffer ownership transfers with the send. Closed by the pump on a
	// read error; readErr then holds the sticky cause.
	innerOut chan []byte
	// inject carries traceProbe's self-built echoes to Read.
	inject chan []byte
	// done is closed by Close. It unblocks waiting probers and refuses new ones;
	// the pump itself exits via the inner device's own close error.
	done chan struct{}

	mu      sync.Mutex
	readErr error
	pending map[probeKey]*pendingProbe
	nextSeq uint16
	// idBase is this mux's ICMP echo identifier, randomized so a probe cannot
	// collide with the ids netstack assigns to its own ping sockets.
	idBase uint16
	closed bool

	// localV4 is the in-tunnel IPv4 source address probes are sent from. An
	// invalid addr means the tunnel has no IPv4 and probing is unsupported.
	localV4 netip.Addr
}

// probeKey correlates one in-flight echo: ICMP identifier + sequence.
type probeKey struct{ id, seq uint16 }

// probeReply is what the Write-side sniffer delivers to a waiting probe.
type probeReply struct {
	responder netip.Addr
	reached   bool
	at        time.Time
}

// pendingProbe is one registered in-flight echo awaiting its reply.
type pendingProbe struct {
	// ch is buffered (cap 1) so the sniffer can deliver without blocking Write.
	ch chan probeReply
	// payload is the exact echo payload sent. Replies must carry it back: the
	// {id,seq} key alone could collide with netstack's own pings, whose ids the
	// stack assigns invisibly (the same reason pingtunnel matches on payload).
	payload []byte
	dest    netip.Addr
}

const (
	// maxPendingProbes bounds concurrent in-flight echoes per tunnel. Traces run
	// hop-by-hop, so even several concurrent traces stay far below this; hitting
	// it means something is leaking and failing hard beats silent misbehavior.
	maxPendingProbes = 64
	// injectQueueDepth buffers built echoes between traceProbe and Read. Probes
	// are paced by their per-attempt round trips, so this never fills in
	// practice; it exists so a send does not require a reader mid-select.
	injectQueueDepth = 16

	ipv4HeaderLen = 20
	icmpEchoLen   = 8
)

// echoPayloadPrefix marks the mux's probes on the wire, ahead of the per-probe
// random token.
var echoPayloadPrefix = []byte("nettact-trace")

// traceProbeFor exposes a mux's probe primitive as a Dialer capability, or nil
// when the tunnel has no IPv4 — the Dialer then fails closed exactly like a
// relay transport asked to carry ICMP.
func traceProbeFor(m *traceMux, localV4 netip.Addr) TraceProbeFunc {
	if !localV4.IsValid() {
		return nil
	}
	return m.traceProbe
}

// newTraceMux wraps a netstack tun device. localV4 may be invalid (no IPv4 in
// the tunnel); the mux then still relays traffic but refuses probes.
func newTraceMux(inner tun.Device, localV4 netip.Addr) *traceMux {
	m := &traceMux{
		inner:    inner,
		innerOut: make(chan []byte),
		inject:   make(chan []byte, injectQueueDepth),
		done:     make(chan struct{}),
		pending:  make(map[probeKey]*pendingProbe),
		localV4:  localV4,
	}
	var b [2]byte
	if _, err := crand.Read(b[:]); err == nil {
		m.idBase = binary.BigEndian.Uint16(b[:])
	}
	go m.pump()
	return m
}

// pump moves netstack's outbound packets onto innerOut. It exists because the
// inner Read blocks with nothing to select against, and Read must also serve
// injected probes. One packet per iteration mirrors the netstack device's own
// contract (BatchSize 1, one packet per Read). Each packet gets a fresh buffer
// — ownership transfers over the channel, and a diagnostic tunnel carries
// probe-scale traffic, not line rate.
func (m *traceMux) pump() {
	mtu, err := m.inner.MTU()
	if err != nil || mtu <= 0 {
		mtu = 1500
	}
	sizes := make([]int, 1)
	for {
		buf := make([]byte, mtu)
		n, err := m.inner.Read([][]byte{buf}, sizes, 0)
		if err != nil {
			m.mu.Lock()
			m.readErr = err
			m.mu.Unlock()
			close(m.innerOut)
			return
		}
		if n == 0 || sizes[0] == 0 {
			continue
		}
		select {
		case m.innerOut <- buf[:sizes[0]]:
		case <-m.done:
			// The device stopped reading before the inner close landed; drop the
			// packet and let the next inner Read surface the close error.
		}
	}
}

// Read hands wireguard-go the next outbound packet: netstack traffic and
// injected probes, whichever is ready first.
func (m *traceMux) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	select {
	case pkt, ok := <-m.innerOut:
		if !ok {
			m.mu.Lock()
			err := m.readErr
			m.mu.Unlock()
			if err == nil {
				err = os.ErrClosed
			}
			return 0, err
		}
		sizes[0] = copy(bufs[0][offset:], pkt)
		return 1, nil
	case pkt := <-m.inject:
		sizes[0] = copy(bufs[0][offset:], pkt)
		return 1, nil
	}
}

// Write forwards every decrypted inbound packet to netstack unchanged, after
// offering each to the probe sniffer.
func (m *traceMux) Write(bufs [][]byte, offset int) (int, error) {
	for _, b := range bufs {
		m.sniff(b[offset:])
	}
	return m.inner.Write(bufs, offset)
}

// sniff inspects one inbound packet for a reply to a registered probe. It only
// ever copies — the packet continues to netstack regardless — and is defensive
// against truncation at every step, because tunnel peers send arbitrary bytes.
func (m *traceMux) sniff(pkt []byte) {
	if len(pkt) < ipv4HeaderLen+icmpEchoLen || pkt[0]>>4 != 4 {
		return
	}
	ihl := int(pkt[0]&0x0f) * 4
	if ihl < ipv4HeaderLen || len(pkt) < ihl+icmpEchoLen {
		return
	}
	if pkt[9] != 1 { // not ICMP
		return
	}
	if binary.BigEndian.Uint16(pkt[6:8])&0x1fff != 0 { // non-first fragment: ICMP header absent
		return
	}
	responder, ok := netip.AddrFromSlice(pkt[12:16])
	if !ok {
		return
	}
	body := pkt[ihl:]

	switch body[0] {
	case 0: // Echo Reply
		if body[1] != 0 {
			return
		}
		key := probeKey{id: binary.BigEndian.Uint16(body[4:6]), seq: binary.BigEndian.Uint16(body[6:8])}
		m.deliver(key, responder, body[icmpEchoLen:], true)
	case 11, 3: // Time Exceeded / Destination Unreachable
		// The quoted original: inner IPv4 header + at least the first 8 bytes of
		// our echo. The token is NOT guaranteed to be quoted, so matching is by
		// {id,seq} plus the quoted destination.
		q := body[icmpEchoLen:]
		if len(q) < ipv4HeaderLen+icmpEchoLen || q[0]>>4 != 4 {
			return
		}
		qihl := int(q[0]&0x0f) * 4
		if qihl < ipv4HeaderLen || len(q) < qihl+icmpEchoLen {
			return
		}
		if q[9] != 1 || q[qihl] != 8 { // quoted packet must be our ICMP Echo Request
			return
		}
		key := probeKey{id: binary.BigEndian.Uint16(q[qihl+4 : qihl+6]), seq: binary.BigEndian.Uint16(q[qihl+6 : qihl+8])}
		quotedDest, ok := netip.AddrFromSlice(q[16:20])
		if !ok {
			return
		}
		m.deliverError(key, responder, quotedDest)
	}
}

// deliver matches an echo reply against the registry. reached is decided here:
// only the probed destination answering its own echo counts, mirroring the
// platform probers' contract.
func (m *traceMux) deliver(key probeKey, responder netip.Addr, payload []byte, echoReply bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, ok := m.pending[key]
	if !ok || (echoReply && !bytes.Equal(payload, p.payload)) {
		return
	}
	r := probeReply{responder: responder, at: time.Now()}
	if echoReply && responder == p.dest {
		r.reached = true
	}
	select {
	case p.ch <- r:
	default:
	}
}

// deliverError matches an ICMP error (Time Exceeded / Destination Unreachable)
// whose quote names one of our probes. The quoted destination must match the
// probe's, guarding against a stale {id,seq} collision.
func (m *traceMux) deliverError(key probeKey, responder, quotedDest netip.Addr) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, ok := m.pending[key]
	if !ok || quotedDest != p.dest {
		return
	}
	select {
	case p.ch <- probeReply{responder: responder, at: time.Now()}:
	default:
	}
}

// traceProbe sends one TTL'd ICMP echo into the tunnel and waits for its
// correlated reply. A missing reply is {Timeout:true}, never an error; errors
// are reserved for conditions that doom the whole trace (mux closed, no
// in-tunnel IPv4, registry full). Context cancellation also reports as a
// timeout — the caller's hop loop owns cancellation classification.
func (m *traceMux) traceProbe(ctx context.Context, dest netip.Addr, ttl int, timeout time.Duration) (TraceProbeReply, error) {
	dest = dest.Unmap()
	if !m.localV4.IsValid() || !dest.Is4() {
		return TraceProbeReply{}, errors.New("in-tunnel probing requires IPv4 on both ends")
	}
	if ttl < 1 || ttl > 255 {
		return TraceProbeReply{}, fmt.Errorf("ttl %d out of range", ttl)
	}

	key, entry, err := m.register(dest)
	if err != nil {
		return TraceProbeReply{}, err
	}
	defer m.unregister(key)

	pkt := buildEchoPacket(m.localV4, dest, ttl, key, entry.payload)
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	sendTime := time.Now()

	select {
	case m.inject <- pkt:
	case <-m.done:
		return TraceProbeReply{}, errors.New("tunnel device closed")
	case <-ctx.Done():
		return TraceProbeReply{Timeout: true}, nil
	case <-timer.C:
		// The device stopped pulling packets; degrade to a timeout, not a deadlock.
		return TraceProbeReply{Timeout: true}, nil
	}

	select {
	case r := <-entry.ch:
		return TraceProbeReply{Responder: r.responder, Reached: r.reached, RTT: r.at.Sub(sendTime)}, nil
	case <-m.done:
		return TraceProbeReply{}, errors.New("tunnel device closed")
	case <-ctx.Done():
		return TraceProbeReply{Timeout: true}, nil
	case <-timer.C:
		return TraceProbeReply{Timeout: true}, nil
	}
}

// register allocates a free {id,seq} key and enters the probe into the
// registry. Late replies after unregister find no entry and are ignored — the
// registration's lifetime IS the probe call frame, so no reaper is needed.
func (m *traceMux) register(dest netip.Addr) (probeKey, *pendingProbe, error) {
	payload := make([]byte, 0, len(echoPayloadPrefix)+8)
	payload = append(payload, echoPayloadPrefix...)
	var token [8]byte
	if _, err := crand.Read(token[:]); err != nil {
		return probeKey{}, nil, fmt.Errorf("probe token: %w", err)
	}
	payload = append(payload, token[:]...)

	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return probeKey{}, nil, errors.New("tunnel device closed")
	}
	if len(m.pending) >= maxPendingProbes {
		return probeKey{}, nil, fmt.Errorf("too many in-flight probes (%d)", maxPendingProbes)
	}
	var key probeKey
	for {
		key = probeKey{id: m.idBase, seq: m.nextSeq}
		m.nextSeq++
		if _, exists := m.pending[key]; !exists {
			break
		}
	}
	p := &pendingProbe{ch: make(chan probeReply, 1), payload: payload, dest: dest}
	m.pending[key] = p
	return key, p, nil
}

func (m *traceMux) unregister(key probeKey) {
	m.mu.Lock()
	delete(m.pending, key)
	m.mu.Unlock()
}

// buildEchoPacket assembles a complete IPv4 + ICMP Echo Request with the probe's
// TTL. The ICMP checksum comes from x/net/icmp's marshal; the IPv4 header
// checksum is computed here — there is no kernel below to fill it in.
func buildEchoPacket(src, dst netip.Addr, ttl int, key probeKey, payload []byte) []byte {
	msg := icmp.Message{
		Type: ipv4.ICMPTypeEcho, Code: 0,
		Body: &icmp.Echo{ID: int(key.id), Seq: int(key.seq), Data: payload},
	}
	body, err := msg.Marshal(nil)
	if err != nil {
		// Marshal of a well-formed echo cannot fail; a zero-length packet would
		// simply time out, and the impossibility is not worth widening the API.
		return nil
	}
	pkt := make([]byte, ipv4HeaderLen+len(body))
	pkt[0] = 0x45 // version 4, IHL 5
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	binary.BigEndian.PutUint16(pkt[4:6], key.seq) // IP identification: any value
	pkt[8] = byte(ttl)
	pkt[9] = 1 // ICMP
	src4, dst4 := src.As4(), dst.As4()
	copy(pkt[12:16], src4[:])
	copy(pkt[16:20], dst4[:])
	binary.BigEndian.PutUint16(pkt[10:12], ipv4HeaderChecksum(pkt[:ipv4HeaderLen]))
	copy(pkt[ipv4HeaderLen:], body)
	return pkt
}

// ipv4HeaderChecksum is the RFC 791 ones'-complement header checksum, computed
// over a header whose checksum field is zero.
func ipv4HeaderChecksum(hdr []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(hdr); i += 2 {
		if i == 10 {
			continue // the checksum field itself counts as zero
		}
		sum += uint32(binary.BigEndian.Uint16(hdr[i : i+2]))
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}

// The remaining tun.Device surface delegates to the inner device.

func (m *traceMux) File() *os.File           { return m.inner.File() }
func (m *traceMux) MTU() (int, error)        { return m.inner.MTU() }
func (m *traceMux) Name() (string, error)    { return m.inner.Name() }
func (m *traceMux) Events() <-chan tun.Event { return m.inner.Events() }
func (m *traceMux) BatchSize() int           { return m.inner.BatchSize() }

// Close unblocks every waiting prober, refuses new ones, and closes the inner
// device — whose own close error is what stops the pump and, through it,
// wireguard-go's reader.
func (m *traceMux) Close() error {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil
	}
	m.closed = true
	close(m.done)
	m.mu.Unlock()
	return m.inner.Close()
}
