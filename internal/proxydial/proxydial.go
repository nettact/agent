// Package proxydial builds and owns the egress proxies a monitoring target can
// be pinned to, and hands the collectors a dialer that routes through one.
//
// Three transports, one interface:
//
//   - socks5 — RFC 1928, with optional username/password auth (RFC 1929). TCP via
//     CONNECT (golang.org/x/net/proxy) and UDP via UDP ASSOCIATE (implemented here in
//     socks5udp.go, since x/net/proxy has no UDP support).
//   - http   — HTTP CONNECT with optional Basic auth. CONNECT is its only command, so
//     it tunnels a TCP byte stream and nothing else.
//   - wireguard — a userspace WireGuard device (wireguard-go + netstack); probes dial
//     from INSIDE the tunnel. It carries raw IP, which is why it is the only transport
//     that can carry ICMP — neither relay protocol has a command for forwarding an
//     ICMP echo.
//
// # Fail-closed
//
// Every path here refuses rather than degrades. A pinned proxy that is absent,
// disabled, unusable for the probe kind, or fails to initialize yields a typed
// error and NO connection — the caller reports ReasonProxyConfig and emits a
// failed probe. It never falls back to a direct dial, because a fallback would
// (a) send the probe from the real egress IP the operator deliberately routed
// away from, and (b) make a green check mean "reachable from somewhere",
// which is not what the monitor was configured to assert.
//
// # Relationship to netguard
//
// The Guard's model is "resolve once, pin the vetted literal IP, dial that" — the
// DNS-rebinding defense. Proxying keeps it wherever it still can:
//
//   - The PROXY ENDPOINT is always dialed through the Guard. It is the address the
//     agent actually connects to, so it gets the full policy check.
//   - With DNS mode local (the default) the TARGET is resolved and vetted by the
//     Guard on the agent, and the approved literal IP is what the proxy is asked
//     to reach. Policy and rebinding defense both survive intact.
//   - With DNS mode remote the hostname goes to the proxy, so the Guard can only
//     check the NAME pre-resolution. That is strictly weaker, which is why it is
//     opt-in per proxy and why monitoreval refuses the combination outright when
//     the policy is an allowlist that has not authorized the name.
package proxydial

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/nettact/agent/internal/netguard"
	pcfg "github.com/nettact/protocol/config"
)

// Errors returned when a pin cannot be honored. Each maps to a probe failure, not
// to a direct dial.
var (
	// ErrUnknownProxy means the target names a proxy id absent from the pushed
	// config — typically because the operator disabled it (the server keeps the
	// target in the push precisely so this is reportable).
	ErrUnknownProxy = errors.New("pinned proxy is not in the pushed config")
	// ErrProxyInit means the proxy is known but could not be built (bad key
	// material, unusable tunnel config, endpoint refused by policy).
	ErrProxyInit = errors.New("pinned proxy could not be initialized")
	// ErrProxyKindUnsupported means this transport cannot carry this probe kind
	// (e.g. an ICMP echo through a CONNECT tunnel).
	ErrProxyKindUnsupported = errors.New("pinned proxy cannot carry this probe kind")
	// ErrProxyGeneration means the caller pinned a specific config generation and
	// the live entry is a different one. Only generation-pinned lookups
	// (DialerForGeneration) return it: running a diagnostic over a config the
	// fault was not observed on would answer a different question.
	ErrProxyGeneration = errors.New("pinned proxy generation does not match")
)

// DialFunc dials a target through a proxy. address is "host:port"; host is a
// literal IP under DNS mode local and may be a hostname under remote.
type DialFunc func(ctx context.Context, network, address string) (net.Conn, error)

// Dialer is one live egress path, shared by every target pinned to it.
type Dialer struct {
	// Spec is the config this dialer was built from. Callers read Type and
	// DNSModeOrDefault from it to decide how to prepare the address.
	Spec pcfg.ProxySpec

	// dial routes a TCP connection through the proxy.
	dial DialFunc
	// pinger opens an ICMP echo channel inside the tunnel. Nil for the relay
	// transports, which cannot carry ICMP at all.
	pinger PingFunc
	// listenPacket opens an UNCONNECTED datagram socket inside the tunnel. Nil for
	// the relay transports, which carry TCP only.
	listenPacket ListenPacketFunc
	// traceProbe sends one TTL'd ICMP echo from inside the tunnel and waits for
	// its correlated reply — the traceroute primitive. Nil for the relay
	// transports (no raw IP) and for a tunnel without an IPv4 address.
	traceProbe TraceProbeFunc
	// closeFn releases transport-owned resources (the WireGuard device). Nil for
	// the stateless relay transports.
	closeFn func()
}

// PingFunc opens a datagram conn that carries ICMP echoes to addr from inside a
// tunnel. network is "ping4" or "ping6".
type PingFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// ListenPacketFunc opens an unconnected datagram socket inside a tunnel.
type ListenPacketFunc func() (net.PacketConn, error)

// TraceProbeFunc sends one TTL'd ICMP echo inside a tunnel and waits for the
// correlated reply. A missing reply is a Timeout result, not an error.
type TraceProbeFunc func(ctx context.Context, dest netip.Addr, ttl int, timeout time.Duration) (TraceProbeReply, error)

// TraceProbeReply is the outcome of one in-tunnel TTL'd echo. Timeout means no
// correlated reply arrived in time — never a broken path by itself. Reached is
// set only when the destination itself answered the echo.
type TraceProbeReply struct {
	Responder netip.Addr
	Reached   bool
	Timeout   bool
	RTT       time.Duration
}

// DialContext routes a TCP connection to address through this proxy.
func (d *Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return d.dial(ctx, network, address)
}

// DialPing opens an ICMP echo conn inside the tunnel. It returns
// ErrProxyKindUnsupported for a transport that cannot carry ICMP, so a caller
// that reached here through a capability-check drift fails closed rather than
// dialing around the proxy.
func (d *Dialer) DialPing(ctx context.Context, network, addr string) (net.Conn, error) {
	if d.pinger == nil {
		return nil, fmt.Errorf("%w: %s cannot carry ICMP", ErrProxyKindUnsupported, d.Spec.Type)
	}
	return d.pinger(ctx, network, addr)
}

// ListenPacket opens an unconnected datagram socket that egresses through this proxy:
// a SOCKS5 UDP association, or the tunnel's netstack socket. STUN behaviour discovery
// needs exactly this shape — its mapping and filtering tests are only meaningful when
// every round trip leaves from ONE local port and can address several destinations.
//
// It returns ErrProxyKindUnsupported for HTTP, whose only command is CONNECT and which
// therefore cannot carry datagrams at all. A caller that got here through a
// capability-check drift then fails closed, rather than opening a socket on the host
// stack and measuring the wrong NAT.
func (d *Dialer) ListenPacket() (net.PacketConn, error) {
	if d.listenPacket == nil {
		return nil, fmt.Errorf("%w: %s cannot carry UDP", ErrProxyKindUnsupported, d.Spec.Type)
	}
	return d.listenPacket()
}

// TraceProbe sends one TTL'd ICMP echo from inside the tunnel — the in-tunnel
// traceroute primitive. It returns ErrProxyKindUnsupported for a transport that
// cannot carry raw IP (or a tunnel without IPv4), so a caller that reached here
// through a capability-check drift fails closed rather than probing from the
// host stack and reporting a path the probe never used.
func (d *Dialer) TraceProbe(ctx context.Context, dest netip.Addr, ttl int, timeout time.Duration) (TraceProbeReply, error) {
	if d.traceProbe == nil {
		return TraceProbeReply{}, fmt.Errorf("%w: %s cannot carry in-tunnel probes", ErrProxyKindUnsupported, d.Spec.Type)
	}
	return d.traceProbe(ctx, dest, ttl, timeout)
}

// ResolvesRemotely reports whether the TARGET hostname is resolved by the proxy
// rather than locally. Collectors use it to decide whether to run (and time) a
// local resolution phase.
func (d *Dialer) ResolvesRemotely() bool {
	return d.Spec.DNSModeOrDefault() == pcfg.ProxyDNSRemote
}

// entry is a built dialer plus the generation it was built from.
type entry struct {
	dialer *Dialer
	// serial is the ProxySpec.ConfigSerial this entry was built from. A changed
	// serial forces a rebuild — that is the mechanism by which rotating a password
	// or re-keying a tunnel actually takes effect instead of the old connection
	// living on in a pool.
	serial int
	// buildErr is a sticky initialization failure, cached so a broken proxy is not
	// retried on every probe cycle (which would turn one bad config into a stream
	// of connection attempts). It clears on the next config generation.
	buildErr error
}

// Manager owns the agent's live proxies. It is driven from the session goroutine
// (Apply) and read from collector goroutines (Dialer), so its map is mutex-guarded.
type Manager struct {
	guard *netguard.Guard

	mu      sync.Mutex
	entries map[string]*entry
}

// NewManager builds an empty Manager. guard vets every proxy endpoint the agent
// dials and, under DNS mode local, every target address handed to a proxy.
func NewManager(guard *netguard.Guard) *Manager {
	return &Manager{guard: guard, entries: map[string]*entry{}}
}

// Apply reconciles the live set to the pushed specs. It is the single place where
// a proxy's lifetime is decided:
//
//   - a NEW id is registered (built lazily, on first use)
//   - a CHANGED generation replaces the entry and CLOSES the old one
//   - a REMOVED id is closed and dropped
//
// Closing on change is the point. Without it, a probe could keep succeeding over a
// tunnel or an authenticated connection the operator has already revoked, and the
// console would report a reachability that no longer reflects the configuration.
//
// Building lazily rather than here keeps a config push cheap and keeps a tunnel
// that nothing uses this cycle from being stood up at all.
func (m *Manager) Apply(specs []pcfg.ProxySpec) {
	next := make(map[string]*entry, len(specs))
	var stale []*Dialer

	m.mu.Lock()
	for _, spec := range specs {
		if spec.ID == "" {
			continue
		}
		if cur, ok := m.entries[spec.ID]; ok && cur.serial == spec.ConfigSerial {
			// Same generation: keep the live dialer (and any sticky build error, so a
			// broken config is not retried every cycle).
			cur.dialer = withSpec(cur.dialer, spec)
			next[spec.ID] = cur
			continue
		}
		if cur, ok := m.entries[spec.ID]; ok && cur.dialer != nil {
			stale = append(stale, cur.dialer)
		}
		next[spec.ID] = &entry{serial: spec.ConfigSerial, dialer: &Dialer{Spec: spec}}
	}
	// Anything not in the new push is gone (deleted or disabled server-side).
	for id, cur := range m.entries {
		if _, kept := next[id]; !kept && cur.dialer != nil {
			stale = append(stale, cur.dialer)
		}
	}
	m.entries = next
	m.mu.Unlock()

	// Close outside the lock: tearing down a WireGuard device blocks on its
	// goroutines, and holding the mutex there would stall every in-flight probe
	// looking up an unrelated proxy.
	for _, d := range stale {
		d.close()
	}
}

// withSpec refreshes the non-material fields (currently the display name) on a
// live dialer without rebuilding it. The generation guarantees nothing that
// affects dialing changed, so the transport is left untouched.
func withSpec(d *Dialer, spec pcfg.ProxySpec) *Dialer {
	if d == nil {
		return &Dialer{Spec: spec}
	}
	d.Spec.Name = spec.Name
	return d
}

// Dialer returns the live dialer for a proxy id, building the transport on first
// use. A pin that cannot be honored yields a typed error and no dialer — the
// caller must report a probe failure, never dial directly.
//
// ctx bounds only the initial construction (a WireGuard handshake, a key parse);
// the returned dialer is not tied to it.
func (m *Manager) Dialer(ctx context.Context, proxyID string) (*Dialer, error) {
	if proxyID == "" {
		return nil, nil // not pinned: a direct dial is what was configured
	}
	m.mu.Lock()
	e, ok := m.entries[proxyID]
	if !ok {
		m.mu.Unlock()
		return nil, fmt.Errorf("%w: %s", ErrUnknownProxy, proxyID)
	}
	if e.buildErr != nil {
		err := e.buildErr
		m.mu.Unlock()
		return nil, err
	}
	if e.dialer != nil && e.dialer.dial != nil {
		d := e.dialer
		m.mu.Unlock()
		return d, nil
	}
	spec := e.dialer.Spec
	m.mu.Unlock()

	// Build outside the lock — a WireGuard device stands up a UDP socket and
	// several goroutines, which must not block probes on other proxies.
	built, err := m.build(ctx, spec)

	m.mu.Lock()
	defer m.mu.Unlock()
	// A concurrent Apply may have superseded this generation while we built. Discard
	// our work rather than installing a dialer for a config that is no longer
	// current.
	cur, still := m.entries[proxyID]
	if !still || cur.serial != spec.ConfigSerial {
		if built != nil {
			built.close()
		}
		if !still {
			return nil, fmt.Errorf("%w: %s", ErrUnknownProxy, proxyID)
		}
		return nil, fmt.Errorf("%w: %s superseded during initialization", ErrProxyInit, proxyID)
	}
	if err != nil {
		wrapped := fmt.Errorf("%w: %v", ErrProxyInit, err)
		// Only a DETERMINISTIC failure is cached. A transient one — the peer endpoint
		// briefly unresolvable, the network down at startup, the setup context cancelled
		// — would otherwise disable the proxy until the server happened to change its
		// generation, long after connectivity returned. Retrying costs one build attempt
		// per probe cycle; not retrying costs the monitor indefinitely.
		if isDeterministicInitError(err) {
			cur.buildErr = wrapped
		}
		return nil, wrapped
	}
	// Another caller may have won the race and installed a dialer already; keep
	// theirs so one proxy never ends up with two live transports.
	if cur.dialer != nil && cur.dialer.dial != nil {
		built.close()
		return cur.dialer, nil
	}
	cur.dialer = built
	return built, nil
}

// DialerForGeneration returns the live dialer for a proxy id ONLY if its config
// generation matches the pinned serial, building lazily like Dialer. It is the
// lookup for generation-pinned diagnostics (an in-tunnel trace must run over
// the exact config the fault was observed on): an absent id is ErrUnknownProxy,
// a different generation is ErrProxyGeneration, and neither ever falls back to
// the current generation or a direct path.
func (m *Manager) DialerForGeneration(ctx context.Context, proxyID string, serial int) (*Dialer, error) {
	if proxyID == "" {
		return nil, fmt.Errorf("%w: empty id", ErrUnknownProxy)
	}
	m.mu.Lock()
	e, ok := m.entries[proxyID]
	if !ok {
		m.mu.Unlock()
		return nil, fmt.Errorf("%w: %s", ErrUnknownProxy, proxyID)
	}
	if e.serial != serial {
		live := e.serial
		m.mu.Unlock()
		return nil, fmt.Errorf("%w: %s is at generation %d, not %d", ErrProxyGeneration, proxyID, live, serial)
	}
	m.mu.Unlock()

	d, err := m.Dialer(ctx, proxyID)
	if err != nil {
		return nil, err
	}
	// A concurrent Apply may have replaced the generation while we built; the
	// returned dialer carries the spec it was built from, so re-check it.
	if d.Spec.ConfigSerial != serial {
		return nil, fmt.Errorf("%w: %s replaced during initialization", ErrProxyGeneration, proxyID)
	}
	return d, nil
}

// invalidConfigError marks an initialization failure that no retry can fix, because
// the configuration itself is wrong (unparsable key material, a missing endpoint, an
// unknown type). Only these are cached as sticky build errors; everything else —
// resolution blips, network errors, a cancelled setup — is retried on the next cycle.
type invalidConfigError struct{ err error }

func (e *invalidConfigError) Error() string { return e.err.Error() }
func (e *invalidConfigError) Unwrap() error { return e.err }

// invalidConfig builds a deterministic (non-retryable) initialization error.
func invalidConfig(format string, a ...any) error {
	return &invalidConfigError{err: fmt.Errorf(format, a...)}
}

// isDeterministicInitError reports whether an init failure will recur regardless of
// how long we wait, and may therefore be cached.
//
// A policy block counts: the target-access policy is immutable for an agent run, so a
// blocked proxy endpoint cannot start working without a new config generation — which
// clears the cache anyway.
func isDeterministicInitError(err error) bool {
	var invalid *invalidConfigError
	if errors.As(err, &invalid) {
		return true
	}
	var blocked *netguard.BlockedError
	return errors.As(err, &blocked)
}

// build constructs the transport for one spec.
func (m *Manager) build(ctx context.Context, spec pcfg.ProxySpec) (*Dialer, error) {
	switch spec.Type {
	case pcfg.ProxyTypeSOCKS5:
		return m.newSOCKS5(spec)
	case pcfg.ProxyTypeHTTP:
		return m.newHTTPConnect(spec)
	case pcfg.ProxyTypeWireGuard:
		return m.newWireGuard(ctx, spec)
	}
	return nil, invalidConfig("unknown proxy type %q", spec.Type)
}

// Close tears down every live proxy. Called when the agent run ends.
func (m *Manager) Close() {
	m.mu.Lock()
	entries := m.entries
	m.entries = map[string]*entry{}
	m.mu.Unlock()
	for _, e := range entries {
		if e.dialer != nil {
			e.dialer.close()
		}
	}
}

func (d *Dialer) close() {
	if d != nil && d.closeFn != nil {
		d.closeFn()
	}
}

// Specs returns the live specs by id, for monitor evaluation (which needs each
// pinned proxy's TYPE to run the capability check). It copies, so the caller can
// read it without holding the manager's lock.
func (m *Manager) Specs() map[string]pcfg.ProxySpec {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make(map[string]pcfg.ProxySpec, len(m.entries))
	for id, e := range m.entries {
		if e.dialer != nil {
			out[id] = e.dialer.Spec
		}
	}
	return out
}
