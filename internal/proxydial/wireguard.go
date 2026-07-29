package proxydial

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"

	"github.com/nettact/agent/internal/netguard"
	pcfg "github.com/nettact/protocol/config"
	"github.com/nettact/protocol/telemetry"
)

// Userspace WireGuard, via wireguard-go + gVisor netstack.
//
// WireGuard is not a proxy: there is no relay to ask for a connection. Instead the
// agent runs a complete IP stack whose only route is the tunnel, and probes dial
// from inside it. Because it carries raw IP it is the only transport that can carry
// ICMP echoes — SOCKS5 relays UDP too (see socks5udp.go), but neither relay protocol
// has any command for forwarding an ICMP echo.
//
// Userspace was chosen over configuring an OS interface deliberately: it needs no
// administrator rights, touches no system routing table (so enabling a proxy for one
// monitor cannot move the host's own traffic), and lets several proxies with
// overlapping address space coexist — each has its own private stack.

// newWireGuard stands up a device for one spec. Unlike the relay transports this
// DOES real work at build time (a UDP socket, a handshake, several goroutines),
// which is why Manager builds lazily on first use and closes on any generation
// change.
func (m *Manager) newWireGuard(ctx context.Context, spec pcfg.ProxySpec) (*Dialer, error) {
	localAddrs, err := parseAddrList(spec.WGLocalAddrs)
	if err != nil {
		return nil, invalidConfig("wg_local_addrs: %v", err)
	}
	if len(localAddrs) == 0 {
		return nil, invalidConfig("wg_local_addrs is empty: the tunnel has no source address")
	}
	dnsAddrs, err := parseAddrList(spec.WGDNS)
	if err != nil {
		return nil, invalidConfig("wg_dns: %v", err)
	}

	// The peer endpoint is a real destination the agent sends UDP to, so it goes
	// through the same policy check as any probe target — and is pinned to the vetted
	// literal. wireguard-go would otherwise resolve the name itself, outside the
	// guard, which is exactly the bypass netguard exists to prevent.
	// Passed through unclassified on purpose: a policy block here is deterministic (and
	// recognized as such by isDeterministicInitError), while a resolution failure is
	// transient and must be retried once DNS recovers.
	endpoint, err := m.vetWireGuardEndpoint(ctx, spec.WGEndpoint)
	if err != nil {
		return nil, err
	}

	// Every wireGuardUAPI failure is a key or CIDR that cannot parse — deterministic,
	// so it is cached rather than retried every cycle.
	uapi, err := wireGuardUAPI(spec, endpoint)
	if err != nil {
		return nil, invalidConfig("%v", err)
	}

	tunDev, tnet, err := netstack.CreateNetTUN(localAddrs, dnsAddrs, spec.WireGuardMTU())
	if err != nil {
		return nil, fmt.Errorf("create tunnel device: %w", err)
	}
	// Silent logger: a tunnel logs per-packet at higher levels, and the agent's
	// diagnosis surface is the probe's error class, not a wireguard trace.
	dev := device.NewDevice(tunDev, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, "wg:"+spec.ID+" "))
	if err := dev.IpcSet(uapi); err != nil {
		dev.Close()
		return nil, fmt.Errorf("apply tunnel config: %w", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, fmt.Errorf("bring tunnel up: %w", err)
	}

	return &Dialer{
		Spec: spec,
		dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			c, derr := tnet.DialContext(ctx, network, address)
			if derr != nil {
				return nil, classifyTunnelError(derr)
			}
			return c, nil
		},
		pinger: func(ctx context.Context, network, addr string) (net.Conn, error) {
			// netstack exposes ICMP as a "ping4"/"ping6" datagram conn. There is no
			// context-aware variant, so the caller sets a deadline on the returned conn.
			c, derr := tnet.Dial(network, addr)
			if derr != nil {
				return nil, classifyTunnelError(derr)
			}
			return c, nil
		},
		listenPacket: func() (net.PacketConn, error) {
			// A nil laddr binds an ephemeral in-tunnel port on the first local address,
			// mirroring net.ListenUDP("udp", nil) on the host stack.
			c, derr := tnet.ListenUDP(nil)
			if derr != nil {
				return nil, classifyTunnelError(derr)
			}
			return c, nil
		},
		closeFn: func() {
			// Closing the device stops its goroutines and releases the UDP socket. It is
			// what makes a re-keyed or deleted proxy actually stop carrying traffic.
			dev.Close()
		},
	}, nil
}

// vetWireGuardEndpoint resolves and policy-checks the peer endpoint, returning a
// literal "ip:port" for the UAPI config.
func (m *Manager) vetWireGuardEndpoint(ctx context.Context, endpoint string) (string, error) {
	host, portStr, err := net.SplitHostPort(strings.TrimSpace(endpoint))
	if err != nil {
		return "", fmt.Errorf("wg_endpoint must be host:port: %w", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return "", fmt.Errorf("wg_endpoint port %q is not in 1-65535", portStr)
	}
	// VetUDPAddr applies the full contract for an unconnected-socket destination:
	// literal IPs get CheckAddr, hostnames get the pre-resolution CheckHost then
	// vetted resolution, and the returned address is the pinned literal.
	udp, err := m.guard.VetUDPAddr(ctx, net.JoinHostPort(host, portStr))
	if err != nil {
		var blocked *netguard.BlockedError
		if errors.As(err, &blocked) {
			return "", fmt.Errorf("wg_endpoint refused by target policy: %w", err)
		}
		return "", fmt.Errorf("resolve wg_endpoint: %w", err)
	}
	addr, ok := netguard.IPToAddr(udp.IP)
	if !ok {
		return "", fmt.Errorf("wg_endpoint resolved to an unusable address")
	}
	return net.JoinHostPort(addr.String(), strconv.Itoa(udp.Port)), nil
}

// wireGuardUAPI renders the spec as a wireguard-go UAPI configuration.
//
// The UAPI takes HEX keys while the console and the wire carry base64 (the format
// wg(8) prints and users copy), so each key is decoded and re-encoded here.
func wireGuardUAPI(spec pcfg.ProxySpec, endpoint string) (string, error) {
	priv, err := decodeWGKey("wg_private_key", spec.WGPrivateKey)
	if err != nil {
		return "", err
	}
	pub, err := decodeWGKey("wg_peer_public_key", spec.WGPeerPublicKey)
	if err != nil {
		return "", err
	}
	allowed, err := parsePrefixList(spec.WGAllowedIPs)
	if err != nil {
		return "", fmt.Errorf("wg_allowed_ips: %w", err)
	}
	if len(allowed) == 0 {
		return "", errors.New("wg_allowed_ips is empty: the tunnel would route nothing")
	}

	var b strings.Builder
	b.WriteString("private_key=" + priv + "\n")
	b.WriteString("public_key=" + pub + "\n")
	b.WriteString("endpoint=" + endpoint + "\n")
	if spec.WGPresharedKey != "" {
		psk, perr := decodeWGKey("wg_preshared_key", spec.WGPresharedKey)
		if perr != nil {
			return "", perr
		}
		b.WriteString("preshared_key=" + psk + "\n")
	}
	for _, p := range allowed {
		b.WriteString("allowed_ip=" + p.String() + "\n")
	}
	if spec.WGKeepaliveSeconds > 0 {
		b.WriteString("persistent_keepalive_interval=" + strconv.Itoa(spec.WGKeepaliveSeconds) + "\n")
	}
	return b.String(), nil
}

// decodeWGKey converts base64 key material to the hex form the UAPI expects.
func decodeWGKey(field, raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", errors.New(field + " is empty")
	}
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return "", fmt.Errorf("%s is not valid base64: %w", field, err)
	}
	if len(b) != 32 {
		return "", fmt.Errorf("%s must decode to 32 bytes, got %d", field, len(b))
	}
	return hex.EncodeToString(b), nil
}

// parseAddrList parses a CSV of addresses (each optionally carrying a prefix
// length, which is discarded — netstack takes bare addresses).
func parseAddrList(csv string) ([]netip.Addr, error) {
	var out []netip.Addr
	for _, part := range splitCSV(csv) {
		if pfx, err := netip.ParsePrefix(part); err == nil {
			out = append(out, pfx.Addr().Unmap())
			continue
		}
		a, err := netip.ParseAddr(part)
		if err != nil {
			return nil, fmt.Errorf("%q is not an IP address", part)
		}
		out = append(out, a.Unmap())
	}
	return out, nil
}

// parsePrefixList parses a CSV of CIDRs.
func parsePrefixList(csv string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, part := range splitCSV(csv) {
		pfx, err := netip.ParsePrefix(part)
		if err != nil {
			return nil, fmt.Errorf("%q is not a CIDR", part)
		}
		out = append(out, pfx.Masked())
	}
	return out, nil
}

func splitCSV(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}

// classifyTunnelError maps a netstack dial failure onto a reason.
//
// Inside a tunnel the two cases the operator must distinguish are "the tunnel is
// not carrying traffic" (peer down, wrong key, handshake never completed — the
// stack reports no route or a timeout) and "the tunnel works and the target refused"
// (a real RST from the far side, which is a genuine target verdict).
func classifyTunnelError(err error) error {
	s := strings.ToLower(err.Error())
	switch {
	case strings.Contains(s, "connection refused"):
		// The tunnel delivered the SYN and got a RST: the target is up and the port is
		// closed. A real target verdict, so it keeps the target's own reason.
		return &ProxyError{Reason: telemetry.ProbeReasonRefused, Err: err, AtTarget: true}
	case strings.Contains(s, "no route to host"), strings.Contains(s, "network is unreachable"),
		strings.Contains(s, "endpoint is closed"), strings.Contains(s, "invalid endpoint state"):
		// Nothing left the tunnel: either allowed_ips does not cover the target or the
		// peer never came up.
		return &ProxyError{Reason: telemetry.ProbeReasonProxyConnect, Err: err}
	case strings.Contains(s, "operation timed out"), strings.Contains(s, "i/o timeout"),
		strings.Contains(s, "context deadline exceeded"):
		// A handshake that never completes looks exactly like this. Attributing it to
		// the target would blame a service the packets never reached.
		return &ProxyError{Reason: telemetry.ProbeReasonProxyConnect, Err: err}
	case strings.Contains(s, "no such host"), strings.Contains(s, "dns"):
		return &ProxyError{Reason: telemetry.ProbeReasonProxyDNS, Err: err}
	}
	return &ProxyError{Reason: telemetry.ProbeReasonProxyConnect, Err: err}
}
