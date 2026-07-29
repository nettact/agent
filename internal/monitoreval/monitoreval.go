// Package monitoreval evaluates each server-pushed monitor against the agent's
// effective permissions and target-access policy, producing the runnable subset
// (handed to the collectors) and a full-state wire.MonitorStatus frame (sent to
// the server, which derives operational issues from it). It also tracks runtime
// target-policy transitions (a hostname that flips from allowed to denied, a
// denied redirect, a recovery) reported by the collectors.
//
// The tracker is owned by the agent runtime and driven from the session
// goroutine, so its state is single-writer and needs no locking beyond the
// runtime-transition path (which is fed from collector goroutines).
package monitoreval

import (
	"net"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/nettact/agent/internal/netguard"
	"github.com/nettact/protocol/config"
	"github.com/nettact/protocol/permission"
	"github.com/nettact/protocol/wire"
)

// ProxySet exposes the live egress proxies to monitor evaluation. Evaluation only
// needs each pinned proxy's TYPE and DNS mode to decide whether a monitor can run,
// so this is an interface rather than a dependency on the transport package —
// keeping monitoreval free of wireguard/netstack.
//
// Satisfied by *proxydial.Manager.
type ProxySet interface {
	Specs() map[string]config.ProxySpec
}

// Tracker holds the immutable policy views plus the latest evaluated state.
type Tracker struct {
	effective  permission.Set
	granted    permission.Set
	supported  permission.Set
	guard      *netguard.Guard
	proxies    ProxySet
	policyHash string
	// minProbeInterval is the agent-local per-target interval floor (the same
	// stability limit the collectors apply). It raises the reported effective
	// interval so the server's freshness window matches what the agent runs.
	minProbeInterval time.Duration
	// uploadIntervalSeconds is the agent's global WAL batch-upload cadence rounded
	// up to whole seconds. Reported frame-level so the server folds the agent's
	// batching + drain latency into the freshness window.
	uploadIntervalSeconds int

	mu            sync.Mutex
	configVersion int
	base          map[string]wire.MonitorStatusEntry // static evaluation per monitor
	runtime       map[string]wire.MonitorStatusEntry // runtime override per monitor
	order         []string                           // monitor ids in push order

	updates chan wire.MonitorStatus // cap-1 latest-wins
}

// New builds a Tracker. minProbeInterval is the agent-local probe-interval floor
// (0 = none) that the reported effective per-target interval is floored by.
// uploadInterval is the agent's global WAL batch-upload cadence, reported at the
// frame level rounded up to whole seconds (a sub-second interval becomes 1).
//
// proxies is the live egress-proxy set. A nil ProxySet is legal and fails closed:
// every target with a proxy pin evaluates as proxy_missing rather than silently
// becoming a direct dial.
func New(effective, granted, supported permission.Set, guard *netguard.Guard, proxies ProxySet, policyHash string, minProbeInterval, uploadInterval time.Duration) *Tracker {
	return &Tracker{
		effective:             effective,
		granted:               granted,
		supported:             supported,
		guard:                 guard,
		proxies:               proxies,
		policyHash:            policyHash,
		minProbeInterval:      minProbeInterval,
		uploadIntervalSeconds: ceilSeconds(uploadInterval),
		base:                  map[string]wire.MonitorStatusEntry{},
		runtime:               map[string]wire.MonitorStatusEntry{},
		updates:               make(chan wire.MonitorStatus, 1),
	}
}

// ceilSeconds rounds a positive duration up to whole seconds (500ms → 1). A
// non-positive duration yields 0.
func ceilSeconds(d time.Duration) int {
	if d <= 0 {
		return 0
	}
	return int((d + time.Second - 1) / time.Second)
}

// Updates is the cap-1 latest-wins channel the session goroutine selects on to
// forward a runtime-transition frame to the server.
func (t *Tracker) Updates() <-chan wire.MonitorStatus { return t.updates }

// ApplyDesired evaluates every target for a new DesiredState version. It returns
// the runnable subset (status active) and the full-state MonitorStatus frame.
// Statically blocked monitors are excluded from the runnable set so they are
// never scheduled — no synthetic failure metric is ever produced for them.
func (t *Tracker) ApplyDesired(configVersion int, targets []config.ProbeTarget) ([]config.ProbeTarget, wire.MonitorStatus) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.configVersion = configVersion
	t.base = map[string]wire.MonitorStatusEntry{}
	t.runtime = map[string]wire.MonitorStatusEntry{}
	t.order = t.order[:0]

	var runnable []config.ProbeTarget
	for _, tgt := range targets {
		if tgt.MonitorID == "" {
			// Only user-created monitors have ids and thus a reportable status.
			runnable = append(runnable, tgt)
			continue
		}
		entry := t.evaluate(tgt)
		t.stampSchedule(&entry, tgt)
		t.base[tgt.MonitorID] = entry
		t.order = append(t.order, tgt.MonitorID)
		if entry.Status == wire.MonitorStatusActive {
			runnable = append(runnable, tgt)
		}
	}
	return runnable, t.frameLocked()
}

// stampSchedule fills the per-entry material generation and the actual effective
// per-target schedule (interval floored by the agent-local MinProbeInterval,
// whole-cycle deadline) from the applied ProbeTarget. Stamped on every entry —
// active or blocked — so the server reads a consistent generation/freshness echo.
func (t *Tracker) stampSchedule(entry *wire.MonitorStatusEntry, tgt config.ProbeTarget) {
	entry.TargetConfigSerial = tgt.ConfigSerial
	iv := config.EffectiveInterval(tgt.Kind, tgt.Params)
	if t.minProbeInterval > 0 && iv < t.minProbeInterval {
		iv = t.minProbeInterval
	}
	entry.EffectiveIntervalSeconds = int(iv / time.Second)
	entry.CycleDeadlineMs = int(config.CycleDeadline(tgt.Kind, tgt.Params) / time.Millisecond)
}

// evaluate computes a monitor's static status: permission first, then the egress
// proxy pin, then target policy. All missing granted-but-unsupported permissions
// yield unsupported; otherwise any missing permission yields permission_blocked
// (combined into one entry). A literal-IP or hostname destination denied by policy
// yields target_blocked.
func (t *Tracker) evaluate(tgt config.ProbeTarget) wire.MonitorStatusEntry {
	entry := wire.MonitorStatusEntry{MonitorID: tgt.MonitorID, Status: wire.MonitorStatusActive}

	var missing, unsupported []string
	for _, id := range permission.RequiredForTarget(tgt) {
		if t.effective.Has(id) {
			continue
		}
		if t.granted.Has(id) && !t.supported.Has(id) {
			unsupported = append(unsupported, string(id))
		} else {
			missing = append(missing, string(id))
		}
	}
	if len(missing) > 0 {
		entry.Status = wire.MonitorStatusPermissionBlocked
		entry.MissingPermissions = missing
		return entry
	}
	if len(unsupported) > 0 {
		entry.Status = wire.MonitorStatusUnsupported
		entry.MissingPermissions = unsupported
		return entry
	}

	// Egress proxy pin. An unhonorable pin makes the monitor un-runnable, never
	// direct: it is excluded from the runnable set here so the probe is not scheduled
	// and fabricates no failure metric, and the reason travels to the server as an
	// operational issue ("this monitor is not running, and here is why").
	if blocked, ok := t.evaluateProxy(tgt); ok {
		return blocked
	}

	// Target policy (static): literal-IP destination fully checked; hostname
	// destination checked for a conclusive deny. Runtime resolution catches a
	// name that resolves into a denied address later.
	host := staticHost(tgt)
	if host == "" {
		return entry
	}
	if a, err := netip.ParseAddr(host); err == nil {
		if dec := t.guard.CheckAddr(a.Unmap()); !dec.Allowed {
			entry.Status = wire.MonitorStatusTargetBlocked
			entry.MatchedSelector = dec.Matched
			entry.Reason = "literal_denied"
		}
		return entry
	}
	if hd := t.guard.CheckHost(host); hd.Denied {
		entry.Status = wire.MonitorStatusTargetBlocked
		entry.MatchedSelector = hd.Matched
		entry.Reason = "literal_denied"
	}
	return entry
}

// RuntimeBlocked records a runtime target-policy block for a monitor and pushes
// an updated full-state frame. The transition is attributed to the generation that
// produced it (configSerial): it is ignored unless it exactly matches the currently
// tracked base entry's TargetConfigSerial, so an obsolete in-flight probe can never
// block, relabel, or otherwise alter the current generation. A monitor already
// statically blocked is left as is (the static block is authoritative for
// scheduling).
func (t *Tracker) RuntimeBlocked(monitorID string, configSerial int, matched, reason string) {
	t.mu.Lock()
	base, tracked := t.base[monitorID]
	if !tracked {
		t.mu.Unlock()
		return
	}
	if configSerial != base.TargetConfigSerial {
		// Obsolete in-flight result from a superseded generation — drop it.
		t.mu.Unlock()
		return
	}
	cur := t.runtime[monitorID]
	if cur.Status == wire.MonitorStatusTargetBlocked && cur.MatchedSelector == matched && cur.Reason == reason {
		t.mu.Unlock()
		return // no change
	}
	t.runtime[monitorID] = wire.MonitorStatusEntry{
		MonitorID: monitorID, Status: wire.MonitorStatusTargetBlocked,
		MatchedSelector: matched, Reason: reason,
		// Retain the current base entry's generation echo + effective schedule so a
		// runtime override reports the same per-target facts as its static counterpart.
		EffectiveIntervalSeconds: base.EffectiveIntervalSeconds,
		CycleDeadlineMs:          base.CycleDeadlineMs,
		TargetConfigSerial:       base.TargetConfigSerial,
	}
	frame := t.frameLocked()
	t.mu.Unlock()
	t.push(frame)
}

// RuntimeOK clears a runtime block for a monitor (a later clean dial) and pushes
// an updated frame if the state changed. Like RuntimeBlocked it is attributed to
// the originating generation (configSerial): a recovery from a superseded generation
// is ignored so an obsolete in-flight result can never clear the current status.
func (t *Tracker) RuntimeOK(monitorID string, configSerial int) {
	t.mu.Lock()
	if _, had := t.runtime[monitorID]; !had {
		t.mu.Unlock()
		return
	}
	if configSerial != t.base[monitorID].TargetConfigSerial {
		// Obsolete in-flight recovery from a superseded generation — drop it.
		t.mu.Unlock()
		return
	}
	delete(t.runtime, monitorID)
	frame := t.frameLocked()
	t.mu.Unlock()
	t.push(frame)
}

// frameLocked builds the full-state frame from base+runtime. Caller holds mu.
func (t *Tracker) frameLocked() wire.MonitorStatus {
	statuses := make([]wire.MonitorStatusEntry, 0, len(t.order))
	for _, id := range t.order {
		if rt, ok := t.runtime[id]; ok && t.base[id].Status == wire.MonitorStatusActive {
			// A runtime block only overrides an otherwise-active monitor.
			statuses = append(statuses, rt)
			continue
		}
		statuses = append(statuses, t.base[id])
	}
	return wire.MonitorStatus{
		ConfigVersion:         t.configVersion,
		PolicyHash:            t.policyHash,
		UploadIntervalSeconds: t.uploadIntervalSeconds,
		Statuses:              statuses,
	}
}

// push writes the latest frame to the cap-1 channel, dropping any stale pending
// frame (latest-wins).
func (t *Tracker) push(frame wire.MonitorStatus) {
	for {
		select {
		case t.updates <- frame:
			return
		default:
			select {
			case <-t.updates:
			default:
				return
			}
		}
	}
}

// Reasons reported for a monitor whose egress-proxy pin cannot be honored. They
// ride wire.MonitorStatusEntry.Reason into the server's operational-issue pipeline,
// so an operator sees the monitor listed as not-running with a cause rather than as
// a silently missing series.
const (
	// ReasonProxyMissing: the pinned proxy is not in the pushed config — normally
	// because it was disabled (the server keeps the target in the push precisely so
	// this stays reportable) or deleted.
	ReasonProxyMissing = "proxy_missing"
	// ReasonProxyUnsupported: the pinned proxy's transport cannot carry this probe
	// kind (e.g. an ICMP echo through a SOCKS5 CONNECT tunnel).
	ReasonProxyUnsupported = "proxy_unsupported"
	// ReasonProxyRemoteDNSDenied: the proxy resolves the target name on its own side,
	// so the agent cannot vet the address the connection actually reaches — and this
	// agent's policy is an allowlist that has not authorized the name. Running anyway
	// would mean probing an address the policy never approved.
	ReasonProxyRemoteDNSDenied = "proxy_remote_dns_denied"
)

// evaluateProxy checks a target's proxy pin. ok is true when the pin makes the
// monitor un-runnable, in which case the returned entry is the status to report.
//
// An unpinned target is always fine (a direct dial is what was configured). A
// pinned one must clear three gates: the proxy must be present, its transport must
// be able to carry this probe kind, and — under proxy-side DNS — the target name
// must be authorized by policy, because that mode is the one case where the agent
// cannot vet the concrete address the connection lands on.
func (t *Tracker) evaluateProxy(tgt config.ProbeTarget) (wire.MonitorStatusEntry, bool) {
	if tgt.ProxyID == "" {
		return wire.MonitorStatusEntry{}, false
	}
	blocked := func(reason string) (wire.MonitorStatusEntry, bool) {
		return wire.MonitorStatusEntry{
			MonitorID: tgt.MonitorID,
			Status:    wire.MonitorStatusUnsupported,
			Reason:    reason,
		}, true
	}
	// No proxy manager at all (a build or test without proxy support) still fails
	// closed: a pinned monitor must not quietly become a direct one.
	if t.proxies == nil {
		return blocked(ReasonProxyMissing)
	}
	spec, ok := t.proxies.Specs()[tgt.ProxyID]
	if !ok {
		return blocked(ReasonProxyMissing)
	}
	if !config.ProxyCapable(tgt.Kind, tgt.Params, spec.Type) {
		return blocked(ReasonProxyUnsupported)
	}
	if spec.DNSModeOrDefault() == config.ProxyDNSRemote {
		if host := staticHost(tgt); host != "" {
			if _, err := netip.ParseAddr(host); err != nil {
				// A hostname resolved on the proxy's side: only the pre-resolution name
				// check is available, so it has to be conclusive.
				hd := t.guard.CheckHost(host)
				if hd.Denied || !hd.NameAuthorized {
					return blocked(ReasonProxyRemoteDNSDenied)
				}
			}
		}
	}
	return wire.MonitorStatusEntry{}, false
}

// staticHost returns the destination host to statically check for a target, or
// "" to skip (e.g. a DNS queried name is not itself dialed; the gateway is an
// OS-supplied IP checked at runtime).
func staticHost(tgt config.ProbeTarget) string {
	switch tgt.Kind {
	case "http":
		if u, err := url.Parse(tgt.Target); err == nil && u.Hostname() != "" {
			return u.Hostname()
		}
		return ""
	case "icmp", "tcp":
		return hostOnly(tgt.Target)
	case "nat":
		return hostOnly(tgt.Target)
	case "dns":
		// The queried name is not dialed by the DNS probe; a custom literal-IP
		// resolver is what would be dialed.
		if tgt.Params.ResolverServer != "" {
			return hostOnly(tgt.Params.ResolverServer)
		}
		return ""
	default:
		return ""
	}
}

// hostOnly strips a :port suffix and any URL scheme from a target string.
func hostOnly(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.Index(s, "://"); i >= 0 {
		if u, err := url.Parse(s); err == nil && u.Hostname() != "" {
			return u.Hostname()
		}
	}
	if h, _, err := net.SplitHostPort(s); err == nil {
		return h
	}
	return s
}
