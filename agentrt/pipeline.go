package agentrt

import (
	"context"
	"log"
	"runtime"
	"time"

	"github.com/nettact/agent/internal/collector"
	"github.com/nettact/agent/internal/conn"
	"github.com/nettact/agent/internal/incidentscene"
	"github.com/nettact/agent/internal/monitoreval"
	"github.com/nettact/agent/internal/netguard"
	"github.com/nettact/agent/internal/platform"
	"github.com/nettact/agent/internal/proxydial"
	"github.com/nettact/agent/internal/scheduler"
	"github.com/nettact/agent/internal/traceegress"
	"github.com/nettact/agent/internal/traceroute"
	"github.com/nettact/agent/internal/tracetrigger"
	"github.com/nettact/agent/internal/wal"
	pcfg "github.com/nettact/protocol/config"
	"github.com/nettact/protocol/permission"
	"github.com/nettact/protocol/telemetry"
)

// permViews is one server's answer to "what may this machine do on your behalf":
// the three permission sets, the target-access guard they run behind, and the
// hash the console shows to tell one policy from another.
//
// Every field is per server, and that is the point of the type. Two servers on
// one machine can hold different grants — the whole of AGENT-007 phase 2 — so
// there is no process-wide "the effective set" to reach for any more. Anything
// that adjudicates (a collector's construction, a monitor's runnability, a
// snapshot's scope, a trace's mode) has to be handed the views of the server
// that asked.
type permViews struct {
	granted   permission.Set
	supported permission.Set
	effective permission.Set
	guard     *netguard.Guard
	source    permission.Source
	hash      string
}

// serverRuntime is one server's whole pipeline: its collectors, its scheduler,
// its evaluation state, and the permission views all of them were built under.
//
// Servers get a pipeline each rather than sharing one because a DesiredState is
// a server's private instruction set. Its MonitorIDs and ConfigSerials are its
// own namespace, its tier intervals are its own cadence, and its proxy specs are
// its own tunnels — a shared collector would have the second push overwrite the
// first's targets, and a shared tracker would report one server's monitors to
// the other. Duplicating the pipeline costs a second local read per tier, which
// is cheaper than any of the schemes that would let them share one.
type serverRuntime struct {
	cfg   ServerConfig
	views permViews

	// report is what this server is told at enrollment and in every Hello. It
	// describes this server's grant only; a server never learns what another was
	// granted.
	report permission.PermissionReport

	outbox        *wal.Store
	proxies       *proxydial.Manager
	tracker       *monitoreval.Tracker
	sched         *scheduler.Scheduler
	configurables []conn.Configurable
	trace         *traceroute.Engine
	// trigger owns the decision to traceroute. It is per server because every
	// input to that decision is: this server's targets produce the rounds, this
	// server's permissions gate the mode, this server's proxy generation pins the
	// egress, and the report belongs in this server's slice of the outbox.
	trigger *tracetrigger.Tracker
	scene   incidentscene.Deps

	// game is nil for every server but the owner (see gameOwner). A nil applier
	// makes the session ignore a pushed GameConfig outright, which is exactly the
	// intended behaviour: a server that will never receive frame data has no
	// business restarting the sensor.
	game conn.GameApplier

	limits Limits
	drain  time.Duration
}

// buildServer constructs one server's pipeline. Collectors are gated on that
// server's effective permissions, so a denied collector is never built and its
// OS/gopsutil operations are never invoked on that server's behalf.
func buildServer(
	sc ServerConfig,
	v permViews,
	report permission.PermissionReport,
	outbox *wal.Store,
	p platform.Platform,
	limits Limits,
	drain time.Duration,
	traceLimit traceroute.Limiter,
	probeGate *collector.ProbeGate,
	hostname string,
) *serverRuntime {
	rt := &serverRuntime{
		cfg:    sc,
		views:  v,
		report: report,
		outbox: outbox,
		limits: limits,
		drain:  drain,
	}

	// Egress proxies are built lazily on first use and torn down whenever a pushed
	// generation changes, so constructing the manager here costs nothing until a
	// target is actually pinned to one.
	rt.proxies = proxydial.NewManager(v.guard)
	rt.tracker = monitoreval.New(v.effective, v.granted, v.supported, v.guard, rt.proxies, v.hash,
		limits.MinProbeInterval, drain)

	var selfSched []collector.Collector
	addProbe := func(c interface {
		conn.Configurable
		collector.Collector
		SetMinInterval(time.Duration)
	}) {
		c.SetMinInterval(limits.MinProbeInterval)
		rt.configurables = append(rt.configurables, c)
		selfSched = append(selfSched, c)
	}
	// The gateway probe is the one kind that is never proxied: it targets the local
	// first hop, where an egress proxy has no meaning.
	if v.effective.Has(permission.NetworkGatewayProbe) {
		addProbe(collector.NewGatewayPingCollector(p, v.guard, probeGate))
	}
	if v.effective.Has(permission.ProbeICMP) {
		addProbe(collector.NewPublicPingCollector(p, v.guard, rt.proxies, probeGate))
	}
	if v.effective.Has(permission.ProbeDNS) {
		addProbe(collector.NewDNSCollector(v.guard, rt.proxies, v.effective, probeGate))
	}
	if v.effective.Has(permission.ProbeHTTP) {
		addProbe(collector.NewHTTPCollector(v.guard, rt.proxies, v.effective.Has(permission.ProbeHTTPExtended), probeGate))
	}
	if v.effective.Has(permission.ProbeTCP) {
		addProbe(collector.NewTCPCollector(v.guard, rt.proxies, probeGate))
	}
	if v.effective.Has(permission.ProbeNAT) {
		addProbe(collector.NewNATCollector(v.guard, rt.proxies, probeGate))
	}

	// Tiered collectors: interface (status), ARP (neighbor), host metrics — each
	// gated on its permission family. Built per server for the same reason as the
	// probes: what a server may be told about this host is its own grant, so a
	// server denied host.cpu.read must have no collector producing it. Reading the
	// same counters twice is the cost of that being structurally true rather than
	// filtered afterwards.
	var tiered []collector.Collector
	if v.effective.Has(permission.NetIfaceStatusRead) {
		tiered = append(tiered, collector.NewInterfaceCollector(
			p,
			v.effective.Has(permission.NetIfaceAddressRead),
			v.effective.Has(permission.NetIfaceAddressRead) || v.effective.Has(permission.NetworkGatewayProbe),
			v.effective.Has(permission.NetWiFiStatusRead),
			v.effective.Has(permission.NetWiFiSSIDRead),
		))
	}
	if v.effective.Has(permission.NetNeighborRead) {
		tiered = append(tiered, collector.NewARPCollector(p, v.effective.Has(permission.NetNeighborHostRead)))
	}
	if hostMetricsEnabled(v.effective) {
		tiered = append(tiered, collector.NewHostMetricsCollector(
			v.effective.Has(permission.HostCPURead),
			v.effective.Has(permission.HostMemoryRead),
			v.effective.Has(permission.HostDiskRead),
			v.effective.Has(permission.HostLoadRead),
			v.effective.Has(permission.HostUptimeRead),
			v.effective.Has(permission.HostNetworkIORead),
			v.effective.Has(permission.HostTemperatureRead),
		))
	}
	rt.sched = scheduler.New(tiered, selfSched, rt.sink)

	// Incident-scene collector and traceroute engine (INCIDENT-002 / DIAG-001).
	// Both reuse this server's permission views, platform HAL, and target-access
	// guard. They are invoked off the session goroutine and their result Frames
	// written by the single session writer, so normal collector cadence is
	// untouched.
	rt.scene = incidentscene.Deps{
		Platform:  p,
		Guard:     v.guard,
		Effective: v.effective,
		Granted:   v.granted,
		Supported: v.supported,
		Identity: incidentscene.Identity{
			Hostname: hostname,
			OS:       runtime.GOOS,
			Version:  Version,
		},
	}
	// traceegress.Resolver is what lets an in-tunnel trace reach the proxy manager
	// while the traceroute package stays independent of it, and it owns the
	// DIAG-004 fail-closed contract (see that package). The limiter is shared with
	// every other server's engine: the concurrency it bounds is the machine's raw
	// sockets and probe threads, which do not multiply just because a second
	// server asked.
	rt.trace = traceroute.New(v.guard, v.effective, v.granted, v.supported, traceLimit,
		traceegress.Resolver(rt.proxies))
	// The trigger is what turns a run of failing rounds into a trace. It is given
	// this server's permission views (the engine re-checks them, but the planner
	// needs them to choose the mode and record a downgrade), this server's proxy
	// specs (so a pinned target's fault is diagnosed on the leg that carried it),
	// and a sink that files the report in this server's outbox slice — the same
	// path the metrics that triggered it took, which is what makes the report
	// survive the outage it describes.
	rt.trigger = tracetrigger.New(sc.Name, v.effective, v.granted, v.supported,
		rt.proxies.Specs, rt.trace.Run, rt.appendTrace)
	rt.configurables = append(rt.configurables, rt.trigger)
	return rt
}

// appendTrace files one finished traceroute report in this server's slice of the
// outbox. It is a group of its own rather than being folded into the next
// collector round: a report is complete on its own and there is nothing it has
// to arrive alongside.
func (rt *serverRuntime) appendTrace(res telemetry.TraceResult) {
	dropped, err := rt.outbox.Append(wal.Records{TraceResults: []telemetry.TraceResult{res}}, rt.cfg.Name)
	if err != nil {
		log.Printf("[%s] wal append trace %s: %v", rt.cfg.Name, res.ReportID, err)
		return
	}
	if dropped > 0 {
		log.Printf("[%s] WAL over capacity: dropped %d oldest samples (data gap)", rt.cfg.Name, dropped)
	}
}

// sink routes one collector result: policy blocks and clean metrics to this
// server's tracker, everything to this server's slice of the outbox.
//
// Each transition carries the originating target generation (ConfigSerial) so
// the tracker can ignore an obsolete in-flight result and never let it alter the
// current generation's status.
func (rt *serverRuntime) sink(res collector.Result) {
	for _, b := range res.Blocked {
		rt.tracker.RuntimeBlocked(b.MonitorID, b.ConfigSerial, b.Matched, b.Reason)
	}
	for _, m := range res.Metrics {
		if m.MonitorID != "" {
			rt.tracker.RuntimeOK(m.MonitorID, m.ConfigSerial)
		}
	}
	// The trigger sees the round before it is queued, not after it is delivered:
	// the whole point of the local trigger is that it keeps working while the
	// outbox is backing up behind an unreachable server.
	rt.trigger.Observe(res.Metrics)
	var snaps []telemetry.InterfaceSnapshot
	if res.InterfaceSnapshot != nil {
		snaps = []telemetry.InterfaceSnapshot{*res.InterfaceSnapshot}
	}
	dropped, err := rt.outbox.Append(wal.Records{
		Metrics:   res.Metrics,
		Events:    res.Events,
		Inventory: res.Inventory,
		Snapshots: snaps,
	}, rt.cfg.Name)
	if err != nil {
		log.Printf("[%s] wal append: %v", rt.cfg.Name, err)
		return
	}
	if dropped > 0 {
		log.Printf("[%s] WAL over capacity: dropped %d oldest samples (data gap)", rt.cfg.Name, dropped)
	}
}

// connDeps assembles the session's dependencies for one enrollment. It is built
// per session rather than once because agentID changes: a revoked server
// re-enrolls under a new identity, and the incident scene stamps that id into
// every snapshot it collects.
func (rt *serverRuntime) connDeps(agentID string) conn.Deps {
	scene := rt.scene
	scene.Identity.AgentID = agentID
	return conn.Deps{
		Outbox:              rt.outbox,
		Configurables:       rt.configurables,
		Scheduler:           rt.sched,
		DrainInterval:       rt.drain,
		Tracker:             rt.tracker,
		Proxies:             rt.proxies,
		Game:                rt.game,
		Diag:                rt.trigger,
		Effective:           rt.views.effective,
		Granted:             rt.views.granted,
		Supported:           rt.views.supported,
		SnapshotMinInterval: rt.limits.SnapshotMinInterval,
		SnapshotTimeout:     rt.limits.SnapshotTimeout,
		CollectIncidentSnapshot: func(ctx context.Context, req pcfg.IncidentSnapshotRequest) telemetry.IncidentSnapshot {
			return incidentscene.Collect(ctx, req, scene)
		},
	}
}
