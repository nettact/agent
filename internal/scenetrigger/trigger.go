//go:build !lite

// Package scenetrigger decides, locally, when this agent should collect a
// description of its own surroundings — and collects it.
//
// # Why the agent decides
//
// The incident scene used to be a server-issued command: an incident opened, the
// opening transaction froze a list of targets, and a request went down the
// WebSocket. That contract fails for exactly the incidents it exists to explain.
// A network fault is overwhelmingly also the reason the agent is unreachable, so
// the request reached a socket that was not there and the entry sat in
// "collecting" until a deadline swept it. The evidence was reliably absent
// whenever it would have been worth having.
//
// Here the agent watches its own two fault edges — a probe streak crossing the
// confirmation threshold (tracetrigger), and its own session to this server
// ending — collects while the fault is still happening, and puts the report in
// the outbox with everything else. The server claims it afterwards as evidence
// for whichever incident the trigger identifies. What a scene MEANS changed with
// the trigger: it now describes what this agent saw when it detected the fault,
// not what the server would have asked about when it opened the incident.
//
// # The disconnect edge
//
// An agent-connectivity fault is detected server-side, by a sweeper noticing the
// agent stopped reporting. Nothing about it crosses a local probe edge — the
// probes are usually fine and only the uplink is not — so without a second
// trigger those incidents would have no scene at all, and they are the ones
// where the local network context IS the answer. That edge arrives through
// SessionLost.
//
// # Pacing
//
// Faults arrive in clusters and a scene describes a machine, not a target, so
// collecting one per edge would gather the same machine several times over.
// Edges crossed during a collection JOIN it (their identity is what the server
// claims by, and one report can be filed under several incidents); edges crossed
// during the cooldown that follows are held and collected together when it
// expires. Nothing is dropped for pacing — a fault whose scene was silently
// skipped is a fault that reads as having no evidence.
package scenetrigger

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/nettact/agent/internal/incidentscene"
	"github.com/nettact/agent/internal/tracetrigger"
	"github.com/nettact/protocol/telemetry"
)

// cooldown is the minimum spacing between two collections for one server.
//
// It is deliberately far shorter than the traceroute cooldown (15 minutes) and
// deliberately not configurable. The two bound different costs: a traceroute
// spends raw sockets and probe threads on a path that has not changed, while a
// scene is a handful of local reads. What a scene actually costs is bytes in the
// outbox and rows in a packet, and one report a minute per server is a bound on
// that which no operator needs to tune. A fault whose scene is at most a minute
// late is still a scene of the fault.
const cooldown = time.Minute

// pendingCap bounds the held triggers. Reaching it means a machine is crossing
// more distinct fault edges than one report a minute can name, which is itself
// worth a log line — the oldest are shed rather than the newest, because the
// newest describe the state the collection is about to capture.
const pendingCap = 32

// Trigger collects one server's incident scenes. Like everything else in a
// server's pipeline it is per server: the fault edges are that server's targets
// failing, the disconnect edge is that server's session, the permission views
// gating collection are that server's grant, and the report belongs in that
// server's slice of the outbox. Two servers watching one machine each get their
// own scene, which is correct — neither may be told what the other was granted.
type Trigger struct {
	name           string
	sink           func(telemetry.SceneReport)
	collectTimeout time.Duration

	mu   sync.Mutex
	deps incidentscene.Deps
	ctx  context.Context
	stop bool
	wg   sync.WaitGroup
	// inflight marks a collection in progress; joined holds the triggers that
	// crossed while it ran, which the collecting goroutine folds into the report
	// it is about to emit.
	inflight bool
	joined   []telemetry.SceneTrigger

	// pending holds the triggers crossed during a cooldown, with the target refs
	// their probe edges want resolved. timer fires when the cooldown expires.
	pending     []telemetry.SceneTrigger
	pendingRefs []heldRef
	lastDone    time.Time
	timer       *time.Timer

	// sessionUp is armed by SessionUp and consumed by the first SessionLost, so
	// one established session produces at most one disconnect edge. Retries that
	// never got a session (a dial failing over and over against a server that is
	// simply gone) find it unarmed and collect nothing: there is no new fact in
	// the fiftieth failed dial that the first one did not already carry.
	sessionUp bool
	// armedOnce records that the process-start arm has been spent. An agent that
	// STARTS while its server is already unreachable never establishes a session,
	// so a session-only arm would leave the restart-during-outage case with no
	// scene at all — while the server's connectivity sweeper happily keeps an
	// incident open over it. The first failed dial of an already-enrolled agent
	// therefore counts as an edge; every later one still does not.
	armedOnce bool
}

// New builds a trigger. deps carries the same platform HAL, target-access guard
// and permission views this server's probes run under; sink files the finished
// report in this server's outbox slice.
func New(name string, deps Deps, collectTimeout time.Duration, sink func(telemetry.SceneReport)) *Trigger {
	return &Trigger{
		name: name,
		deps: incidentscene.Deps{
			Platform:  deps.Platform,
			Guard:     deps.Guard,
			Effective: deps.Effective,
			Granted:   deps.Granted,
			Supported: deps.Supported,
			Identity: incidentscene.Identity{
				Hostname: deps.Hostname,
				OS:       deps.OS,
				Version:  deps.Version,
			},
		},
		collectTimeout: collectTimeout,
		sink:           sink,
	}
}

// Start arms the trigger with the runtime context. Until it is called edges are
// observed but nothing is collected — construction happens before there is a
// context to cancel against, and a collection started outside the runtime's
// lifetime would append to an outbox that is about to close.
func (t *Trigger) Start(ctx context.Context) {
	t.mu.Lock()
	t.ctx = ctx
	t.mu.Unlock()
}

// Wait joins the in-flight collection. The agent runtime calls it in the same
// phase as the schedulers' and the trace trigger's Wait, and for the same
// reason: these goroutines append to the outbox, which must not close
// underneath them.
func (t *Trigger) Wait() {
	t.mu.Lock()
	t.stop = true
	if t.timer != nil {
		t.timer.Stop()
		t.timer = nil
	}
	t.mu.Unlock()
	t.wg.Wait()
}

// SetAgentID stamps the identity this server enrolled under. It changes when a
// revoked server re-enrolls, and every scene records the id it was collected
// under so a later re-enrollment does not rewrite history.
func (t *Trigger) SetAgentID(id string) {
	t.mu.Lock()
	t.deps.Identity.AgentID = id
	// A credential in hand means this agent was enrolled before now, so its first
	// failed dial describes a machine that lost a server it used to reach. Arm
	// once for that; a session established later re-arms through SessionUp.
	if id != "" && !t.armedOnce {
		t.armedOnce, t.sessionUp = true, true
	}
	t.mu.Unlock()
}

// OnFaultEdge records a confirmed probe fault. It satisfies
// tracetrigger.SceneSink and therefore runs on the collector's goroutine, so it
// only ever enqueues.
func (t *Trigger) OnFaultEdge(e tracetrigger.FaultEdge) {
	t.enqueue(telemetry.SceneTrigger{
		Kind:          telemetry.SceneTriggerProbeFault,
		MonitorID:     e.MonitorID,
		ConfigSerial:  e.ConfigSerial,
		TriggerStreak: e.Streak,
		FirstFailedAt: e.FirstFailedAt,
	}, refFor(e))
}

// SessionUp arms the disconnect edge. Called when a session is established.
func (t *Trigger) SessionUp() {
	t.mu.Lock()
	t.sessionUp = true
	t.mu.Unlock()
}

// Disarm spends the edge without collecting, for a session that ended in a way
// no scene should describe.
//
// It exists because OnSession(false) cannot do this job: it fires before the
// retry hook on EVERY session end, so disarming there would consume the arm
// before the disconnect edge that needs it and the feature would never fire at
// all. The terminal endings — a superseded connection, a revoked credential, a
// schema mismatch — return from Run instead of retrying, leaving the arm set
// with nothing to consume it. The next enrollment reuses this trigger, so a
// first dial that fails before Hello would find that stale arm and file a
// disconnect scene for a session which never existed.
func (t *Trigger) Disarm() {
	t.mu.Lock()
	t.sessionUp = false
	t.mu.Unlock()
}

// SessionLost records that an established session ended and the agent is about
// to retry, with the agent's own classification of what ended it.
//
// It is wired to the retry hook rather than to the session-ended one because the
// retry hook fires for exactly the endings worth a scene. A superseded
// connection (a second agent process took this server over), a revoked
// credential and a schema mismatch all END a session, but they end the RUN too
// and never reach a retry — and none of them is a network fault: collecting for
// them would file a description of a healthy machine under an incident that will
// never exist. Shutdown is the same story from the other side, which is why the
// runtime context is re-checked here as well.
func (t *Trigger) SessionLost(reason string, at time.Time) {
	t.mu.Lock()
	armed := t.sessionUp
	t.sessionUp = false
	stopped := t.stop || t.ctx == nil || (t.ctx != nil && t.ctx.Err() != nil)
	t.mu.Unlock()
	if !armed || stopped {
		return
	}
	t.enqueue(telemetry.SceneTrigger{
		Kind:           telemetry.SceneTriggerServerDisconnect,
		DisconnectedAt: at.UTC(),
		Reason:         reason,
		EdgeCount:      1,
	}, incidentscene.TargetRef{})
}

// refFor derives the target this probe edge wants resolved. Only the failing
// monitor is resolved, not every target the server knows about: the frozen
// server-side list is gone with the request that carried it, and the target that
// just failed is the one whose resolution answers something.
func refFor(e tracetrigger.FaultEdge) incidentscene.TargetRef {
	return incidentscene.TargetRef{
		MonitorID: e.MonitorID,
		Kind:      e.Kind,
		Target:    e.Target,
		Port:      e.Port,
		Iface:     e.Iface,
	}
}

// enqueue routes one crossed edge: into the collection already running, into the
// cooldown's held set, or into a collection of its own. A zero-valued ref (the
// disconnect edge) resolves nothing.
func (t *Trigger) enqueue(trig telemetry.SceneTrigger, ref incidentscene.TargetRef) {
	now := time.Now()
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.stop || t.ctx == nil {
		return
	}
	if t.inflight {
		// The machine is being described right now; this edge's identity joins that
		// description. Its target is not resolved — the collection is already past
		// that stage — which costs one target row and keeps the report claimable
		// under this fault, the part that cannot be reconstructed later.
		t.joined = mergeTrigger(t.joined, trig)
		return
	}
	if wait := cooldown - now.Sub(t.lastDone); !t.lastDone.IsZero() && wait > 0 {
		t.hold(trig, ref)
		if t.timer == nil {
			t.timer = time.AfterFunc(wait, t.drainPending)
		}
		return
	}
	t.startLocked([]telemetry.SceneTrigger{trig}, refsOf(ref))
}

// hold adds an edge to the cooldown's held set, shedding the oldest at the cap.
//
// Refs are kept per (monitor, generation) rather than per monitor. Two outages
// of one unedited monitor share a ref — same endpoint, one thing to resolve —
// but a monitor materially edited during the cooldown keeps both triggers, and
// its new generation can name a different host, port or NIC. Collapsing those
// onto the monitor id would resolve the OLD endpoint and file it as the new
// generation's evidence.
func (t *Trigger) hold(trig telemetry.SceneTrigger, ref incidentscene.TargetRef) {
	before := len(t.pending)
	t.pending = mergeTrigger(t.pending, trig)
	added := len(t.pending) > before
	if added && ref.MonitorID != "" && !t.holdsRef(ref.MonitorID, trig.ConfigSerial) {
		t.pendingRefs = append(t.pendingRefs, heldRef{serial: trig.ConfigSerial, ref: ref})
	}
	if len(t.pending) <= pendingCap {
		return
	}
	drop := len(t.pending) - pendingCap
	log.Printf("[%s] incident scene: %d held triggers over the cap, dropping the oldest %d",
		t.name, len(t.pending), drop)
	t.pending = t.pending[drop:]
	// Rebuild from what SURVIVED rather than deleting per shed trigger. Two
	// outages of one monitor share a ref, so removing it because the older one was
	// shed would strip the target evidence off a trigger that is still held.
	kept := t.pendingRefs[:0]
	for _, h := range t.pendingRefs {
		if t.retains(h) {
			kept = append(kept, h)
		}
	}
	t.pendingRefs = kept
}

// retains reports whether any still-held trigger wants this ref resolved.
func (t *Trigger) retains(h heldRef) bool {
	for _, p := range t.pending {
		if p.Kind == telemetry.SceneTriggerProbeFault &&
			p.MonitorID == h.ref.MonitorID && p.ConfigSerial == h.serial {
			return true
		}
	}
	return false
}

// heldRef is one queued target resolution, tagged with the generation that asked
// for it so an edit mid-cooldown does not silently reuse the old endpoint.
type heldRef struct {
	serial int
	ref    incidentscene.TargetRef
}

// holdsRef reports whether this generation of a target is already queued.
func (t *Trigger) holdsRef(monitorID string, serial int) bool {
	for _, h := range t.pendingRefs {
		if h.ref.MonitorID == monitorID && h.serial == serial {
			return true
		}
	}
	return false
}

// targetRefs is the held set as the collector wants it.
func targetRefs(held []heldRef) []incidentscene.TargetRef {
	if len(held) == 0 {
		return nil
	}
	out := make([]incidentscene.TargetRef, 0, len(held))
	for _, h := range held {
		out = append(out, h.ref)
	}
	return out
}

// drainPending starts the collection the cooldown deferred.
func (t *Trigger) drainPending() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.timer = nil
	if len(t.pending) == 0 || t.inflight {
		return
	}
	trigs, refs := t.pending, targetRefs(t.pendingRefs)
	t.pending, t.pendingRefs = nil, nil
	t.startLocked(trigs, refs)
}

// startLocked launches one collection. Caller holds mu.
func (t *Trigger) startLocked(trigs []telemetry.SceneTrigger, refs []incidentscene.TargetRef) {
	if t.stop || t.ctx == nil || len(trigs) == 0 {
		return
	}
	t.inflight = true
	t.joined = nil
	deps, ctx := t.deps, t.ctx
	t.wg.Add(1)
	go func() {
		defer t.wg.Done()
		t.collect(ctx, deps, trigs, refs)
	}()
}

// collect gathers one scene and files it.
func (t *Trigger) collect(ctx context.Context, deps incidentscene.Deps, trigs []telemetry.SceneTrigger, refs []incidentscene.TargetRef) {
	cctx, cancel := context.WithTimeout(ctx, t.collectTimeout)
	defer cancel()
	scene := incidentscene.Collect(cctx, deps, refs)
	scene.ReportID = "scene_" + uuid.NewString()

	t.mu.Lock()
	// Shutdown cancelled the runtime context mid-collection. Every group came back
	// failed-with-a-context-reason, which would upload on the next run and read as
	// "this machine's network and resources were unreadable when the fault
	// happened" — a false statement about the incident, and a worse outcome than
	// the honest absence of a scene. The collection is dropped, not filed.
	if ctx.Err() != nil {
		t.inflight = false
		t.joined = nil
		t.mu.Unlock()
		return
	}
	scene.Triggers = trigs
	for _, j := range t.joined {
		scene.Triggers = mergeTrigger(scene.Triggers, j)
	}
	t.joined = nil
	t.inflight = false
	t.lastDone = time.Now()
	// Anything held while this ran is owed a collection of its own once the
	// cooldown from THIS one expires.
	if len(t.pending) > 0 && t.timer == nil && !t.stop {
		t.timer = time.AfterFunc(cooldown, t.drainPending)
	}
	t.mu.Unlock()

	log.Printf("[%s] incident scene %s collected for %d trigger(s)", t.name, scene.ReportID, len(scene.Triggers))
	t.sink(scene)
}

// mergeTrigger folds one trigger into a set, keeping each fault edge once.
//
// A probe edge is identified by (monitor, generation, streak start). The streak
// start is what makes two OUTAGES of one monitor distinct, and leaving it out is
// a quiet way to lose one: the tracker clears its fired bit on a healthy round,
// so a target that fails, recovers and fails again inside the cooldown produces
// a second legitimate edge with the same monitor and generation. Folding that
// into the first entry would keep the FIRST outage's start time — and the server
// picks the owning outage by exactly that timestamp, so the later incident could
// never claim the scene it appears in.
//
// Disconnect edges DO collapse into a single entry counting them, because the
// server's connectivity signal is per agent and a flapping link produces edges
// faster than a scene is worth collecting. The count travels so the merge does
// not read as one clean drop.
func mergeTrigger(set []telemetry.SceneTrigger, add telemetry.SceneTrigger) []telemetry.SceneTrigger {
	for i := range set {
		s := &set[i]
		if s.Kind != add.Kind {
			continue
		}
		if add.Kind == telemetry.SceneTriggerServerDisconnect {
			s.EdgeCount += add.EdgeCount
			s.Reason = add.Reason // the latest classification describes the current outage
			return set
		}
		if s.MonitorID == add.MonitorID && s.ConfigSerial == add.ConfigSerial &&
			s.FirstFailedAt.Equal(add.FirstFailedAt) {
			// The same edge re-presented. One streak fires once, so this is
			// defensive rather than expected; keep the longer observed run.
			if add.TriggerStreak > s.TriggerStreak {
				s.TriggerStreak = add.TriggerStreak
			}
			return set
		}
	}
	return append(set, add)
}

// refsOf makes a one-element slice, or none for the zero ref.
func refsOf(ref incidentscene.TargetRef) []incidentscene.TargetRef {
	if ref.MonitorID == "" {
		return nil
	}
	return []incidentscene.TargetRef{ref}
}
