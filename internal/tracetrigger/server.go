package tracetrigger

import (
	"log"
	"strings"
	"time"

	"github.com/google/uuid"
	pcfg "github.com/nettact/protocol/config"
	"github.com/nettact/protocol/telemetry"
)

// The server-disconnect edge.
//
// An agent-connectivity fault is detected server-side, by a sweeper noticing
// the agent stopped reporting, and no local probe edge crosses for it — the
// monitored targets are often fine and only the path to the server is not. So
// the fault the operator sees first, "this agent is offline", is the one the
// probe trigger can never trace. The session ending is that fault's edge as the
// agent sees it, and the path worth walking is the one the session used: toward
// the server's own address.
//
// Like every other trace it is gated on this server's traceroute permissions
// and lands in this server's slice of the outbox, which is the only thing that
// can hold it until the session it describes is back. Unlike a probe-fault
// trace, a denial is silent: there is no monitor whose evidence would read as
// missing, and the connectivity fault stands on its own without it.
//
// Arming mirrors the scene trigger's disconnect edge. SessionUp arms; the first
// SessionLost spends the arm, so one established session produces at most one
// trace however many dials fail after it. The process-start arm covers an agent
// that starts while its server is already unreachable — it never gets a
// session, and the server keeps that agent's offline fault open regardless.
// Disarm spends the arm without tracing, for endings that are not network
// faults (shutdown, a terminal close).

// serverCohortPrefix keeps the disconnect trace's cooldown and in-flight slot
// apart from a probe-fault trace of the same address. The two answer different
// questions for different faults, and a monitor that happens to watch the
// server's host must not suppress the connectivity fault's only trace.
const serverCohortPrefix = "server|"

// SessionUp arms the disconnect edge: the session to this server is
// established, so the next loss is a new fact worth tracing.
func (t *Tracker) SessionUp() {
	t.mu.Lock()
	t.sessionUp = true
	t.armedOnce = true
	t.mu.Unlock()
}

// Disarm spends the disconnect arm without tracing.
func (t *Tracker) Disarm() {
	t.mu.Lock()
	t.sessionUp = false
	t.armedOnce = true
	t.mu.Unlock()
}

// SessionLost takes the disconnect edge: when armed, it traces toward the
// server at serverURL, at most once per established session. lostAt is when
// the session was lost; it rides the report as FirstFailedAt, which is what
// the server places the edge against its own record of the outage by.
//
// It never blocks: the trace runs on a goroutine of its own, joined by Wait.
func (t *Tracker) SessionLost(serverURL string, lostAt time.Time) {
	t.mu.Lock()
	armed := t.sessionUp || !t.armedOnce
	t.sessionUp = false
	t.armedOnce = true
	pol := t.policy
	t.mu.Unlock()
	if !armed || !pol.Enabled {
		return
	}

	p, ok := planServer(serverURL)
	if !ok {
		return
	}
	p = gatePlan(p, t.effective, t.granted, t.supported)
	if p.terminal != "" {
		return
	}

	now := time.Now()
	t.mu.Lock()
	cohort := serverCohortPrefix + p.cohortKey()
	if _, running := t.inflight[cohort]; running {
		t.mu.Unlock()
		return
	}
	if last, seen := t.cooldown[cohort]; seen && now.Sub(last) < pol.Cooldown {
		t.mu.Unlock()
		return
	}
	if t.stop || t.ctx == nil {
		t.mu.Unlock()
		return
	}
	t.inflight[cohort] = struct{}{}
	ctx := t.ctx
	// Added under the lock for the same reason planAndTrace does: Wait sets stop
	// under this mutex before joining.
	t.wg.Add(1)
	t.mu.Unlock()

	req := p.request("trace_"+uuid.NewString(), pol, 0, lostAt.UTC())
	req.TriggerReason = telemetry.TraceTriggerServerDisconnect
	log.Printf("[%s] traceroute %s %s after losing the server session", t.name, p.mode, p.destHost)
	go func() {
		defer t.wg.Done()
		res := t.runner(ctx, req, now)
		t.mu.Lock()
		delete(t.inflight, cohort)
		t.cooldown[cohort] = time.Now()
		t.mu.Unlock()
		t.sink(res)
	}()
}

// planServer plans a TCP trace toward the server's own host and port — the
// same port the session dialled, so a TCP walk follows the path the session
// used. ok=false for an address with no network path worth tracing: an
// unparseable URL, or a loopback server on this very machine.
func planServer(serverURL string) (plan, bool) {
	host, port, err := hostPortFromURL(serverURL)
	if err != nil || isLoopbackHost(strings.Trim(host, "[]")) {
		return plan{}, false
	}
	destKey, destHost := CanonicalDest(host)
	return plan{
		mode:        pcfg.TraceModeTCP,
		destKey:     destKey,
		destHost:    destHost,
		port:        port,
		subjectKind: telemetry.TraceSubjectTarget,
		pathScope:   telemetry.TracePathDirect,
	}, true
}
