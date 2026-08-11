// Package wal is the agent's outbox (architecture §3.3): collectors append
// samples locally so monitoring never stops when the server is unreachable, and
// batches carry a sequence so a crash mid-upload re-sends the SAME sequence and
// the server dedups on (agent_id, sequence).
//
// # One log, N consumers
//
// An agent may be enrolled at several servers at once, each with its own
// session, its own credential and its own view of what this machine should
// probe. They share this one outbox rather than getting a queue each, because
// duplicating the log would multiply the disk a disconnected agent needs by the
// number of servers configured — and the servers are independent, so they are
// disconnected at independent times.
//
// Sharing the storage does NOT mean sharing the records. Every group is appended
// with exactly one owner and is only ever served to that server. A probe result
// names a MonitorID and a ConfigSerial minted by the server that pushed the
// target; handing it to a second server would have it store a series under an
// identity that means something else there. Host-level data is likewise appended
// once per server that is permitted to receive it (the agent runs a collector
// pipeline per server, so the per-server permission grant decides what exists to
// append at all) rather than broadcast from one group — which is what keeps the
// ownership rule total and this file free of audience arithmetic.
//
// Ownership is by server NAME, and a name outlives the credential behind it: a
// revoked agent deletes its credential and re-enrolls at the same configured
// server, coming back as a different agent_id. The server files every packet
// under the identity that authenticated it, so each cursor also records which
// identity its queue was collected under, and a session that binds a different
// one discards that queue outright rather than filing one machine's evidence
// under another's name. See BindIdentity in either build.
//
// Each server therefore has a cursor: how far it has acknowledged, and the one
// batch it currently owes an ack for. A group's bytes become collectable when
// its owner acks it; a server that is offline for a week pins only its own
// backlog, and the row cap sheds the oldest unclaimed groups — which are that
// laggard's — rather than growing disk without bound. Sequences come from one
// allocator shared by every server: they only have to be unique per (agent,
// server) pair, servers take MAX for their watermark and never require
// contiguity, so one counter with gaps is cheaper than one counter per server.
//
// There are two implementations of Store, selected by build tag, sharing the
// types in this file, the on-disk format in segment.go, and the ordering rules
// the uploader depends on:
//
//   - wal.go (default) buffers in memory in front of a spill to plain segment
//     files, so a healthy agent writes nothing to disk but a disconnected one
//     keeps its backlog across a restart.
//   - wal_lite.go (-tags lite, the OpenWrt router builds) buffers in memory and
//     spills the SAME format, but only for a server it knows to be disconnected
//     and only for a bounded window after that server dropped. On a device whose
//     only writable storage is the flash it boots from, a backlog that is being
//     uploaded every 30 seconds is not worth an erase cycle; one that cannot be
//     uploaded, on a router its owner is about to power-cycle to "fix" the
//     internet, is the only copy that exists. See Store there for the window.
//
// Both honour the same contract for everything above them: FIFO delivery per
// server, whole Records groups claimed indivisibly, and an in-flight packet
// re-served under its original sequence until acked.
package wal

import (
	"time"

	"github.com/nettact/protocol/gamesense"
	"github.com/nettact/protocol/telemetry"
)

// Options are the store's tunables at Open. They exist in both builds so a
// caller needs no build-specific branch, and the default build ignores every
// field: its durable tier is unconditional and its retention is fixed, so a
// "should this persist" question has no meaning there.
type Options struct {
	// Persist enables the lite build's durable tier. False is the historical
	// lite behaviour — memory only, everything lost on reboot.
	//
	// It is a switch rather than a constant because the flash it writes to is
	// the one part of a router that wears out, and an owner who would rather
	// lose an outage's telemetry than spend erase cycles on it is making a
	// legitimate choice about their own hardware. Ignored by the default build.
	Persist bool

	// PersistWindow is how long after a server disconnects the lite build keeps
	// writing that server's backlog to flash. Zero selects 30 minutes. Ignored
	// by the default build. See Store in wal_lite.go for why the window is
	// anchored at the disconnect rather than being a size or a rate.
	PersistWindow time.Duration

	// Clock supplies the correction for telemetry stamped while this machine's
	// wall clock was wrong — the ordinary state of a router with no RTC that has
	// just been power-cycled during an outage. Nil disables correction entirely
	// and is the historical behaviour; both builds honour it identically.
	Clock ClockSource
}

// ClockSource is what the outbox needs from a clock monitor (implemented by
// internal/clockmon). It is an interface rather than a direct dependency so the
// WAL's tests can state a correction outright instead of simulating a machine
// whose clock is wrong.
//
// The revision parameter is what makes an in-flight packet safe. A batch that is
// re-sent after a session drops must carry the timestamps it carried the first
// time: the server dedups on (agent_id, sequence), so a retry whose content
// differs is swallowed rather than replacing what was stored. A claim therefore
// freezes the revision it was built under and asks for the correction as of
// then, no matter how much the model has learned since.
type ClockSource interface {
	// Epoch identifies the process instance. Groups tagged with another epoch are
	// never corrected — a previous run's clock error is not recoverable from this
	// one's observations.
	Epoch() string
	// Mono is the monotonic reading to stamp on a group being appended now.
	Mono() int64
	// Revision is the number of clock observations so far, frozen into a claim.
	Revision() int
	// OffsetAt is how much to add to a wall stamp taken at mono during epoch, as
	// the model stood at rev (rev <= 0 meaning "as it stands now").
	OffsetAt(epoch string, mono int64, rev int) time.Duration
}

// Records is one Append's worth of telemetry. A struct rather than a parameter
// per payload kind because the kinds are added to over time and every caller
// fills two or three of them: naming the ones it has beats counting nils.
//
// Everything in one Records is stored as one indivisible group, so a caller that
// puts related records together — a run and the buckets that hang from it — is
// guaranteed they reach the server in the same packet.
type Records struct {
	Metrics         []telemetry.Metric
	Events          []telemetry.Event
	Inventory       []telemetry.InventoryItem
	Snapshots       []telemetry.InterfaceSnapshot
	GameRuns        []gamesense.Run
	GameBuckets     []gamesense.Bucket
	GameGaps        []gamesense.Gap
	GameHostSeconds []gamesense.HostSecond
	// TraceResults are the traceroutes this agent decided to run on its own.
	//
	// They are in the outbox rather than answered live on the socket for the
	// reason the whole feature exists: the fault a trace diagnoses is the most
	// likely cause of the socket being unusable, so a result written straight to
	// the connection is lost precisely in the outage it was collected to explain.
	// Here it inherits everything the outbox already guarantees — survives a
	// restart, replays under its original sequence, dedups server-side — at the
	// cost of arriving one drain later than a live write would have.
	//
	// A trace belongs to the server whose pipeline triggered it, like every other
	// group: it was planned against that server's targets, permissions and proxy
	// generation, and means nothing to a second server that never pushed them.
	TraceResults []telemetry.TraceResult
	// SceneReports are the incident scenes this agent collected on fault edges it
	// detected itself. Same argument as the traces above, and one degree stronger:
	// one of the two edges IS this server's session dropping, so a scene written
	// to the connection would be a scene that could never be sent at all. It is
	// the outbox that makes "collect while disconnected, deliver on reconnect" a
	// coherent thing to do.
	//
	// Never present in a lite build, whose scene trigger collects nothing.
	SceneReports []telemetry.SceneReport
}

// Batch is a packet to upload.
type Batch struct {
	Sequence        uint64
	Metrics         []telemetry.Metric
	Events          []telemetry.Event
	Inventory       []telemetry.InventoryItem
	Snapshots       []telemetry.InterfaceSnapshot
	GameRuns        []gamesense.Run
	GameBuckets     []gamesense.Bucket
	GameGaps        []gamesense.Gap
	GameHostSeconds []gamesense.HostSecond
	TraceResults    []telemetry.TraceResult
	SceneReports    []telemetry.SceneReport
}

// memGroup is one Append held in memory: an indivisible Records, the server it
// belongs to, the wall clock it arrived at (its created_at if it is ever
// spilled) and its row count.
//
// gid is the store-wide group id: a monotonic counter that survives a restart
// via state.json. It is what a claim addresses, so a claimed group keeps its
// identity when the buffer spills underneath it — the memory and durable tiers
// hold different representations of the same numbered sequence of groups, not
// two separate queues.
type memGroup struct {
	gid   uint64
	owner string
	at    time.Time
	rec   Records
	n     int
	// epoch/mono say which process stamped this group's payload and when, on the
	// monotonic clock of that process. They are what lets a clock correction be
	// applied to exactly the groups it describes: the ones this process stamped
	// before it found out its wall clock was wrong. A group from an earlier
	// process carries that run's epoch and is never corrected.
	epoch string
	mono  int64
}

// claim is one server's in-flight packet: the sequence it went out under and the
// gid range it covers. A range rather than a group count because the log is
// interleaved — the claimed groups are this server's, contiguous in ITS
// subsequence but with other servers' groups sitting between them — and because
// a range stays valid across a spill, which a positional index would not.
//
// n is how many groups the range covered when the claim was taken. It is
// bookkeeping for exactly one job: after a crash, a range that resolves to a
// different number of groups says the spill that was supposed to make them
// durable never landed, and the claim must not be served short under a sequence
// the server may already associate with different content.
type claim struct {
	seq  uint64
	from uint64
	to   uint64
	n    int
	// clockRev is the clock model's revision when this claim was taken. Every
	// re-serve asks for the correction as of it, so the packet's timestamps are a
	// pure function of (stored stamps, frozen revision) and a retry reproduces
	// the first attempt byte for byte. Without it, a clock step landing between
	// the send and the ack would re-send different content under a sequence the
	// server dedups on — and the corrected version would be silently discarded.
	//
	// It is in memory only, not in state.json, because the case it would cover
	// resolves itself: a claim recovered after a restart addresses groups stamped
	// by the PREVIOUS process, which this one never corrects at all (see
	// ClockSource.Epoch). The retry then carries the stored stamps — the same
	// bytes as the original if that original was itself uncorrected, and
	// otherwise a packet the server either already holds (dedup keeps the
	// corrected one) or never received (it ingests the uncorrected one, minutes
	// out at worst). Persisting the revision would not improve either outcome,
	// since the model it indexes into died with the process.
	clockRev int
}

// covers reports whether a group belongs to this claim.
func (c *claim) covers(gid uint64) bool {
	return c != nil && gid >= c.from && gid <= c.to
}

// countClaimed returns how many of a server's claimed groups are present in the
// given tiers. It lives beside claim rather than in either build's store because
// both ask the same question of the same two tiers — "did all the groups this
// sequence went out over survive?" — and an answer that differed between the
// builds would mean a packet re-served short under a sequence the server already
// associates with more content.
func countClaimed(owner string, cl *claim, disk []diskGroup, mem []memGroup) int {
	n := 0
	for _, g := range disk {
		if g.owner == owner && cl.covers(g.gid) {
			n++
		}
	}
	for _, g := range mem {
		if g.owner == owner && cl.covers(g.gid) {
			n++
		}
	}
	return n
}

// cursor is one server's position in the shared log: every group of its own with
// gid <= acked is delivered and done, and claim is the packet it currently owes
// an ack for.
//
// acked is the persisted truth about what is dead; the in-memory group lists are
// a cache of it that Ack prunes eagerly. Keeping the watermark rather than a
// consumed-prefix pointer is what makes N consumers work: server A acking its
// groups leaves holes in the middle of the log that B has not reached yet, and a
// single prefix could not describe that.
type cursor struct {
	acked uint64
	claim *claim
	// identity is the agent_id this server's sessions have been running under,
	// as last stated by BindIdentity. It is the one piece of credential identity
	// the log carries, and it is deliberately here — one per consumer — rather
	// than on every group.
	//
	// A group needs no identity of its own because the cursor already answers the
	// only question that has an answer: everything this server still owes was
	// collected under the identity recorded here, because the moment that
	// identity changes the whole backlog is discarded (see BindIdentity). Per
	// group, the field would have to be persisted on every line and would only
	// enable a handover the server side cannot authenticate anyway.
	//
	// Empty means no session has ever bound one: a fresh install, or a server
	// just added to the configuration. That is a real steady state rather than a
	// missing value, which is why the persisted field is optional.
	identity string
}

// flatten concatenates the claimed groups into the packet to send, preserving
// arrival order across groups and payload order within each.
//
// offsets, when non-nil, is one clock correction per group, applied as each
// group's payload is copied in. Applying it HERE rather than to the stored
// groups is what keeps the correction safe to redo: append copies every record
// by value into the batch's own arrays, so the shift lands on the copy and the
// stored timestamps are never touched. A re-served claim re-reads pristine
// stamps and re-derives the same result from its frozen revision.
func flatten(seq uint64, recs []Records, offsets []time.Duration) Batch {
	b := Batch{Sequence: seq}
	for i, r := range recs {
		var d time.Duration
		if i < len(offsets) {
			d = offsets[i]
		}
		mStart, eStart := len(b.Metrics), len(b.Events)
		iStart, sStart := len(b.Inventory), len(b.Snapshots)
		b.Metrics = append(b.Metrics, r.Metrics...)
		b.Events = append(b.Events, r.Events...)
		b.Inventory = append(b.Inventory, r.Inventory...)
		b.Snapshots = append(b.Snapshots, r.Snapshots...)
		b.GameRuns = append(b.GameRuns, r.GameRuns...)
		b.GameBuckets = append(b.GameBuckets, r.GameBuckets...)
		b.GameGaps = append(b.GameGaps, r.GameGaps...)
		b.GameHostSeconds = append(b.GameHostSeconds, r.GameHostSeconds...)
		b.TraceResults = append(b.TraceResults, r.TraceResults...)
		b.SceneReports = append(b.SceneReports, r.SceneReports...)
		if d == 0 {
			continue
		}
		// Only the payloads whose timestamps all belong to ONE collection cycle
		// are corrected, because the group carries one monotonic reading — taken
		// when it was appended, which is the end of that cycle. That reading
		// describes a probe round or a tier sweep, both of which are stamped
		// seconds before it.
		//
		// It does NOT describe a game run spanning minutes of play, or a
		// traceroute carrying a start, a completion and a per-hop time. A clock
		// step landing inside one of those would correct part of it and not the
		// rest, which is worse than leaving it alone: a run whose end precedes its
		// start is a corrupt record, while one stamped consistently early is
		// merely early. Those payloads are therefore left as collected, and the
		// residual is stated in clockmon's package comment.
		for j := mStart; j < len(b.Metrics); j++ {
			b.Metrics[j].TS = b.Metrics[j].TS.Add(d)
		}
		for j := eStart; j < len(b.Events); j++ {
			b.Events[j].TS = b.Events[j].TS.Add(d)
		}
		for j := iStart; j < len(b.Inventory); j++ {
			if !b.Inventory[j].LastSeen.IsZero() {
				b.Inventory[j].LastSeen = b.Inventory[j].LastSeen.Add(d)
			}
		}
		for j := sStart; j < len(b.Snapshots); j++ {
			b.Snapshots[j].SampledAt = b.Snapshots[j].SampledAt.Add(d)
		}
	}
	return b
}

// rowsOf counts the sample rows one Records would occupy.
func rowsOf(r Records) int {
	return len(r.Metrics) + len(r.Events) + len(r.Inventory) + len(r.Snapshots) +
		len(r.GameRuns) + len(r.GameBuckets) + len(r.GameGaps) + len(r.GameHostSeconds) +
		len(r.TraceResults) + len(r.SceneReports)
}

// clockTag returns the epoch and monotonic reading to stamp on a group being
// appended now. A nil source yields the zero tag, which never matches a live
// epoch and therefore never attracts a correction.
func clockTag(c ClockSource) (string, int64) {
	if c == nil {
		return "", 0
	}
	return c.Epoch(), c.Mono()
}

// clockRevOf is the model revision to freeze into a claim being taken now.
func clockRevOf(c ClockSource) int {
	if c == nil {
		return 0
	}
	return c.Revision()
}

// clockOffset is one group's correction under a frozen revision.
func clockOffset(c ClockSource, epoch string, mono int64, rev int) time.Duration {
	if c == nil || epoch == "" {
		return 0
	}
	return c.OffsetAt(epoch, mono, rev)
}

// expiredAt reports whether a group is older than retention.
//
// For a group THIS process stamped there is one right answer: both sides move
// into the corrected domain — its time by its own offset, the present by the
// standing error. Moving only one is wrong in both directions and each direction
// loses data (correct only the stored side and a clock running far AHEAD pulls
// every group past an unmoved cutoff; correct only the present and a clock far
// BEHIND pushes the cutoff past everything).
//
// For a group an EARLIER process stamped there is no right answer, because that
// run's error is not recoverable from this one's observations (see
// ClockSource.Epoch) — and the two available readings disagree:
//
//   - Raw versus raw. The stamp and an uncorrected now came from the same
//     machine's clock, wrong in the same direction, so this is self-consistent.
//     Its failure mode is retention: sysfixtime sets a no-RTC clock from the
//     newest file mtime, which is the agent's own last write, so after a week
//     powered off the raw clock lands back on those stamps and week-old backlog
//     reads as brand new and is uploaded past the window server-core prunes its
//     dedup rows on.
//   - Corrected present versus raw stamp. This measures the true downtime in
//     that case, but it is catastrophic in the other one: an agent that restarts
//     on the SAME boot while its clock is wrong by more than the retention
//     window — wrong for any reason other than downtime — deletes a
//     seconds-old segment before it has been drained.
//
// This uses the RAW comparison, and never deletes on the strength of a
// correction it cannot apply to the stamp, because the two failure modes are not
// remotely equal in cost. Deleting is permanent and destroys exactly the outage
// evidence this whole feature exists to preserve. Replaying late is bounded and
// self-healing: server-core stores samples with INSERT OR IGNORE on
// (series_id, ts), so re-ingesting them changes nothing, and the availability
// detector's watermark rejects every round at or below the newest it has already
// folded — so a packet that outlives its dedup row costs some repeated work and
// alters no history.
func expiredAt(c ClockSource, at time.Time, epoch string, mono int64, now time.Time, retention time.Duration) bool {
	if !correctable(c, epoch) {
		return at.Before(now.Add(-retention))
	}
	return correctedAt(c, at, epoch, mono).Before(correctedNow(c, now).Add(-retention))
}

// correctable reports whether this process's clock model has anything to say
// about stamps carrying the given epoch.
func correctable(c ClockSource, epoch string) bool {
	return c != nil && epoch != "" && epoch == c.Epoch()
}

// correctedAt is a group's arrival time as the corrected clock would have
// recorded it.
func correctedAt(c ClockSource, at time.Time, epoch string, mono int64) time.Time {
	if d := clockOffset(c, epoch, mono, 0); d != 0 {
		return at.Add(d)
	}
	return at
}

// correctedNow is a wall-clock reading of THIS instant in the corrected domain.
// It asks the model about the present rather than about a stored group, which is
// what "now" means: the standing error, with no step left to apply.
func correctedNow(c ClockSource, now time.Time) time.Time {
	if c == nil {
		return now
	}
	if d := c.OffsetAt(c.Epoch(), c.Mono(), 0); d != 0 {
		return now.Add(d)
	}
	return now
}
