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
// types in this file and the ordering rules the uploader depends on:
//
//   - wal.go (default) buffers in memory in front of a spill to plain segment
//     files, so a healthy agent writes nothing to disk but a disconnected one
//     keeps its backlog across a restart. See segment.go for the format.
//   - wal_lite.go (-tags lite, the OpenWrt router builds) is memory-only: on a
//     device whose only writable storage is the flash it boots from, and whose
//     binary may be running from a tmpfs a reboot clears anyway, a durable
//     backlog costs write cycles for very little.
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
}

// covers reports whether a group belongs to this claim.
func (c *claim) covers(gid uint64) bool {
	return c != nil && gid >= c.from && gid <= c.to
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
}

// flatten concatenates the claimed groups into the packet to send, preserving
// arrival order across groups and payload order within each.
func flatten(seq uint64, recs []Records) Batch {
	b := Batch{Sequence: seq}
	for _, r := range recs {
		b.Metrics = append(b.Metrics, r.Metrics...)
		b.Events = append(b.Events, r.Events...)
		b.Inventory = append(b.Inventory, r.Inventory...)
		b.Snapshots = append(b.Snapshots, r.Snapshots...)
		b.GameRuns = append(b.GameRuns, r.GameRuns...)
		b.GameBuckets = append(b.GameBuckets, r.GameBuckets...)
		b.GameGaps = append(b.GameGaps, r.GameGaps...)
		b.GameHostSeconds = append(b.GameHostSeconds, r.GameHostSeconds...)
		b.TraceResults = append(b.TraceResults, r.TraceResults...)
	}
	return b
}

// rowsOf counts the sample rows one Records would occupy.
func rowsOf(r Records) int {
	return len(r.Metrics) + len(r.Events) + len(r.Inventory) + len(r.Snapshots) +
		len(r.GameRuns) + len(r.GameBuckets) + len(r.GameGaps) + len(r.GameHostSeconds) +
		len(r.TraceResults)
}
