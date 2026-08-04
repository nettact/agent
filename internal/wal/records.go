// Package wal is the agent's outbox (architecture §3.3): collectors append
// samples locally so monitoring never stops when the server is unreachable, and
// batches carry a sequence so a crash mid-upload re-sends the SAME sequence and
// the server dedups on (agent_id, sequence).
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
// Both honour the same contract for everything above them: FIFO delivery, whole
// Records groups claimed indivisibly, and an in-flight packet re-served under
// its original sequence until acked.
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
}

// memGroup is one Append held in memory: an indivisible Records plus the wall
// clock it arrived at (its created_at if it is ever spilled) and its row count.
type memGroup struct {
	at  time.Time
	rec Records
	n   int
}

// memBatch is the one memory-served packet handed to the uploader and awaiting
// its ack. It keeps the groups rather than a flattened Batch so a spill can
// write them back out with their own created_at and grouping intact.
type memBatch struct {
	seq    uint64
	groups []memGroup
}

// batch flattens the claimed groups into the packet to send, preserving arrival
// order across groups and payload order within each.
func (m *memBatch) batch() Batch {
	b := Batch{Sequence: m.seq}
	for _, g := range m.groups {
		b.Metrics = append(b.Metrics, g.rec.Metrics...)
		b.Events = append(b.Events, g.rec.Events...)
		b.Inventory = append(b.Inventory, g.rec.Inventory...)
		b.Snapshots = append(b.Snapshots, g.rec.Snapshots...)
		b.GameRuns = append(b.GameRuns, g.rec.GameRuns...)
		b.GameBuckets = append(b.GameBuckets, g.rec.GameBuckets...)
		b.GameGaps = append(b.GameGaps, g.rec.GameGaps...)
		b.GameHostSeconds = append(b.GameHostSeconds, g.rec.GameHostSeconds...)
	}
	return b
}

// rowsOf counts the sample rows one Records would occupy.
func rowsOf(r Records) int {
	return len(r.Metrics) + len(r.Events) + len(r.Inventory) + len(r.Snapshots) +
		len(r.GameRuns) + len(r.GameBuckets) + len(r.GameGaps) + len(r.GameHostSeconds)
}
