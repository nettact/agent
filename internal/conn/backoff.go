package conn

import (
	"math/rand"
	"time"
)

// backoff produces reconnect delays: exponential from base up to cap, with
// ±20% jitter so a fleet of agents that lost the same server doesn't redial in
// lockstep (thundering herd). Not safe for concurrent use — only the Run loop
// touches it.
type backoff struct {
	base, cap time.Duration
	cur       time.Duration // last un-jittered delay; 0 = start over at base
}

// next returns the delay to sleep before the next dial attempt.
func (b *backoff) next() time.Duration {
	if b.cur == 0 {
		b.cur = b.base
	} else {
		b.cur *= 2
		if b.cur > b.cap {
			b.cur = b.cap
		}
	}
	// ±20% jitter. math/rand is fine — this is scheduling noise, not crypto.
	jitter := 1 + (rand.Float64()*0.4 - 0.2)
	return time.Duration(float64(b.cur) * jitter)
}

// reset restarts the sequence at base; called after a session lived long
// enough to prove the server is healthy again.
func (b *backoff) reset() { b.cur = 0 }
