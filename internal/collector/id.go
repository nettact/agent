package collector

import "github.com/google/uuid"

// newID returns a fresh event ID used for server-side (agent_id, id) dedup.
func newID() string { return uuid.NewString() }
