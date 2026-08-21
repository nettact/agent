package conn

import (
	"errors"
	"fmt"
	"testing"

	"github.com/nettact/protocol/wire"
)

// The verdict must survive losing the race to the pinger.
//
// Both the reader and the pinger report into one channel, and only the reader
// parses close frames. When a peer close tears the transport down, the pinger's
// in-flight write usually fails first with a generic error, so the coded close
// sits behind it in the buffer. Reading a single value therefore picks the
// wrong one exactly when a code is present — and the code is what decides
// whether the runner re-dials in the other schema, stops for a superseded
// credential, or deletes a revoked one.
//
// MUTATION: replace the drain loop in preferCloseCause with a single receive →
// the "pinger first" cases below return the generic error and turn red.
func TestPreferCloseCauseDrainsPastANonCloseError(t *testing.T) {
	generic := errors.New("use of closed network connection")
	coded := fmt.Errorf("read: %w", &wire.CloseError{Code: wire.CloseUnsupportedSchema})

	cases := []struct {
		name     string
		reported []error // in the order the goroutines reported them
		want     wire.CloseCode
	}{
		{"pinger first, then the reader's code", []error{generic, coded}, wire.CloseUnsupportedSchema},
		{"reader's code first", []error{coded, generic}, wire.CloseUnsupportedSchema},
		{"only the code", []error{coded}, wire.CloseUnsupportedSchema},
		{"no code at all", []error{generic}, -1},
		{"nothing reported", nil, -1},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			errCh := make(chan error, 2) // same shape as the session's channel
			for _, e := range tc.reported {
				errCh <- e
			}

			r := &runner{}
			got := r.preferCloseCause(generic, errCh)

			if status := wire.CloseStatus(got); status != tc.want {
				t.Fatalf("close status = %d, want %d (error %v)", status, tc.want, got)
			}
		})
	}
}
