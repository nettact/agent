package wal

import (
	"os"
	"testing"
	"time"
)

// tempWALDir returns a directory to hold a WAL, removed on a best-effort basis
// when the test ends.
//
// t.TempDir is the wrong owner for it on Windows: its cleanup fails the test if
// RemoveAll errors, and Windows can release a just-closed file slightly after
// Close returns — so a passing test intermittently reports a failure on the
// unlink rather than on anything it asserted. (server-core has the same helper,
// for the same reason.) Retry briefly and never fail: a leftover directory under
// the OS temp root is the operating system's to reap.
//
// It lives in this untagged file because both the default and the lite build
// write segments now, and each build's test files only compile under their own
// tag.
func tempWALDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "nettact-wal-")
	if err != nil {
		t.Fatalf("temp dir: %v", err)
	}
	t.Cleanup(func() {
		for i := 0; i < 20; i++ {
			if os.RemoveAll(dir) == nil {
				return
			}
			time.Sleep(25 * time.Millisecond)
		}
	})
	return dir
}
