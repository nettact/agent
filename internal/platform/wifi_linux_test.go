//go:build linux

package platform

import (
	"errors"
	"syscall"
	"testing"
)

func TestLinuxPermissionClassification(t *testing.T) {
	if !isPermErr(syscall.EPERM) || !isPermErr(syscall.EACCES) {
		t.Fatal("EPERM/EACCES must classify as permission errors")
	}
	if isPermErr(errors.New("driver failed")) {
		t.Fatal("generic driver error classified as permission")
	}
	got := classifyLinuxWiFiOpenErr(syscall.EPERM)
	if got.State != "unreadable" || got.Reason != "permission" || len(got.Adapters) != 0 {
		t.Fatalf("classifyLinuxWiFiOpenErr(EPERM)=%+v", got)
	}
}
