package platform

import (
	"bytes"
	"testing"
)

func TestTrimIPv4HeaderStripsPlainHeader(t *testing.T) {
	pkt := append([]byte{0x45, 0, 0, 28, 0, 0, 0, 0, 64, 1, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2}, 0, 0, 0xbe, 0xef)
	got := trimIPv4Header(pkt)
	if !bytes.Equal(got, []byte{0, 0, 0xbe, 0xef}) {
		t.Fatalf("payload after 20-byte header = %x", got)
	}
}

func TestTrimIPv4HeaderStripsOptionsBearingHeader(t *testing.T) {
	// IHL 6 → 24-byte header.
	hdr := make([]byte, 24)
	hdr[0] = 0x46
	pkt := append(hdr, 8, 0)
	got := trimIPv4Header(pkt)
	if !bytes.Equal(got, []byte{8, 0}) {
		t.Fatalf("payload after options-bearing header = %x", got)
	}
}

func TestTrimIPv4HeaderLeavesNonIPv4Alone(t *testing.T) {
	for name, b := range map[string][]byte{
		"bare ICMP echo reply": append([]byte{0, 0, 0, 0}, make([]byte, 20)...), // version nibble 0
		"short":                {0x45, 0, 0},
		"empty":                nil,
		"IHL below minimum":    append([]byte{0x44}, make([]byte, 23)...),
		"shorter than stated IHL": {0x4f, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
	} {
		if got := trimIPv4Header(b); !bytes.Equal(got, b) {
			t.Fatalf("%s: buffer must be returned unchanged, got %x", name, got)
		}
	}
}
