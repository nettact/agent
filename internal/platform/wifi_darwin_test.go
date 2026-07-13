//go:build darwin

package platform

import "testing"

func TestNormalizeCWPermissionAndMissingFields(t *testing.T) {
	got := normalizeCW(cwAdapter{
		Name: "en0", PoweredOn: true, HasChannel: true, Band: "6", Channel: 5,
		SSIDKnown: false, RSSI: -65, HasRSSI: true, TxRateMbps: 866.66, HasTxRate: true,
	})
	if got.State != "connected" || got.Reason != "permission" || got.SSID != "" {
		t.Fatalf("privacy-withheld connection=%+v", got)
	}
	if got.SignalDBm == nil || *got.SignalDBm != -65 || got.Quality == nil || *got.Quality != 70 {
		t.Fatalf("readable signal fields lost: %+v", got)
	}
	if got.TxMbps == nil || *got.TxMbps != 866.7 || got.RxMbps != nil {
		t.Fatalf("link rates=%+v", got)
	}
	if got.Band != "6" || got.Channel != 5 {
		t.Fatalf("band/channel=%q/%d", got.Band, got.Channel)
	}

	disconnected := normalizeCW(cwAdapter{Name: "en0", PoweredOn: false, SSID: "stale", SSIDKnown: true, RSSI: -40, HasRSSI: true})
	if disconnected.State != "disconnected" || disconnected.SSID != "" || disconnected.SignalDBm != nil {
		t.Fatalf("disconnected adapter retained details: %+v", disconnected)
	}
}

func TestCWBand(t *testing.T) {
	for in, want := range map[int]string{0: "", 1: "2.4", 2: "5", 3: "6", 4: ""} {
		if got := cwBand(in); got != want {
			t.Errorf("cwBand(%d)=%q want %q", in, got, want)
		}
	}
}
