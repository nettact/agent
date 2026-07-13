package platform

import "testing"

func TestWiFiFrequencyNormalization(t *testing.T) {
	tests := []struct {
		mhz     int
		band    string
		channel int
	}{
		{0, "", 0},
		{2400, "2.4", 0},
		{2412, "2.4", 1},
		{2437, "2.4", 6},
		{2472, "2.4", 13},
		{2484, "2.4", 14},
		{2500, "2.4", 0},
		{5160, "5", 32},
		{5180, "5", 36},
		{5885, "5", 177},
		{5899, "5", 0},
		{5925, "6", 0},
		{5955, "6", 1},
		{7115, "6", 233},
		{7125, "6", 0},
		{5181, "5", 0},
	}
	for _, tt := range tests {
		if got := bandFromFrequencyMHz(tt.mhz); got != tt.band {
			t.Errorf("bandFromFrequencyMHz(%d)=%q want %q", tt.mhz, got, tt.band)
		}
		if got := channelFromFrequencyMHz(tt.mhz); got != tt.channel {
			t.Errorf("channelFromFrequencyMHz(%d)=%d want %d", tt.mhz, got, tt.channel)
		}
	}
}

func TestWiFiQualityConversionsClamp(t *testing.T) {
	for _, tt := range []struct{ dbm, quality int }{
		{-120, 0}, {-100, 0}, {-80, 40}, {-60, 80}, {-50, 100}, {-20, 100},
	} {
		if got := qualityFromDBm(tt.dbm); got != tt.quality {
			t.Errorf("qualityFromDBm(%d)=%d want %d", tt.dbm, got, tt.quality)
		}
	}
	for _, tt := range []struct{ quality, dbm int }{
		{-1, -100}, {0, -100}, {40, -80}, {100, -50}, {101, -50},
	} {
		if got := dbmFromQuality(tt.quality); got != tt.dbm {
			t.Errorf("dbmFromQuality(%d)=%d want %d", tt.quality, got, tt.dbm)
		}
	}
}
