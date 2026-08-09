package platform

import "math"

// Pure, platform-independent Wi-Fi normalization helpers shared by every OS
// adapter. Kept build-tag-free so they compile and unit-test on any host: band
// and channel are derived deterministically from the operating frequency, and
// quality↔dBm conversions are documented linear mappings (not inference of
// missing data — a caller only converts a value it actually read).

// bandFromFrequencyMHz maps a channel center frequency (MHz) to the operating
// band string ("2.4" | "5" | "6"), or "" when the frequency is outside the
// known Wi-Fi bands / unknown (0). 5 and 6 GHz channel numbers overlap, so band
// is derived from frequency, never guessed from a channel number.
func bandFromFrequencyMHz(mhz int) string {
	switch {
	case mhz >= 2400 && mhz <= 2500:
		return "2.4"
	case mhz >= 4900 && mhz <= 5899:
		return "5"
	case mhz >= 5925 && mhz <= 7125:
		return "6"
	default:
		return ""
	}
}

// channelFromFrequencyMHz maps a channel center frequency (MHz) to its channel
// number, or 0 when the frequency is not an actual valid channel center. Each
// band is a 5 MHz grid off a band-specific anchor; a positive channel is
// returned only when the frequency is grid-aligned AND inside that band's real
// channel range — band edges, off-grid values and out-of-range inputs return 0
// (never a channel invented from a broad range alone).
func channelFromFrequencyMHz(mhz int) int {
	switch {
	// 2.4 GHz: channels 1-13 on a 5 MHz grid off 2407 (2412…2472), plus the
	// documented channel 14 exception at 2484 MHz.
	case mhz == 2484:
		return 14
	case mhz >= 2412 && mhz <= 2472 && (mhz-2407)%5 == 0:
		return (mhz - 2407) / 5
	// 5 GHz: channels on a 5 MHz grid off 5000 (ch 32 = 5160 … ch 177 = 5885).
	case mhz >= 5160 && mhz <= 5885 && (mhz-5000)%5 == 0:
		return (mhz - 5000) / 5
	// 6 GHz: channels 1-233 on a 5 MHz grid off 5950 (ch 1 = 5955 … ch 233 = 7115).
	case mhz >= 5955 && mhz <= 7115 && (mhz-5950)%5 == 0:
		return (mhz - 5950) / 5
	default:
		return 0
	}
}

// qualityFromDBm converts a signal strength (dBm) to a 0-100 link-quality
// percentage using the common linear approximation quality = 2×(dBm + 100),
// clamped. Used when the OS exposes dBm but no native quality percent through
// the path we read (on Windows the driver's own quality only comes with the
// location-gated query, so the ungated tick derives it here instead — deriving
// both numbers from one live reading also keeps the two series from ever
// disagreeing, which a cached native quality beside a live dBm would).
func qualityFromDBm(dbm int) int {
	q := 2 * (dbm + 100)
	if q < 0 {
		return 0
	}
	if q > 100 {
		return 100
	}
	return q
}

// dbmFromQuality is the inverse approximation dBm = quality/2 − 100, used only
// as a fallback when the OS reports a quality percent but no native dBm.
func dbmFromQuality(quality int) int {
	if quality < 0 {
		quality = 0
	}
	if quality > 100 {
		quality = 100
	}
	return quality/2 - 100
}

// round1 rounds a value to one decimal place (used for Mbps link rates).
func round1(v float64) float64 { return math.Round(v*10) / 10 }
