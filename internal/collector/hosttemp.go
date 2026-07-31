package collector

import (
	"context"
	"math"
	"strconv"
	"strings"
	"time"

	pshost "github.com/shirou/gopsutil/v3/host"
)

// Temperature sensing is the one host metric family that a machine may simply
// not have: server boards expose a dozen sensors, VMs and many consumer boards
// expose none, and Windows reaches them through a WMI ACPI class that is often
// absent or elevation-gated. So the read path here is shared by two callers —
// the collector, and the startup capability probe that decides whether the
// agent advertises host.temperature.read at all.

// readSensors is the gopsutil seam, replaced in tests.
var readSensors = pshost.SensorsTemperaturesWithContext

// sensorTimeout caps a single sensor read. The Windows WMI provider can block
// for far longer than the regular collection tier if the ACPI thermal zone is
// unhealthy, and a stuck read would stall every other host metric behind it.
const sensorTimeout = 3 * time.Second

// tempReading is one accepted sensor: a series-safe target and its value.
type tempReading struct {
	target  string
	celsius float64
}

// collectTemps returns every plausible sensor reading, with keys sanitized and
// deduplicated so each maps to a stable series target.
//
// gopsutil's error is deliberately ignored: on Linux it returns the readings it
// managed to parse *plus* a non-nil warnings error, so honouring err would
// discard good data. The plausibility filter is the real gate — no plausible
// reading means no temperature support, whatever err says.
func collectTemps(ctx context.Context) []tempReading {
	ctx, cancel := context.WithTimeout(ctx, sensorTimeout)
	defer cancel()

	stats, _ := readSensors(ctx)
	out := make([]tempReading, 0, len(stats))
	seen := make(map[string]int, len(stats))
	for _, s := range stats {
		if !plausibleTemp(s.Temperature) {
			continue
		}
		key := sanitizeSensorKey(s.SensorKey)
		// Distinct sensors can sanitize to the same key (or report the same key
		// outright). Suffix the repeats so they don't collapse into one series.
		seen[key]++
		if n := seen[key]; n > 1 {
			key += "_" + strconv.Itoa(n)
		}
		out = append(out, tempReading{target: key, celsius: s.Temperature})
	}
	return out
}

// plausibleTemp rejects readings no real sensor produces. Firmware that has no
// live sensor behind a slot commonly reports exactly 0, and some WMI providers
// return a fixed constant that converts to a negative Celsius value.
func plausibleTemp(v float64) bool {
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return false
	}
	return v > 0 && v < 150
}

// maxSensorKeyLen bounds a target so one verbose firmware label can't dominate
// the series table.
const maxSensorKeyLen = 64

// sanitizeSensorKey turns a raw sensor label into a stable series target.
// Windows reports the WMI instance name (`ACPI\ThermalZone\TZ00_0`), Linux the
// hwmon label (`coretemp_package_id_0`); both must survive as one URL-safe,
// case-stable token.
func sanitizeSensorKey(k string) string {
	var b strings.Builder
	b.Grow(len(k))
	for _, r := range strings.ToLower(strings.TrimSpace(k)) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '.', r == '-':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	// Collapse the runs the substitution above tends to create.
	key := b.String()
	for strings.Contains(key, "__") {
		key = strings.ReplaceAll(key, "__", "_")
	}
	key = strings.Trim(key, "_")
	if len(key) > maxSensorKeyLen {
		key = strings.Trim(key[:maxSensorKeyLen], "_")
	}
	if key == "" {
		return "sensor"
	}
	return key
}

// TemperatureSupported reports whether this machine actually yields a usable
// sensor reading right now. The agent calls it once at startup to decide
// whether host.temperature.read belongs in its supported set, mirroring how
// traceroute.Supported gates the traceroute permissions.
func TemperatureSupported(ctx context.Context) bool {
	return len(collectTemps(ctx)) > 0
}
