package collector

import (
	"context"
	"math"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	pshost "github.com/shirou/gopsutil/v3/host"
)

// Temperature sensing is the one host metric family that a machine may simply
// not have: server boards expose a dozen sensors while VMs and many consumer
// boards expose none. The read path is shared by the collector and the startup
// capability probe that decides whether the agent advertises
// host.temperature.read at all.

// temperaturePlatformSupported is a test seam around the build-tagged platform
// decision. Windows deliberately returns false: its standard WMI ACPI thermal
// zones are commonly stale, synthetic, or unrelated to CPU/mainboard sensors,
// so reporting them as host temperature is less honest than reporting the
// capability unsupported. Keep the check before readSensors so Windows never
// touches WMI for this metric.
var temperaturePlatformSupported = nativeTemperaturePlatformSupported

// readSensors is the gopsutil seam, replaced in tests.
var readSensors = pshost.SensorsTemperaturesWithContext

// sensorTimeout caps how long a caller waits for a sensor read. A stuck provider
// would otherwise stall every other host metric behind it. A var so tests can
// shorten the wait.
var sensorTimeout = 3 * time.Second

// sensorBusy is held for as long as a read is genuinely outstanding, which is
// not the same as "a caller is waiting". A provider may return from its public
// call before all of its internal work stops, so a hung provider would otherwise
// strand one more query on every 30s collection cycle. Skipping while the
// previous read is still in flight bounds that at one.
var sensorBusy atomic.Bool

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
	if !temperaturePlatformSupported() {
		return nil
	}
	stats, ok := readSensorsGuarded(ctx)
	if !ok {
		return nil
	}
	out := make([]tempReading, 0, len(stats))
	used := make(map[string]bool, len(stats))
	for _, s := range stats {
		if !plausibleTemp(s.Temperature) {
			continue
		}
		// Distinct sensors can sanitize onto one key, and a machine can also
		// report a key that already looks like a suffixed one ("cpu" twice plus
		// a literal "cpu_2"). Probing for the first free target rather than
		// counting occurrences of the base keeps every target unique, so two
		// sensors can never collapse into one series.
		key := sanitizeSensorKey(s.SensorKey)
		if used[key] {
			base := key
			for n := 2; ; n++ {
				key = base + "_" + strconv.Itoa(n)
				if !used[key] {
					break
				}
			}
		}
		used[key] = true
		out = append(out, tempReading{target: key, celsius: s.Temperature})
	}
	return out
}

// readSensorsGuarded performs the sensor read on its own goroutine and stops
// waiting after sensorTimeout, reporting ok=false. The goroutine keeps sensorBusy
// held until the underlying call actually returns — detached from the caller's
// context on purpose, so that giving up on a stuck provider does not license the
// next cycle to start another query behind it.
func readSensorsGuarded(ctx context.Context) ([]pshost.TemperatureStat, bool) {
	if !sensorBusy.CompareAndSwap(false, true) {
		return nil, false
	}
	ch := make(chan []pshost.TemperatureStat, 1)
	go func() {
		stats, _ := readSensors(context.WithoutCancel(ctx))
		// Release before publishing, so a caller that receives the result can
		// immediately start the next read.
		sensorBusy.Store(false)
		ch <- stats
	}()
	select {
	case stats := <-ch:
		return stats, true
	case <-time.After(sensorTimeout):
		return nil, false
	}
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

// TemperatureSupported reports whether this build can read a usable sensor
// value on this machine right now. It is false without reading anything where
// the platform has no trustworthy backend (Windows), and elsewhere only if a
// real read yields a plausible value. The agent calls it once at startup to
// decide whether host.temperature.read belongs in its supported set, mirroring
// how traceroute.Supported gates the traceroute permissions.
func TemperatureSupported(ctx context.Context) bool {
	return len(collectTemps(ctx)) > 0
}
