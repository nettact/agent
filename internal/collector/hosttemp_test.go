package collector

import (
	"context"
	"errors"
	"math"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nettact/protocol/telemetry"

	pshost "github.com/shirou/gopsutil/v3/host"
)

// stubSensors swaps the gopsutil seam for one test and restores it afterwards.
func stubSensors(t *testing.T, stats []pshost.TemperatureStat, err error) {
	t.Helper()
	prev := readSensors
	readSensors = func(context.Context) ([]pshost.TemperatureStat, error) { return stats, err }
	t.Cleanup(func() { readSensors = prev })
}

func TestSanitizeSensorKey(t *testing.T) {
	for _, tc := range []struct{ name, in, want string }{
		{"windows WMI instance name", `ACPI\ThermalZone\TZ00_0`, "acpi_thermalzone_tz00_0"},
		{"linux hwmon label", "coretemp_package_id_0", "coretemp_package_id_0"},
		{"already clean", "nvme.composite-1", "nvme.composite-1"},
		{"collapses separator runs", "cpu //  core", "cpu_core"},
		{"trims edge separators", "  __k10temp__  ", "k10temp"},
		{"empty falls back", "   ", "sensor"},
		{"non-ascii becomes separators", "温度传感器", "sensor"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := sanitizeSensorKey(tc.in); got != tc.want {
				t.Fatalf("sanitizeSensorKey(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// A long firmware label must not become an unbounded series target, and must not
// come back with a trailing separator once truncated.
func TestSanitizeSensorKeyBoundsLength(t *testing.T) {
	got := sanitizeSensorKey(strings.Repeat("a", 100) + `\` + strings.Repeat("b", 20))
	if len(got) > maxSensorKeyLen {
		t.Fatalf("key length %d exceeds cap %d: %q", len(got), maxSensorKeyLen, got)
	}
	if strings.HasSuffix(got, "_") {
		t.Fatalf("truncated key kept a trailing separator: %q", got)
	}
}

func TestPlausibleTemp(t *testing.T) {
	for _, v := range []float64{1, 42.5, 149.9} {
		if !plausibleTemp(v) {
			t.Fatalf("%v should be plausible", v)
		}
	}
	// 0 is what firmware reports for an empty sensor slot; the negative value is
	// a fixed WMI constant converted out of Kelvin; 150+ is out of range.
	for _, v := range []float64{0, -273.15, 150, 1e6, math.NaN(), math.Inf(1), math.Inf(-1)} {
		if plausibleTemp(v) {
			t.Fatalf("%v should be rejected", v)
		}
	}
}

func TestCollectTempsFiltersAndDedupes(t *testing.T) {
	stubSensors(t, []pshost.TemperatureStat{
		{SensorKey: `ACPI\ThermalZone\TZ00_0`, Temperature: 47.5},
		{SensorKey: "empty_slot", Temperature: 0},     // dropped
		{SensorKey: "bad_provider", Temperature: -40}, // dropped
		{SensorKey: "coretemp_core_0", Temperature: 61},
		{SensorKey: "coretemp/core/0", Temperature: 62}, // sanitizes onto the previous key
	}, nil)

	got := collectTemps(context.Background())
	if len(got) != 3 {
		t.Fatalf("expected 3 plausible readings, got %d (%+v)", len(got), got)
	}
	want := []tempReading{
		{target: "acpi_thermalzone_tz00_0", celsius: 47.5},
		{target: "coretemp_core_0", celsius: 61},
		{target: "coretemp_core_0_2", celsius: 62},
	}
	for i, w := range want {
		if got[i] != w {
			t.Fatalf("reading %d = %+v, want %+v", i, got[i], w)
		}
	}
}

// A machine can report a key that already looks like the suffixed form of
// another. Every emitted target must still be distinct, or two sensors collapse
// onto one series and one value overwrites the other at the same timestamp.
func TestCollectTempsTargetsStayUniqueAgainstNaturalSuffixes(t *testing.T) {
	stubSensors(t, []pshost.TemperatureStat{
		{SensorKey: "cpu", Temperature: 40},
		{SensorKey: "cpu", Temperature: 41},   // collides -> cpu_2
		{SensorKey: "cpu_2", Temperature: 42}, // natural cpu_2 -> must not reuse
		{SensorKey: "cpu", Temperature: 43},   // -> cpu_3
	}, nil)

	got := collectTemps(context.Background())
	if len(got) != 4 {
		t.Fatalf("expected 4 readings, got %d (%+v)", len(got), got)
	}
	seen := map[string]bool{}
	for _, r := range got {
		if seen[r.target] {
			t.Fatalf("duplicate target %q in %+v", r.target, got)
		}
		seen[r.target] = true
	}
	// Every distinct reading must survive with its own value.
	byTarget := map[string]float64{}
	for _, r := range got {
		byTarget[r.target] = r.celsius
	}
	for _, want := range []float64{40, 41, 42, 43} {
		found := false
		for _, v := range byTarget {
			if v == want {
				found = true
			}
		}
		if !found {
			t.Fatalf("reading %v was dropped: %+v", want, got)
		}
	}
}

// A provider that never answers must not accumulate queries: the first caller
// waits out sensorTimeout, and callers after it are refused until the stuck read
// finally returns.
func TestCollectTempsKeepsAtMostOneReadInFlight(t *testing.T) {
	prevTimeout := sensorTimeout
	sensorTimeout = 20 * time.Millisecond
	t.Cleanup(func() { sensorTimeout = prevTimeout })

	release := make(chan struct{})
	var calls atomic.Int32
	prev := readSensors
	readSensors = func(context.Context) ([]pshost.TemperatureStat, error) {
		calls.Add(1)
		<-release
		return []pshost.TemperatureStat{{SensorKey: "k10temp", Temperature: 55}}, nil
	}
	t.Cleanup(func() {
		readSensors = prev
		close(release)
		// Let the stuck goroutine finish so it cannot leak into another test.
		for sensorBusy.Load() {
			runtime.Gosched()
		}
	})

	if got := collectTemps(context.Background()); got != nil {
		t.Fatalf("a stuck read must yield nothing, got %+v", got)
	}
	if got := collectTemps(context.Background()); got != nil {
		t.Fatalf("second call must be refused while the read is in flight, got %+v", got)
	}
	if n := calls.Load(); n != 1 {
		t.Fatalf("expected exactly 1 underlying read, got %d", n)
	}
}

// gopsutil on Linux returns the sensors it could parse alongside a non-nil
// warnings error. Honouring that error would throw away good readings.
func TestCollectTempsKeepsReadingsDespiteWarnings(t *testing.T) {
	stubSensors(t, []pshost.TemperatureStat{{SensorKey: "k10temp", Temperature: 55}}, errors.New("warnings: 1 error occurred"))

	if got := collectTemps(context.Background()); len(got) != 1 || got[0].celsius != 55 {
		t.Fatalf("warnings must not discard readings, got %+v", got)
	}
	if !TemperatureSupported(context.Background()) {
		t.Fatal("a usable reading means temperature is supported")
	}
}

func TestTemperatureUnsupportedWithoutPlausibleReadings(t *testing.T) {
	t.Run("read failed", func(t *testing.T) {
		stubSensors(t, nil, errors.New("not implemented yet"))
		if TemperatureSupported(context.Background()) {
			t.Fatal("no sensors must report unsupported")
		}
	})
	t.Run("all readings implausible", func(t *testing.T) {
		stubSensors(t, []pshost.TemperatureStat{
			{SensorKey: "tz0", Temperature: 0},
			{SensorKey: "tz1", Temperature: -273.15},
		}, nil)
		if TemperatureSupported(context.Background()) {
			t.Fatal("a sensor list with no usable value must report unsupported")
		}
	})
}

// The collector must emit the per-sensor detail plus the hottest reading as the
// "host" aggregate, and nothing at all from the families it wasn't granted.
func TestHostMetricsCollectorEmitsTemperature(t *testing.T) {
	stubSensors(t, []pshost.TemperatureStat{
		{SensorKey: "coretemp_core_0", Temperature: 61},
		{SensorKey: "coretemp_package_id_0", Temperature: 72.5},
		{SensorKey: "unused", Temperature: 0},
	}, nil)

	c := NewHostMetricsCollector(false, false, false, false, false, false, true)
	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(res.Metrics) != 3 {
		t.Fatalf("expected 2 sensor series + 1 aggregate, got %d (%+v)", len(res.Metrics), res.Metrics)
	}

	var aggregate *telemetry.Metric
	for i := range res.Metrics {
		m := &res.Metrics[i]
		if m.Unit != telemetry.UnitCelsius {
			t.Fatalf("%s has unit %q, want %q", m.Kind, m.Unit, telemetry.UnitCelsius)
		}
		if m.Layer != telemetry.LayerLocal {
			t.Fatalf("%s has layer %q, want %q", m.Kind, m.Layer, telemetry.LayerLocal)
		}
		if m.MonitorID != "" {
			t.Fatalf("host metrics carry no monitor binding, got %q", m.MonitorID)
		}
		if m.Kind == telemetry.HostTempC {
			aggregate = m
		}
	}
	if aggregate == nil {
		t.Fatal("missing the host.temp.c aggregate")
	}
	if aggregate.Target != "host" || aggregate.Value != 72.5 {
		t.Fatalf("aggregate = (%q, %v), want (\"host\", 72.5)", aggregate.Target, aggregate.Value)
	}
}

// A sensorless machine must leave a gap rather than report a synthetic zero.
func TestHostMetricsCollectorSkipsTemperatureWhenUnreadable(t *testing.T) {
	stubSensors(t, nil, errors.New("not implemented yet"))

	c := NewHostMetricsCollector(false, false, false, false, false, false, true)
	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(res.Metrics) != 0 {
		t.Fatalf("expected no samples, got %+v", res.Metrics)
	}
}

// A denied family must not reach the sensors at all.
func TestHostMetricsCollectorSkipsTemperatureWhenDenied(t *testing.T) {
	called := false
	prev := readSensors
	readSensors = func(context.Context) ([]pshost.TemperatureStat, error) {
		called = true
		return []pshost.TemperatureStat{{SensorKey: "k10temp", Temperature: 55}}, nil
	}
	t.Cleanup(func() { readSensors = prev })

	c := NewHostMetricsCollector(false, false, false, false, false, false, false)
	if _, err := c.Collect(context.Background()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if called {
		t.Fatal("temperature permission denied, but the sensors were read anyway")
	}
}
