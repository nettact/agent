//go:build windows

package collector

import (
	"context"
	"testing"

	pshost "github.com/shirou/gopsutil/v3/host"
)

func TestWindowsTemperatureIsUnsupportedWithoutReadingWMI(t *testing.T) {
	prevReadSensors := readSensors
	prevPlatformSupported := temperaturePlatformSupported
	called := false
	readSensors = func(context.Context) ([]pshost.TemperatureStat, error) {
		called = true
		return []pshost.TemperatureStat{{SensorKey: "acpi", Temperature: 42}}, nil
	}
	temperaturePlatformSupported = nativeTemperaturePlatformSupported
	t.Cleanup(func() {
		readSensors = prevReadSensors
		temperaturePlatformSupported = prevPlatformSupported
	})

	if TemperatureSupported(context.Background()) {
		t.Fatal("Windows temperature must be reported unsupported")
	}
	if called {
		t.Fatal("Windows temperature support check touched the sensor provider")
	}
}
