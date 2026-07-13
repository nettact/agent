//go:build !windows && !linux && !darwin

package platform

import "github.com/nettact/protocol/capability"

// On platforms without a Wi-Fi adapter implementation the collection always
// succeeds with no wireless adapters ("no adapter"), and the host advertises no
// Wi-Fi capability so the console shows "platform not supported" rather than a
// false "no adapter".

func (genericPlatform) WiFi() WiFiResult { return WiFiResult{State: "ok"} }

func wifiCapability() capability.Capability { return "" }

func ifaceIsWireless(string) bool { return false }
