//go:build windows

package platform

import (
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestWinWlanNotificationLayout(t *testing.T) {
	if got, want := unsafe.Sizeof(wlanNotificationData{}), uintptr(40); got != want {
		t.Errorf("wlanNotificationData size=%d want %d", got, want)
	}
	if got, want := unsafe.Offsetof(wlanNotificationData{}.Data), uintptr(32); got != want {
		t.Errorf("wlanNotificationData.Data offset=%d want %d", got, want)
	}
}

func TestWinWlanNotificationEvent(t *testing.T) {
	guid := windows.GUID{Data1: 0xabc}

	if _, ok := wlanNotificationEvent(nil); ok {
		t.Fatal("nil data must be dropped")
	}

	// Interesting ACM/MSM codes pass through with source/code/guid intact.
	for _, tc := range []struct{ source, code uint32 }{
		{wlanNotificationSourceACM, acmConnectionComplete},
		{wlanNotificationSourceACM, acmInterfaceRemoval},
		{wlanNotificationSourceACM, acmDisconnected},
		{wlanNotificationSourceMSM, msmConnected},
		{wlanNotificationSourceMSM, msmRoamingEnd},
		{wlanNotificationSourceMSM, msmDisconnected},
		{wlanNotificationSourceMSM, msmAdapterRemoval},
	} {
		ev, ok := wlanNotificationEvent(&wlanNotificationData{
			NotificationSource: tc.source, NotificationCode: tc.code, InterfaceGUID: guid,
		})
		if !ok || ev.Source != tc.source || ev.Code != tc.code || ev.GUID != guid {
			t.Fatalf("source=%#x code=%d: ev=%+v ok=%v", tc.source, tc.code, ev, ok)
		}
	}

	// Signal-quality events carry the ULONG payload; a missing/short payload is
	// dropped rather than dereferenced.
	q := uint32(73)
	ev, ok := wlanNotificationEvent(&wlanNotificationData{
		NotificationSource: wlanNotificationSourceMSM,
		NotificationCode:   msmSignalQualityChange,
		InterfaceGUID:      guid,
		DataSize:           4,
		Data:               unsafe.Pointer(&q),
	})
	if !ok || ev.Quality != 73 {
		t.Fatalf("quality ev=%+v ok=%v", ev, ok)
	}
	if _, ok := wlanNotificationEvent(&wlanNotificationData{
		NotificationSource: wlanNotificationSourceMSM,
		NotificationCode:   msmSignalQualityChange,
	}); ok {
		t.Fatal("payload-less quality event must be dropped")
	}

	// Uninteresting codes (scan chatter etc.) and unknown sources are dropped —
	// the callback runs on a WlanSvc thread and must do no work for them.
	for _, tc := range []struct{ source, code uint32 }{
		{wlanNotificationSourceACM, 7}, // scan_complete
		{wlanNotificationSourceACM, 9}, // connection_start
		{wlanNotificationSourceMSM, 1}, // associating
		{0x00000004, acmDisconnected},  // security source
	} {
		if _, ok := wlanNotificationEvent(&wlanNotificationData{
			NotificationSource: tc.source, NotificationCode: tc.code,
		}); ok {
			t.Fatalf("source=%#x code=%d must be dropped", tc.source, tc.code)
		}
	}
}

func TestWinWiFiFallsBackWhenWatcherUnavailable(t *testing.T) {
	// Force the "watcher failed to start recently" state so getWinWatcher
	// declines without touching WlanSvc, and observe the routing decision.
	winWatcherMu.Lock()
	savedInst, savedFail := winWatcherInst, winWatcherLastFail
	winWatcherInst, winWatcherLastFail = nil, time.Now()
	winWatcherMu.Unlock()
	savedRead := wifiFullReadFn
	defer func() {
		winWatcherMu.Lock()
		winWatcherInst, winWatcherLastFail = savedInst, savedFail
		winWatcherMu.Unlock()
		wifiFullReadFn = savedRead
	}()

	called := false
	wifiFullReadFn = func(includeSSID bool) WiFiResult {
		called = true
		return WiFiResult{State: "ok"}
	}
	res := winPlatform{}.WiFi(false)
	if !called {
		t.Fatal("watcher-less WiFi() must route to the full read")
	}
	if res.State != "ok" {
		t.Fatalf("res=%+v", res)
	}
}
