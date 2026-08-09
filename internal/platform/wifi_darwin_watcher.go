//go:build darwin

package platform

import (
	"runtime"
	"sync"
	"time"

	"github.com/ebitengine/purego/objc"
)

// macOS event source for the shared wifiCache: a CWWiFiClient delegate whose
// events mark the cache dirty so the gated -ssid read runs only when the
// network actually changed. The delegate IMPs run on CoreWLAN's internal
// dispatch queue (a foreign thread): they do NO Objective-C work at all — not
// even extracting the interface-name argument — and just signal a channel,
// because a purego callback crash there is not recoverable in-process. Which
// adapter changed is coarse-grained away (NoteChangeAll); Macs have one Wi-Fi
// interface and reconcile cleans up any overreach.
//
// Delegate registration is best-effort: if it fails, the cache's ungated
// transition reconcile (link state, channel, band changes seen by the tick)
// still refreshes the SSID, with one documented blind spot — switching between
// two same-channel same-band networks entirely between two ticks keeps the old
// SSID until the next observable transition.

// CWEventType values (CWWiFiClient.h; verify against the SDK header on
// change — there is a layout test for the Windows equivalent but these two
// are enum constants with no struct to assert).
const (
	cwEventTypeSSIDDidChange = 2
	cwEventTypeLinkDidChange = 5
)

type darwinWiFiEvent uint8

const (
	darwinEvChange darwinWiFiEvent = iota
	darwinEvInvalidated
)

type darwinWiFiWatcher struct {
	cl       cwClient
	cache    *wifiCache
	events   chan darwinWiFiEvent
	listener objc.ID // delegate instance, held for process lifetime

	retryMu    sync.Mutex
	retryArmed bool
}

var (
	darwinWatcherOnce sync.Once
	darwinWatcherInst *darwinWiFiWatcher
	darwinWatcherErr  error
)

// getDarwinWatcher returns the process singleton (see wifi_cache.go for why it
// must be process-wide and process-lifetime). Unlike Windows there is no
// separate fallback read path: the tick's ungated reads are identical with or
// without events, so a failed delegate setup just means reconcile-only SSID
// refreshes.
func getDarwinWatcher() (*darwinWiFiWatcher, error) {
	darwinWatcherOnce.Do(func() {
		cl, err := newCWClient()
		if err != nil {
			darwinWatcherErr = err
			return
		}
		w := &darwinWiFiWatcher{
			cl: cl,
			cache: newWiFiCache(wifiCacheConfig{
				MinRefreshInterval:             5 * time.Second,
				SSIDDemandWindow:               90 * time.Second,
				ReasonPermissionWhenSSIDAbsent: true,
			}, time.Now),
			events: make(chan darwinWiFiEvent, 8),
		}
		if c, ok := cl.(*coreWLANClient); ok {
			w.startDelegate(c)
		}
		go w.pump()
		darwinWatcherInst = w
	})
	return darwinWatcherInst, darwinWatcherErr
}

// startDelegate registers the runtime Objective-C listener class and points
// CWWiFiClient at it. Best-effort by design: any failure (class collision,
// runtime refusal) leaves the watcher in reconcile-only mode rather than
// degrading data or crashing — hence the blanket recover.
func (w *darwinWiFiWatcher) startDelegate(c *coreWLANClient) {
	defer func() { _ = recover() }()

	notify := func(ev darwinWiFiEvent) {
		select {
		case w.events <- ev:
		default: // shed: pump coalesces, reconcile self-heals
		}
	}
	// CWWiFiClient dispatches delegate methods by respondsToSelector:, so a
	// plain NSObject subclass carrying the selectors suffices — no formal
	// protocol adoption needed.
	cls, err := objc.RegisterClass("NetTactCWEventListener", objc.GetClass("NSObject"), nil, nil,
		[]objc.MethodDef{
			{Cmd: objc.RegisterName("ssidDidChangeForWiFiInterfaceWithName:"),
				Fn: func(_ objc.ID, _ objc.SEL, _ objc.ID) { notify(darwinEvChange) }},
			{Cmd: objc.RegisterName("linkDidChangeForWiFiInterfaceWithName:"),
				Fn: func(_ objc.ID, _ objc.SEL, _ objc.ID) { notify(darwinEvChange) }},
			{Cmd: objc.RegisterName("clientConnectionInterrupted"),
				Fn: func(_ objc.ID, _ objc.SEL) { notify(darwinEvInvalidated) }},
			{Cmd: objc.RegisterName("clientConnectionInvalidated"),
				Fn: func(_ objc.ID, _ objc.SEL) { notify(darwinEvInvalidated) }},
		})
	if err != nil {
		return
	}
	listener := objc.ID(cls).Send(objc.RegisterName("alloc")).Send(objc.RegisterName("init"))
	if listener == 0 {
		return
	}
	w.listener = listener
	w.monitor(c)
}

// monitor (re)attaches the delegate and subscribes to the SSID and link
// events. Also used after clientConnectionInvalidated, when the XPC connection
// to airportd was rebuilt and the subscriptions may have been lost.
func (w *darwinWiFiWatcher) monitor(c *coreWLANClient) {
	if w.listener == 0 {
		return
	}
	defer func() { _ = recover() }()
	cw := c.cw
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	pool := cw.poolPush()
	defer cw.poolPop(pool)

	cw.shared.Send(objc.RegisterName("setDelegate:"), w.listener)
	start := objc.RegisterName("startMonitoringEventWithType:error:")
	objc.Send[bool](cw.shared, start, int64(cwEventTypeSSIDDidChange), uintptr(0))
	objc.Send[bool](cw.shared, start, int64(cwEventTypeLinkDidChange), uintptr(0))
}

func (w *darwinWiFiWatcher) pump() {
	for ev := range w.events {
		if ev == darwinEvInvalidated {
			w.cache.Reset()
			if c, ok := w.cl.(*coreWLANClient); ok {
				w.monitor(c)
			}
		}
		w.eagerRefresh()
	}
}

// eagerRefresh marks every currently-connected adapter dirty and refreshes the
// claimable ones immediately, so an SSID change lands ~seconds after the event
// instead of on the next 30s tick. Rate-limited leftovers get one timer-driven
// catch-up (connect bursts deliver link + ssid events inside the claim
// window); anything still stale after that is the tick reconcile's job.
func (w *darwinWiFiWatcher) eagerRefresh() {
	ads, err := w.cl.adapters()
	if err != nil {
		return
	}
	stillDirty := false
	for _, a := range ads {
		if !a.PoweredOn || !a.HasChannel {
			continue
		}
		w.cache.NoteConnect(a.Name)
		claim, ok := w.cache.ClaimRefresh(a.Name)
		if !ok {
			stillDirty = true
			continue
		}
		if facts, rok := refreshDarwinAdapter(w.cl, w.cache, a.Name); rok {
			w.cache.ApplyRefresh(claim, facts)
		} else {
			stillDirty = true
		}
	}
	if stillDirty {
		w.armRetry()
	}
}

func (w *darwinWiFiWatcher) armRetry() {
	w.retryMu.Lock()
	defer w.retryMu.Unlock()
	if w.retryArmed {
		return
	}
	w.retryArmed = true
	time.AfterFunc(6*time.Second, func() {
		w.retryMu.Lock()
		w.retryArmed = false
		w.retryMu.Unlock()
		w.eagerRefresh()
	})
}
