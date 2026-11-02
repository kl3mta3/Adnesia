// Package tray shows Adnesia's system-tray icon and menu.
//
// systray.Run owns the thread it is called on and blocks until Quit, so the
// caller runs it from main. The core (proxy, dashboard, system proxy) is
// started in onReady via Handlers.OnStart and torn down in onExit via
// Handlers.OnStop, keeping all GUI concerns in this package.
package tray

import (
	"log/slog"

	"fyne.io/systray"
)

// Handlers wire the tray menu to the rest of the app.
type Handlers struct {
	OnStart       func() error // start the core; returning an error quits
	OnStop        func()       // tear the core down
	Enabled       func() bool  // current filtering state
	SetEnabled    func(bool)   // toggle filtering
	OpenDashboard func()       // open the dashboard in a browser
	Log           *slog.Logger
}

// Run shows the tray and blocks until the user quits. It must be called from
// the program's main goroutine.
func Run(h Handlers) {
	systray.Run(func() { onReady(h) }, func() {
		if h.OnStop != nil {
			h.OnStop()
		}
	})
}

func onReady(h Handlers) {
	if h.OnStart != nil {
		if err := h.OnStart(); err != nil {
			h.Log.Error("startup failed", "err", err)
			systray.Quit()
			return
		}
	}

	systray.SetIcon(iconICO())
	systray.SetTitle("Adnesia")
	systray.SetTooltip("Adnesia — ad blocker")

	mToggle := systray.AddMenuItemCheckbox("Blocking enabled", "Turn filtering on or off", h.Enabled())
	mOpen := systray.AddMenuItem("Open dashboard", "Open the Adnesia dashboard")
	systray.AddSeparator()
	mQuit := systray.AddMenuItem("Quit Adnesia", "Stop Adnesia and restore the system proxy")

	go func() {
		for {
			select {
			case <-mToggle.ClickedCh:
				h.SetEnabled(!h.Enabled())
				if h.Enabled() {
					mToggle.Check()
				} else {
					mToggle.Uncheck()
				}
			case <-mOpen.ClickedCh:
				if h.OpenDashboard != nil {
					h.OpenDashboard()
				}
			case <-mQuit.ClickedCh:
				systray.Quit()
				return
			}
		}
	}()
}
