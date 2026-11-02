// Package sysproxy points the Windows system proxy at Adnesia and restores the
// previous setting on shutdown.
//
// Setting the proxy writes the per-user WinINET values (the ones the Settings
// app's "Manual proxy setup" shows) and notifies WinINET so running apps pick
// up the change.
//
// Clearing also deletes the binary connection-settings blob that Chromium and
// Electron apps (Chrome, Discord) read: it can keep stale proxy/PAC flags after
// the plain values are cleared, leaving those apps pointed at a dead proxy.
// Windows regenerates it as a direct connection.
package sysproxy

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const (
	settingsKey    = `Software\Microsoft\Windows\CurrentVersion\Internet Settings`
	connectionsKey = settingsKey + `\Connections`
)

const (
	internetOptionSettingsChanged = 39
	internetOptionRefresh         = 37
)

// Controller sets and restores the system proxy, remembering the prior state.
type Controller struct {
	prevEnable uint32
	prevServer string
	prevValid  bool
}

// Set routes system HTTP/HTTPS traffic through addr (e.g. "127.0.0.1:8080"),
// after capturing the previous settings so Unset can restore them.
func (c *Controller) Set(addr string) error {
	k, err := registry.OpenKey(registry.CURRENT_USER, settingsKey, registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("open internet settings: %w", err)
	}
	defer k.Close()

	// Remember current state for restoration.
	if !c.prevValid {
		if v, _, err := k.GetIntegerValue("ProxyEnable"); err == nil {
			c.prevEnable = uint32(v)
		}
		if v, _, err := k.GetStringValue("ProxyServer"); err == nil {
			c.prevServer = v
		}
		c.prevValid = true
	}

	_ = k.DeleteValue("AutoConfigURL")
	if err := k.SetDWordValue("ProxyEnable", 1); err != nil {
		return fmt.Errorf("set ProxyEnable: %w", err)
	}
	if err := k.SetStringValue("ProxyServer", addr); err != nil {
		return fmt.Errorf("set ProxyServer: %w", err)
	}
	// Let local and intranet addresses bypass the proxy.
	if err := k.SetStringValue("ProxyOverride", "<local>"); err != nil {
		return fmt.Errorf("set ProxyOverride: %w", err)
	}

	return notifyWinINET()
}

// Unset restores the proxy settings captured by Set. If Set was never called,
// or the previous setting was Adnesia's own, it switches to a direct
// connection.
func (c *Controller) Unset() error {
	if c.prevValid && c.prevEnable == 1 && c.prevServer != "" && c.prevServer != "127.0.0.1:8080" {
		k, err := registry.OpenKey(registry.CURRENT_USER, settingsKey, registry.SET_VALUE)
		if err != nil {
			return fmt.Errorf("open internet settings: %w", err)
		}
		defer k.Close()
		if err := k.SetDWordValue("ProxyEnable", 1); err != nil {
			return fmt.Errorf("restore ProxyEnable: %w", err)
		}
		if err := k.SetStringValue("ProxyServer", c.prevServer); err != nil {
			return fmt.Errorf("restore ProxyServer: %w", err)
		}
		return notifyWinINET()
	}
	return Reset()
}

// Reset unconditionally switches to a direct connection: proxy off, no PAC,
// and the stale connection-settings blob removed. Used by -reset-proxy and the
// crash watchdog.
func Reset() error {
	k, err := registry.OpenKey(registry.CURRENT_USER, settingsKey, registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("open internet settings: %w", err)
	}
	defer k.Close()
	if err := k.SetDWordValue("ProxyEnable", 0); err != nil {
		return fmt.Errorf("clear ProxyEnable: %w", err)
	}
	if err := k.DeleteValue("AutoConfigURL"); err != nil && err != registry.ErrNotExist {
		return fmt.Errorf("clear AutoConfigURL: %w", err)
	}
	if ck, err := registry.OpenKey(registry.CURRENT_USER, connectionsKey, registry.SET_VALUE); err == nil {
		_ = ck.DeleteValue("DefaultConnectionSettings")
		_ = ck.DeleteValue("SavedLegacySettings")
		ck.Close()
	}
	return notifyWinINET()
}

// notifyWinINET tells WinINET its settings changed so open handles refresh.
func notifyWinINET() error {
	setOption := windows.NewLazySystemDLL("wininet.dll").NewProc("InternetSetOptionW")
	for _, opt := range []uintptr{internetOptionSettingsChanged, internetOptionRefresh} {
		r, _, err := setOption.Call(0, opt, uintptr(unsafe.Pointer(nil)), 0)
		if r == 0 {
			return fmt.Errorf("InternetSetOption(%d) failed: %w", opt, err)
		}
	}
	return nil
}
