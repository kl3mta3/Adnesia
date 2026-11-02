// Package autostart manages whether Adnesia launches at user login.
//
// It uses the per-user "Run" registry key, which starts the program in the
// logged-in user's session. This is deliberately NOT a Windows service: the
// system proxy Adnesia sets lives in the per-user hive (HKCU) and the tray
// icon needs an interactive desktop, neither of which a session-0 service
// has. Login auto-start is the correct model for a per-user desktop tool.
package autostart

import (
	"fmt"
	"strings"

	"golang.org/x/sys/windows/registry"
)

const (
	runKey    = `Software\Microsoft\Windows\CurrentVersion\Run`
	valueName = "Adnesia"
)

// command returns the command line stored in the Run value: the quoted exe
// path followed by any extra args.
func command(exePath string, args ...string) string {
	cmd := `"` + exePath + `"`
	if len(args) > 0 {
		cmd += " " + strings.Join(args, " ")
	}
	return cmd
}

// Enable registers Adnesia to start at login with the given arguments.
func Enable(exePath string, args ...string) error {
	k, _, err := registry.CreateKey(registry.CURRENT_USER, runKey, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("open Run key: %w", err)
	}
	defer k.Close()
	if err := k.SetStringValue(valueName, command(exePath, args...)); err != nil {
		return fmt.Errorf("set Run value: %w", err)
	}
	return nil
}

// Disable removes the login auto-start entry. It is not an error if none
// exists.
func Disable() error {
	k, err := registry.OpenKey(registry.CURRENT_USER, runKey, registry.SET_VALUE)
	if err != nil {
		return nil
	}
	defer k.Close()
	err = k.DeleteValue(valueName)
	if err == registry.ErrNotExist {
		return nil
	}
	return err
}

// IsEnabled reports whether the login auto-start entry exists, and its command.
func IsEnabled() (bool, string) {
	k, err := registry.OpenKey(registry.CURRENT_USER, runKey, registry.QUERY_VALUE)
	if err != nil {
		return false, ""
	}
	defer k.Close()
	v, _, err := k.GetStringValue(valueName)
	if err != nil {
		return false, ""
	}
	return true, v
}
