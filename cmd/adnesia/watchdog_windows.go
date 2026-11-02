package main

import (
	"golang.org/x/sys/windows"

	"adnesia/internal/sysproxy"
)

// runWatchdog waits for the given PID to exit, then clears Adnesia's
// system-proxy settings. It is launched as a detached helper process so that
// if the main process crashes (and so can't clean up after itself), the
// browser is never left pointed at a dead proxy — the internet self-heals.
func runWatchdog(pid int) {
	h, err := windows.OpenProcess(windows.SYNCHRONIZE, false, uint32(pid))
	if err != nil {
		// The process is already gone; just reset and exit.
		_ = sysproxy.Reset()
		return
	}
	defer windows.CloseHandle(h)

	_, _ = windows.WaitForSingleObject(h, windows.INFINITE)
	_ = sysproxy.Reset()
}
