package main

import (
	"syscall"

	"golang.org/x/sys/windows"
)

var ctrlCleanup func()

// installConsoleCtrlHandler registers a Windows console control handler so that
// closing the console window, logging off, or shutting down runs cleanup
// (restoring the system proxy) before the process is killed.
//
// This is a best-effort safety net. The primary protection against a dangling
// proxy is the PAC's DIRECT fallback, which works even if cleanup never runs.
func installConsoleCtrlHandler(cleanup func()) {
	ctrlCleanup = cleanup
	proc := windows.NewLazySystemDLL("kernel32.dll").NewProc("SetConsoleCtrlHandler")
	cb := syscall.NewCallback(func(ctrlType uint32) uintptr {
		if ctrlCleanup != nil {
			ctrlCleanup()
		}
		// Return FALSE so the default handler still runs and the process exits.
		return 0
	})
	_, _, _ = proc.Call(cb, 1)
}
