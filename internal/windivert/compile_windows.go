package windivert

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

var procCompile = dll.NewProc("WinDivertHelperCompileFilter")

// CompileFilter validates a filter string with WinDivert's own compiler. It
// needs the DLL but not the driver or admin rights, so it can run anywhere.
func CompileFilter(filter string, layer Layer) error {
	fp, err := windows.BytePtrFromString(filter)
	if err != nil {
		return err
	}
	var errStr *byte
	var errPos uint32
	r, _, callErr := procCompile.Call(
		uintptr(unsafe.Pointer(fp)), uintptr(layer), 0, 0,
		uintptr(unsafe.Pointer(&errStr)), uintptr(unsafe.Pointer(&errPos)))
	if r == 0 {
		msg := ""
		if errStr != nil {
			msg = windows.BytePtrToString(errStr)
		}
		return fmt.Errorf("invalid filter at position %d: %s (%v)", errPos, msg, callErr)
	}
	return nil
}
