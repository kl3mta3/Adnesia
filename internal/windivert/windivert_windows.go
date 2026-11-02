// Package windivert is a thin wrapper over the official WinDivert user-mode
// library (WinDivert.dll) and its signed kernel driver (WinDivert64.sys).
//
// We deliberately do NOT pull in a third-party Go binding: this package loads
// the official, signed WinDivert.dll at runtime via LazyDLL and calls only the
// handful of functions we need. The kernel driver that actually touches the
// network stack is WinDivert's own signed .sys — we add no unsigned kernel
// code of our own (which modern Windows would refuse to load anyway).
//
// The DLL/driver are not bundled; the user installs them from the official
// WinDivert release. Because the procs resolve lazily, this package compiles
// and links fine without them present — it only fails at the first call.
//
// EXPERIMENTAL / UNVERIFIED: this and the redirect/transparent packages have
// not been exercised against a live driver. They compile and are structured
// correctly, but need real-hardware testing (admin + installed WinDivert +
// real traffic) before being relied on.
package windivert

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Layer selects which WinDivert layer to open.
type Layer int

const (
	LayerNetwork Layer = 0 // WINDIVERT_LAYER_NETWORK
)

// Open flags (subset).
const (
	FlagSniff   = 0x0001
	FlagDrop    = 0x0002
	FlagRecvOnly = 0x0004
	FlagSendOnly = 0x0008
	FlagNoInstall = 0x0010
)

// Checksum helper flags.
const (
	HelperNoIPChecksum  = 1
	HelperNoTCPChecksum = 4
)

const invalidHandle = ^uintptr(0)

var (
	dll          = windows.NewLazyDLL("WinDivert.dll")
	procOpen     = dll.NewProc("WinDivertOpen")
	procRecv     = dll.NewProc("WinDivertRecv")
	procSend     = dll.NewProc("WinDivertSend")
	procClose    = dll.NewProc("WinDivertClose")
	procChecksum = dll.NewProc("WinDivertHelperCalcChecksums")
)

// Address mirrors WINDIVERT_ADDRESS (64 bytes). We treat it as opaque bytes
// and only read/write the few bit flags we need; the rest is passed back to
// the driver untouched on reinjection.
type Address [64]byte

// flags dword lives at offset 8 (little-endian). Bit layout (from offset 8):
// 0-7 Layer, 8-15 Event, 16 Sniffed, 17 Outbound, 18 Loopback, 19 Impostor,
// 20 IPv6, 21 IPChecksum, 22 TCPChecksum, 23 UDPChecksum.
func (a *Address) flagsWord() uint32 {
	return *(*uint32)(unsafe.Pointer(&a[8]))
}
func (a *Address) setFlagsWord(v uint32) {
	*(*uint32)(unsafe.Pointer(&a[8])) = v
}

// Outbound reports whether the packet is outbound.
func (a *Address) Outbound() bool { return a.flagsWord()&(1<<17) != 0 }

// SetOutbound sets or clears the outbound bit (used when re-injecting a packet
// in the opposite direction).
func (a *Address) SetOutbound(v bool) {
	w := a.flagsWord()
	if v {
		w |= 1 << 17
	} else {
		w &^= 1 << 17
	}
	a.setFlagsWord(w)
}

// Handle is an open WinDivert handle.
type Handle struct{ h uintptr }

// Open opens a WinDivert handle for the given filter and layer.
func Open(filter string, layer Layer, priority int16, flags uint64) (*Handle, error) {
	fp, err := windows.BytePtrFromString(filter)
	if err != nil {
		return nil, err
	}
	r, _, callErr := procOpen.Call(
		uintptr(unsafe.Pointer(fp)),
		uintptr(layer),
		uintptr(priority),
		uintptr(flags),
	)
	if r == invalidHandle {
		return nil, fmt.Errorf("WinDivertOpen failed: %w", callErr)
	}
	return &Handle{h: r}, nil
}

// Recv receives one packet into buf, returning the number of bytes and the
// packet's address metadata.
func (h *Handle) Recv(buf []byte) (int, Address, error) {
	var addr Address
	var recvLen uint32
	r, _, callErr := procRecv.Call(
		h.h,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
		uintptr(unsafe.Pointer(&recvLen)),
		uintptr(unsafe.Pointer(&addr[0])),
	)
	if r == 0 {
		return 0, addr, fmt.Errorf("WinDivertRecv failed: %w", callErr)
	}
	return int(recvLen), addr, nil
}

// Send injects one packet described by addr.
func (h *Handle) Send(packet []byte, addr *Address) (int, error) {
	var sentLen uint32
	r, _, callErr := procSend.Call(
		h.h,
		uintptr(unsafe.Pointer(&packet[0])),
		uintptr(len(packet)),
		uintptr(unsafe.Pointer(&sentLen)),
		uintptr(unsafe.Pointer(addr)),
	)
	if r == 0 {
		return 0, fmt.Errorf("WinDivertSend failed: %w", callErr)
	}
	return int(sentLen), nil
}

// Close closes the handle.
func (h *Handle) Close() error {
	r, _, callErr := procClose.Call(h.h)
	if r == 0 {
		return fmt.Errorf("WinDivertClose failed: %w", callErr)
	}
	return nil
}

// CalcChecksums recomputes IP/TCP/UDP checksums for a (possibly modified)
// packet in place.
func CalcChecksums(packet []byte, addr *Address, flags uint64) error {
	r, _, callErr := procChecksum.Call(
		uintptr(unsafe.Pointer(&packet[0])),
		uintptr(len(packet)),
		uintptr(unsafe.Pointer(addr)),
		uintptr(flags),
	)
	if r == 0 {
		return fmt.Errorf("WinDivertHelperCalcChecksums failed: %w", callErr)
	}
	return nil
}

// Available reports whether WinDivert.dll could be loaded (i.e. is installed).
func Available() error {
	return dll.Load()
}
