// Package redirect uses WinDivert to steer outbound web traffic from apps that
// ignore the system proxy into Adnesia's transparent listener, then restores
// the return path so the app is none the wiser.
//
// Mechanism (IPv4/TCP only, first cut): we capture outbound TCP to ports 80/443
// and rewrite the destination to this same host on the transparent port, using
// the standard "swap destination to source" loopback trick so the reply routes
// back. We remember each flow by the client's source port and rewrite the
// return packets (from the transparent port) to look like they came from the
// real server. The transparent listener asks us, via Lookup, where a given
// client port was originally headed.
//
// EXPERIMENTAL / UNVERIFIED: this has not been run against a live WinDivert
// driver. It compiles and follows the documented recipe, but packet-level code
// needs real-hardware testing before it can be trusted.
package redirect

import (
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"sync"

	"adnesia/internal/dialer"
	"adnesia/internal/windivert"
)

// dest is a captured flow's original destination.
type dest struct {
	ip   [4]byte
	port uint16
}

// Engine runs the capture/rewrite loop.
type Engine struct {
	proxyPort uint16
	handle    *windivert.Handle
	log       *slog.Logger

	mu    sync.RWMutex
	table map[uint16]dest // keyed by the client's source port

	stop chan struct{}
}

// New returns an Engine that redirects to the transparent listener on
// proxyPort (on this host).
func New(proxyPort uint16, log *slog.Logger) *Engine {
	return &Engine{
		proxyPort: proxyPort,
		log:       log,
		table:     make(map[uint16]dest),
		stop:      make(chan struct{}),
	}
}

// Lookup returns the original destination for a client source port.
func (e *Engine) Lookup(srcPort uint16) (ip string, port uint16, ok bool) {
	e.mu.RLock()
	d, ok := e.table[srcPort]
	e.mu.RUnlock()
	if !ok {
		return "", 0, false
	}
	return net.IP(d.ip[:]).String(), d.port, true
}

// Start opens WinDivert and runs the capture loop until Stop. It returns an
// error immediately if WinDivert is unavailable or the handle cannot open.
func (e *Engine) Start() error {
	if err := windivert.Available(); err != nil {
		return fmt.Errorf("WinDivert not installed: %w", err)
	}
	// Capture web traffic to redirect, and the transparent port's replies to
	// restore — but never Adnesia's own upstream connections, which dial from
	// the reserved source-port range (otherwise they'd loop back into us).
	filter := Filter(e.proxyPort)
	// Validate with WinDivert's own compiler first (user mode, no admin) so a
	// bad filter is reported as such instead of a bare "parameter is incorrect".
	if err := windivert.CompileFilter(filter, windivert.LayerNetwork); err != nil {
		return fmt.Errorf("WinDivert filter rejected: %w", err)
	}
	h, err := windivert.Open(filter, windivert.LayerNetwork, 0, 0)
	if err != nil {
		return err
	}
	e.handle = h
	go e.loop()
	e.log.Warn("transparent capture active (EXPERIMENTAL)", "transparent_port", e.proxyPort)
	return nil
}

// Stop ends the capture loop.
func (e *Engine) Stop() {
	select {
	case <-e.stop:
	default:
		close(e.stop)
	}
	if e.handle != nil {
		_ = e.handle.Close()
	}
}

func (e *Engine) loop() {
	buf := make([]byte, 65535)
	for {
		select {
		case <-e.stop:
			return
		default:
		}
		n, addr, err := e.handle.Recv(buf)
		if err != nil {
			select {
			case <-e.stop:
				return
			default:
				e.log.Debug("windivert recv", "err", err)
				continue
			}
		}
		pkt := buf[:n]
		e.rewrite(pkt, &addr)
		if err := windivert.CalcChecksums(pkt, &addr, 0); err != nil {
			e.log.Debug("checksum", "err", err)
		}
		if _, err := e.handle.Send(pkt, &addr); err != nil {
			e.log.Debug("windivert send", "err", err)
		}
	}
}

// rewrite applies the redirect/restore transformation in place.
func (e *Engine) rewrite(pkt []byte, addr *windivert.Address) {
	if len(pkt) < 20 {
		return
	}
	ihl := int(pkt[0]&0x0f) * 4
	if pkt[9] != 6 || len(pkt) < ihl+20 { // not TCP, or too short
		return
	}
	src := pkt[12:16]
	dst := pkt[16:20]
	tcp := pkt[ihl:]
	srcPort := binary.BigEndian.Uint16(tcp[0:2])
	dstPort := binary.BigEndian.Uint16(tcp[2:4])

	switch {
	case srcPort >= dialer.PortMin && srcPort <= dialer.PortMax:
		// Our own upstream connection: leave it alone.
	case dstPort == 80 || dstPort == 443:
		// Outbound to a real server: remember it, then send to ourselves on
		// the transparent port (dst = src makes it loop back to this host).
		var d dest
		copy(d.ip[:], dst)
		d.port = dstPort
		e.mu.Lock()
		e.table[srcPort] = d
		e.mu.Unlock()

		copy(dst, src)                                    // dst = src (loop back)
		binary.BigEndian.PutUint16(tcp[2:4], e.proxyPort) // dport = transparent port
		addr.SetOutbound(false)                           // now inbound to this host

	case srcPort == e.proxyPort:
		// Return path from the transparent listener to the app: restore the
		// source so the app believes it is talking to the real server.
		e.mu.RLock()
		d, ok := e.table[dstPort]
		e.mu.RUnlock()
		if ok {
			copy(src, d.ip[:])
			binary.BigEndian.PutUint16(tcp[0:2], d.port)
			addr.SetOutbound(true)
		}
	}
}

// Filter returns the WinDivert filter for a transparent listener on proxyPort:
// outbound web traffic to redirect, plus the listener's own replies to restore,
// but never Adnesia's upstream connections, which dial from the reserved
// source-port range (otherwise they'd loop back into us). WinDivert's filter
// language has no "not (a and b)" over compound expressions, so the exclusion
// is written as an open range.
func Filter(proxyPort uint16) string {
	return fmt.Sprintf(
		"ip and tcp and (((tcp.DstPort == 80 or tcp.DstPort == 443) and (tcp.SrcPort < %d or tcp.SrcPort > %d)) or tcp.SrcPort == %d)",
		dialer.PortMin, dialer.PortMax, proxyPort,
	)
}
