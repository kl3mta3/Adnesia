// Package dialer opens Adnesia's own outbound connections from a reserved
// local port range.
//
// In transparent-capture mode the WinDivert redirector grabs every outbound
// connection to :80/:443 — which would include the connections Adnesia itself
// makes to real servers, looping them back into the proxy. Binding our own
// connections to a known source-port range lets the redirector's packet
// filter skip exactly those, with no process tracking needed.
package dialer

import (
	"context"
	"errors"
	"math/rand"
	"net"
	"strings"
	"syscall"
	"time"
)

// PortMin and PortMax bound the reserved source-port range. The range is
// large enough that TIME_WAIT churn on a busy machine won't exhaust it.
const (
	PortMin = 40000
	PortMax = 44999
)

const attempts = 32

// DialContext dials like net.Dialer.DialContext but binds the local side to a
// free port in [PortMin, PortMax].
func DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	var lastErr error
	for i := 0; i < attempts; i++ {
		port := PortMin + rand.Intn(PortMax-PortMin+1)
		d := net.Dialer{Timeout: 30 * time.Second, LocalAddr: &net.TCPAddr{Port: port}}
		c, err := d.DialContext(ctx, network, addr)
		if err == nil {
			return c, nil
		}
		lastErr = err
		if !addrInUse(err) {
			return nil, err
		}
	}
	return nil, errors.New("dialer: no free local port in reserved range: " + lastErr.Error())
}

func addrInUse(err error) bool {
	if errors.Is(err, syscall.EADDRINUSE) {
		return true
	}
	s := err.Error()
	return strings.Contains(s, "address already in use") ||
		strings.Contains(s, "Only one usage of each socket address")
}
