package transparent

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"adnesia/internal/dialer"
)

// tunnel relays client <-> dialAddr as raw bytes, with no interception. Used
// for passthrough hosts, so a pinned or WebSocket-based app behaves exactly as
// if Adnesia weren't there.
func (s *Server) tunnel(client net.Conn, dialAddr string) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	up, err := dialer.DialContext(ctx, "tcp", dialAddr)
	cancel()
	if err != nil {
		s.opts.Log.Debug("tunnel dial", "addr", dialAddr, "err", err)
		return
	}
	defer up.Close()
	pipe(client, up)
}

// splice forwards an already-read Upgrade request (e.g. WebSocket) to the
// server and then relays both directions raw. br may hold bytes the client
// sent after the request headers, so it — not the bare conn — is copied.
func (s *Server) splice(client net.Conn, br *bufio.Reader, req *http.Request, scheme, dialAddr, serverName string) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	raw, err := dialer.DialContext(ctx, "tcp", dialAddr)
	if err != nil {
		writeSimple(client, req, http.StatusBadGateway)
		return
	}
	var up net.Conn = raw
	if scheme == "https" {
		tc := tls.Client(raw, &tls.Config{ServerName: serverName}) // verifies upstream
		if err := tc.HandshakeContext(ctx); err != nil {
			_ = raw.Close()
			writeSimple(client, req, http.StatusBadGateway)
			return
		}
		up = tc
	}
	defer up.Close()

	_ = client.SetReadDeadline(time.Time{}) // long-lived connection
	if err := req.Write(up); err != nil {
		return
	}
	pipeReader(client, br, up)
}

// pipe copies both directions until one side closes.
func pipe(a, b net.Conn) {
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(b, a); done <- struct{}{} }()
	go func() { _, _ = io.Copy(a, b); done <- struct{}{} }()
	<-done
}

// pipeReader is pipe, but reads the client side through an existing buffered
// reader so nothing already buffered is lost.
func pipeReader(client net.Conn, clientR io.Reader, up net.Conn) {
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(up, clientR); done <- struct{}{} }()
	go func() { _, _ = io.Copy(client, up); done <- struct{}{} }()
	<-done
}

// isUpgrade reports whether the request asks to switch protocols.
func isUpgrade(req *http.Request) bool {
	if req.Header.Get("Upgrade") == "" {
		return false
	}
	for _, v := range req.Header.Values("Connection") {
		for _, tok := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(tok), "upgrade") {
				return true
			}
		}
	}
	return false
}
