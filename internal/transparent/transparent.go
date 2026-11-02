// Package transparent serves connections that the redirect engine steered to
// us from apps that ignore the system proxy. It mirrors the HTTP-proxy path:
// it MITMs HTTPS with the local CA, blocks ad/tracker requests, injects
// cosmetic CSS and the YouTube strip script, and forwards to the real server.
//
// EXPERIMENTAL / UNVERIFIED: this runs only when transparent capture is on,
// which needs WinDivert and real traffic. It compiles and reuses the tested
// filter/cosmetic/youtube/rewrite code, but the transparent socket path itself
// has not been exercised end to end.
package transparent

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	"adnesia/internal/ca"
	"adnesia/internal/cosmetic"
	"adnesia/internal/dialer"
	"adnesia/internal/filter"
	"adnesia/internal/rewrite"
	"adnesia/internal/stats"
	"adnesia/internal/youtube"
)

// LookupFunc resolves a client source port to its original destination.
type LookupFunc func(srcPort uint16) (ip string, port uint16, ok bool)

// Options configures the transparent listener.
type Options struct {
	Addr          string // e.g. "0.0.0.0:8082"
	Lookup        LookupFunc
	Signer        *ca.Signer
	Engine        *filter.Engine
	Cosmetic      *cosmetic.Engine
	InjectGeneric bool
	Stats         *stats.Stats
	Enabled       func() bool
	Bypass        Bypasser // hosts to tunnel through untouched (never intercepted)
	Log           *slog.Logger
}

// Bypasser decides which hosts must not be intercepted (the passthrough list).
type Bypasser interface {
	Match(host string) bool
}

// Server accepts redirected connections.
type Server struct {
	opts Options
	ln   net.Listener
}

// New builds the listener.
func New(opts Options) *Server { return &Server{opts: opts} }

// Start begins accepting. Run it in a goroutine.
func (s *Server) Start() error {
	ln, err := net.Listen("tcp", s.opts.Addr)
	if err != nil {
		return err
	}
	s.ln = ln
	s.opts.Log.Info("transparent listener up (EXPERIMENTAL)", "addr", s.opts.Addr)
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go s.handle(conn)
	}
}

// Stop closes the listener.
func (s *Server) Stop() {
	if s.ln != nil {
		_ = s.ln.Close()
	}
}

func (s *Server) handle(conn net.Conn) {
	defer conn.Close()

	rport, err := portOf(conn.RemoteAddr())
	if err != nil {
		return
	}
	ip, oport, ok := s.opts.Lookup(rport)
	if !ok {
		return
	}

	if oport == 443 {
		// Learn the hostname from the TLS handshake before deciding anything:
		// hosts on the passthrough list (Discord, Steam, banks, ...) are
		// tunneled through byte-for-byte, exactly as the proxy path does.
		pc, sni := peekSNI(conn)
		if sni != "" && s.opts.Bypass != nil && s.opts.Bypass.Match(sni) {
			s.tunnel(pc, net.JoinHostPort(ip, "443"))
			return
		}
		s.serveTLS(pc, ip)
		return
	}
	s.serveHTTP(conn, "http", "", net.JoinHostPort(ip, fmt.Sprint(oport)), "")
}

func (s *Server) serveTLS(conn net.Conn, ip string) {
	tlsConn := tls.Server(conn, &tls.Config{
		GetCertificate: s.opts.Signer.GetCertificate,
		MinVersion:     tls.VersionTLS12,
	})
	if err := tlsConn.Handshake(); err != nil {
		s.opts.Log.Debug("transparent TLS handshake", "ip", ip, "err", err)
		return
	}
	host := tlsConn.ConnectionState().ServerName
	if host == "" {
		host = ip
	}
	s.serveHTTP(tlsConn, "https", host, net.JoinHostPort(ip, "443"), host)
}

// serveHTTP runs the request/response loop over rw. scheme is http/https; host
// is the public host (SNI) used for filtering and the Host header; dialAddr is
// the real server's ip:port; serverName drives upstream TLS verification.
func (s *Server) serveHTTP(rw net.Conn, scheme, host, dialAddr, serverName string) {
	tr := upstreamTransport(dialAddr, serverName, scheme == "https")
	defer tr.CloseIdleConnections()

	br := bufio.NewReader(rw)
	for {
		_ = rw.SetReadDeadline(time.Now().Add(90 * time.Second))
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		h := host
		if h == "" {
			h = req.Host
		}
		keepAlive := s.handleRequest(rw, br, req, scheme, h, dialAddr, serverName, tr)
		if !keepAlive {
			return
		}
	}
}

// handleRequest processes one request; returns whether the connection may be
// reused for another.
func (s *Server) handleRequest(rw net.Conn, br *bufio.Reader, req *http.Request, scheme, host, dialAddr, serverName string, tr *http.Transport) bool {
	defer func() {
		if req.Body != nil {
			_ = req.Body.Close()
		}
	}()

	filtering := s.opts.Enabled == nil || s.opts.Enabled()
	if s.opts.Bypass != nil && s.opts.Bypass.Match(host) {
		filtering = false // passthrough host: relay, never filter or modify
	}
	fullURL := scheme + "://" + host + req.URL.RequestURI()

	// WebSocket and other upgrades can't be proxied request-by-request;
	// splice the connection straight through to the server instead.
	if isUpgrade(req) {
		s.splice(rw, br, req, scheme, dialAddr, serverName)
		return false
	}

	if filtering && s.opts.Engine != nil {
		fr := filter.NewRequest(fullURL, host, docDomain(req), typeHint(req))
		if blocked, cat := s.opts.Engine.Match(fr); blocked {
			if s.opts.Stats != nil {
				s.opts.Stats.RecordBlocked(cat, host, fullURL)
			}
			return writeSimple(rw, req, http.StatusForbidden)
		}
		if s.opts.Stats != nil {
			s.opts.Stats.RecordAllowed()
		}
	}

	// Forward to the real server.
	req.URL.Scheme = scheme
	req.URL.Host = host
	req.RequestURI = ""
	resp, err := tr.RoundTrip(req)
	if err != nil {
		return writeSimple(rw, req, http.StatusBadGateway)
	}
	defer resp.Body.Close()

	if filtering {
		s.applyResponseFilters(resp, host, req.URL.Path)
	}

	resp.Close = shouldClose(req, resp)
	if err := resp.Write(rw); err != nil {
		return false
	}
	return !resp.Close
}

// applyResponseFilters mirrors the HTTP proxy's response handling.
func (s *Server) applyResponseFilters(resp *http.Response, host, path string) {
	if youtube.IsPlayerAPI(host, path) {
		_, _ = rewrite.TransformJSON(resp, youtube.StripPlayerJSON)
		return
	}
	var inj rewrite.Injection
	if s.opts.Cosmetic != nil {
		inj.CSS = s.opts.Cosmetic.CSSFor(host, s.opts.InjectGeneric)
	}
	if youtube.IsHost(host) {
		inj.JS = append(inj.JS, youtube.Script())
	}
	if !inj.Empty() {
		_, _ = rewrite.IntoHTML(resp, inj)
	}
}

func upstreamTransport(dialAddr, serverName string, isTLS bool) *http.Transport {
	tr := &http.Transport{
		MaxIdleConns:        16,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 15 * time.Second,
	}
	if isTLS {
		tr.DialTLSContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
			raw, err := dialer.DialContext(ctx, "tcp", dialAddr)
			if err != nil {
				return nil, err
			}
			c := tls.Client(raw, &tls.Config{ServerName: serverName}) // verifies upstream
			if err := c.HandshakeContext(ctx); err != nil {
				_ = raw.Close()
				return nil, err
			}
			return c, nil
		}
	} else {
		tr.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, "tcp", dialAddr)
		}
	}
	return tr
}

func writeSimple(rw net.Conn, req *http.Request, status int) bool {
	keep := req.ProtoAtLeast(1, 1) && !req.Close
	resp := &http.Response{
		StatusCode:    status,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        http.Header{},
		Body:          http.NoBody,
		ContentLength: 0,
		Request:       req,
		Close:         !keep,
	}
	_ = resp.Write(rw)
	return keep
}

func shouldClose(req *http.Request, resp *http.Response) bool {
	return req.Close || resp.ProtoMajor != 1 || resp.ProtoMinor != 1
}

func portOf(a net.Addr) (uint16, error) {
	_, portStr, err := net.SplitHostPort(a.String())
	if err != nil {
		return 0, err
	}
	var p uint16
	_, err = fmt.Sscan(portStr, &p)
	return p, err
}

func docDomain(req *http.Request) string {
	ref := req.Header.Get("Referer")
	if ref == "" {
		return ""
	}
	if u, err := req.URL.Parse(ref); err == nil && u.Hostname() != "" {
		return filter.RegisteredDomain(u.Hostname())
	}
	return ""
}

func typeHint(req *http.Request) string {
	switch req.Header.Get("Sec-Fetch-Dest") {
	case "document":
		return "document"
	case "iframe", "frame":
		return "subdocument"
	case "script":
		return "script"
	case "image":
		return "image"
	case "style":
		return "stylesheet"
	case "font":
		return "font"
	case "audio", "video", "track":
		return "media"
	case "empty":
		return "xmlhttprequest"
	case "object", "embed":
		return "object"
	default:
		return ""
	}
}
