// Package proxy runs Adnesia's local MITM HTTP/HTTPS proxy.
//
// In Phase 1 the proxy performs TLS interception for every host except those
// on the bypass list (which are tunneled through untouched), but does not yet
// filter anything — it simply proves the interception path works end to end.
// Phases 2–4 attach request/response hooks here to block ad requests and
// rewrite page content.
package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync/atomic"

	"github.com/elazarl/goproxy"

	"adnesia/internal/cosmetic"
	"adnesia/internal/dialer"
	"adnesia/internal/filter"
	"adnesia/internal/rewrite"
	"adnesia/internal/stats"
	"adnesia/internal/youtube"
)

// Bypasser decides which hosts are tunneled through without interception.
// Both bypass.Matcher and bypass.Manager satisfy it.
type Bypasser interface {
	Match(host string) bool
}

// Options configures a Proxy.
type Options struct {
	Addr          string
	CACert        tls.Certificate
	Bypass        Bypasser
	Engine        *filter.Engine
	Cosmetic      *cosmetic.Engine
	Stats         *stats.Stats
	InjectGeneric bool // include generic (site-agnostic) cosmetic selectors
	Log           *slog.Logger
}

// Proxy wraps a goproxy server configured with Adnesia's local CA.
type Proxy struct {
	addr          string
	server        *goproxy.ProxyHttpServer
	http          *http.Server
	bypass        Bypasser
	engine        *filter.Engine
	cosmetic      *cosmetic.Engine
	injectGeneric atomic.Bool
	stats         *stats.Stats
	enabled       atomic.Bool
	ghost         atomic.Bool
	log           *slog.Logger
}

// New builds a proxy from opts: it signs intercepted hosts with opts.CACert,
// tunnels hosts matched by opts.Bypass, blocks requests matched by opts.Engine,
// and injects opts.Cosmetic's hiding CSS into HTML responses.
func New(opts Options) (*Proxy, error) {
	addr := opts.Addr
	caCert := opts.CACert
	bypassMatcher := opts.Bypass
	engine := opts.Engine
	st := opts.Stats
	log := opts.Log
	// Ensure the CA's parsed leaf is available for the signer.
	if caCert.Leaf == nil {
		leaf, err := x509.ParseCertificate(caCert.Certificate[0])
		if err != nil {
			return nil, err
		}
		caCert.Leaf = leaf
	}

	// Point goproxy's on-the-fly certificate signer at our CA. These package
	// level actions are what goproxy uses when it decides to intercept.
	setCA(caCert)

	gp := goproxy.NewProxyHttpServer()
	gp.Logger = slogAdapter{log}

	// Verify the real server's certificate when we intercept. This is a
	// security requirement: if an upstream site has a genuinely invalid
	// certificate, the request must fail rather than us minting a locally
	// trusted cert and hiding the problem from the browser. Also never chain
	// through a system proxy, which could loop back into us.
	if gp.Tr == nil {
		gp.Tr = &http.Transport{}
	}
	gp.Tr.Proxy = nil
	if gp.Tr.TLSClientConfig == nil {
		gp.Tr.TLSClientConfig = &tls.Config{}
	}
	gp.Tr.TLSClientConfig.InsecureSkipVerify = false
	// Dial upstream from the reserved port range so transparent capture can
	// recognise and skip our own connections (see package dialer).
	gp.Tr.DialContext = dialer.DialContext

	p := &Proxy{
		addr:          addr,
		server:        gp,
		bypass:   bypassMatcher,
		engine:   engine,
		cosmetic: opts.Cosmetic,
		stats:    st,
		log:      log,
	}
	p.enabled.Store(true)
	p.injectGeneric.Store(opts.InjectGeneric)

	// Decide per CONNECT whether to intercept (MITM) or tunnel (bypass).
	gp.OnRequest().HandleConnectFunc(func(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
		if p.bypass.Match(host) {
			log.Debug("tunnel (bypass)", "host", host)
			return goproxy.OkConnect, host
		}
		return goproxy.MitmConnect, host
	})

	// Filter every (plain or intercepted) request against the block lists.
	gp.OnRequest().DoFunc(p.filterRequest)

	// Inject cosmetic-hiding CSS into HTML responses.
	gp.OnResponse().DoFunc(p.injectResponse)

	return p, nil
}

// injectResponse strips YouTube player ads and injects cosmetic-hiding CSS.
func (p *Proxy) injectResponse(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
	if resp == nil || !p.enabled.Load() || ctx.Req == nil {
		return resp
	}
	host := ctx.Req.URL.Hostname()
	path := ctx.Req.URL.Path

	// YouTube player API: strip ad fields from the JSON response.
	if youtube.IsPlayerAPI(host, path) {
		if changed, err := rewrite.TransformJSON(resp, youtube.StripPlayerJSON); err != nil {
			p.log.Debug("youtube json strip failed", "err", err)
		} else if changed {
			p.log.Debug("youtube player ads stripped", "host", host)
		}
		return resp
	}

	// HTML: cosmetic CSS (gated by Ad Blocking / Annoyances) plus the YouTube
	// strip script on YT pages (gated by Ad Blocking).
	cosmeticsOn := p.engine == nil || p.engine.CategoryEnabled(filter.CatAds) || p.engine.CategoryEnabled(filter.CatAnnoyances)
	adsOn := p.engine == nil || p.engine.CategoryEnabled(filter.CatAds)

	var inj rewrite.Injection
	if p.cosmetic != nil && cosmeticsOn {
		inj.CSS = p.cosmetic.CSSFor(host, p.injectGeneric.Load())
	}
	if adsOn && youtube.IsHost(host) {
		inj.JS = append(inj.JS, youtube.Script())
	}
	if inj.Empty() {
		return resp
	}
	if _, err := rewrite.IntoHTML(resp, inj); err != nil {
		p.log.Debug("html inject failed", "host", host, "err", err)
	}
	return resp
}

// SetEnabled turns filtering on or off at runtime (the tray kill switch).
// When off, requests pass through unfiltered.
func (p *Proxy) SetEnabled(on bool) { p.enabled.Store(on) }

// Enabled reports whether filtering is currently active.
func (p *Proxy) Enabled() bool { return p.enabled.Load() }

// SetGhost toggles Ghost Mode (strip Referer, send DNT, drop tracking params).
func (p *Proxy) SetGhost(on bool) { p.ghost.Store(on) }

// Ghost reports whether Ghost Mode is active.
func (p *Proxy) Ghost() bool { return p.ghost.Load() }

// SetCategory enables/disables a filtering category (maps to a dashboard toggle).
func (p *Proxy) SetCategory(cat filter.Category, on bool) {
	if p.engine != nil {
		p.engine.SetCategory(cat, on)
	}
}

// CategoryEnabled reports whether a filtering category is active.
func (p *Proxy) CategoryEnabled(cat filter.Category) bool {
	return p.engine != nil && p.engine.CategoryEnabled(cat)
}

// SetInjectGeneric toggles generic (site-agnostic) cosmetic injection.
func (p *Proxy) SetInjectGeneric(on bool) { p.injectGeneric.Store(on) }

// InjectGeneric reports whether generic cosmetic injection is on.
func (p *Proxy) InjectGeneric() bool { return p.injectGeneric.Load() }

// filterRequest blocks ad/tracker requests. Returning a non-nil response
// short-circuits the request; returning (req, nil) lets it proceed.
func (p *Proxy) filterRequest(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	if !p.enabled.Load() || p.engine == nil {
		return req, nil
	}
	normalizeAcceptEncoding(req.Header)

	host := req.URL.Hostname()
	docDomain := ""
	if ref := req.Header.Get("Referer"); ref != "" {
		if ru, err := req.URL.Parse(ref); err == nil && ru.Hostname() != "" {
			docDomain = filter.RegisteredDomain(ru.Hostname())
		}
	}
	typeHint := secFetchDestToType(req.Header.Get("Sec-Fetch-Dest"))

	fr := filter.NewRequest(req.URL.String(), host, docDomain, typeHint)
	if blocked, cat := p.engine.Match(fr); blocked {
		if p.stats != nil {
			p.stats.RecordBlocked(cat, host, req.URL.String())
		}
		p.log.Debug("blocked", "host", host, "cat", cat, "url", req.URL.String())
		ct, body := noopResponse(typeHint)
		status := http.StatusOK
		// Connectivity probes (Chrome's own /generate_204, Google's gen_204
		// beacons, ping/beacon requests) expect exactly "204 No Content"; a
		// 200 can make the browser think it's behind a captive portal.
		if typeHint == "ping" || strings.HasSuffix(req.URL.Path, "_204") {
			status, body = http.StatusNoContent, ""
		}
		resp := goproxy.NewResponse(req, ct, status, body)
		// A cross-origin XHR/fetch is only "successful" to the page if the
		// reply carries CORS headers; without them the browser fails it
		// anyway (ERR_FAILED), and the no-op reply never reaches the page.
		if origin := req.Header.Get("Origin"); origin != "" {
			resp.Header.Set("Access-Control-Allow-Origin", origin)
			resp.Header.Set("Access-Control-Allow-Credentials", "true")
			resp.Header.Set("Vary", "Origin")
		}
		return req, resp
	}
	if p.stats != nil {
		p.stats.RecordAllowed()
	}
	// Ghost Mode: minimize what allowed requests reveal upstream.
	if p.ghost.Load() {
		applyGhost(req)
	}
	return req, nil
}

// normalizeAcceptEncoding drops encodings the proxy cannot decode (zstd and
// shared-dictionary brotli, which Chrome advertises and Google serves) so the
// server answers with gzip/brotli/plain instead. Without this, pages from
// Google properties arrive in an encoding we can't open, and injection
// silently does nothing. Clients that sent no Accept-Encoding are left alone.
func normalizeAcceptEncoding(h http.Header) {
	ae := h.Get("Accept-Encoding")
	if ae == "" {
		return
	}
	var keep []string
	for _, part := range strings.Split(ae, ",") {
		tok := strings.ToLower(strings.TrimSpace(strings.SplitN(part, ";", 2)[0]))
		switch tok {
		case "gzip", "x-gzip", "deflate", "br", "identity":
			keep = append(keep, tok)
		}
	}
	if len(keep) == 0 {
		keep = []string{"identity"}
	}
	h.Set("Accept-Encoding", strings.Join(keep, ", "))
}

// noopGIF is a 1x1 transparent GIF, served in place of blocked images.
const noopGIF = "GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\xff\xff\xff\x21\xf9\x04\x01\x00\x00\x00\x00\x2c\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02\x44\x01\x00\x3b"

// noopResponse picks the empty "no-op" body served for a blocked request,
// by resource type. Blocked requests get a harmless empty 200 rather than an
// error: the ad or tracker still never loads, but the page's own code — which
// often awaits these requests (YouTube's pagead/id is the classic case) — keeps
// running instead of hanging on a failure. This mirrors uBlock/AdGuard's
// "redirect=noop.*" behaviour.
func noopResponse(typeHint string) (contentType, body string) {
	switch typeHint {
	case "script":
		return "application/javascript", ""
	case "stylesheet":
		return "text/css", ""
	case "image":
		return "image/gif", noopGIF
	case "subdocument", "document":
		return "text/html", ""
	case "xmlhttprequest":
		// An empty body makes response.json() throw; "{}" parses cleanly.
		// This is AdGuard's "noopjson" behaviour.
		return "application/json", "{}"
	default:
		return goproxy.ContentTypeText, ""
	}
}

// trackingParams are query parameters Ghost Mode strips from allowed requests.
var trackingParams = []string{
	"utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
	"fbclid", "gclid", "gclsrc", "dclid", "msclkid", "mc_eid", "igshid", "yclid",
}

func applyGhost(req *http.Request) {
	req.Header.Del("Referer")
	req.Header.Set("DNT", "1")
	q := req.URL.Query()
	changed := false
	for _, k := range trackingParams {
		if q.Has(k) {
			q.Del(k)
			changed = true
		}
	}
	if changed {
		req.URL.RawQuery = q.Encode()
	}
}

// secFetchDestToType maps a Sec-Fetch-Dest header value to an ABP resource
// type keyword. An empty/unknown value yields "" (treated as "other").
func secFetchDestToType(dest string) string {
	switch dest {
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

// Handler exposes the underlying proxy as an http.Handler (useful for tests).
func (p *Proxy) Handler() http.Handler { return p.server }

// Start begins serving. It blocks until the server stops; run it in a
// goroutine. Stop triggers a clean shutdown.
func (p *Proxy) Start() error {
	p.http = &http.Server{Addr: p.addr, Handler: p.server}
	p.log.Info("proxy listening", "addr", p.addr)
	return p.http.ListenAndServe()
}

// Stop gracefully shuts the proxy down.
func (p *Proxy) Stop(ctx context.Context) error {
	if p.http == nil {
		return nil
	}
	return p.http.Shutdown(ctx)
}

// setCA installs caCert as the signer for all goproxy interception actions.
func setCA(caCert tls.Certificate) {
	goproxy.GoproxyCa = caCert
	tlsConfig := goproxy.TLSConfigFromCA(&caCert)
	goproxy.OkConnect = &goproxy.ConnectAction{Action: goproxy.ConnectAccept, TLSConfig: tlsConfig}
	goproxy.MitmConnect = &goproxy.ConnectAction{Action: goproxy.ConnectMitm, TLSConfig: tlsConfig}
	goproxy.HTTPMitmConnect = &goproxy.ConnectAction{Action: goproxy.ConnectHTTPMitm, TLSConfig: tlsConfig}
	goproxy.RejectConnect = &goproxy.ConnectAction{Action: goproxy.ConnectReject, TLSConfig: tlsConfig}
}

// slogAdapter lets goproxy's Printf-style logger write through slog.
type slogAdapter struct{ log *slog.Logger }

func (s slogAdapter) Printf(format string, v ...interface{}) {
	s.log.Debug("goproxy", "msg", fmt.Sprintf(format, v...))
}
