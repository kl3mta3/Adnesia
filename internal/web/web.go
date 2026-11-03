// Package web serves Adnesia's local control dashboard: a small single-page
// UI plus a JSON API for status, live block stats, the on/off switch, and
// passthrough-list management.
//
// It listens on a loopback address only. Because localhost bypasses the
// system proxy (ProxyOverride "<local>"), the dashboard is always reachable
// directly and is never itself intercepted or exposed to the network.
package web

import (
	"context"
	"embed"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"adnesia/internal/bypass"
	"adnesia/internal/stats"
	"adnesia/internal/update"
)

//go:embed static/*
var staticFS embed.FS

// Controller is what the dashboard drives: the master switch plus the
// per-feature toggles.
type Controller interface {
	Enabled() bool
	SetEnabled(bool)
	Features() map[string]bool            // feature name -> on/off
	SetFeature(name string, on bool) bool // returns false for an unknown name
	TransparentStatus() string            // short state for the experimental toggle
	CATrusted() bool                      // whether Windows trusts Adnesia's CA
}

// Options configures the dashboard server.
type Options struct {
	Addr          string
	Controller    Controller
	Stats         *stats.Stats
	Bypass        *bypass.Manager
	NetworkRules  int
	CosmeticRules int
	ProxyAddr     string
	Build         string  // build stamp, so the dashboard shows which copy is running
	Version       string  // release version shown beside the build stamp
	Updater       Updater // optional: GitHub release check
	Log           *slog.Logger
}

// Updater reports and triggers the release check (see internal/update).
type Updater interface {
	Status() update.Status
	Check(ctx context.Context) update.Status
}

// Server is the dashboard HTTP server.
type Server struct {
	opts Options
	http *http.Server
}

// New builds the dashboard server.
func New(opts Options) *Server {
	s := &Server{opts: opts}
	mux := http.NewServeMux()
	mux.Handle("/static/", http.FileServer(http.FS(staticFS)))
	mux.HandleFunc("/", s.handleRoot)
	mux.HandleFunc("/proxy.pac", s.handlePAC)
	mux.HandleFunc("/api/status", s.handleStatus)
	mux.HandleFunc("/api/stats", s.handleStats)
	mux.HandleFunc("/api/stats/clear", s.handleStatsClear)
	mux.HandleFunc("/api/update", s.handleUpdate)
	mux.HandleFunc("/api/update/check", s.handleUpdateCheck)
	mux.HandleFunc("/api/toggle", s.handleToggle)
	mux.HandleFunc("/api/feature", s.handleFeature)
	mux.HandleFunc("/api/bypass", s.handleBypass)
	mux.HandleFunc("/api/bypass/add", s.handleBypassAdd)
	mux.HandleFunc("/api/bypass/remove", s.handleBypassRemove)
	s.http = &http.Server{Addr: opts.Addr, Handler: mux}
	return s
}

// Start serves until Stop; run it in a goroutine.
func (s *Server) Start() error {
	s.opts.Log.Info("dashboard listening", "url", "http://"+s.opts.Addr)
	return s.http.ListenAndServe()
}

// Stop shuts the dashboard down.
func (s *Server) Stop(ctx context.Context) error {
	if s.http == nil {
		return nil
	}
	return s.http.Shutdown(ctx)
}

func (s *Server) handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	data, err := staticFS.ReadFile("static/index.html")
	if err != nil {
		http.Error(w, "dashboard asset missing", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(data)
}

// handlePAC serves the proxy auto-config script. It routes ALL non-local
// traffic through Adnesia with NO per-request "; DIRECT" fallback — that
// fallback let the browser quietly bypass the proxy for some requests, which
// leaked ads. Crash recovery instead comes from the PAC itself becoming
// unreachable: if Adnesia dies, this server dies with it, the browser can no
// longer fetch the PAC, and it fails open to a direct connection. The no-store
// header keeps the browser re-checking so that recovery is prompt.
func (s *Server) handlePAC(w http.ResponseWriter, r *http.Request) {
	pac := "function FindProxyForURL(url, host) {\n" +
		"  if (host == \"127.0.0.1\" || host == \"localhost\" || isPlainHostName(host)) return \"DIRECT\";\n" +
		"  return \"PROXY " + s.opts.ProxyAddr + "\";\n" +
		"}\n"
	w.Header().Set("Content-Type", "application/x-ns-proxy-autoconfig")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(pac))
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{
		"enabled":            s.opts.Controller.Enabled(),
		"features":           s.opts.Controller.Features(),
		"transparent_status": s.opts.Controller.TransparentStatus(),
		"ca_trusted":         s.opts.Controller.CATrusted(),
		"build":              s.opts.Build,
		"version":            s.opts.Version,
		"proxy_addr":         s.opts.ProxyAddr,
		"network_rules":      s.opts.NetworkRules,
		"cosmetic_rules":     s.opts.CosmeticRules,
	})
}

func (s *Server) handleFeature(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		Name string `json:"name"`
		On   bool   `json:"on"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024)).Decode(&body); err != nil || body.Name == "" {
		http.Error(w, "expected JSON {\"name\":\"...\",\"on\":true}", http.StatusBadRequest)
		return
	}
	if !s.opts.Controller.SetFeature(body.Name, body.On) {
		http.Error(w, "unknown feature", http.StatusBadRequest)
		return
	}
	writeJSON(w, map[string]any{"features": s.opts.Controller.Features()})
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.opts.Stats.Snapshot())
}

func (s *Server) handleStatsClear(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	s.opts.Stats.ClearRecent()
	writeJSON(w, map[string]any{"cleared": true})
}

func (s *Server) handleToggle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	s.opts.Controller.SetEnabled(!s.opts.Controller.Enabled())
	s.opts.Log.Info("filtering toggled", "enabled", s.opts.Controller.Enabled())
	writeJSON(w, map[string]any{"enabled": s.opts.Controller.Enabled()})
}

func (s *Server) handleBypass(w http.ResponseWriter, r *http.Request) {
	defaults, user, added := s.opts.Bypass.Lists()
	writeJSON(w, map[string]any{"defaults": defaults, "user": user, "added": added})
}

func (s *Server) handleBypassAdd(w http.ResponseWriter, r *http.Request) {
	pattern, ok := readPattern(w, r)
	if !ok {
		return
	}
	if err := s.opts.Bypass.Add(pattern); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]any{"ok": true})
}

func (s *Server) handleBypassRemove(w http.ResponseWriter, r *http.Request) {
	pattern, ok := readPattern(w, r)
	if !ok {
		return
	}
	removed, err := s.opts.Bypass.Remove(pattern)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]any{"removed": removed})
}

func readPattern(w http.ResponseWriter, r *http.Request) (string, bool) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return "", false
	}
	var body struct {
		Pattern string `json:"pattern"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body); err != nil || body.Pattern == "" {
		http.Error(w, "expected JSON {\"pattern\":\"...\"}", http.StatusBadRequest)
		return "", false
	}
	return body.Pattern, true
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

// handleUpdate reports the last release-check result.
func (s *Server) handleUpdate(w http.ResponseWriter, r *http.Request) {
	if s.opts.Updater == nil {
		writeJSON(w, update.Status{Current: s.opts.Version})
		return
	}
	writeJSON(w, s.opts.Updater.Status())
}

// handleUpdateCheck runs a release check now (the dashboard's button).
func (s *Server) handleUpdateCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	if s.opts.Updater == nil {
		writeJSON(w, update.Status{Current: s.opts.Version})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
	defer cancel()
	writeJSON(w, s.opts.Updater.Check(ctx))
}
