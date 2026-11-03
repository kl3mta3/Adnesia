package web

import (
	"context"
	"io"
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"

	"adnesia/internal/bypass"
	"adnesia/internal/stats"
	"adnesia/internal/update"
)

type fakeController struct {
	on   bool
	feat map[string]bool
}

func (f *fakeController) Enabled() bool     { return f.on }
func (f *fakeController) SetEnabled(v bool) { f.on = v }
func (f *fakeController) Features() map[string]bool {
	if f.feat == nil {
		f.feat = map[string]bool{"ad_blocking": true}
	}
	return f.feat
}
func (f *fakeController) SetFeature(name string, on bool) bool {
	if f.feat == nil {
		f.feat = map[string]bool{}
	}
	f.feat[name] = on
	return true
}
func (f *fakeController) TransparentStatus() string { return "off" }
func (f *fakeController) CATrusted() bool           { return true }

func newTestServer(t *testing.T) *Server {
	t.Helper()
	bp, err := bypass.NewManager(t.TempDir(), nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	return New(Options{
		Addr:       "127.0.0.1:0",
		Controller: &fakeController{on: true},
		Stats:      stats.New(10),
		Bypass:     bp,
		ProxyAddr:  "127.0.0.1:8080",
		Log:        slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
}

func TestPACServed(t *testing.T) {
	s := newTestServer(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/proxy.pac", nil)
	s.http.Handler.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "return \"PROXY 127.0.0.1:8080\"") {
		t.Errorf("PAC missing proxy directive:\n%s", body)
	}
	if strings.Contains(body, "; DIRECT") {
		t.Errorf("PAC should NOT have a per-request DIRECT fallback (it leaks):\n%s", body)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/x-ns-proxy-autoconfig" {
		t.Errorf("content-type = %q", ct)
	}
}

func TestToggleRoute(t *testing.T) {
	s := newTestServer(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/toggle", nil)
	s.http.Handler.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("toggle status = %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"enabled":false`) {
		t.Errorf("toggle should have flipped to disabled, got %s", rec.Body.String())
	}
}

func TestStatsClearRoute(t *testing.T) {
	s := newTestServer(t)
	s.opts.Stats.RecordBlocked(0, "ads.example", "https://ads.example/x.js")
	if n := len(s.opts.Stats.Snapshot().Recent); n != 1 {
		t.Fatalf("want 1 recent entry before clear, got %d", n)
	}

	rec := httptest.NewRecorder()
	s.http.Handler.ServeHTTP(rec, httptest.NewRequest("GET", "/api/stats/clear", nil))
	if rec.Code != 405 {
		t.Fatalf("GET clear status = %d, want 405", rec.Code)
	}

	rec = httptest.NewRecorder()
	s.http.Handler.ServeHTTP(rec, httptest.NewRequest("POST", "/api/stats/clear", nil))
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"cleared":true`) {
		t.Fatalf("POST clear: %d %s", rec.Code, rec.Body.String())
	}
	snap := s.opts.Stats.Snapshot()
	if len(snap.Recent) != 0 {
		t.Errorf("recent should be empty after clear, got %d", len(snap.Recent))
	}
	if snap.Blocked != 1 {
		t.Errorf("counters must survive a clear, blocked = %d", snap.Blocked)
	}
}

type fakeUpdater struct{ st update.Status }

func (f *fakeUpdater) Status() update.Status { return f.st }
func (f *fakeUpdater) Check(context.Context) update.Status {
	f.st.Latest, f.st.URL, f.st.Available = "1.0.0", "https://example/rel", true
	return f.st
}

func TestUpdateRoutes(t *testing.T) {
	s := newTestServer(t)
	rec := httptest.NewRecorder()
	s.http.Handler.ServeHTTP(rec, httptest.NewRequest("GET", "/api/update", nil))
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"available":false`) {
		t.Fatalf("no updater: %d %s", rec.Code, rec.Body.String())
	}

	s.opts.Updater = &fakeUpdater{st: update.Status{Current: "0.9.0"}}
	s.opts.Version = "0.9.0"
	rec = httptest.NewRecorder()
	s.http.Handler.ServeHTTP(rec, httptest.NewRequest("GET", "/api/update/check", nil))
	if rec.Code != 405 {
		t.Fatalf("GET check status = %d, want 405", rec.Code)
	}
	rec = httptest.NewRecorder()
	s.http.Handler.ServeHTTP(rec, httptest.NewRequest("POST", "/api/update/check", nil))
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"latest":"1.0.0"`) || !strings.Contains(rec.Body.String(), `"available":true`) {
		t.Fatalf("POST check: %d %s", rec.Code, rec.Body.String())
	}
	rec = httptest.NewRecorder()
	s.http.Handler.ServeHTTP(rec, httptest.NewRequest("GET", "/api/status", nil))
	if !strings.Contains(rec.Body.String(), `"version":"0.9.0"`) {
		t.Errorf("status should carry the version: %s", rec.Body.String())
	}
}
