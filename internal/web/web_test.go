package web

import (
	"io"
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"

	"adnesia/internal/bypass"
	"adnesia/internal/stats"
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
func (f *fakeController) CATrusted() bool          { return true }

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
