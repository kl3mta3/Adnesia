package rewrite

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"strings"
	"testing"
)

func gzipBytes(s string) []byte {
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	_, _ = w.Write([]byte(s))
	_ = w.Close()
	return buf.Bytes()
}

func newResp(contentType, encoding string, body []byte, csp string) *http.Response {
	h := http.Header{}
	h.Set("Content-Type", contentType)
	if encoding != "" {
		h.Set("Content-Encoding", encoding)
	}
	if csp != "" {
		h.Set("Content-Security-Policy", csp)
	}
	return &http.Response{
		StatusCode: 200,
		Header:     h,
		Body:       io.NopCloser(bytes.NewReader(body)),
	}
}

func TestInjectGzipHTML(t *testing.T) {
	html := "<html><head><title>x</title></head><body>hi</body></html>"
	resp := newResp("text/html; charset=utf-8", "gzip", gzipBytes(html),
		"default-src 'self'; style-src 'self'")

	css := ".ad,.promo{display:none!important}"
	modified, err := IntoHTML(resp, Injection{CSS: css})
	if err != nil {
		t.Fatalf("IntoHTML error: %v", err)
	}
	if !modified {
		t.Fatal("expected response to be modified")
	}

	got, _ := io.ReadAll(resp.Body)
	out := string(got)

	if !strings.Contains(out, "<style nonce=\"") || !strings.Contains(out, css) {
		t.Errorf("injected style/css missing:\n%s", out)
	}
	styleIdx := strings.Index(out, "<style")
	headIdx := strings.Index(out, "</head>")
	if styleIdx < 0 || headIdx < 0 || styleIdx > headIdx {
		t.Errorf("style should be inserted before </head> (style=%d head=%d)", styleIdx, headIdx)
	}
	if resp.Header.Get("Content-Encoding") != "" {
		t.Error("Content-Encoding should be dropped after decompression")
	}
	if resp.Header.Get("Content-Length") == "" {
		t.Error("Content-Length should be set")
	}
	if csp := resp.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "nonce-") {
		t.Errorf("CSP should carry the nonce, got %q", csp)
	}
}

// The policy YouTube serves to a signed-in Chrome allows inline scripts via
// 'unsafe-inline' with no nonce. Appending a nonce would disable
// 'unsafe-inline' and block every inline script on the page, so the directive
// must be left exactly as it was.
func TestCSPUnsafeInlineLeftAlone(t *testing.T) {
	policy := "script-src 'unsafe-eval' 'self' 'unsafe-inline' https://a.example https://b.example; style-src 'self' 'unsafe-inline'; object-src 'none'"
	got := addNonceToCSP(policy, "'nonce-OURS'")
	if got != policy {
		t.Errorf("directive with 'unsafe-inline' (no nonce) must not be modified:\n got: %s\nwant: %s", got, policy)
	}
}

// Where the page already uses nonces (so inline is nonce-gated) our nonce must
// be added, or our own injection would be blocked.
func TestCSPNonceAddedWhereNonceGated(t *testing.T) {
	policy := "script-src 'report-sample' 'nonce-abc' 'unsafe-inline' 'strict-dynamic' https: http:; object-src 'none'"
	got := addNonceToCSP(policy, "'nonce-OURS'")
	if !strings.Contains(got, "'nonce-abc'") || !strings.Contains(got, "'nonce-OURS'") {
		t.Errorf("expected both nonces present, got: %s", got)
	}
	// A strict allowlist with no inline at all also needs our nonce.
	got = addNonceToCSP("default-src 'self'", "'nonce-OURS'")
	if !strings.Contains(got, "'nonce-OURS'") {
		t.Errorf("expected nonce added to strict default-src, got: %s", got)
	}
}

func TestNonHTMLUntouched(t *testing.T) {
	body := []byte("not html at all")
	resp := newResp("application/json", "", body, "")
	modified, err := IntoHTML(resp, Injection{CSS: ".x{display:none!important}"})
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if modified {
		t.Fatal("non-HTML response should not be modified")
	}
	got, _ := io.ReadAll(resp.Body)
	if !bytes.Equal(got, body) {
		t.Error("body should be unchanged")
	}
}

func TestEmptyInjectionNoop(t *testing.T) {
	resp := newResp("text/html", "", []byte("<html></html>"), "")
	modified, _ := IntoHTML(resp, Injection{})
	if modified {
		t.Fatal("empty injection should be a no-op")
	}
}
