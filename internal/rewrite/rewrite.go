// Package rewrite modifies HTML responses in flight so Adnesia can inject a
// cosmetic-hiding stylesheet (Phase 3) and, later, the YouTube ad-stripping
// script (Phase 4).
//
// It decompresses the body (gzip/deflate/brotli), splices the injection in
// just before </head>, and adjusts the headers. To keep any Content-Security-
// Policy from blocking the injected <style>/<script>, it adds a one-off nonce
// to the relevant CSP directives — additively, so nothing already allowed on
// the page is broken.
package rewrite

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"crypto/rand"
	"encoding/base64"
	"io"
	"net/http"
	"strings"

	"github.com/andybalholm/brotli"
)

// maxHTMLBytes caps how large a response we will buffer and rewrite. Larger
// HTML documents are left untouched rather than held entirely in memory.
const maxHTMLBytes = 8 << 20 // 8 MiB

// Injection describes what to insert into an HTML document.
type Injection struct {
	CSS string   // injected inside a <style> element (may be empty)
	JS  []string // each entry injected inside its own <script> element
}

// Empty reports whether there is nothing to inject.
func (in Injection) Empty() bool {
	if in.CSS != "" {
		return false
	}
	for _, j := range in.JS {
		if j != "" {
			return false
		}
	}
	return true
}

// IntoHTML applies in to an HTML response, in place. Non-HTML responses, empty
// injections, oversized bodies and unknown content encodings are left
// untouched. It returns true if the response was modified.
func IntoHTML(resp *http.Response, in Injection) (bool, error) {
	if resp == nil || in.Empty() {
		return false, nil
	}
	if !contentTypeHas(resp, "text/html") {
		return false, nil
	}

	nonce := newNonce()
	snippet := buildSnippet(in, nonce)
	changed, err := rewriteBody(resp, func(body []byte) ([]byte, bool) {
		return spliceIntoHead(body, snippet), true
	})
	if changed {
		patchCSP(resp.Header, nonce)
	}
	return changed, err
}

// TransformJSON rewrites a JSON response body with transform, which returns
// the new bytes and whether it changed anything. Non-JSON responses and
// unchanged bodies are left untouched.
func TransformJSON(resp *http.Response, transform func(body []byte) ([]byte, bool)) (bool, error) {
	if resp == nil || !contentTypeHas(resp, "json") {
		return false, nil
	}
	return rewriteBody(resp, transform)
}

func contentTypeHas(resp *http.Response, needle string) bool {
	return strings.Contains(strings.ToLower(resp.Header.Get("Content-Type")), needle)
}

// rewriteBody reads and decodes resp's body, runs transform, and — only if
// transform reports a change — writes the decoded+transformed bytes back,
// dropping Content-Encoding and fixing Content-Length. Oversized bodies and
// unknown encodings are left untouched.
func rewriteBody(resp *http.Response, transform func(body []byte) ([]byte, bool)) (bool, error) {
	if resp == nil || resp.Body == nil {
		return false, nil
	}
	enc := strings.ToLower(strings.TrimSpace(resp.Header.Get("Content-Encoding")))
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxHTMLBytes+1))
	resp.Body.Close()
	if err != nil {
		return false, err
	}
	if len(raw) > maxHTMLBytes {
		resp.Body = io.NopCloser(bytes.NewReader(raw))
		return false, nil
	}

	body, err := decode(raw, enc)
	if err != nil {
		// Unknown/failed encoding: do not risk corrupting it.
		resp.Body = io.NopCloser(bytes.NewReader(raw))
		return false, nil
	}

	out, changed := transform(body)
	if !changed {
		// Restore the original (still-encoded) bytes untouched.
		resp.Body = io.NopCloser(bytes.NewReader(raw))
		return false, nil
	}

	resp.Header.Del("Content-Encoding")
	resp.Body = io.NopCloser(bytes.NewReader(out))
	resp.ContentLength = int64(len(out))
	resp.Header.Set("Content-Length", itoa(len(out)))
	return true, nil
}

func decode(raw []byte, enc string) ([]byte, error) {
	switch enc {
	case "", "identity":
		return raw, nil
	case "gzip", "x-gzip":
		r, err := gzip.NewReader(bytes.NewReader(raw))
		if err != nil {
			return nil, err
		}
		defer r.Close()
		return io.ReadAll(r)
	case "deflate":
		r := flate.NewReader(bytes.NewReader(raw))
		defer r.Close()
		return io.ReadAll(r)
	case "br":
		return io.ReadAll(brotli.NewReader(bytes.NewReader(raw)))
	default:
		return nil, errUnsupportedEncoding
	}
}

var errUnsupportedEncoding = &encError{}

type encError struct{}

func (*encError) Error() string { return "unsupported content-encoding" }

func buildSnippet(in Injection, nonce string) []byte {
	var b strings.Builder
	if in.CSS != "" {
		b.WriteString(`<style nonce="`)
		b.WriteString(nonce)
		b.WriteString(`">`)
		b.WriteString(in.CSS)
		b.WriteString(`</style>`)
	}
	for _, js := range in.JS {
		if js == "" {
			continue
		}
		b.WriteString(`<script nonce="`)
		b.WriteString(nonce)
		b.WriteString(`">`)
		b.WriteString(js)
		b.WriteString(`</script>`)
	}
	return []byte(b.String())
}

// spliceIntoHead inserts snippet just before </head>, or before <body>, or at
// the very start as a last resort.
func spliceIntoHead(body, snippet []byte) []byte {
	if i := indexFold(body, []byte("</head>")); i >= 0 {
		return splice(body, snippet, i)
	}
	if i := indexFold(body, []byte("<body")); i >= 0 {
		return splice(body, snippet, i)
	}
	out := make([]byte, 0, len(snippet)+len(body))
	out = append(out, snippet...)
	out = append(out, body...)
	return out
}

func splice(body, snippet []byte, at int) []byte {
	out := make([]byte, 0, len(body)+len(snippet))
	out = append(out, body[:at]...)
	out = append(out, snippet...)
	out = append(out, body[at:]...)
	return out
}

// indexFold is a case-insensitive bytes.Index.
func indexFold(haystack, needle []byte) int {
	return bytes.Index(bytes.ToLower(haystack), bytes.ToLower(needle))
}

// patchCSP adds 'nonce-<nonce>' to the style/script directives of any
// Content-Security-Policy headers so the injected elements are permitted.
func patchCSP(h http.Header, nonce string) {
	const key = "Content-Security-Policy"
	vals := h.Values(key)
	if len(vals) == 0 {
		return
	}
	src := "'nonce-" + nonce + "'"
	out := make([]string, 0, len(vals))
	for _, v := range vals {
		out = append(out, addNonceToCSP(v, src))
	}
	h.Del(key)
	for _, v := range out {
		h.Add(key, v)
	}
}

// addNonceToCSP adds our nonce to the directives that govern inline scripts
// and styles — but ONLY where that doesn't change what the page already
// allows. Per the CSP spec, 'unsafe-inline' is IGNORED as soon as any nonce
// or hash is present in a directive. So if a site permits its own inline
// scripts purely via 'unsafe-inline' (YouTube does this for signed-in Chrome),
// appending a nonce would switch 'unsafe-inline' off and block every one of
// the site's inline scripts — exactly the "skeleton screen forever" failure.
// In that case our injection is already allowed, so we leave the directive
// untouched. We add the nonce only where the directive already uses nonces/
// hashes, or allows no inline at all.
func addNonceToCSP(policy, src string) string {
	dirs := strings.Split(policy, ";")
	for i, d := range dirs {
		name := strings.ToLower(strings.TrimSpace(d))
		switch {
		case strings.HasPrefix(name, "default-src"),
			strings.HasPrefix(name, "script-src"),
			strings.HasPrefix(name, "style-src"):
			if needsNonce(name) {
				dirs[i] = strings.TrimRight(dirs[i], " ") + " " + src
			}
		}
	}
	return strings.Join(dirs, ";")
}

// needsNonce reports whether adding a nonce to this (lower-cased) directive
// is both useful and safe: false when 'unsafe-inline' is in effect, i.e. it
// is present and no nonce/hash source already disables it.
func needsNonce(dir string) bool {
	hasInline := strings.Contains(dir, "'unsafe-inline'")
	hasNonceOrHash := strings.Contains(dir, "'nonce-") ||
		strings.Contains(dir, "'sha256-") ||
		strings.Contains(dir, "'sha384-") ||
		strings.Contains(dir, "'sha512-")
	if hasInline && !hasNonceOrHash {
		return false // inline already allowed; a nonce would revoke that
	}
	return true
}

func newNonce() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return base64.RawStdEncoding.EncodeToString(b[:])
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
