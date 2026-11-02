// Package bypass decides which hosts must be tunneled straight through the
// proxy without TLS interception.
//
// Some apps and sites use certificate pinning and will refuse any connection
// whose certificate was minted by our local CA. For those we must NOT act as
// a man-in-the-middle: we open a blind TCP tunnel instead, so they keep
// working exactly as if Adnesia were not running. This also means Adnesia
// cannot (and should not) see inside that traffic.
//
// Phase 1 ships a minimal matcher driven by the config's BypassDomains.
// Phase 5 expands this with a maintained default list and live editing.
package bypass

import "strings"

// Matcher tests hosts against a set of patterns.
//
// Patterns are matched case-insensitively and may use a single leading
// "*." wildcard to match a domain and all its subdomains:
//
//	example.com     matches exactly example.com
//	*.example.com   matches foo.example.com, a.b.example.com, and example.com
type Matcher struct {
	exact    map[string]struct{}
	suffixes []string // stored as ".example.com" for *.example.com
	bare     []string // the bare apex for a "*." pattern, e.g. "example.com"
}

// New builds a Matcher from a list of patterns.
func New(patterns []string) *Matcher {
	m := &Matcher{exact: make(map[string]struct{})}
	for _, p := range patterns {
		p = strings.ToLower(strings.TrimSpace(p))
		if p == "" {
			continue
		}
		if strings.HasPrefix(p, "*.") {
			apex := p[2:]
			m.suffixes = append(m.suffixes, "."+apex)
			m.bare = append(m.bare, apex)
			continue
		}
		m.exact[p] = struct{}{}
	}
	return m
}

// Match reports whether host should bypass interception. host may include a
// port (e.g. "example.com:443"), which is stripped before matching.
func (m *Matcher) Match(host string) bool {
	host = strings.ToLower(host)
	if i := strings.LastIndex(host, ":"); i != -1 {
		// Only strip when it looks like host:port, not an IPv6 literal.
		if !strings.Contains(host[i+1:], ":") {
			host = host[:i]
		}
	}
	host = strings.TrimSuffix(host, ".")

	if _, ok := m.exact[host]; ok {
		return true
	}
	for i, suf := range m.suffixes {
		if strings.HasSuffix(host, suf) || host == m.bare[i] {
			return true
		}
	}
	return false
}
