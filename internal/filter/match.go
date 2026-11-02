package filter

import (
	"regexp"
	"strings"
	"sync"
)

// matcher tests a URL against a single Adblock-Plus pattern. The pattern is
// compiled to a regular expression lazily, the first time the rule is actually
// a candidate, so lists with tens of thousands of rules do not pay to compile
// patterns that are never hit.
type matcher struct {
	pattern string
	once    sync.Once
	re      *regexp.Regexp
	err     error
}

func newMatcher(pattern string) *matcher { return &matcher{pattern: pattern} }

// match reports whether url matches the pattern.
func (m *matcher) match(url string) bool {
	m.once.Do(func() { m.re, m.err = regexp.Compile(abpToRegex(m.pattern)) })
	if m.err != nil || m.re == nil {
		return false
	}
	return m.re.MatchString(url)
}

// abpToRegex converts an Adblock-Plus network pattern to a Go regular
// expression string.
//
//	||        anchor at a domain boundary (optional scheme + optional subdomains)
//	|  (lead) anchor at start of the URL
//	|  (tail) anchor at end of the URL
//	^         separator: any char that is not a-z A-Z 0-9 _ - . % , or end
//	*         wildcard (any run of characters)
//	other     matched literally
//
// Matching is case-insensitive.
func abpToRegex(p string) string {
	var b strings.Builder
	b.WriteString("(?i)")

	i := 0
	// Leading anchors.
	if strings.HasPrefix(p, "||") {
		// Optional scheme, then optional leading labels ending in a dot.
		b.WriteString(`^(?:[^:/?#]+://)?(?:[^/?#]*\.)?`)
		i = 2
	} else if strings.HasPrefix(p, "|") {
		b.WriteString(`^`)
		i = 1
	}

	// Trailing "|" end anchor.
	tailAnchor := false
	end := len(p)
	if end > i && p[end-1] == '|' {
		tailAnchor = true
		end--
	}

	for ; i < end; i++ {
		c := p[i]
		switch c {
		case '*':
			b.WriteString(`.*`)
		case '^':
			b.WriteString(`(?:[^a-zA-Z0-9_\-.%]|$)`)
		default:
			// Escape anything regex-special, write the rest literally.
			if strings.IndexByte(`\.+?()[]{}$|`, c) >= 0 {
				b.WriteByte('\\')
			}
			b.WriteByte(c)
		}
	}

	if tailAnchor {
		b.WriteString(`$`)
	}
	return b.String()
}

// tokenRE picks out alphanumeric runs used for bucketing and lookup.
var tokenRE = regexp.MustCompile(`[a-z0-9]+`)

// bucketToken returns the token a generic rule is indexed under: the longest
// alphanumeric run in its pattern. Returns "" when the pattern has no run of
// at least 3 characters (such rules go in the catch-all bucket).
func bucketToken(pattern string) string {
	best := ""
	for _, tok := range tokenRE.FindAllString(strings.ToLower(pattern), -1) {
		if len(tok) > len(best) {
			best = tok
		}
	}
	if len(best) < 3 {
		return ""
	}
	return best
}

// urlTokens returns the distinct alphanumeric tokens in url (lowercased).
func urlTokens(url string) []string {
	return tokenRE.FindAllString(strings.ToLower(url), -1)
}
