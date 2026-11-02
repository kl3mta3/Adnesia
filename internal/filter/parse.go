package filter

import (
	"net"
	"strings"
)

// parseLine turns one filter-list line into a rule, or nil when the line is a
// comment, blank, unsupported, or a cosmetic rule (handled in a later phase).
func parseLine(line string) *rule {
	line = strings.TrimSpace(line)
	if line == "" {
		return nil
	}

	// ABP comments and list headers.
	if line[0] == '!' || line[0] == '[' {
		return nil
	}

	// Cosmetic / scriptlet rules: skip in the network phase.
	if isCosmetic(line) {
		return nil
	}

	// hosts-file format: "0.0.0.0 host" / "127.0.0.1 host" / "host".
	if r := parseHostsLine(line); r != nil {
		return r
	}

	// Plain "#" comment (hosts-style) that was not an ABP cosmetic rule.
	if line[0] == '#' {
		return nil
	}

	return parseABPNetwork(line)
}

// isCosmetic reports whether the line is an element-hiding or scriptlet rule.
func isCosmetic(line string) bool {
	for _, sep := range []string{"##", "#@#", "#?#", "#$#", "#%#"} {
		if strings.Contains(line, sep) {
			return true
		}
	}
	return false
}

var sinkIPs = map[string]bool{
	"0.0.0.0": true, "127.0.0.1": true, "::": true, "::1": true,
}

// parseHostsLine handles hosts-file entries. Returns nil if the line is not in
// that format.
func parseHostsLine(line string) *rule {
	// Strip trailing comment.
	if i := strings.IndexByte(line, '#'); i >= 0 {
		line = strings.TrimSpace(line[:i])
		if line == "" {
			return nil
		}
	}

	fields := strings.Fields(line)
	switch len(fields) {
	case 2:
		if sinkIPs[fields[0]] {
			host := strings.ToLower(fields[1])
			if isPlainHost(host) && strings.Contains(host, ".") {
				return &rule{raw: line, pureHost: host, pattern: "||" + host + "^"}
			}
		}
	case 1:
		// A bare hostname list (e.g. "ads.example.com"). Only treat as hosts
		// format when it really looks like a domain and not an ABP pattern.
		host := strings.ToLower(fields[0])
		if looksLikeBareDomain(host) {
			return &rule{raw: line, pureHost: host, pattern: "||" + host + "^"}
		}
	}
	return nil
}

// parseABPNetwork parses an Adblock-Plus network rule.
func parseABPNetwork(line string) *rule {
	r := &rule{raw: line}

	if strings.HasPrefix(line, "@@") {
		r.exception = true
		line = line[2:]
	}

	// Regex rules ("/.../") are not supported; skip to avoid mis-parsing.
	if len(line) >= 2 && line[0] == '/' && line[len(line)-1] == '/' {
		return nil
	}

	// Split options after the first "$".
	if i := strings.IndexByte(line, '$'); i >= 0 {
		opts, ok := parseOptions(line[i+1:])
		if !ok {
			return nil
		}
		r.opts = opts
		line = line[:i]
	}

	r.pattern = line
	if r.pattern == "" {
		return nil
	}

	// Detect the pure domain-anchored fast path: "||host" or "||host^".
	if strings.HasPrefix(r.pattern, "||") {
		rest := strings.TrimSuffix(r.pattern[2:], "^")
		rest = strings.ToLower(rest)
		if isPlainHost(rest) && strings.Contains(rest, ".") {
			r.pureHost = rest
		}
	}

	if r.pureHost == "" {
		r.compiled = newMatcher(r.pattern)
	}
	return r
}

// isPlainHost reports whether s is only domain characters (no wildcard, no
// path, no separator) — i.e. a literal hostname.
func isPlainHost(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z',
			c >= 'A' && c <= 'Z',
			c >= '0' && c <= '9',
			c == '.' || c == '-' || c == '_':
		default:
			return false
		}
	}
	return true
}

// looksLikeBareDomain is stricter than isPlainHost: it requires a dot and a
// valid-looking TLD so we don't mistake an ABP keyword for a domain.
func looksLikeBareDomain(s string) bool {
	if !isPlainHost(s) || !strings.Contains(s, ".") {
		return false
	}
	// Reject anything that is actually an IP address literal with a port, etc.
	if net.ParseIP(s) != nil {
		return false
	}
	labels := strings.Split(s, ".")
	tld := labels[len(labels)-1]
	if len(tld) < 2 {
		return false
	}
	for i := 0; i < len(tld); i++ {
		if tld[i] < 'a' || tld[i] > 'z' {
			return false
		}
	}
	return true
}
