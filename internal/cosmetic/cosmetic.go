// Package cosmetic parses element-hiding ("cosmetic") filter rules and builds
// the CSS to hide matched elements on a given page.
//
// It handles the two plain forms:
//
//	##.ad-banner              hide .ad-banner everywhere (generic)
//	a.com,b.com##.sponsored   hide .sponsored on those domains
//	a.com#@#.sponsored        exception: do NOT hide .sponsored on a.com
//
// Procedural rules (:has-text, :-abp-…), scriptlet injections (##+js(…),
// #%#, #$#) and other non-standard-CSS forms are skipped — they need a JS
// engine in the page and are out of scope for Phase 3.
package cosmetic

import (
	"bufio"
	"bytes"
	"strings"
)

// Engine holds parsed cosmetic rules.
type Engine struct {
	genericHide   []string            // selectors hidden on every site
	genericExcept map[string]struct{} // generic exceptions (#@# with no domain)
	domainRules   []domainRule        // rules scoped to specific domains
}

type domainRule struct {
	include   []string // domains the rule applies to (lowercased)
	selector  string
	exception bool // true for #@# (un-hide)
}

// NewEngine returns an empty cosmetic engine.
func NewEngine() *Engine {
	return &Engine{genericExcept: map[string]struct{}{}}
}

// AddList scans raw filter-list bytes for cosmetic rules and adds them.
func (e *Engine) AddList(data []byte) int {
	added := 0
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		if e.addLine(sc.Text()) {
			added++
		}
	}
	return added
}

// addLine parses one line; returns true if it added a cosmetic rule.
func (e *Engine) addLine(line string) bool {
	line = strings.TrimSpace(line)
	if line == "" || line[0] == '!' || line[0] == '[' {
		return false
	}

	// Locate the separator and whether it is a hide (##) or exception (#@#).
	domainsPart, selector, exception, ok := splitCosmetic(line)
	if !ok {
		return false
	}
	selector = strings.TrimSpace(selector)
	if selector == "" || isProcedural(selector) {
		return false
	}

	include, generic := parseDomains(domainsPart)

	if generic {
		if exception {
			e.genericExcept[selector] = struct{}{}
		} else {
			e.genericHide = append(e.genericHide, selector)
		}
		return true
	}
	if len(include) == 0 {
		// Only negated domains (e.g. "~a.com##.x"): treat as generic hide.
		if !exception {
			e.genericHide = append(e.genericHide, selector)
			return true
		}
		return false
	}
	e.domainRules = append(e.domainRules, domainRule{include: include, selector: selector, exception: exception})
	return true
}

// splitCosmetic finds the cosmetic separator and splits the line. It returns
// ok=false for network rules and for scriptlet/procedural separators.
func splitCosmetic(line string) (domains, selector string, exception, ok bool) {
	// Reject scriptlet separators outright.
	if strings.Contains(line, "#$#") || strings.Contains(line, "#%#") || strings.Contains(line, "#?#") {
		return "", "", false, false
	}
	if i := strings.Index(line, "#@#"); i >= 0 {
		return line[:i], line[i+3:], true, true
	}
	if i := strings.Index(line, "##"); i >= 0 {
		sel := line[i+2:]
		if strings.HasPrefix(sel, "+js(") { // uBO scriptlet
			return "", "", false, false
		}
		return line[:i], sel, false, true
	}
	return "", "", false, false
}

// parseDomains splits the pre-separator domain list. generic is true when
// there are no positive (non-negated) domains.
func parseDomains(part string) (include []string, generic bool) {
	part = strings.TrimSpace(part)
	if part == "" {
		return nil, true
	}
	for _, d := range strings.Split(part, ",") {
		d = strings.ToLower(strings.TrimSpace(d))
		if d == "" || strings.HasPrefix(d, "~") {
			continue // negated domains are ignored (approximation)
		}
		include = append(include, d)
	}
	return include, len(include) == 0
}

// isProcedural reports whether a selector uses non-standard-CSS extensions
// that a plain stylesheet cannot express.
func isProcedural(sel string) bool {
	for _, p := range []string{
		":-abp-", ":has-text(", ":contains(", ":matches-css", ":xpath(",
		":upward(", ":nth-ancestor(", ":remove(", ":style(", ":watch-attr(",
		":min-text-length(",
	} {
		if strings.Contains(sel, p) {
			return true
		}
	}
	return false
}

// CSSFor returns a stylesheet hiding the elements matched for host. When
// includeGeneric is false, only domain-specific rules are applied (far
// smaller, and they catch most real site-specific ad containers).
func (e *Engine) CSSFor(host string, includeGeneric bool) string {
	host = strings.ToLower(host)

	// Selectors excepted (un-hidden) for this host.
	excepted := make(map[string]struct{}, len(e.genericExcept))
	for s := range e.genericExcept {
		excepted[s] = struct{}{}
	}
	for _, r := range e.domainRules {
		if r.exception && hostMatches(host, r.include) {
			excepted[r.selector] = struct{}{}
		}
	}

	seen := map[string]struct{}{}
	var sels []string
	add := func(s string) {
		if _, dup := seen[s]; dup {
			return
		}
		if _, ex := excepted[s]; ex {
			return
		}
		seen[s] = struct{}{}
		sels = append(sels, s)
	}

	if includeGeneric {
		for _, s := range e.genericHide {
			add(s)
		}
	}
	for _, r := range e.domainRules {
		if !r.exception && hostMatches(host, r.include) {
			add(r.selector)
		}
	}

	if len(sels) == 0 {
		return ""
	}
	return strings.Join(sels, ",") + "{display:none!important}"
}

// Count returns the number of cosmetic rules loaded.
func (e *Engine) Count() int {
	return len(e.genericHide) + len(e.genericExcept) + len(e.domainRules)
}

func hostMatches(host string, domains []string) bool {
	for _, d := range domains {
		if host == d || strings.HasSuffix(host, "."+d) {
			return true
		}
	}
	return false
}
