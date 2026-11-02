package filter

import (
	"bufio"
	"bytes"
	"strings"
	"sync/atomic"

	"golang.org/x/net/publicsuffix"
)

// Category groups rules by the user-facing feature that controls them, so the
// dashboard's per-feature toggles can enable or disable whole classes of rules.
type Category uint8

const (
	CatAds        Category = iota // ad servers, ad scripts, ad elements
	CatPrivacy                    // trackers / analytics (EasyPrivacy)
	CatAnnoyances                 // cookie notices, nags, social widgets
	CatSecurity                   // malware / phishing domains
	CatOther                      // uncategorised (default)
	numCategories
)

// Request describes a single network request to be evaluated.
type Request struct {
	URL        string // full request URL
	Host       string // request host (no port)
	DocDomain  string // registered domain of the first party (document), may be ""
	ThirdParty bool
	typ        resType
}

// NewRequest builds a Request, classifying its resource type from typeHint
// (an ABP type keyword such as "script"/"image"/"document", typically derived
// from the Sec-Fetch-Dest header) and computing third-party status from the
// document domain.
func NewRequest(fullURL, reqHost, docRegDomain, typeHint string) *Request {
	r := &Request{
		URL:       fullURL,
		Host:      stripPort(strings.ToLower(reqHost)),
		DocDomain: strings.ToLower(docRegDomain),
		typ:       typeOther,
	}
	if t, ok := typeKeywords[strings.ToLower(typeHint)]; ok {
		r.typ = t
	}
	if r.DocDomain != "" {
		r.ThirdParty = RegisteredDomain(r.Host) != r.DocDomain
	}
	return r
}

// RegisteredDomain returns the eTLD+1 (registrable domain) of host, or host
// itself if it cannot be reduced.
func RegisteredDomain(host string) string {
	host = stripPort(strings.ToLower(host))
	if d, err := publicsuffix.EffectiveTLDPlusOne(host); err == nil {
		return d
	}
	return host
}

func stripPort(host string) string {
	if i := strings.LastIndexByte(host, ':'); i >= 0 && !strings.Contains(host[i+1:], ":") {
		return host[:i]
	}
	return host
}

// ruleIndex buckets rules for fast candidate lookup.
type ruleIndex struct {
	hostMap  map[string][]*rule // pure domain rules keyed by host
	buckets  map[string][]*rule // generic rules keyed by their longest token
	catchAll []*rule            // generic rules with no usable token
}

func newRuleIndex() ruleIndex {
	return ruleIndex{hostMap: map[string][]*rule{}, buckets: map[string][]*rule{}}
}

func (idx *ruleIndex) add(r *rule) {
	if r.pureHost != "" {
		idx.hostMap[r.pureHost] = append(idx.hostMap[r.pureHost], r)
		return
	}
	if tok := bucketToken(r.pattern); tok != "" {
		idx.buckets[tok] = append(idx.buckets[tok], r)
	} else {
		idx.catchAll = append(idx.catchAll, r)
	}
}

// firstMatch returns the first rule that applies to req and satisfies pred
// (pred may be nil to accept any rule), or nil.
func (idx *ruleIndex) firstMatch(req *Request, pred func(*rule) bool) *rule {
	ok := func(r *rule) bool {
		if pred != nil && !pred(r) {
			return false
		}
		return r.matchOptions(req)
	}

	// Domain fast path: walk the host and its parent domains.
	for h := req.Host; h != ""; {
		for _, r := range idx.hostMap[h] {
			if ok(r) {
				return r
			}
		}
		i := strings.IndexByte(h, '.')
		if i < 0 {
			break
		}
		h = h[i+1:]
	}

	// Generic rules, reached via the URL's tokens.
	seenTok := map[string]struct{}{}
	for _, tok := range urlTokens(req.URL) {
		if _, dup := seenTok[tok]; dup {
			continue
		}
		seenTok[tok] = struct{}{}
		for _, r := range idx.buckets[tok] {
			if (pred == nil || pred(r)) && r.compiled.match(req.URL) && r.matchOptions(req) {
				return r
			}
		}
	}
	for _, r := range idx.catchAll {
		if (pred == nil || pred(r)) && r.compiled.match(req.URL) && r.matchOptions(req) {
			return r
		}
	}
	return nil
}

// Engine holds the compiled block and allow rule sets plus per-category state.
type Engine struct {
	block ruleIndex
	allow ruleIndex
	n     int
	catOn [numCategories]atomic.Bool
}

// NewEngine returns an empty engine with all categories enabled.
func NewEngine() *Engine {
	e := &Engine{block: newRuleIndex(), allow: newRuleIndex()}
	for i := range e.catOn {
		e.catOn[i].Store(true)
	}
	return e
}

// AddList parses raw filter-list bytes into the uncategorised bucket.
func (e *Engine) AddList(data []byte) int { return e.AddListCat(data, CatOther) }

// AddListCat parses raw filter-list bytes and tags every rule with cat.
func (e *Engine) AddListCat(data []byte, cat Category) int {
	added := 0
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		r := parseLine(sc.Text())
		if r == nil {
			continue
		}
		r.cat = cat
		if r.exception {
			e.allow.add(r)
		} else {
			e.block.add(r)
		}
		added++
		e.n++
	}
	return added
}

// Count returns the number of rules loaded.
func (e *Engine) Count() int { return e.n }

// SetCategory enables or disables a whole category of block rules at runtime.
func (e *Engine) SetCategory(cat Category, on bool) {
	if int(cat) < len(e.catOn) {
		e.catOn[cat].Store(on)
	}
}

// CategoryEnabled reports whether cat is currently active.
func (e *Engine) CategoryEnabled(cat Category) bool {
	return int(cat) < len(e.catOn) && e.catOn[cat].Load()
}

// Match reports whether req should be blocked and, if so, by which category.
// A block rule in a disabled category is ignored; an exception (allow) rule
// overrides a block regardless of category.
func (e *Engine) Match(req *Request) (bool, Category) {
	br := e.block.firstMatch(req, func(r *rule) bool { return e.catOn[r.cat].Load() })
	if br == nil {
		return false, CatOther
	}
	if e.allow.firstMatch(req, nil) != nil {
		return false, CatOther
	}
	return true, br.cat
}

// Explain returns the raw text of the block rule that matches req (empty if
// none) and of the exception rule that overrides it (empty if none). Used by
// diagnostics to answer "why is this URL blocked?".
func (e *Engine) Explain(req *Request) (block, exception string) {
	br := e.block.firstMatch(req, func(r *rule) bool { return e.catOn[r.cat].Load() })
	if br == nil {
		return "", ""
	}
	if ar := e.allow.firstMatch(req, nil); ar != nil {
		return br.raw, ar.raw
	}
	return br.raw, ""
}

// Blocked reports whether req should be blocked (category ignored by caller).
func (e *Engine) Blocked(req *Request) bool {
	b, _ := e.Match(req)
	return b
}
