// Package filter parses ad-block filter lists and matches request URLs
// against them.
//
// It understands two list formats:
//
//   - Adblock Plus / EasyList syntax: "||ads.example^", "/pagead/",
//     "@@||allowed.example^", with "$" options (third-party, domain=,
//     resource types).
//   - hosts-file syntax: "0.0.0.0 ads.example.com" / "127.0.0.1 tracker.example".
//
// Phase 2 implements NETWORK blocking only. Cosmetic rules ("##selector")
// and scriptlet rules are recognised and skipped here; they arrive in Phase 3.
package filter

import "strings"

// resType is a request's resource type, used to evaluate ABP type options.
type resType string

const (
	typeOther      resType = "other"
	typeScript     resType = "script"
	typeImage      resType = "image"
	typeStylesheet resType = "stylesheet"
	typeObject     resType = "object"
	typeXHR        resType = "xmlhttprequest"
	typeSubdoc     resType = "subdocument"
	typeDocument   resType = "document"
	typeFont       resType = "font"
	typeMedia      resType = "media"
	typeWebsocket  resType = "websocket"
	typePing       resType = "ping"
	// typePopup is a type a proxy never sees (new-window navigations), so a
	// "$popup"-only rule correctly matches nothing here. Treating it as a
	// plain block turned "||doubleclick.net^$popup" into a block of every
	// doubleclick request — including YouTube's pagead/id, which hangs YouTube.
	typePopup resType = "popup"
)

// options holds the parsed "$" modifiers of a network rule. A zero options
// value means "applies to any request".
type options struct {
	// thirdParty: 0 = unspecified, 1 = only third-party, -1 = only first-party.
	thirdParty int

	// includeDomains / excludeDomains come from the domain= modifier and are
	// matched against the first-party (document) domain.
	includeDomains []string
	excludeDomains []string

	// includeTypes / excludeTypes come from resource-type modifiers. When
	// includeTypes is non-empty the rule applies only to those types; any
	// type in excludeTypes disqualifies the rule.
	includeTypes map[resType]bool
	excludeTypes map[resType]bool

	// unsupported marks that the rule carried a modifier we do not implement
	// (e.g. "csp", "redirect"). Such rules are dropped to avoid misfiring.
	unsupported bool
}

// rule is one parsed network filter.
type rule struct {
	raw       string
	pattern   string // the matchable portion, without "@@" or "$options"
	exception bool   // true for "@@" allow rules

	// Fast-path fields for pure domain-anchored rules ("||host^" with no
	// wildcards in the host and nothing after the separator):
	pureHost string // non-empty when this rule is a plain domain block

	opts     options
	compiled *matcher // lazily built for generic (non-pure) rules
	cat      Category // which feature this rule belongs to
}

var typeKeywords = map[string]resType{
	"script":         typeScript,
	"image":          typeImage,
	"stylesheet":     typeStylesheet,
	"css":            typeStylesheet, // uBO/AdGuard short form
	"object":         typeObject,
	"xmlhttprequest": typeXHR,
	"xhr":            typeXHR, // short form
	"subdocument":    typeSubdoc,
	"frame":          typeSubdoc, // short form
	"document":       typeDocument,
	"doc":            typeDocument, // short form
	"font":           typeFont,
	"media":          typeMedia,
	"websocket":      typeWebsocket,
	"ping":           typePing,
	"beacon":         typePing,
	"other":          typeOther,
	"popup":          typePopup,
	"popunder":       typePopup,
}

// modifiers we knowingly ignore (they do not change whether a plain network
// block fires in a way we model) rather than treating as unsupported.
var ignoredModifiers = map[string]bool{
	"important":  true,
	"all":        true,
	"match-case": true,
}

// ignoredPrefixes are modifiers with a value that we treat the same as a plain
// block. "redirect=" in particular means "answer with an empty no-op resource
// instead of an error" — which is exactly what the proxy now does for every
// block, so the rule's intent is honoured.
var ignoredPrefixes = []string{"redirect=", "rewrite="}

// parseOptions parses the text after "$" into an options value. It returns
// ok=false when the rule uses a modifier we cannot honour safely.
func parseOptions(s string) (options, bool) {
	var o options
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		neg := strings.HasPrefix(part, "~")
		bare := strings.TrimPrefix(part, "~")

		switch {
		case bare == "third-party" || bare == "3p":
			if neg {
				o.thirdParty = -1
			} else {
				o.thirdParty = 1
			}
		case bare == "first-party" || bare == "1p":
			if neg {
				o.thirdParty = 1
			} else {
				o.thirdParty = -1
			}
		case hasAnyPrefix(bare, ignoredPrefixes):
			// no-op (see ignoredPrefixes)
		case strings.HasPrefix(bare, "domain="):
			for _, d := range strings.Split(bare[len("domain="):], "|") {
				d = strings.ToLower(strings.TrimSpace(d))
				if d == "" {
					continue
				}
				if strings.HasPrefix(d, "~") {
					o.excludeDomains = append(o.excludeDomains, d[1:])
				} else {
					o.includeDomains = append(o.includeDomains, d)
				}
			}
		case typeKeywords[bare] != "":
			t := typeKeywords[bare]
			if neg {
				if o.excludeTypes == nil {
					o.excludeTypes = map[resType]bool{}
				}
				o.excludeTypes[t] = true
			} else {
				if o.includeTypes == nil {
					o.includeTypes = map[resType]bool{}
				}
				o.includeTypes[t] = true
			}
		case ignoredModifiers[part], ignoredModifiers[bare]:
			// no-op
		default:
			// A modifier we do not model (csp=, redirect=, removeparam=, etc.).
			// Dropping the rule is safer than applying it incorrectly.
			o.unsupported = true
			return o, false
		}
	}
	return o, true
}

// matchOptions reports whether this rule's options permit it to apply to req.
func (r *rule) matchOptions(req *Request) bool {
	o := r.opts
	if o.thirdParty == 1 && !req.ThirdParty {
		return false
	}
	if o.thirdParty == -1 && req.ThirdParty {
		return false
	}
	if len(o.includeTypes) > 0 && !o.includeTypes[req.typ] {
		return false
	}
	if o.excludeTypes[req.typ] {
		return false
	}
	if len(o.includeDomains) > 0 {
		if !domainInList(req.DocDomain, o.includeDomains) {
			return false
		}
	}
	if len(o.excludeDomains) > 0 && domainInList(req.DocDomain, o.excludeDomains) {
		return false
	}
	return true
}

func hasAnyPrefix(s string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

// domainInList reports whether domain equals or is a subdomain of any entry.
func domainInList(domain string, list []string) bool {
	domain = strings.ToLower(domain)
	for _, d := range list {
		if domain == d || strings.HasSuffix(domain, "."+d) {
			return true
		}
	}
	return false
}
