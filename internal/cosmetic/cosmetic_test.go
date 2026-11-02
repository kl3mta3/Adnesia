package cosmetic

import (
	"strings"
	"testing"
)

func engineFrom(lines string) *Engine {
	e := NewEngine()
	e.AddList([]byte(lines))
	return e
}

func TestDomainSpecificHide(t *testing.T) {
	e := engineFrom("example.com##.sponsored\nother.com##.promo\n")

	css := e.CSSFor("example.com", false)
	if !strings.Contains(css, ".sponsored") {
		t.Errorf("expected .sponsored for example.com, got %q", css)
	}
	if strings.Contains(css, ".promo") {
		t.Errorf("did not expect other.com's .promo for example.com, got %q", css)
	}
	if !strings.HasSuffix(css, "{display:none!important}") {
		t.Errorf("css should end with the hide declaration, got %q", css)
	}
}

func TestSubdomainMatch(t *testing.T) {
	e := engineFrom("example.com##.ad\n")
	if css := e.CSSFor("www.example.com", false); !strings.Contains(css, ".ad") {
		t.Errorf("subdomain should match parent-domain rule, got %q", css)
	}
}

func TestGenericGatedByFlag(t *testing.T) {
	e := engineFrom("##.banner-ad\n")

	if css := e.CSSFor("any.example", false); css != "" {
		t.Errorf("generic rule should be excluded when includeGeneric=false, got %q", css)
	}
	if css := e.CSSFor("any.example", true); !strings.Contains(css, ".banner-ad") {
		t.Errorf("generic rule should apply when includeGeneric=true, got %q", css)
	}
}

func TestExceptionUnhides(t *testing.T) {
	e := engineFrom("##.ad\nexample.com#@#.ad\n")

	if css := e.CSSFor("example.com", true); strings.Contains(css, ".ad") {
		t.Errorf("#@# should un-hide .ad on example.com, got %q", css)
	}
	if css := e.CSSFor("other.com", true); !strings.Contains(css, ".ad") {
		t.Errorf(".ad should still be hidden on other.com, got %q", css)
	}
}

func TestProceduralAndScriptletSkipped(t *testing.T) {
	e := engineFrom(
		"example.com##.x:has-text(Ad)\n" +
			"example.com##+js(nano)\n" +
			"example.com#$#.y { remove: true; }\n" +
			"example.com#%#//scriptlet('x')\n",
	)
	if e.Count() != 0 {
		t.Errorf("procedural/scriptlet rules should be skipped, got %d", e.Count())
	}
}
