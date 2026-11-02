package filter

import "testing"

func engineFrom(lines string) *Engine {
	e := NewEngine()
	e.AddList([]byte(lines))
	return e
}

func TestDomainAnchor(t *testing.T) {
	e := engineFrom("||ads.example.com^\n")

	cases := []struct {
		url, host string
		want      bool
	}{
		{"http://ads.example.com/banner.js", "ads.example.com", true},
		{"https://sub.ads.example.com/x", "sub.ads.example.com", true},
		{"https://ads.example.com", "ads.example.com", true},
		{"https://notads.example.com/x", "notads.example.com", false},
		{"https://example.com/x", "example.com", false},
	}
	for _, c := range cases {
		req := NewRequest(c.url, c.host, "", "")
		if got := e.Blocked(req); got != c.want {
			t.Errorf("Blocked(%q) = %v, want %v", c.url, got, c.want)
		}
	}
}

func TestHostsFormat(t *testing.T) {
	e := engineFrom("0.0.0.0 tracker.test\n127.0.0.1 ads.test # a comment\n")
	for _, h := range []string{"tracker.test", "ads.test"} {
		req := NewRequest("https://"+h+"/beacon", h, "", "")
		if !e.Blocked(req) {
			t.Errorf("expected %s to be blocked", h)
		}
	}
	req := NewRequest("https://safe.test/x", "safe.test", "", "")
	if e.Blocked(req) {
		t.Error("safe.test should not be blocked")
	}
}

func TestExceptionOverrides(t *testing.T) {
	e := engineFrom("||ads.example^\n@@||ads.example/allowed^\n")

	blocked := NewRequest("https://ads.example/track", "ads.example", "", "")
	if !e.Blocked(blocked) {
		t.Error("ads.example/track should be blocked")
	}
	allowed := NewRequest("https://ads.example/allowed/x", "ads.example", "", "")
	if e.Blocked(allowed) {
		t.Error("ads.example/allowed should be exempt via @@ rule")
	}
}

func TestThirdPartyOption(t *testing.T) {
	e := engineFrom("||widget.com^$third-party\n")

	third := NewRequest("https://widget.com/w.js", "widget.com", "example.com", "")
	if !e.Blocked(third) {
		t.Error("widget.com as third-party should be blocked")
	}
	first := NewRequest("https://widget.com/w.js", "widget.com", "widget.com", "")
	if e.Blocked(first) {
		t.Error("widget.com as first-party should not be blocked")
	}
}

func TestDomainOption(t *testing.T) {
	e := engineFrom("||track.com^$domain=foo.com\n")

	onFoo := NewRequest("https://track.com/t", "track.com", "foo.com", "")
	if !e.Blocked(onFoo) {
		t.Error("track.com on foo.com should be blocked")
	}
	onBar := NewRequest("https://track.com/t", "track.com", "bar.com", "")
	if e.Blocked(onBar) {
		t.Error("track.com on bar.com should not be blocked")
	}
}

func TestTypeOption(t *testing.T) {
	e := engineFrom("||cdn.com/x^$script\n")

	asScript := NewRequest("https://cdn.com/x", "cdn.com", "", "script")
	if !e.Blocked(asScript) {
		t.Error("script request should be blocked")
	}
	asImage := NewRequest("https://cdn.com/x", "cdn.com", "", "image")
	if e.Blocked(asImage) {
		t.Error("image request should not be blocked by a $script rule")
	}
}

func TestGenericPathRule(t *testing.T) {
	e := engineFrom("/pagead/*\n")

	hit := NewRequest("https://anything.example/pagead/ad.js", "anything.example", "", "")
	if !e.Blocked(hit) {
		t.Error("url containing /pagead/ should be blocked")
	}
	miss := NewRequest("https://anything.example/content.js", "anything.example", "", "")
	if e.Blocked(miss) {
		t.Error("unrelated url should not be blocked")
	}
}

func TestCosmeticAndCommentsSkipped(t *testing.T) {
	e := engineFrom("! comment\n[Adblock Plus 2.0]\nexample.com##.ad-banner\nexample.com#@#.foo\n")
	if e.Count() != 0 {
		t.Errorf("expected 0 network rules from cosmetic/comment lines, got %d", e.Count())
	}
}

func TestCategoryToggle(t *testing.T) {
	e := NewEngine()
	e.AddListCat([]byte("||ads.example^\n"), CatAds)
	e.AddListCat([]byte("||track.example^\n"), CatPrivacy)

	adReq := NewRequest("https://ads.example/x", "ads.example", "", "")
	trReq := NewRequest("https://track.example/x", "track.example", "", "")

	// Both on by default.
	if b, c := e.Match(adReq); !b || c != CatAds {
		t.Errorf("ad should be blocked as CatAds, got %v/%d", b, c)
	}
	if b, c := e.Match(trReq); !b || c != CatPrivacy {
		t.Errorf("tracker should be blocked as CatPrivacy, got %v/%d", b, c)
	}

	// Disable ads only.
	e.SetCategory(CatAds, false)
	if e.Blocked(adReq) {
		t.Error("ad should pass when CatAds disabled")
	}
	if !e.Blocked(trReq) {
		t.Error("tracker should still be blocked when only CatAds disabled")
	}
}

// A "$popup"-only rule must not block ordinary requests — this is the exact
// rule that was taking down YouTube (pagead/id) when popup was ignored.
func TestPopupOnlyRuleDoesNotBlockNormalRequests(t *testing.T) {
	e := engineFrom("||doubleclick.net^$popup\n")
	req := NewRequest("https://googleads.g.doubleclick.net/pagead/id", "googleads.g.doubleclick.net", "youtube.com", "xmlhttprequest")
	if e.Blocked(req) {
		t.Error("popup-only rule should not block an xhr request")
	}
}

// Short-form type modifiers must parse; an unknown modifier used to drop the
// whole rule, which for "@@" exceptions means over-blocking.
func TestShortFormModifiersAndExceptions(t *testing.T) {
	e := engineFrom("||ads.example^\n@@||ads.example/keep^$xhr,1p\n")
	blocked := NewRequest("https://ads.example/track", "ads.example", "ads.example", "xmlhttprequest")
	if !e.Blocked(blocked) {
		t.Error("plain block should still apply")
	}
	kept := NewRequest("https://ads.example/keep", "ads.example", "ads.example", "xmlhttprequest")
	if e.Blocked(kept) {
		t.Error("$xhr,1p exception should be honoured, not dropped")
	}
}

// "redirect=" rules are plain blocks for us (every block is already served as
// an empty no-op), so they must not be discarded.
func TestRedirectRuleStillBlocks(t *testing.T) {
	e := engineFrom("||ads.example/x^$script,redirect=noop.js\n")
	req := NewRequest("https://ads.example/x", "ads.example", "", "script")
	if !e.Blocked(req) {
		t.Error("redirect= rule should block (and be served as a no-op)")
	}
}

func TestSeparatorMatch(t *testing.T) {
	e := engineFrom("||example.com/ads^\n")
	hit := NewRequest("https://example.com/ads?x=1", "example.com", "", "")
	if !e.Blocked(hit) {
		t.Error("separator ^ should match '?'")
	}
	miss := NewRequest("https://example.com/adsense/x", "example.com", "", "")
	if e.Blocked(miss) {
		t.Error("'^' should not match a letter (adsense)")
	}
}
