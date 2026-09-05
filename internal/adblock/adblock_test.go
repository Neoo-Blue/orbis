package adblock

import (
	"strings"
	"testing"
)

func TestParseListFormats(t *testing.T) {
	input := `# a comment
! an adblock comment
0.0.0.0 ads.example.com
0.0.0.0 localhost
127.0.0.1 tracker.example.net another.example.net
plain.example.org
*.wildcard.example
.dotted.example
||abp.example^
||has-a-path.example/ads
||with-options.example^$third-party
@@||exception.example^
address=/dnsmasq.example/0.0.0.0
server=/forwarded.example/1.2.3.4
##.cosmetic-selector
1.2.3.4
`
	exact, wild, err := ParseList(strings.NewReader(input))
	if err != nil {
		t.Fatalf("ParseList: %v", err)
	}
	has := func(list []string, d string) bool {
		for _, x := range list {
			if x == d {
				return true
			}
		}
		return false
	}

	for _, want := range []string{"ads.example.com", "tracker.example.net", "another.example.net", "plain.example.org"} {
		if !has(exact, want) {
			t.Errorf("exact list is missing %q", want)
		}
	}
	for _, want := range []string{"wildcard.example", "dotted.example", "abp.example", "dnsmasq.example", "forwarded.example"} {
		if !has(wild, want) {
			t.Errorf("wildcard list is missing %q", want)
		}
	}
	// The entries that must NOT make it through: an exception rule would
	// invert the list, a path rule cannot be honoured at the DNS layer, and
	// "localhost" in a hosts file is not a block.
	for _, unwanted := range []string{"exception.example", "localhost", "1.2.3.4"} {
		if has(exact, unwanted) || has(wild, unwanted) {
			t.Errorf("%q should have been skipped", unwanted)
		}
	}
	if has(wild, "has-a-path.example") {
		t.Error("an ABP rule with a path should be skipped, not treated as a domain block")
	}
	if has(wild, "with-options.example") {
		t.Error("an ABP rule with option modifiers should be skipped")
	}
}

func TestParseListDNSRewriteIsABlock(t *testing.T) {
	input := `||popup.example^$dnsrewrite=ad-block.dns.adguard.com
||nullroute.example^$dnsrewrite=0.0.0.0
||important.example^$dnsrewrite=blocked.example,important
||thirdparty.example^$third-party,dnsrewrite=blocked.example
`
	exact, wild, err := ParseList(strings.NewReader(input))
	if err != nil {
		t.Fatalf("ParseList: %v", err)
	}
	has := func(list []string, d string) bool {
		for _, x := range list {
			if x == d {
				return true
			}
		}
		return false
	}
	for _, want := range []string{"popup.example", "nullroute.example", "important.example"} {
		if !has(wild, want) {
			t.Errorf("a $dnsrewrite rule should be treated as a block: %q missing", want)
		}
	}
	if has(exact, "thirdparty.example") || has(wild, "thirdparty.example") {
		t.Error("a $dnsrewrite rule combined with an unhandled modifier should still be skipped")
	}
}

func TestMatcherHierarchy(t *testing.T) {
	m := New()
	b := NewBuilder()
	b.AddBlock("doubleclick.net", "list", "ads", true)
	b.AddBlock("exact.example.com", "list", "ads", false)
	b.AddAllow("safe.doubleclick.net", false)
	m.Commit(b)

	cases := []struct {
		domain      string
		wantBlocked bool
		wantAllowed bool
		why         string
	}{
		{"doubleclick.net", true, false, "the wildcard root itself"},
		{"ads.doubleclick.net", true, false, "a subdomain of a wildcard"},
		{"a.b.c.doubleclick.net", true, false, "a deep subdomain"},
		{"safe.doubleclick.net", false, true, "an explicit allow beats the wildcard"},
		{"exact.example.com", true, false, "an exact entry"},
		{"sub.exact.example.com", false, false, "an exact entry must not cover subdomains"},
		{"notdoubleclick.net", false, false, "a suffix must match on a label boundary"},
		{"doubleclick.net.evil.test", false, false, "the rule appearing mid-name is not a match"},
		{"", false, false, "empty input"},
	}
	for _, c := range cases {
		got := m.Lookup(c.domain)
		if got.Blocked != c.wantBlocked || got.Allowed != c.wantAllowed {
			t.Errorf("Lookup(%q) = blocked:%v allowed:%v, want blocked:%v allowed:%v (%s)",
				c.domain, got.Blocked, got.Allowed, c.wantBlocked, c.wantAllowed, c.why)
		}
	}
}

func TestMatcherNeverBlocksTLD(t *testing.T) {
	// A malformed list entry of "com" must not take the whole internet down.
	m := New()
	b := NewBuilder()
	b.AddBlock("com", "bad-list", "ads", true)
	m.Commit(b)
	if r := m.Lookup("example.com"); r.Blocked {
		t.Error("a single-label wildcard must not match every domain under that TLD")
	}
}

func TestLookupChainUncloaksCNAME(t *testing.T) {
	m := New()
	b := NewBuilder()
	b.AddBlock("adtech.example", "list", "tracking", true)
	m.Commit(b)

	// The queried name is innocent; the CNAME target is not. This is the
	// entire point of uncloaking.
	chain := []string{"analytics.firstparty.example", "edge.adtech.example"}
	got := m.LookupChain(chain)
	if !got.Blocked {
		t.Fatal("a CNAME into a blocked zone should be blocked")
	}
	if !strings.Contains(got.Source, "CNAME") {
		t.Errorf("Source = %q, should say the block came via a CNAME", got.Source)
	}
}

func TestNormalizeRejectsNonDomains(t *testing.T) {
	for _, bad := range []string{"", "1.2.3.4", "has space.com", "http://x.com", strings.Repeat("a", 300)} {
		if got := normalize(bad); got != "" {
			t.Errorf("normalize(%q) = %q, want empty", bad, got)
		}
	}
	if got := normalize("*.Example.COM."); got != "example.com" {
		t.Errorf("normalize did not strip the wildcard, case and trailing dot: %q", got)
	}
}

func TestHeuristicSeparatesAdsFromServices(t *testing.T) {
	adServer := DomainEvidence{
		Domain: "px.adserver-tracking.example", Observations: 220, DistinctClients: 7,
		ReferringSites: []string{"a.example", "b.example", "c.example", "d.example",
			"e.example", "f.example", "g.example", "h.example"},
		ThirdPartyRatio: 1.0, AvgResponseBytes: 43, SubdomainDepth: 2,
		LabelEntropy: 1.9, KeywordHits: keywordHits("px.adserver-tracking.example"),
		SamplePaths: []string{"/pixel?id=1"},
	}
	service := DomainEvidence{
		Domain: "api.myapp.example", Observations: 340, DistinctClients: 2,
		ReferringSites: []string{"myapp.example"}, ThirdPartyRatio: 0.02,
		AvgResponseBytes: 240_000, SubdomainDepth: 1, LabelEntropy: 1.5,
	}
	cdn := DomainEvidence{
		Domain: "d3abc123xyz.cloudfront.net", Observations: 90, DistinctClients: 5,
		ReferringSites:  []string{"shop.example", "news.example", "blog.example"},
		ThirdPartyRatio: 1.0, AvgResponseBytes: 180_000, SubdomainDepth: 2, LabelEntropy: 3.9,
	}

	adScore := Heuristic(adServer)
	serviceScore := Heuristic(service)
	cdnScore := Heuristic(cdn)

	if adScore < 0.7 {
		t.Errorf("an obvious ad server scored %.2f, expected well above 0.7", adScore)
	}
	if serviceScore > 0.35 {
		t.Errorf("a first-party API scored %.2f, expected low", serviceScore)
	}
	if cdnScore >= adScore {
		t.Errorf("a CDN (%.2f) scored at or above an ad server (%.2f); the CDN dampener is not working",
			cdnScore, adScore)
	}
}

func TestHeuristicNeverFlagsInfrastructure(t *testing.T) {
	// These have every superficial marker of a tracker — many devices, high
	// third-party ratio, small responses — and blocking any of them breaks
	// the network rather than removing an ad.
	for _, d := range []string{
		"ocsp.pki.goog", "time.windows.com", "push.apple.com",
		"gateway.icloud.com", "connectivity-check.ubuntu.com",
	} {
		ev := DomainEvidence{
			Domain: d, Observations: 500, DistinctClients: 12,
			ThirdPartyRatio: 1.0, AvgResponseBytes: 120,
			SubdomainDepth: strings.Count(d, "."), KeywordHits: keywordHits(d),
		}
		if score := Heuristic(ev); score > 0.5 {
			t.Errorf("%s scored %.2f — critical infrastructure must never reach auto-block range", d, score)
		}
	}
}

func TestRegistrableHandlesMultiLabelSuffixes(t *testing.T) {
	cases := map[string]string{
		"ads.example.co.uk":       "example.co.uk",
		"a.b.example.com":         "example.com",
		"example.com":             "example.com",
		"deep.sub.example.com.au": "example.com.au",
		"single":                  "single",
	}
	for in, want := range cases {
		if got := registrable(in); got != want {
			t.Errorf("registrable(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestIsInfrastructure(t *testing.T) {
	for _, d := range []string{"router.lan", "printer.local", "1.0.168.192.in-addr.arpa", "apple.com", "bare"} {
		if !isInfrastructure(d) {
			t.Errorf("%q should be treated as infrastructure and never auto-blocked", d)
		}
	}
	for _, d := range []string{"ads.example.com", "tracker.example.net"} {
		if isInfrastructure(d) {
			t.Errorf("%q should not be treated as infrastructure", d)
		}
	}
}

func TestOperatorCanStillBlockATLD(t *testing.T) {
	// The TLD guard protects against bad list data, not against an operator
	// who deliberately typed "*.zip".
	m := New()
	b := NewBuilder()
	b.AddBlock("zip", "local:user", "manual", true)
	m.Commit(b)
	if r := m.Lookup("download.zip"); !r.Blocked {
		t.Error("a locally-authored TLD rule should still apply")
	}
}
