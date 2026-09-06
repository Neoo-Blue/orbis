package adblock

import (
	"sort"
	"strings"
	"testing"
)

func has(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func TestParseAdGuardSyntax(t *testing.T) {
	input := `[Adblock Plus 2.0]
! Title: test
||ads.example.com^
||tracker.example.net^$important
@@||cdn.example.com^
||ad*.banners.example^
/^stats[0-9]*\.example\.org$/
||example.org^$denyallow=safe.example.org
||typed.example^$dnstype=AAAA
||client.example^$client=192.168.1.5
||rewrite.example^$dnsrewrite=1.2.3.4
||sink.example^$dnsrewrite=0.0.0.0
||popup.example^$dnsrewrite=ad-block.dns.adguard.com
||page.example^$third-party
||path.example.com/ads^
example.com##.banner
bare.example
|exact.example^
://scheme.example^
||*.wild.example^
`
	e, err := Parse(strings.NewReader(input), ParseOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range []string{"ads.example.com", "tracker.example.net", "example.org", "sink.example", "popup.example", "bare.example", "wild.example"} {
		if !has(e.Wildcard, w) {
			t.Errorf("wildcard %s missing: %v", w, e.Wildcard)
		}
	}
	if !has(e.Exact, "exact.example") {
		t.Errorf("|exact.example^ should be exact: %v", e.Exact)
	}
	if !has(e.Wildcard, "scheme.example") {
		t.Errorf("://scheme.example^ should be wildcard in an ABP list: %v", e.Wildcard)
	}
	if !e.Important["tracker.example.net"] {
		t.Errorf("$important not recorded")
	}
	if !has(e.AllowWildcard, "cdn.example.com") || !has(e.AllowWildcard, "safe.example.org") {
		t.Errorf("exceptions missing: %v", e.AllowWildcard)
	}
	if len(e.Regex) != 2 {
		t.Errorf("want 2 regexes (wildcard rule + /re/), got %v", e.Regex)
	}
	for _, r := range []string{"dnstype", "client", "rewrite", "not-dns", "path", "cosmetic"} {
		if e.Skipped[r] == 0 {
			t.Errorf("expected a skipped %s entry: %v", r, e.Skipped)
		}
	}
	for _, bad := range []string{"typed.example", "client.example", "rewrite.example", "page.example", "path.example.com", "example.com"} {
		if has(e.Wildcard, bad) || has(e.Exact, bad) {
			t.Errorf("%s should not have been imported", bad)
		}
	}
}

func TestParsePiholeAndHosts(t *testing.T) {
	input := `# hosts
0.0.0.0 ads.example.com   # trailing comment
127.0.0.1 localhost
::1 ip6-localhost
1.2.3.4 nas.home
0.0.0.0 one.example two.example
address=/dnsmasq.example/0.0.0.0
server=/server.example/#
local-zone: "unbound.example" always_nxdomain
rpz.example CNAME .
*.rpzwild.example CNAME .
(\.|^)regex\.example$
^ad[0-9]+\.
.dotwild.example
*.starwild.example
plain.example
`
	e, err := Parse(strings.NewReader(input), ParseOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for _, x := range []string{"ads.example.com", "one.example", "two.example", "rpz.example", "plain.example"} {
		if !has(e.Exact, x) {
			t.Errorf("exact %s missing: %v", x, e.Exact)
		}
	}
	for _, w := range []string{"dnsmasq.example", "server.example", "unbound.example", "rpzwild.example", "dotwild.example", "starwild.example"} {
		if !has(e.Wildcard, w) {
			t.Errorf("wildcard %s missing: %v", w, e.Wildcard)
		}
	}
	if has(e.Exact, "localhost") || has(e.Exact, "nas.home") || has(e.Exact, "1.2.3.4") {
		t.Errorf("noise or rewrite imported: %v", e.Exact)
	}
	if e.Skipped["hosts-rewrite"] != 1 {
		t.Errorf("hosts rewrite should be skipped once: %v", e.Skipped)
	}
	sort.Strings(e.Regex)
	if len(e.Regex) != 2 {
		t.Errorf("want two Pi-hole regexes, got %v", e.Regex)
	}
}

func TestParseRegexFormatAndAllowList(t *testing.T) {
	e, err := Parse(strings.NewReader("(\\.|^)ads\\.example$\n^tele.*\\.example$;querytype=A\n# c\nbroken[\n"), ParseOptions{Format: "regex"})
	if err != nil {
		t.Fatal(err)
	}
	if len(e.Regex) != 1 || e.Skipped["querytype"] != 1 || e.Skipped["bad-regex"] != 1 {
		t.Errorf("regex format: %v skipped %v", e.Regex, e.Skipped)
	}
	a, err := Parse(strings.NewReader("||keep.example^\n0.0.0.0 keep2.example\n"), ParseOptions{Allow: true})
	if err != nil {
		t.Fatal(err)
	}
	if !has(a.AllowWildcard, "keep.example") || !has(a.AllowExact, "keep2.example") || a.Blocks() != 0 {
		t.Errorf("allow list: %+v", a)
	}
}

func TestMatcherImportantAndListExceptions(t *testing.T) {
	b := NewBuilder()
	b.AddBlockImportant("tracker.example", "list", "ads", true, true)
	b.AddBlock("ads.example", "list", "ads", true)
	b.AddAllowFrom("ads.example", true, false)     // a list exception
	b.AddAllowFrom("tracker.example", true, false) // a list exception that must lose to $important
	b.AddAllow("mine.example", false)              // the operator's own
	b.AddBlockImportant("mine.example", "list", "ads", false, true)
	if err := b.AddAllowRegex(`^ok[0-9]+\.example$`, false); err != nil {
		t.Fatal(err)
	}
	b.AddBlock("example", "list", "ads", true)
	m := New()
	m.Commit(b)

	if r := m.Lookup("x.ads.example"); !r.Allowed {
		t.Errorf("list exception should allow a list block: %+v", r)
	}
	if r := m.Lookup("x.tracker.example"); !r.Blocked || !r.Important {
		t.Errorf("$important block should beat a list exception: %+v", r)
	}
	if r := m.Lookup("mine.example"); !r.Allowed {
		t.Errorf("operator allow should beat $important: %+v", r)
	}
	if r := m.Lookup("ok7.example"); !r.Allowed {
		t.Errorf("allow regex should apply: %+v", r)
	}
	if r := m.Lookup("other.example"); r.Blocked {
		t.Errorf("a whole-TLD wildcard from a list must be ignored: %+v", r)
	}
}

func TestProtected(t *testing.T) {
	for _, d := range []string{"apple.com", "updates.apple.com", "cdn.cloudflare.com", "nas.local", "ocsp.digicert.com", "ab.io"} {
		if ok, _ := Protected(d); !ok {
			t.Errorf("%s should be protected", d)
		}
	}
	for _, d := range []string{"malware-c2.evil-example.xyz", "tracking.bad-adnetwork.com"} {
		if ok, why := Protected(d); ok {
			t.Errorf("%s should not be protected (%s)", d, why)
		}
	}
}
