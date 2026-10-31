package adblock

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Neoo-Blue/orbis/internal/config"
	"github.com/Neoo-Blue/orbis/internal/store"
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
		ReferringSites: []string{"shop.example", "news.example", "blog.example"},
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
		"ads.example.co.uk":     "example.co.uk",
		"a.b.example.com":       "example.com",
		"example.com":           "example.com",
		"deep.sub.example.com.au": "example.com.au",
		"single":                "single",
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

func TestDomainSetSurvivesGrowth(t *testing.T) {
	var s domainSet
	const n = 50000
	for i := 0; i < n; i++ {
		s.set(hashDomain(fmt.Sprintf("host-%d.example.com", i)), uint32(i))
	}
	if s.n != n {
		t.Fatalf("n = %d", s.n)
	}
	for i := 0; i < n; i++ {
		if v, ok := s.find(hashDomain(fmt.Sprintf("host-%d.example.com", i))); !ok || v != uint32(i) {
			t.Fatalf("entry %d: %d %v", i, v, ok)
		}
	}
	if _, ok := s.find(hashDomain("absent.example.com")); ok {
		t.Fatal("found a name that was never added")
	}
	s.set(hashDomain("host-7.example.com"), 99)
	if v, _ := s.find(hashDomain("host-7.example.com")); v != 99 || s.n != n {
		t.Fatalf("replacing an entry: v=%d n=%d", v, s.n)
	}
}

func TestAttributionDoesNotDependOnRowOrder(t *testing.T) {
	build := func(order []string) Match {
		b := NewBuilder()
		for _, src := range order {
			b.AddBlockImportant("ads.example.com", src, "cat-"+src, false, src == "a-list")
		}
		m := New()
		m.Commit(b)
		return m.Lookup("ads.example.com")
	}
	x, y := build([]string{"a-list", "b-list"}), build([]string{"b-list", "a-list"})
	if x != y || x.Source != "b-list" || x.Category != "cat-b-list" || !x.Important {
		t.Fatalf("got %+v and %+v", x, y)
	}
}

func TestBuiltinRuleKeepsItsAttributionOverAList(t *testing.T) {
	b := NewBuilder()
	b.AddBlock("dns.google", "zzz-list", "ads", true)
	b.AddBlock("dns.google", "builtin:doh-bypass", "bypass", true)
	m := New()
	m.Commit(b)
	if got := m.Lookup("dns.google"); got.Source != "builtin:doh-bypass" {
		t.Fatalf("got %+v", got)
	}
}

func TestRegexVerdictIsRememberedPerIndex(t *testing.T) {
	b := NewBuilder()
	if err := b.AddRegex(`^ad[0-9]+\.`, "local:manual", "ads"); err != nil {
		t.Fatal(err)
	}
	m := New()
	m.Commit(b)
	for i := 0; i < 3; i++ {
		if got := m.Lookup("ad7.example.com"); !got.Blocked {
			t.Fatalf("lookup %d: %+v", i, got)
		}
	}
	// A new index must not inherit the old one's answers.
	m.Commit(NewBuilder())
	if got := m.Lookup("ad7.example.com"); got.Blocked {
		t.Fatalf("stale verdict: %+v", got)
	}
}

func BenchmarkLookupMiss(b *testing.B) {
	bd := NewBuilder()
	for i := 0; i < 1_000_000; i++ {
		bd.AddBlock(fmt.Sprintf("host-%d.ads.example.net", i), "list", "ads", i%2 == 0)
	}
	for i := 0; i < 1200; i++ {
		if err := bd.AddRegex(fmt.Sprintf(`^ad%d[0-9]+\.tracker`, i), "list", "ads"); err != nil {
			b.Fatal(err)
		}
	}
	m := New()
	m.Commit(bd)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		m.Lookup("www.example-site.co.uk")
	}
}

func TestSavedIndexAnswersLikeTheOriginal(t *testing.T) {
	b := NewBuilder()
	b.AddBlock("ads.example.com", "list-a", "ads", false)
	b.AddBlockImportant("tracker.example.net", "list-b", "tracking", true, true)
	b.AddAllowFrom("ok.tracker.example.net", false, false, "list-c")
	if err := b.AddRegex(`^ad[0-9]+\.`, "list-a", "ads"); err != nil {
		t.Fatal(err)
	}
	if err := b.AddAllowRegex(`^safe[0-9]+\.`, false, "list-c"); err != nil {
		t.Fatal(err)
	}
	m := New()
	m.Commit(b)
	path := filepath.Join(t.TempDir(), "index.bin")
	if err := m.SaveIndex(path, "lists"); err != nil {
		t.Fatal(err)
	}
	loaded := New()
	if err := loaded.LoadIndex(path, "lists"); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"ads.example.com", "x.tracker.example.net", "ok.tracker.example.net", "ad7.example.org", "safe1.tracker.example.net", "fine.example.org"} {
		if got, want := loaded.Lookup(name), m.Lookup(name); got != want {
			t.Errorf("%s: got %+v, want %+v", name, got, want)
		}
	}
	if loaded.Count() != m.Count() {
		t.Fatalf("count %d, want %d", loaded.Count(), m.Count())
	}
}

func TestDamagedIndexIsRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "index.bin")
	b := NewBuilder()
	b.AddBlock("ads.example.com", "list-a", "ads", false)
	m := New()
	m.Commit(b)
	if err := m.SaveIndex(path, "lists"); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data[:len(data)/2], 0o600); err != nil {
		t.Fatal(err)
	}
	fresh := New()
	if err := fresh.LoadIndex(path, "lists"); err == nil {
		t.Fatal("a truncated index must be refused")
	}
	if fresh.Count() != 0 {
		t.Fatal("a refused index must leave the matcher untouched")
	}
}

func TestAnIndexBuiltFromOtherListsIsRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "index.bin")
	b := NewBuilder()
	b.AddBlock("ads.example.com", "list-a", "ads", false)
	m := New()
	m.Commit(b)
	if err := m.SaveIndex(path, "lists"); err != nil {
		t.Fatal(err)
	}
	if err := New().LoadIndex(path, "other lists"); err == nil {
		t.Fatal("a list switched off in the YAML must not come back from the snapshot")
	}
}

func TestImpossibleTablesAreRefused(t *testing.T) {
	for _, tc := range []struct {
		name string
		head [2]uint64
		keys []uint64
	}{
		{"no empty slot, so a lookup would spin", [2]uint64{4, 4}, []uint64{1, 2, 3, 4}},
		{"count disagrees with the keys", [2]uint64{3, 4}, []uint64{1, 0, 0, 0}},
		{"larger than the file", [2]uint64{0, 1 << 40}, nil},
		{"size that overflows", [2]uint64{0, 1 << 62}, nil},
	} {
		var buf bytes.Buffer
		_ = binary.Write(&buf, binary.LittleEndian, tc.head)
		_ = binary.Write(&buf, binary.LittleEndian, tc.keys)
		_ = binary.Write(&buf, binary.LittleEndian, make([]uint32, len(tc.keys)))
		var s domainSet
		if err := s.read(bufio.NewReader(&buf), int64(buf.Len())); err == nil {
			t.Errorf("%s: accepted", tc.name)
		}
	}
}

func TestListRowsChangingForcesARebuildAtBoot(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "orbis.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	cfg := config.Default()
	cfg.Store.Path = filepath.Join(dir, "orbis.db")
	mgr := NewManager(st, New(), cfg, func(string, ...any) {})
	if err := mgr.Rebuild(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !mgr.restore() {
		t.Fatal("a saved index should load")
	}
	if _, err := st.ReplaceListDomains(context.Background(), "some-list", "ads", store.ListEntries{Exact: []string{"ads.example.com"}}); err != nil {
		t.Fatal(err)
	}
	if mgr.restore() {
		t.Fatal("the rows moved on, so the saved index is stale")
	}
	if err := mgr.Rebuild(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !mgr.restore() {
		t.Fatal("a rebuild should clear the marker")
	}
}

func TestAppServersWorkWhileTheirTrackersStayBlocked(t *testing.T) {
	works := []string{"b-graph.facebook.com", "b-graph-fallback.facebook.com", "mqtt-mini.facebook.com",
		"mshopandroidphone.triggers-v1.prod.mobile.weblab.a2z.com"}
	trackers := []string{"an.facebook.com", "pixel.facebook.com", "unagi.amazon.com"}
	b := NewBuilder()
	for _, d := range append(trackers, works...) {
		b.AddBlock(d, "aggressive-list", "ads", false)
	}
	addEssentialHosts(b)
	m := New()
	m.Commit(b)
	for _, d := range works {
		if m.Lookup(d).Blocked {
			t.Errorf("%s is blocked, and the app stops working", d)
		}
	}
	for _, d := range trackers {
		if !m.Lookup(d).Blocked {
			t.Errorf("%s is a tracker and must stay blocked", d)
		}
	}
}
