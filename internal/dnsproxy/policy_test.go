package dnsproxy

import (
	"net/netip"
	"testing"
	"time"

	"github.com/Neoo-Blue/orbis/internal/config"
	"github.com/miekg/dns"
)

func at(day time.Weekday, hour, min int) time.Time {
	// 2026-08-23 is a Sunday, so adding the weekday index lands on that day.
	base := time.Date(2026, 8, 23, hour, min, 0, 0, time.UTC)
	return base.AddDate(0, 0, int(day))
}

func TestScheduleActive(t *testing.T) {
	cases := []struct {
		name string
		spec string
		when time.Time
		want bool
	}{
		{"empty is always on", "", at(time.Wednesday, 3, 0), true},
		{"weekday in window", "mon-fri 09:00-17:00", at(time.Wednesday, 10, 0), true},
		{"weekday outside hours", "mon-fri 09:00-17:00", at(time.Wednesday, 18, 0), false},
		{"weekend excluded", "mon-fri 09:00-17:00", at(time.Sunday, 10, 0), false},
		{"day only, matching", "sat sun", at(time.Sunday, 4, 0), true},
		{"day only, not matching", "sat sun", at(time.Tuesday, 4, 0), false},
		{"union of two days", "sat sun", at(time.Saturday, 23, 0), true},
		{"time only applies daily", "22:00-23:00", at(time.Tuesday, 22, 30), true},
		{"time only outside", "22:00-23:00", at(time.Tuesday, 21, 30), false},
		{"wraps midnight, late", "22:00-06:00", at(time.Tuesday, 23, 30), true},
		{"wraps midnight, early", "22:00-06:00", at(time.Tuesday, 2, 0), true},
		{"wraps midnight, outside", "22:00-06:00", at(time.Tuesday, 12, 0), false},
		{"garbage is fail-open", "notaday 99:99", at(time.Tuesday, 12, 0), true},
		{"boundary start inclusive", "mon-fri 09:00-17:00", at(time.Monday, 9, 0), true},
		{"boundary end exclusive", "mon-fri 09:00-17:00", at(time.Monday, 17, 0), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ScheduleActive(tc.spec, tc.when); got != tc.want {
				t.Fatalf("ScheduleActive(%q, %v) = %v, want %v", tc.spec, tc.when, got, tc.want)
			}
		})
	}
}

func TestSafeSearchTarget(t *testing.T) {
	cases := map[string]string{
		"google.com":       "forcesafesearch.google.com",
		"www.google.co.uk": "forcesafesearch.google.com",
		"google.de":        "forcesafesearch.google.com",
		"www.bing.com":     "strict.bing.com",
		"duckduckgo.com":   "safe.duckduckgo.com",
		"youtube.com":      "restrictmoderate.youtube.com",
		"example.com":      "",
		"notgoogle.com":    "",
		// A deep subdomain of google is infrastructure, not the search page;
		// rewriting it would break services.
		"apis.sub.google.com": "",
	}
	for in, want := range cases {
		if got := SafeSearchTarget(in); got != want {
			t.Errorf("SafeSearchTarget(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestMatchBlockedService(t *testing.T) {
	ids := []string{"tiktok", "roblox"}
	if _, hit := MatchBlockedService("www.tiktok.com", ids); !hit {
		t.Error("tiktok subdomain should match")
	}
	if name, hit := MatchBlockedService("tiktokcdn.com", ids); !hit || name != "TikTok" {
		t.Errorf("cdn domain should match TikTok, got %q %v", name, hit)
	}
	if _, hit := MatchBlockedService("example.com", ids); hit {
		t.Error("unrelated domain must not match")
	}
	// A service not selected must not block, even though it is in the catalogue.
	if _, hit := MatchBlockedService("discord.com", ids); hit {
		t.Error("unselected service must not match")
	}
	if _, hit := MatchBlockedService("tiktok.com", nil); hit {
		t.Error("empty selection must never match")
	}
	// Substring traps: a domain that merely ends in the same letters is not
	// a subdomain and must not be caught.
	if _, hit := MatchBlockedService("nottiktok.com", ids); hit {
		t.Error("suffix-without-dot must not match")
	}
}

func TestIsDoHBypass(t *testing.T) {
	for _, n := range []string{"dns.google", "cloudflare-dns.com", "dns.adguard.com"} {
		if !IsDoHBypass(n) {
			t.Errorf("%s should be a known DoH endpoint", n)
		}
	}
	for _, n := range []string{"google.com", "example.com", "mydns.google.com.evil.com"} {
		if IsDoHBypass(n) {
			t.Errorf("%s should not be flagged", n)
		}
	}
}

func TestRateLimiter(t *testing.T) {
	rl := NewRateLimiter(3)
	c := netip.MustParseAddr("192.168.1.10")
	now := time.Unix(1000, 0)
	for i := 0; i < 3; i++ {
		if !rl.Allow(c, now) {
			t.Fatalf("query %d within limit should pass", i+1)
		}
	}
	if rl.Allow(c, now) {
		t.Fatal("fourth query in the same second must be refused")
	}
	// A different client has its own bucket.
	if !rl.Allow(netip.MustParseAddr("192.168.1.11"), now) {
		t.Fatal("other client must not be affected")
	}
	// The next second resets.
	if !rl.Allow(c, now.Add(time.Second)) {
		t.Fatal("new window should reset the bucket")
	}
	// Zero disables it entirely.
	rl.SetLimit(0)
	for i := 0; i < 100; i++ {
		if !rl.Allow(c, now) {
			t.Fatal("limit 0 must disable rate limiting")
		}
	}
}

func TestRebindProtection(t *testing.T) {
	for _, ip := range []string{"192.168.1.1", "10.0.0.5", "127.0.0.1", "169.254.1.1", "::1", "fc00::1"} {
		if !IsRebindAddr(netip.MustParseAddr(ip)) {
			t.Errorf("%s should be treated as local", ip)
		}
	}
	for _, ip := range []string{"1.1.1.1", "8.8.8.8", "2606:4700::1111"} {
		if IsRebindAddr(netip.MustParseAddr(ip)) {
			t.Errorf("%s is public and must not be flagged", ip)
		}
	}

	// Local names are exempt so internal resolution keeps working.
	if !RebindAllowed("nas.lan", "lan", nil) {
		t.Error("local domain must be exempt")
	}
	if !RebindAllowed("1.1.168.192.in-addr.arpa", "lan", nil) {
		t.Error("reverse lookups must be exempt")
	}
	if !RebindAllowed("vpn.example.com", "lan", []string{"vpn.example.com"}) {
		t.Error("allowlisted name must be exempt")
	}
	if RebindAllowed("evil.com", "lan", nil) {
		t.Error("public name must not be exempt")
	}
}

func TestStripRebindKeepsPublicRecords(t *testing.T) {
	m := new(dns.Msg)
	m.SetQuestion("evil.com.", dns.TypeA)
	hdr := func(n string) dns.RR_Header {
		return dns.RR_Header{Name: n, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}
	}
	m.Answer = []dns.RR{
		&dns.A{Hdr: hdr("evil.com."), A: netip.MustParseAddr("93.184.216.34").AsSlice()},
		&dns.A{Hdr: hdr("evil.com."), A: netip.MustParseAddr("192.168.1.1").AsSlice()},
	}
	dropped := StripRebind(m)
	if dropped != 1 {
		t.Fatalf("expected 1 dropped record, got %d", dropped)
	}
	if len(m.Answer) != 1 {
		t.Fatalf("expected the public record to survive, got %d records", len(m.Answer))
	}
	if a, ok := m.Answer[0].(*dns.A); !ok || a.A.String() != "93.184.216.34" {
		t.Fatalf("wrong record survived: %v", m.Answer[0])
	}
}

func TestApplyRewrite(t *testing.T) {
	r := new(dns.Msg)
	r.SetQuestion("printer.lan.", dns.TypeA)
	q := r.Question[0]

	rules := []config.DNSRewrite{{Domain: "printer.lan", Answer: "192.168.1.50"}}
	m := ApplyRewrite(rules, r, q, "printer.lan")
	if m == nil || len(m.Answer) != 1 {
		t.Fatalf("expected an A answer, got %v", m)
	}
	if a := m.Answer[0].(*dns.A); a.A.String() != "192.168.1.50" {
		t.Fatalf("wrong address %v", a.A)
	}

	// Wildcards.
	if m := ApplyRewrite([]config.DNSRewrite{{Domain: "*.corp", Answer: "10.0.0.1"}},
		r, q, "host.corp"); m == nil || len(m.Answer) != 1 {
		t.Fatal("wildcard rewrite should match a subdomain")
	}

	// "#" is NXDOMAIN.
	if m := ApplyRewrite([]config.DNSRewrite{{Domain: "bad.com", Answer: "#"}},
		r, q, "bad.com"); m == nil || m.Rcode != dns.RcodeNameError {
		t.Fatal("# should produce NXDOMAIN")
	}

	// CNAME target.
	if m := ApplyRewrite([]config.DNSRewrite{{Domain: "a.com", Answer: "b.com"}},
		r, q, "a.com"); m == nil || len(m.Answer) != 1 {
		t.Fatal("non-IP answer should produce a CNAME")
	} else if _, ok := m.Answer[0].(*dns.CNAME); !ok {
		t.Fatalf("expected CNAME, got %T", m.Answer[0])
	}

	// A rule for a different name must not fire.
	if m := ApplyRewrite(rules, r, q, "other.lan"); m != nil {
		t.Fatal("non-matching rule must return nil")
	}

	// An AAAA rule queried as A answers empty rather than leaking the real A.
	aaaa := []config.DNSRewrite{{Domain: "printer.lan", Answer: "fd00::1"}}
	if m := ApplyRewrite(aaaa, r, q, "printer.lan"); m == nil {
		t.Fatal("family mismatch must still answer, not fall through")
	} else if len(m.Answer) != 0 {
		t.Fatalf("family mismatch should answer empty, got %d records", len(m.Answer))
	}
}

func TestMatchForwardZoneMostSpecific(t *testing.T) {
	zones := []config.ForwardZone{
		{Domain: "corp.example", Upstreams: []string{"10.0.0.1:53"}},
		{Domain: "db.corp.example", Upstreams: []string{"10.0.0.2:53"}},
	}
	if got := MatchForwardZone(zones, "host.db.corp.example"); got != "db.corp.example" {
		t.Fatalf("most specific zone should win, got %q", got)
	}
	if got := MatchForwardZone(zones, "web.corp.example"); got != "corp.example" {
		t.Fatalf("expected the general zone, got %q", got)
	}
	if got := MatchForwardZone(zones, "example.com"); got != "" {
		t.Fatalf("unrelated name should not match, got %q", got)
	}
	// A zone with no upstreams is ignored rather than blackholing the name.
	empty := []config.ForwardZone{{Domain: "corp.example"}}
	if got := MatchForwardZone(empty, "a.corp.example"); got != "" {
		t.Fatalf("zone without upstreams must be skipped, got %q", got)
	}
}
