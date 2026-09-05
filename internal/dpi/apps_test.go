package dpi

import "testing"

func TestClassifyPrefersLongestSuffix(t *testing.T) {
	cases := map[string]string{
		"music.youtube.com":             "YouTube Music",
		"rr3---sn-abc.googlevideo.com":  "YouTube",
		"tv.apple.com":                  "Apple TV",
		"mesu.apple.com":                "Apple Updates",
		"www.apple.com":                 "Apple",
		"static.xx.fbcdn.net":           "Meta",
		"scontent.cdninstagram.com":     "Instagram",
		"pagead2.googlesyndication.com": "Ad/Tracking",
		"app-measurement.com":           "Telemetry",
		"news.bbc.co.uk":                "BBC",
		"api.openrouter.ai":             "OpenRouter",
	}
	for host, want := range cases {
		got := ClassifyApp(host)
		if got != want {
			t.Errorf("ClassifyApp(%q) = %q, want %q", host, got, want)
		}
	}
	if got := ClassifyApp("totally-unknown-shop.example"); got != "" {
		t.Errorf("unknown host classified as %q", got)
	}
}

func TestServiceForFallsBackToRegistrableDomain(t *testing.T) {
	if s := ServiceFor("cdn.assets.someshop.com"); s.Name != "someshop.com" || s.Category != CatOther {
		t.Errorf("fallback = %+v", s)
	}
	if s := ServiceFor("news.bbc.co.uk"); s.Name != "BBC" {
		t.Errorf("bbc = %+v", s)
	}
	if s := ServiceFor(""); s.Name != "Unresolved" {
		t.Errorf("empty = %+v", s)
	}
	if s := ServiceFor("192.168.50.75"); s.Name != "Local network" {
		t.Errorf("private address = %+v", s)
	}
	if s := ServiceFor("142.251.218.70"); s.Name != "Unresolved" {
		t.Errorf("public address = %+v", s)
	}
	if s := ServiceFor("one.one.one.one"); s.Name != "Cloudflare" {
		t.Errorf("1.1.1.1 name = %+v", s)
	}
	if got := RegistrableDomain("a.b.example.co.uk"); got != "example.co.uk" {
		t.Errorf("registrable = %q", got)
	}
	if got := RegistrableDomain("foo.github.io"); got != "foo.github.io" {
		t.Errorf("github.io pages should keep the user label, got %q", got)
	}
}

func TestCatalogueHasNoDuplicateSuffixes(t *testing.T) {
	seen := map[string]string{}
	for _, m := range appMatchers {
		for _, s := range m.suffixes {
			if prev, ok := seen[s]; ok && prev != m.name {
				t.Errorf("suffix %q is claimed by both %q and %q", s, prev, m.name)
			}
			seen[s] = m.name
		}
	}
	if len(appMatchers) < 100 {
		t.Errorf("catalogue has %d services; expected a few hundred hostnames across 100+", len(appMatchers))
	}
}
