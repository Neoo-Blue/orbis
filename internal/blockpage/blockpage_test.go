package blockpage

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

func testServer() *Server {
	return &Server{Explain: func(_ context.Context, host string, _ netip.Addr) Page {
		return Page{Host: host, Blocked: true, Why: "It is on a list.", When: "now",
			Stations: []Station{{Title: "Your device", Class: "clear"}, {Title: "Blocklist", Class: "decided"}, {Title: "The site", Class: "unreached"}}}
	}}
}

func get(s *Server, host string, headers map[string]string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, "http://"+host+"/path", nil)
	r.Host = host
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	return w
}

func TestABrowserOpeningTheSiteGetsThePage(t *testing.T) {
	w := get(testServer(), "ads.example.com", map[string]string{"Sec-Fetch-Dest": "document", "Accept": "text/html"})
	if w.Code != http.StatusForbidden {
		t.Fatalf("code = %d", w.Code)
	}
	body := w.Body.String()
	for _, want := range []string{"ads.<wbr>example.com", "Orbis stopped this site", "It is on a list.", `class="stop decided"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("page is missing %q", want)
		}
	}
	csp := w.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "default-src 'none'") || strings.Contains(csp, "unsafe") {
		t.Fatalf("csp = %q", csp)
	}
}

func TestEverythingElseFailsQuietly(t *testing.T) {
	for _, h := range []map[string]string{
		{"Sec-Fetch-Dest": "image"}, {"Sec-Fetch-Dest": "script"}, {"Sec-Fetch-Dest": "iframe", "Accept": "text/html"},
		{"Accept": "application/json"}, {},
	} {
		if w := get(testServer(), "ads.example.com", h); w.Code != http.StatusNoContent || w.Body.Len() != 0 {
			t.Fatalf("%v: code %d, %d bytes", h, w.Code, w.Body.Len())
		}
	}
}

func TestOldBrowsersStillGetThePage(t *testing.T) {
	if w := get(testServer(), "ads.example.com:80", map[string]string{"Accept": "text/html,*/*"}); w.Code != http.StatusForbidden {
		t.Fatalf("code = %d", w.Code)
	}
}

func TestTheHostnameCannotInjectIntoThePage(t *testing.T) {
	s := testServer()
	s.Explain = func(_ context.Context, _ string, _ netip.Addr) Page {
		return Page{Host: `"><script>alert(1)</script>`, Blocked: true, Why: `<img src=x onerror=alert(1)>`, Copy: `"><b>`, When: "now",
			AdminURL: "javascript:alert(1)"}
	}
	body := get(s, "x.example.com", map[string]string{"Sec-Fetch-Dest": "document"}).Body.String()
	if strings.Contains(body, "<script>alert") || strings.Contains(body, "<img src=x") || strings.Contains(body, `href="javascript:`) {
		t.Fatal("unescaped input reached the page")
	}
}

func TestSomethingAllowedSinceSaysSo(t *testing.T) {
	s := testServer()
	s.Explain = func(_ context.Context, host string, _ netip.Addr) Page { return Page{Host: host, When: "now"} }
	w := get(s, "fine.example.com", map[string]string{"Sec-Fetch-Dest": "document"})
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "no longer blocks") {
		t.Fatalf("code %d", w.Code)
	}
}

func guardOn(prefix string) *Guard {
	g := NewGuard()
	g.interfaces = func() ([]netip.Prefix, error) { return []netip.Prefix{netip.MustParsePrefix(prefix)}, nil }
	return g
}

func TestGuardSendsClientsToTheAddressOnTheirNetwork(t *testing.T) {
	g := guardOn("192.168.50.75/24")
	now := time.Now()
	if a, ok := g.AddrFor(netip.MustParseAddr("192.168.50.9"), now); !ok || a.String() != "192.168.50.75" {
		t.Fatalf("got %v %v", a, ok)
	}
	if _, ok := g.AddrFor(netip.MustParseAddr("127.0.0.1"), now); ok {
		t.Fatal("this node looking itself up must get the sinkhole")
	}
}

func TestGuardFallsBackAfterRejectionsThenTriesAgain(t *testing.T) {
	g := guardOn("192.168.50.75/24")
	c := netip.MustParseAddr("192.168.50.9")
	now := time.Now()
	for i := 0; i < rejectionsToFallBack-1; i++ {
		g.Note(c, false, now)
	}
	if _, ok := g.AddrFor(c, now); !ok {
		t.Fatal("too few rejections to give up")
	}
	g.Note(c, false, now)
	if _, ok := g.AddrFor(c, now); ok {
		t.Fatal("a device that refuses the certificate must get the sinkhole")
	}
	if _, ok := g.AddrFor(c, now.Add(fallBackFor+time.Minute)); !ok {
		t.Fatal("a device that installs the CA later must be picked up again")
	}
}

func TestOnePinnedAppDoesNotUndoWhatABrowserProved(t *testing.T) {
	g := guardOn("192.168.50.75/24")
	c := netip.MustParseAddr("192.168.50.9")
	now := time.Now()
	g.Note(c, true, now)
	for i := 0; i < rejectionsToFallBack*3; i++ {
		g.Note(c, false, now)
	}
	if _, ok := g.AddrFor(c, now); !ok {
		t.Fatal("a pinned app on a device that trusts the CA must not switch the page off")
	}
}

func TestOnlyPlausibleHostnamesReachTheCA(t *testing.T) {
	for name, want := range map[string]bool{
		"ads.example.com": true, "a_b-c.example": true,
		"": false, "bad name.example": false, "new\nline.example": false, "evil/../x": false,
		strings.Repeat("a", 254): false,
	} {
		if got := hostname(name); got != want {
			t.Errorf("%q = %v", name, got)
		}
	}
}

func TestCertificatesAreOnlyMintedForClaimedNames(t *testing.T) {
	minted := 0
	s := &Server{
		Claims: func(host string, _ netip.Addr) bool { return host == "ads.example.com" },
		Leaf:   func(string) (*tls.Certificate, error) { minted++; return &tls.Certificate{}, nil },
	}
	var refused sync.Map
	minting := make(chan struct{}, 1)
	if _, err := s.certificate(&tls.ClientHelloInfo{ServerName: "bank.example.com"}, &refused, minting); err == nil || minted != 0 {
		t.Fatalf("minted %d for a name nobody was sent here for: %v", minted, err)
	}
	if _, err := s.certificate(&tls.ClientHelloInfo{ServerName: "ads.example.com"}, &refused, minting); err != nil || minted != 1 {
		t.Fatalf("minted %d: %v", minted, err)
	}
	minting <- struct{}{}
	if _, err := s.certificate(&tls.ClientHelloInfo{ServerName: "ads.example.com"}, &refused, minting); err == nil || minted != 1 {
		t.Fatalf("minted %d with no capacity left: %v", minted, err)
	}
}
