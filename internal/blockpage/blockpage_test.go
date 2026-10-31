package blockpage

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"math/big"
	"net"
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
	if a, ok := g.AddrFor(netip.MustParseAddr("192.168.50.9"), "ads.example.com", now); !ok || a.String() != "192.168.50.75" {
		t.Fatalf("got %v %v", a, ok)
	}
	if _, ok := g.AddrFor(netip.MustParseAddr("127.0.0.1"), "ads.example.com", now); ok {
		t.Fatal("this node looking itself up must get the sinkhole")
	}
}

func TestARefusingDeviceKeepsThePageOverHTTP(t *testing.T) {
	g := guardOn("192.168.50.75/24")
	c := netip.MustParseAddr("192.168.50.9")
	now := time.Now()
	for i := 0; i < rejectionsToFallBack-1; i++ {
		g.Note(c, false, now)
	}
	if g.Refusing(c, now) {
		t.Fatal("too few rejections to give up")
	}
	g.Note(c, false, now)
	if !g.Refusing(c, now) {
		t.Fatal("a device that refuses the certificate should stop being offered it")
	}
	if _, ok := g.AddrFor(c, "ads.example.com", now); !ok {
		t.Fatal("it must still reach the page: plain http needs no certificate")
	}
	if g.Refusing(c, now.Add(fallBackFor+time.Minute)) {
		t.Fatal("a device that installs the CA later must be picked up again")
	}
	g.Note(c, false, now)
	g.Note(c, false, now)
	g.Note(c, false, now)
	g.Forgive(c)
	if g.Refusing(c, now) {
		t.Fatal("fetching the CA should start the device over")
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
	if g.Refusing(c, now) {
		t.Fatal("a pinned app on a device that trusts the CA must not switch HTTPS off")
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
	allow := true
	s := &Server{
		Claims: func(host string) bool { return host == "ads.example.com" },
		Allow:  func(netip.Addr) bool { return allow },
		Leaf:   func(string) (*tls.Certificate, error) { minted++; return &tls.Certificate{}, nil },
	}
	var offered sync.Map
	minting := make(chan struct{}, 1)
	if _, err := s.certificate(&tls.ClientHelloInfo{ServerName: "bank.example.com"}, &offered, minting); err == nil || minted != 0 {
		t.Fatalf("minted %d for a name nobody was sent here for: %v", minted, err)
	}
	if _, err := s.certificate(&tls.ClientHelloInfo{ServerName: "ads.example.com"}, &offered, minting); err != nil || minted != 1 {
		t.Fatalf("minted %d: %v", minted, err)
	}
	allow = false
	if _, err := s.certificate(&tls.ClientHelloInfo{ServerName: "ads.example.com"}, &offered, minting); err == nil || minted != 1 {
		t.Fatalf("minted %d past the limit: %v", minted, err)
	}
	allow = true
	minting <- struct{}{}
	if _, err := s.certificate(&tls.ClientHelloInfo{ServerName: "ads.example.com"}, &offered, minting); err == nil || minted != 1 {
		t.Fatalf("minted %d with no capacity left: %v", minted, err)
	}
}

func TestOnlyNamesTheResolverPointedHereAreClaimed(t *testing.T) {
	g := guardOn("192.168.50.75/24")
	c := netip.MustParseAddr("192.168.50.9")
	now := time.Now()
	if _, ok := g.AddrFor(c, "Ads.Example.com.", now); !ok {
		t.Fatal("expected the page")
	}
	if !g.Pointed("ads.example.com", now) {
		t.Fatal("the name just answered is not claimed")
	}
	if g.Pointed("other.example.com", now) {
		t.Fatal("a name never answered is claimed")
	}
	if g.Pointed("ads.example.com", now.Add(pointedFor)) {
		t.Fatal("an unblocked name must stop being claimed")
	}
	if _, ok := g.AddrFor(netip.MustParseAddr("127.0.0.1"), "local.example.com", now); ok || g.Pointed("local.example.com", now) {
		t.Fatal("a client given the sinkhole leaves no claim")
	}
}

func TestAFullTableFallsBackToTheSinkhole(t *testing.T) {
	g := guardOn("192.168.50.75/24")
	c := netip.MustParseAddr("192.168.50.9")
	now := time.Now()
	for i := range guardMaxNames {
		g.pointed[fmt.Sprintf("n%d.example.com", i)] = now
	}
	if _, ok := g.AddrFor(c, "new.example.com", now); ok {
		t.Fatal("unrecorded, this name would fall through to the interface")
	}
	if _, ok := g.AddrFor(c, "n1.example.com", now); !ok {
		t.Fatal("a name already recorded needs no new room")
	}
	if _, ok := g.AddrFor(c, "new.example.com", now.Add(pointedFor+time.Second)); !ok {
		t.Fatal("once the old names lapse there is room again")
	}
}

func listenBlockPage(t *testing.T, g *Guard) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), NotAfter: time.Now().Add(time.Hour), DNSNames: []string{"ads.example.com"}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	s := testServer()
	s.Guard = g
	s.Claims = func(string) bool { return true }
	s.Leaf = func(string) (*tls.Certificate, error) {
		return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	if err := s.ListenTLS(addr); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return addr
}

func refusing(t *testing.T, g *Guard, c netip.Addr, want bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		got := g.Refusing(c, time.Now())
		// Connections close asynchronously: "not refusing" needs time for a
		// wrong verdict to appear.
		if got == want && (want || time.Now().After(deadline)) {
			return
		}
		if got != want && time.Now().After(deadline) {
			t.Fatalf("refusing = %v, want %v", got, want)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func dialAndRefuse(t *testing.T, addr string) {
	t.Helper()
	if conn, err := tls.Dial("tcp", addr, &tls.Config{ServerName: "ads.example.com"}); err == nil {
		conn.Close()
		t.Fatal("this client must refuse the certificate")
	}
}

func TestProbesDoNotSwitchThePageOff(t *testing.T) {
	g := guardOn("127.0.0.1/8")
	addr := listenBlockPage(t, g)
	c := netip.MustParseAddr("127.0.0.1")
	for range rejectionsToFallBack * 2 {
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = conn.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
		conn.Close()
	}
	refusing(t, g, c, false)
	for range rejectionsToFallBack {
		dialAndRefuse(t, addr)
	}
	refusing(t, g, c, true)
}

func TestAToolSkippingVerificationProvesNothing(t *testing.T) {
	g := guardOn("127.0.0.1/8")
	addr := listenBlockPage(t, g)
	client := http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: "ads.example.com"}}}
	defer client.CloseIdleConnections()
	resp, err := client.Get("https://" + addr + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	for range rejectionsToFallBack {
		dialAndRefuse(t, addr)
	}
	refusing(t, g, netip.MustParseAddr("127.0.0.1"), true)
}

func TestABrowserOverTLSIsProof(t *testing.T) {
	g := guardOn("192.168.50.75/24")
	s := testServer()
	s.Guard = g
	c := netip.MustParseAddr("192.168.50.9")
	r := httptest.NewRequest(http.MethodGet, "https://ads.example.com/ad.js", nil)
	r.RemoteAddr, r.TLS = "192.168.50.9:5000", &tls.ConnectionState{}
	r.Header.Set("Sec-Fetch-Dest", "script")
	s.ServeHTTP(httptest.NewRecorder(), r)
	now := time.Now()
	for range rejectionsToFallBack {
		g.Note(c, false, now)
	}
	if g.Refusing(c, now) {
		t.Fatal("this device already showed it trusts the CA")
	}
}

func askServer() (*Server, *[]string) {
	calls := &[]string{}
	s := testServer()
	s.Claims = func(host string) bool { return host == "ads.example.com" }
	s.Ask = func(host string, f AskForm, _ netip.Addr) (AskState, error) {
		*calls = append(*calls, fmt.Sprintf("ask:%s:%s:%s:%d", host, f.Reason, f.Note, f.Minutes))
		return AskState{State: "pending"}, nil
	}
	s.Status = func(string, netip.Addr) AskState { return AskState{State: "approved"} }
	s.Self = func(host string, minutes int, _ netip.Addr) (AskState, error) {
		*calls = append(*calls, fmt.Sprintf("self:%s:%d", host, minutes))
		return AskState{State: "approved"}, nil
	}
	return s, calls
}

func post(s *Server, path, host, origin, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	r.Host = host
	if origin != "" {
		r.Header.Set("Origin", origin)
	}
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	return w
}

func TestTheFormAsksAndReturnsToThePage(t *testing.T) {
	s, calls := askServer()
	w := post(s, "/__orbis/ask", "ads.example.com", "http://ads.example.com", "reason=Work&minutes=15&note=homework&back=%2Fa%3Fb%3D1")
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/a?b=1" {
		t.Fatalf("code %d, location %q", w.Code, w.Header().Get("Location"))
	}
	if len(*calls) != 1 || (*calls)[0] != "ask:ads.example.com:Work:homework:15" {
		t.Fatalf("calls %v", *calls)
	}
	r := httptest.NewRequest(http.MethodGet, "/__orbis/ask", nil)
	r.Host = "ads.example.com"
	w = httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if !strings.Contains(w.Body.String(), `"approved"`) {
		t.Fatalf("status: %s", w.Body.String())
	}
}

func TestOnlyWhatIsOfferedCanBeAskedFor(t *testing.T) {
	s, calls := askServer()
	post(s, "/__orbis/ask", "ads.example.com", "http://ads.example.com", "reason=made+up&minutes=99999")
	if (*calls)[0] != "ask:ads.example.com:::60" {
		t.Fatalf("calls %v", *calls)
	}
	post(s, "/__orbis/self", "ads.example.com", "http://ads.example.com", "minutes=0")
	if (*calls)[1] != "self:ads.example.com:60" {
		t.Fatalf("a trusted device must not open a site for good from the page: %v", *calls)
	}
}

func TestTheReturnAddressStaysOnThisSite(t *testing.T) {
	for raw, want := range map[string]string{
		"/a/b?c=1": "/a/b?c=1", "": "/", "https://evil.example/": "/", "//evil.example": "/",
		"javascript:alert(1)": "/", "/__orbis/ask": "/",
	} {
		if got := backPath(raw); got != want {
			t.Errorf("%q = %q", raw, got)
		}
	}
}

func TestAnotherPageCannotAskOrUnblock(t *testing.T) {
	s, calls := askServer()
	for _, tc := range []struct{ path, host, origin string }{
		{"/__orbis/ask", "ads.example.com", "http://evil.example"},
		{"/__orbis/ask", "ads.example.com", ""},
		{"/__orbis/ask", "ads.example.com", "null"},
		{"/__orbis/self", "ads.example.com", "http://evil.example"},
		{"/__orbis/ask", "not-claimed.example", "http://not-claimed.example"},
	} {
		if w := post(s, tc.path, tc.host, tc.origin, "minutes=60"); w.Code < 400 {
			t.Errorf("%+v went through with %d", tc, w.Code)
		}
	}
	if len(*calls) != 0 {
		t.Fatalf("calls %v", *calls)
	}
}

func TestThePageOffersReasonsAndTimes(t *testing.T) {
	body := get(testServer(), "ads.example.com", map[string]string{"Sec-Fetch-Dest": "document"}).Body.String()
	for _, want := range []string{`action="/__orbis/ask"`, "Blocked by mistake", "15 minutes", "Today", "Always", `value="60" checked`} {
		if !strings.Contains(body, want) {
			t.Fatalf("missing %q", want)
		}
	}
}

func TestAThreatSiteIsNotOfferedForGood(t *testing.T) {
	s := testServer()
	s.Explain = func(_ context.Context, host string, _ netip.Addr) Page {
		return Page{Host: host, Blocked: true, Risky: true, When: "now"}
	}
	body := get(s, "bad.example", map[string]string{"Sec-Fetch-Dest": "document"}).Body.String()
	if strings.Contains(body, "<span>Always</span>") {
		t.Fatal("always should not be offered for a site on a threat list")
	}
}

func TestTheApprovalPageCarriesNothingUnescaped(t *testing.T) {
	w := httptest.NewRecorder()
	WriteApproval(w, Approval{Host: "a.example", Device: "<b>phone</b>", Note: `"><script>alert(1)</script>`, State: "pending", Token: "tok", Minutes: 15, Wants: "for 15 minutes"})
	body := w.Body.String()
	if strings.Contains(body, "<script>alert") || strings.Contains(body, "<b>phone") {
		t.Fatal("a guest's note reached the owner's page unescaped")
	}
	if !strings.Contains(body, "Allow 15 minutes") || !strings.Contains(w.Header().Get("Referrer-Policy"), "no-referrer") {
		t.Fatalf("referrer %q", w.Header().Get("Referrer-Policy"))
	}
}

func TestThePageNeverHoldsAConnectionOpen(t *testing.T) {
	s := testServer()
	s.Explain = func(_ context.Context, host string, _ netip.Addr) Page { return Page{Host: host, When: "now"} }
	w := get(s, "fine.example.com", map[string]string{"Sec-Fetch-Dest": "document"})
	if w.Header().Get("Connection") != "close" {
		t.Fatal("a browser would reuse this connection and land back on the page after approval")
	}
	if !strings.Contains(w.Body.String(), "<title>Opening fine.example.com</title>") {
		t.Fatalf("title in the opening state: %.200s", w.Body.String())
	}
}
