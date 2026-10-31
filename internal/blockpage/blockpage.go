// Package blockpage shows a person why Orbis stopped a site.
//
// A DNS block on its own looks like a broken site. With this on, the resolver
// answers a blocked name with this node's address, so the browser arrives here
// and gets a page saying what was stopped, what decided it and how to change
// that, instead of an error.
//
// HTTPS is the catch. The browser checks the certificate before it shows
// anything, and only a device that trusts the Orbis CA accepts one for a
// site that is not ours. A device that does not trust it gets a certificate
// error rather than the quick failure a sinkhole gives, so the Guard learns:
// after a few rejections and no success, that device goes back to the plain
// sinkhole for a day.
package blockpage

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

//go:embed approve.html
var approveHTML string

//go:embed page.html
var pageHTML string

//go:embed geist.woff2
var font []byte

//go:embed geist-mono.woff2
var monoFont []byte

var pageTemplate = template.Must(template.New("page").Parse(pageHTML))
var approvalTemplate = template.Must(template.New("approve").Parse(approveHTML))

// Station is one stop on the line drawn from the device to the decision.
type Station struct {
	Title  string
	Detail string
	// Class is "" for a stage that was passed, "clear" for the device and the
	// resolver, "decided" for the stage that stopped the request and
	// "unreached" for what the request never got to.
	Class string
	// Address sets Detail as an address rather than as words.
	Address bool
}

// Page is everything shown for one blocked name.
type Page struct {
	Host     string
	Blocked  bool
	Why      string
	Stations []Station
	Rule     string
	Source   string
	Category string
	Device   string
	// DeviceAddress says Device is an address, because the device has no name.
	DeviceAddress bool
	When          string
	AdminURL      string
	Copy          string
	Nonce         string
	// HostParts lets a long name wrap at its dots, not in the middle of a word.
	HostParts []string
	Long      bool
	// Trusted is a device that may unblock without asking.
	Trusted bool
	// Risky is a site on a threat list, which takes a second look.
	Risky bool
	// Asked is where this device's request stands, if it made one.
	Asked string
	// Path is where the visitor was going, so an answer brings them back to it.
	Path string
	// Problem is why the last thing they tried did not work.
	Problem string
	// Reasons and Durations are what the form offers.
	Reasons   []string
	Durations []Duration
}

// AskState is what the page learns about its request.
type AskState struct {
	State string `json:"state"`
}

// AskForm is what someone filled in.
type AskForm struct {
	Reason  string
	Note    string
	Minutes int
}

// Duration is a length of time on offer.
type Duration struct {
	Minutes int
	Label   string
	On      bool
}

// reasons are offered so asking takes one tap and reads the same every time.
var reasons = []string{"Work", "School", "Shopping or banking", "Blocked by mistake", "Something else"}

// durations are the temporary options. Asking for good is offered only for a
// site that is not on a threat list.
func durations(risky bool) []Duration {
	out := []Duration{{15, "15 minutes", false}, {60, "1 hour", true}, {1440, "Today", false}}
	if !risky {
		out = append(out, Duration{0, "Always", false})
	}
	return out
}

func minutesFrom(raw string, allowForever bool) int {
	n, err := strconv.Atoi(raw)
	if err != nil {
		return 60
	}
	switch {
	case n == 15, n == 60, n == 1440, n == 0 && allowForever:
		return n
	}
	return 60
}

// Server answers on port 443 and on whatever serves port 80.
type Server struct {
	// Explain fills in a page for a name asked for by a client.
	Explain func(ctx context.Context, host string, client netip.Addr) Page
	// Claims reports whether the resolver pointed a name here.
	Claims func(hostport string) bool
	// Allow limits TLS handshakes per client.
	Allow func(client netip.Addr) bool
	// Ask, Status and Self are the page's way to the owner: request the site,
	// see the answer, and for a trusted device open it without asking.
	Ask    func(host string, form AskForm, client netip.Addr) (AskState, error)
	Status func(host string, client netip.Addr) AskState
	Self   func(host string, minutes int, client netip.Addr) (AskState, error)
	// Leaf mints a certificate for a name from the Orbis CA.
	Leaf func(host string) (*tls.Certificate, error)
	// Guard learns which devices can show the page over HTTPS.
	Guard *Guard
	Log   func(string, ...any)

	mu  sync.Mutex
	srv *http.Server
}

// maxMinting bounds certificates signed at once. Each one is a signature with
// the CA key, tens of milliseconds on a Raspberry Pi that also answers DNS, so
// a device looping through names gets a failed handshake, not all four cores.
const maxMinting = 2

var errNotBlocked = errors.New("not a blocked name")

// hostname reports a plausible DNS name, and nothing else reaches the CA.
func hostname(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '-' || c == '_' {
			continue
		}
		return false
	}
	return true
}

// certificate answers a TLS hello: only for a name the resolver sent here, only
// to a device that has not been refusing them, and only as fast as the node can
// spare. Each refusal here leaves offered unset, because a handshake we ended
// says nothing about whether the client trusts the CA.
func (s *Server) certificate(hello *tls.ClientHelloInfo, offered *sync.Map, minting chan struct{}) (*tls.Certificate, error) {
	client := netip.Addr{}
	remote := ""
	if hello.Conn != nil {
		remote = hello.Conn.RemoteAddr().String()
		if ap, err := netip.ParseAddrPort(remote); err == nil {
			client = ap.Addr().Unmap()
		}
	}
	if s.Allow != nil && !s.Allow(client) {
		return nil, errors.New("too many handshakes from this client")
	}
	if s.Guard != nil && s.Guard.Refusing(client, time.Now()) {
		return nil, errors.New("this client does not trust the certificate")
	}
	name := hello.ServerName
	if !hostname(name) || (s.Claims != nil && !s.Claims(name)) {
		return nil, errNotBlocked
	}
	select {
	case minting <- struct{}{}:
		defer func() { <-minting }()
	default:
		return nil, errors.New("too many certificates at once")
	}
	cert, err := s.Leaf(name)
	if err == nil {
		offered.Store(remote, true)
	}
	return cert, err
}

// ServeHTTP renders the page for a browser opening the blocked site, and
// nothing at all for everything else. A blocked ad is a script or an image
// inside someone else's page, and it should fail quietly and fast.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Keep no connection open: this page exists to be left. A browser would
	// reuse one for its next try and land back here, even with the site allowed.
	w.Header().Set("Connection", "close")
	client := netip.Addr{}
	if ap, err := netip.ParseAddrPort(r.RemoteAddr); err == nil {
		client = ap.Addr().Unmap()
	}
	// Proof the CA is trusted needs a browser: a tool that skips verification
	// completes the handshake too, and must not vouch for the whole device.
	if r.TLS != nil && s.Guard != nil && (r.Header.Get("Sec-Fetch-Dest") != "" || opensDocument(r)) {
		s.Guard.Note(client, true, time.Now())
	}
	if r.URL.Path == "/__orbis/ask" || r.URL.Path == "/__orbis/self" {
		s.serveAsk(w, r, client)
		return
	}
	if face, ok := map[string][]byte{"/__orbis/geist.woff2": font, "/__orbis/geist-mono.woff2": monoFont}[r.URL.Path]; ok {
		w.Header().Set("Content-Type", "font/woff2")
		w.Header().Set("Cache-Control", "public, max-age=604800, immutable")
		_, _ = w.Write(face)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	if !opensDocument(r) {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	s.render(w, r, client, r.URL.RequestURI(), "")
}

func (s *Server) render(w http.ResponseWriter, r *http.Request, client netip.Addr, path, problem string) {
	page := s.Explain(r.Context(), hostOnly(r.Host), client)
	page.Nonce = nonce()
	page.Path, page.Problem = path, problem
	page.Reasons, page.Durations = reasons, durations(page.Risky)
	page.HostParts, page.Long = breakable(page.Host), len(page.Host) > 26
	var body bytes.Buffer
	if err := pageTemplate.Execute(&body, page); err != nil {
		http.Error(w, "this site is blocked by Orbis", http.StatusForbidden)
		return
	}
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Content-Security-Policy", "default-src 'none'; style-src 'nonce-"+page.Nonce+"'; script-src 'nonce-"+page.Nonce+"'; font-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
	h.Set("X-Content-Type-Options", "nosniff")
	// same-origin, not no-referrer: that would send the form with Origin: null.
	h.Set("Referrer-Policy", "same-origin")
	if page.Blocked {
		w.WriteHeader(http.StatusForbidden)
	}
	_, _ = w.Write(body.Bytes())
}

// serveAsk takes the page's forms. They are real form posts and not script
// calls, because a form is a navigation: a browser extension, a script error or
// a blip in the connection cannot quietly swallow it, and it works with
// JavaScript off. A request still becomes a notification on someone's phone, so
// it has to come from this page and not from one elsewhere.
func (s *Server) serveAsk(w http.ResponseWriter, r *http.Request, client netip.Addr) {
	host := hostOnly(r.Host)
	w.Header().Set("Cache-Control", "no-store")
	if s.Ask == nil || s.Status == nil || s.Self == nil || (s.Claims != nil && !s.Claims(host)) {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if r.Method == http.MethodGet {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(s.Status(host, client))
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if r.Method != http.MethodPost || !sameOrigin(r) || r.ParseForm() != nil {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	back := backPath(r.PostFormValue("back"))
	var err error
	if r.URL.Path == "/__orbis/self" {
		_, err = s.Self(host, minutesFrom(r.PostFormValue("minutes"), false), client)
	} else {
		_, err = s.Ask(host, AskForm{
			Reason:  offered(r.PostFormValue("reason")),
			Note:    r.PostFormValue("note"),
			Minutes: minutesFrom(r.PostFormValue("minutes"), true),
		}, client)
	}
	if err != nil {
		w.Header().Set("Referrer-Policy", "same-origin")
		s.render(w, r, client, back, err.Error())
		return
	}
	http.Redirect(w, r, back, http.StatusSeeOther)
}

func offered(reason string) string {
	for _, x := range reasons {
		if x == reason {
			return x
		}
	}
	return ""
}

// backPath keeps a return address on this site. Only the path survives, so the
// field cannot send anyone anywhere else.
func backPath(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host != "" || u.Scheme != "" || !strings.HasPrefix(u.Path, "/") ||
		strings.HasPrefix(u.Path, "//") || strings.HasPrefix(u.Path, "/__orbis") {
		return "/"
	}
	return u.RequestURI()
}

// sameOrigin holds a form to this page's own origin.
func sameOrigin(r *http.Request) bool {
	from := r.Header.Get("Origin")
	if from == "" || from == "null" {
		from = r.Header.Get("Referer")
	}
	u, err := url.Parse(from)
	return err == nil && u.Host != "" && u.Host == r.Host
}

// Approval is the page behind a one-tap link.
type Approval struct {
	Host, Device, Note, Reason, Why, State, Token, Wants string
	Risky                                                bool
	Nonce                                                string
	// Minutes is what they asked for, and Durations what can be given by link.
	Minutes   int
	Durations []Duration
}

// WriteApproval renders it.
func WriteApproval(w http.ResponseWriter, a Approval) {
	a.Nonce = nonce()
	a.Durations = []Duration{{15, "15 minutes", a.Minutes == 15}, {60, "1 hour", a.Minutes == 60 || a.Minutes == 0}, {1440, "Today", a.Minutes == 1440}}
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Content-Security-Policy", "default-src 'none'; style-src 'nonce-"+a.Nonce+"'; font-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
	h.Set("X-Content-Type-Options", "nosniff")
	// A token in the address must not leave in a Referer.
	h.Set("Referrer-Policy", "no-referrer")
	_ = approvalTemplate.Execute(w, a)
}

// opensDocument reports a browser navigating to the site, as opposed to a
// page loading something from it or an app calling it.
func opensDocument(r *http.Request) bool {
	if dest := r.Header.Get("Sec-Fetch-Dest"); dest != "" {
		return dest == "document"
	}
	return r.Method == http.MethodGet && strings.Contains(r.Header.Get("Accept"), "text/html")
}

func breakable(host string) []string {
	parts := strings.SplitAfter(host, ".")
	if n := len(parts); n > 1 && len(parts[n-1]) < 5 {
		// The top-level domain stays with the name before it.
		parts[n-2] += parts[n-1]
		parts = parts[:n-1]
	}
	return parts
}

func hostOnly(h string) string {
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	return strings.ToLower(strings.TrimSuffix(h, "."))
}

func nonce() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// ListenTLS serves the page on addr with a certificate for whichever name was
// asked for. A busy port is the caller's to report: the rest of Orbis does not
// depend on it.
func (s *Server) ListenTLS(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	var offered sync.Map // remote address that was sent our certificate
	minting := make(chan struct{}, maxMinting)
	srv := &http.Server{
		Handler:           s,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       30 * time.Second,
		// A blocked site's page is one small document; HTTP/1.1 is plenty.
		TLSNextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){},
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			NextProtos: []string{"http/1.1"},
			GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
				return s.certificate(hello, &offered, minting)
			},
		},
		ConnState: func(c net.Conn, st http.ConnState) {
			if st != http.StateClosed {
				return
			}
			// Only a client that saw the certificate and walked away refused
			// it. A port scan, or plain http sent to this port, did not.
			_, sent := offered.LoadAndDelete(c.RemoteAddr().String())
			tc, isTLS := c.(*tls.Conn)
			if !sent || !isTLS || s.Guard == nil || tc.ConnectionState().HandshakeComplete {
				return
			}
			if ap, err := netip.ParseAddrPort(c.RemoteAddr().String()); err == nil {
				s.Guard.Note(ap.Addr().Unmap(), false, time.Now())
			}
		},
		// A refused certificate is expected here, not worth a journal line.
		ErrorLog: log.New(io.Discard, "", 0),
	}
	s.mu.Lock()
	s.srv = srv
	s.mu.Unlock()
	go func() {
		if err := srv.ServeTLS(ln, "", ""); err != nil && !errors.Is(err, http.ErrServerClosed) && s.Log != nil {
			s.Log("blockpage: listener stopped: %v", err)
		}
	}()
	return nil
}

// Listening reports whether the HTTPS listener is up.
func (s *Server) Listening() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.srv != nil
}

func (s *Server) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.srv != nil {
		_ = s.srv.Close()
		s.srv = nil
	}
}

const (
	// rejectionsToFallBack is how many refused certificates with no success
	// stop this node offering a device HTTPS.
	rejectionsToFallBack = 3
	// fallBackFor is how long, so a device that installs the CA later gets
	// the page over HTTPS again without anyone touching anything.
	fallBackFor = time.Hour
	// trustedFor stops one pinned app from undoing what a browser proved.
	trustedFor = 7 * 24 * time.Hour
	// guardMaxClients bounds the table; a home network never reaches it.
	guardMaxClients = 4096
	// pointedFor is how long a name stays claimed after the resolver sent it
	// here. It outlasts the answer and a browser's own cache of it, and it is
	// what ends a claim once a name is unblocked.
	pointedFor = 5 * time.Minute
	// guardMaxNames bounds the names kept for that long.
	guardMaxNames = 8192
	// interfacesEvery is how often this node's own addresses are re-read.
	interfacesEvery = time.Minute
)

type trust struct {
	rejected int
	until    time.Time
	proven   time.Time
}

// Guard decides whether a device should be sent to the page at all, and what
// address it should use to get here.
type Guard struct {
	mu      sync.Mutex
	clients map[netip.Addr]*trust
	// pointed is every name just answered with this node, and when. This is
	// the only thing that reaches the page and the CA: the resolver's own
	// record of what it did, not a second opinion on what it would do.
	pointed map[string]time.Time
	swept   time.Time

	nets     []netip.Prefix
	netsRead time.Time
	// interfaces reads this node's addresses. Replaced in tests.
	interfaces func() ([]netip.Prefix, error)
}

func NewGuard() *Guard {
	return &Guard{clients: map[netip.Addr]*trust{}, pointed: map[string]time.Time{}, interfaces: localPrefixes}
}

func nameKey(name string) string {
	return strings.ToLower(strings.TrimSuffix(name, "."))
}

// remember records a name about to be pointed here. It reports false when the
// table cannot take it: a name sent here but not recorded would fall through to
// the interface, so such a name has to get the sinkhole.
func (g *Guard) remember(name string, now time.Time) bool {
	if _, known := g.pointed[name]; !known && len(g.pointed) >= guardMaxNames {
		if now.Sub(g.swept) < time.Minute {
			return false
		}
		g.swept = now
		for n, at := range g.pointed {
			if now.Sub(at) >= pointedFor {
				delete(g.pointed, n)
			}
		}
		if len(g.pointed) >= guardMaxNames {
			return false
		}
	}
	g.pointed[name] = now
	return true
}

// Pointed reports whether the resolver sent a name here within pointedFor.
func (g *Guard) Pointed(name string, now time.Time) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	key := nameKey(name)
	at, ok := g.pointed[key]
	if !ok || now.Sub(at) >= pointedFor {
		return false
	}
	// Someone waiting on the page should not lose it while they wait.
	g.pointed[key] = now
	return true
}

// Note records how a TLS connection from a client ended.
func (g *Guard) Note(client netip.Addr, ok bool, now time.Time) {
	g.mu.Lock()
	defer g.mu.Unlock()
	t := g.clients[client]
	if t == nil {
		if len(g.clients) >= guardMaxClients {
			g.clients = map[netip.Addr]*trust{}
		}
		t = &trust{}
		g.clients[client] = t
	}
	if ok {
		*t = trust{proven: now}
		return
	}
	if now.Sub(t.proven) < trustedFor {
		return
	}
	if t.rejected++; t.rejected >= rejectionsToFallBack {
		t.rejected, t.until = 0, now.Add(fallBackFor)
	}
}

// Refusing reports a device that has been turning down the certificate. It
// fails TLS at once rather than being sent the sinkhole, because the same answer
// serves plain http: a browser falling back from https then shows the page, with
// no CA installed at all.
func (g *Guard) Refusing(client netip.Addr, now time.Time) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	t := g.clients[client]
	return t != nil && now.Before(t.until)
}

// Forgive starts a device over, for when it has just fetched the CA.
func (g *Guard) Forgive(client netip.Addr) {
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.clients, client)
}

// AddrFor returns the address a client should be sent to for a blocked name, or
// false when it should get the plain sinkhole instead. It stakes a claim on the
// name, so it is the resolver's alone: a page that claimed its own Host would
// let anyone turn this node's address into a blocked site.
func (g *Guard) AddrFor(client netip.Addr, name string, now time.Time) (netip.Addr, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	addr, ok := g.reach(client, now)
	if !ok {
		return addr, false
	}
	return addr, g.remember(nameKey(name), now)
}

// Reach returns this node's address on a client's network, and claims nothing.
func (g *Guard) Reach(client netip.Addr, now time.Time) (netip.Addr, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.reach(client, now)
}

func (g *Guard) reach(client netip.Addr, now time.Time) (netip.Addr, bool) {
	if now.Sub(g.netsRead) > interfacesEvery {
		if nets, err := g.interfaces(); err == nil {
			g.nets, g.netsRead = nets, now
		}
	}
	for _, p := range g.nets {
		if p.Contains(client) {
			return p.Addr(), true
		}
	}
	return netip.Addr{}, false
}

// localPrefixes lists this node's IPv4 networks. A client on one of them can
// reach the address Orbis holds there; anything else, including this node
// looking itself up on loopback, gets the sinkhole.
func localPrefixes() ([]netip.Prefix, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var out []netip.Prefix
	for _, i := range ifs {
		if i.Flags&net.FlagUp == 0 || i.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := i.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			n, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip, ok := netip.AddrFromSlice(n.IP.To4())
			if !ok {
				continue
			}
			ones, _ := n.Mask.Size()
			if i.Name != "" && strings.HasPrefix(i.Name, "tailscale") {
				ones = 10 // the tailnet is 100.64.0.0/10 however the interface reports it
			}
			out = append(out, netip.PrefixFrom(ip, ones))
		}
	}
	return out, nil
}

// Sentence puts a list category into words.
func Sentence(category string) string {
	switch strings.ToLower(category) {
	case "ads", "advertising":
		return "ads"
	case "tracking", "trackers", "privacy":
		return "tracking"
	case "malware", "threat", "threats", "security":
		return "malware and other threats"
	case "phishing", "scam":
		return "phishing and scams"
	case "bypass":
		return "tools that get around this network's filtering"
	case "manual":
		return "sites blocked by hand"
	case "":
		return ""
	}
	return fmt.Sprintf("%s sites", strings.ToLower(category))
}
