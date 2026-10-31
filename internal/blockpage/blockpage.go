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
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"
)

//go:embed page.html
var pageHTML string

//go:embed geist.woff2
var font []byte

var pageTemplate = template.Must(template.New("page").Parse(pageHTML))

// Station is one stop on the line drawn from the device to the decision.
type Station struct {
	Title  string
	Detail string
	// Class is "" for a stage that was passed, "clear" for the device and the
	// resolver, "decided" for the stage that stopped the request and
	// "unreached" for what the request never got to.
	Class string
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
	When     string
	AdminURL string
	Copy     string
	Nonce    string
	// HostParts lets a long name wrap at its dots, not in the middle of a word.
	HostParts []string
	Long      bool
}

// Server answers on port 443 and on whatever serves port 80.
type Server struct {
	// Explain fills in a page for a name asked for by a client.
	Explain func(ctx context.Context, host string, client netip.Addr) Page
	// Leaf mints a certificate for a name from the Orbis CA.
	Leaf func(host string) (*tls.Certificate, error)
	// Guard learns which devices can show the page over HTTPS.
	Guard *Guard
	Log   func(string, ...any)

	srv *http.Server
}

// ServeHTTP renders the page for a browser opening the blocked site, and
// nothing at all for everything else. A blocked ad is a script or an image
// inside someone else's page, and it should fail quietly and fast.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/__orbis/geist.woff2" {
		w.Header().Set("Content-Type", "font/woff2")
		w.Header().Set("Cache-Control", "public, max-age=604800, immutable")
		_, _ = w.Write(font)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	if !opensDocument(r) {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	client := netip.Addr{}
	if ap, err := netip.ParseAddrPort(r.RemoteAddr); err == nil {
		client = ap.Addr().Unmap()
	}
	page := s.Explain(r.Context(), hostOnly(r.Host), client)
	page.Nonce = nonce()
	page.HostParts, page.Long = breakable(page.Host), len(page.Host) > 26
	var body bytes.Buffer
	if err := pageTemplate.Execute(&body, page); err != nil {
		http.Error(w, "this site is blocked by Orbis", http.StatusForbidden)
		return
	}
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Content-Security-Policy", "default-src 'none'; style-src 'nonce-"+page.Nonce+"'; script-src 'nonce-"+page.Nonce+"'; font-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	if page.Blocked {
		w.WriteHeader(http.StatusForbidden)
	}
	_, _ = w.Write(body.Bytes())
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
	var seen sync.Map // net.Conn that sent a request or finished a handshake
	s.srv = &http.Server{
		Handler:           s,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       30 * time.Second,
		// A blocked site's page is one small document; HTTP/1.1 is plenty.
		TLSNextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){},
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			NextProtos: []string{"http/1.1"},
			GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
				name := hello.ServerName
				if name == "" {
					name = "orbis.lan"
				}
				return s.Leaf(name)
			},
		},
		ConnState: func(c net.Conn, st http.ConnState) {
			switch st {
			case http.StateActive:
				seen.Store(c, true)
			case http.StateClosed:
				_, ok := seen.LoadAndDelete(c)
				tc, isTLS := c.(*tls.Conn)
				if !isTLS || s.Guard == nil {
					return
				}
				ok = ok || tc.ConnectionState().HandshakeComplete
				if ap, err := netip.ParseAddrPort(c.RemoteAddr().String()); err == nil {
					s.Guard.Note(ap.Addr().Unmap(), ok, time.Now())
				}
			}
		},
		// A refused certificate is expected here, not worth a journal line.
		ErrorLog: log.New(io.Discard, "", 0),
	}
	go func() {
		if err := s.srv.ServeTLS(ln, "", ""); err != nil && !errors.Is(err, http.ErrServerClosed) && s.Log != nil {
			s.Log("blockpage: listener stopped: %v", err)
		}
	}()
	return nil
}

func (s *Server) Close() {
	if s.srv != nil {
		_ = s.srv.Close()
	}
}

const (
	// rejectionsToFallBack is how many refused certificates with no success
	// send a device back to the plain sinkhole.
	rejectionsToFallBack = 3
	// fallBackFor is how long, so a device that installs the CA later gets
	// the page again without anyone touching anything.
	fallBackFor = 24 * time.Hour
	// trustedFor stops one pinned app from undoing what a browser proved.
	trustedFor = 7 * 24 * time.Hour
	// guardMaxClients bounds the table; a home network never reaches it.
	guardMaxClients = 4096
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

	nets     []netip.Prefix
	netsRead time.Time
	// interfaces reads this node's addresses. Replaced in tests.
	interfaces func() ([]netip.Prefix, error)
}

func NewGuard() *Guard {
	return &Guard{clients: map[netip.Addr]*trust{}, interfaces: localPrefixes}
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

// AddrFor returns the address a client should be sent to for the page, or
// false when it should get the plain sinkhole instead.
func (g *Guard) AddrFor(client netip.Addr, now time.Time) (netip.Addr, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if t := g.clients[client]; t != nil && now.Before(t.until) {
		return netip.Addr{}, false
	}
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
