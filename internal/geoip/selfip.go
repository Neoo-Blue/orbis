package geoip

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// SelfLocator discovers the node's own public address so the globe can place
// it correctly. A node behind NAT has no public address on any interface, and
// guessing from the timezone puts a Californian network in the middle of the
// Atlantic.
//
// The address is discovered over DNS by preference: the queries below ask a
// resolver to echo back the source address it saw, which is a single UDP
// exchange with a resolver the node already talks to. The *geolocation* then
// happens against the local MaxMind database, so the node's position is never
// sent anywhere.
type SelfLocator struct {
	resolver *Resolver
	log      func(string, ...any)

	mu        sync.RWMutex
	addr      netip.Addr
	loc       Location
	lastCheck time.Time
	lastErr   string
	method    string
	enabled   bool
}

func NewSelfLocator(r *Resolver, log func(string, ...any)) *SelfLocator {
	if log == nil {
		log = func(string, ...any) {}
	}
	return &SelfLocator{resolver: r, log: log, enabled: true}
}

func (s *SelfLocator) SetEnabled(v bool) {
	s.mu.Lock()
	s.enabled = v
	if !v {
		s.addr = netip.Addr{}
		s.loc = Location{}
		s.method = ""
	}
	s.mu.Unlock()
}

// Location returns the cached public location, if one has been discovered.
func (s *SelfLocator) Location() (Location, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if !s.addr.IsValid() || (s.loc.Lat == 0 && s.loc.Lon == 0) {
		return Location{}, false
	}
	return s.loc, true
}

func (s *SelfLocator) Status() map[string]any {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := map[string]any{"enabled": s.enabled}
	if s.addr.IsValid() {
		// The address itself is deliberately not returned in full: it is the
		// operator's home address, and the UI only needs to say where it is.
		out["public_ip"] = maskAddr(s.addr)
		out["method"] = s.method
		out["city"] = s.loc.City
		out["country"] = s.loc.Country
		out["lat"] = s.loc.Lat
		out["lon"] = s.loc.Lon
		out["checked"] = s.lastCheck
	}
	if s.lastErr != "" {
		out["last_error"] = s.lastErr
	}
	return out
}

// maskAddr keeps enough of an address to be recognisable without printing it
// whole into a screenshot.
func maskAddr(a netip.Addr) string {
	s := a.String()
	if a.Is4() {
		parts := strings.Split(s, ".")
		if len(parts) == 4 {
			return parts[0] + "." + parts[1] + ".x.x"
		}
	}
	if i := strings.LastIndex(s, ":"); i > 0 {
		return s[:i] + ":…"
	}
	return s
}

// Refresh discovers the public address and geolocates it. Safe to call on a
// timer; a residential address can change at any reconnect.
func (s *SelfLocator) Refresh(ctx context.Context) error {
	s.mu.RLock()
	enabled := s.enabled
	s.mu.RUnlock()
	if !enabled {
		return nil
	}

	addr, method, err := DiscoverPublicIP(ctx)
	if err != nil {
		s.mu.Lock()
		s.lastErr = err.Error()
		s.lastCheck = time.Now()
		s.mu.Unlock()
		return err
	}
	loc := s.resolver.LookupAddr(addr)

	s.mu.Lock()
	s.addr = addr
	s.loc = loc
	s.method = method
	s.lastErr = ""
	s.lastCheck = time.Now()
	s.mu.Unlock()

	where := loc.City
	if where == "" {
		where = loc.Country
	}
	if where == "" {
		where = "unknown location"
	}
	s.log("geoip: this node appears to be in %s (via %s)", where, method)
	return nil
}

// Run keeps the discovered address fresh.
func (s *SelfLocator) Run(ctx context.Context) {
	// A short initial delay lets the network settle after boot; a query sent
	// before the default route exists just fails and burns a retry.
	select {
	case <-ctx.Done():
		return
	case <-time.After(5 * time.Second):
	}
	if err := s.Refresh(ctx); err != nil {
		s.log("geoip: could not determine the public address (%v); the globe will fall back to the configured timezone", err)
	}
	t := time.NewTicker(6 * time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			_ = s.Refresh(ctx)
		}
	}
}

// probe describes one way to ask "what address do you see me coming from".
type probe struct {
	name string
	fn   func(context.Context) (netip.Addr, error)
}

// DiscoverPublicIP tries several independent methods and returns the first
// answer. They are ordered DNS-first: a DNS query is one UDP round trip to a
// resolver the node already uses, whereas the HTTPS fallbacks involve a TLS
// handshake with a third party.
func DiscoverPublicIP(ctx context.Context) (netip.Addr, string, error) {
	probes := []probe{
		{"cloudflare-dns", func(c context.Context) (netip.Addr, error) {
			// whoami.cloudflare in the CHAOS class returns the client address
			// as a TXT record.
			return dnsProbe(c, "1.1.1.1:53", "whoami.cloudflare.", dns.TypeTXT, dns.ClassCHAOS)
		}},
		{"opendns", func(c context.Context) (netip.Addr, error) {
			return dnsProbe(c, "208.67.222.222:53", "myip.opendns.com.", dns.TypeA, dns.ClassINET)
		}},
		{"google-dns", func(c context.Context) (netip.Addr, error) {
			return dnsProbe(c, "216.239.32.10:53", "o-o.myaddr.l.google.com.", dns.TypeTXT, dns.ClassINET)
		}},
		{"cloudflare-trace", func(c context.Context) (netip.Addr, error) {
			return httpProbe(c, "https://1.1.1.1/cdn-cgi/trace")
		}},
		{"icanhazip", func(c context.Context) (netip.Addr, error) {
			return httpProbe(c, "https://ipv4.icanhazip.com")
		}},
	}

	var errs []string
	for _, p := range probes {
		pctx, cancel := context.WithTimeout(ctx, 6*time.Second)
		addr, err := p.fn(pctx)
		cancel()
		if err == nil && addr.IsValid() && !IsPrivate(addr) {
			return addr, p.name, nil
		}
		if err != nil {
			errs = append(errs, p.name+": "+err.Error())
		} else {
			errs = append(errs, p.name+": returned a private address")
		}
	}
	return netip.Addr{}, "", fmt.Errorf("every method failed (%s)", strings.Join(errs, "; "))
}

// dnsProbe asks a resolver to echo the source address it saw.
func dnsProbe(ctx context.Context, server, name string, qtype, qclass uint16) (netip.Addr, error) {
	m := new(dns.Msg)
	m.Id = dns.Id()
	m.RecursionDesired = true
	m.Question = []dns.Question{{Name: name, Qtype: qtype, Qclass: qclass}}

	// The query goes straight to the named resolver rather than through the
	// local one: the whole point is to learn what that specific server sees.
	c := &dns.Client{Net: "udp", Timeout: 5 * time.Second}
	resp, _, err := c.ExchangeContext(ctx, m, server)
	if err != nil {
		return netip.Addr{}, err
	}
	for _, rr := range resp.Answer {
		switch v := rr.(type) {
		case *dns.A:
			if a, ok := netip.AddrFromSlice(v.A.To4()); ok {
				return a, nil
			}
		case *dns.TXT:
			for _, txt := range v.Txt {
				if a, err := netip.ParseAddr(strings.TrimSpace(txt)); err == nil {
					return a, nil
				}
			}
		}
	}
	return netip.Addr{}, fmt.Errorf("no address in the answer")
}

// httpProbe is the fallback for networks that block outbound DNS to anything
// but their own resolver.
func httpProbe(ctx context.Context, url string) (netip.Addr, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return netip.Addr{}, err
	}
	req.Header.Set("User-Agent", "orbis/1.0")
	client := &http.Client{
		Timeout: 6 * time.Second,
		Transport: &http.Transport{
			// Force IPv4: a node with both will otherwise report whichever
			// the dialer happened to pick, and the globe wants the address
			// the operator's traffic actually leaves from.
			DialContext: func(c context.Context, _, addr string) (net.Conn, error) {
				return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(c, "tcp4", addr)
			},
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return netip.Addr{}, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return netip.Addr{}, err
	}
	text := string(body)
	// cdn-cgi/trace is a key=value block; the plain services return the bare
	// address on one line.
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if v, ok := strings.CutPrefix(line, "ip="); ok {
			line = v
		}
		if a, err := netip.ParseAddr(line); err == nil {
			return a, nil
		}
	}
	return netip.Addr{}, fmt.Errorf("no address in the response")
}
