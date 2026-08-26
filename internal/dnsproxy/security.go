package dnsproxy

import (
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// ---- rate limiting ----

// RateLimiter is a per-client token bucket over a one-second window. It exists
// to stop this resolver being used as an amplifier: an open resolver reachable
// beyond the LAN will be enrolled in a reflection attack within hours, and the
// victim sees the traffic as coming from here.
//
// The window is coarse on purpose. Precise smoothing would cost a timer per
// client; a resolver only needs to distinguish "a browser opening a page" from
// "a flood", and a whole-second bucket does that.
type RateLimiter struct {
	mu      sync.Mutex
	buckets map[netip.Addr]*bucket
	limit   int
	lastGC  time.Time
}

type bucket struct {
	count  int
	window int64 // unix second this count belongs to
	seen   time.Time
}

func NewRateLimiter(limit int) *RateLimiter {
	return &RateLimiter{buckets: map[netip.Addr]*bucket{}, limit: limit}
}

// SetLimit updates the cap. Zero or negative disables limiting entirely.
func (r *RateLimiter) SetLimit(n int) {
	r.mu.Lock()
	r.limit = n
	r.mu.Unlock()
}

// Allow reports whether this client may make another query now.
func (r *RateLimiter) Allow(client netip.Addr, now time.Time) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.limit <= 0 {
		return true
	}
	sec := now.Unix()
	b, ok := r.buckets[client]
	if !ok {
		b = &bucket{}
		r.buckets[client] = b
	}
	if b.window != sec {
		b.window = sec
		b.count = 0
	}
	b.count++
	b.seen = now
	allowed := b.count <= r.limit

	// Opportunistic sweep so a network that has seen many short-lived
	// addresses does not grow this map without bound.
	if now.Sub(r.lastGC) > time.Minute {
		r.lastGC = now
		for addr, bk := range r.buckets {
			if now.Sub(bk.seen) > 2*time.Minute {
				delete(r.buckets, addr)
			}
		}
	}
	return allowed
}

// ---- DNS rebinding protection ----

// rebindNets are the ranges an answer from the public internet has no business
// pointing at. A page on the attacker's domain that resolves to 192.168.1.1
// can drive requests against the victim's router from inside their browser,
// with the browser's same-origin policy satisfied. Refusing those answers is
// the standard defence and costs nothing on legitimate traffic.
var rebindNets = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"),
}

// IsRebindAddr reports whether addr is in private or otherwise local space.
func IsRebindAddr(addr netip.Addr) bool {
	addr = addr.Unmap()
	for _, p := range rebindNets {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// RebindAllowed reports whether name is exempt from rebinding protection.
// The local domain and any operator-listed suffix are exempt, because
// resolving internal names to internal addresses is the entire point of a
// local resolver and would otherwise trip this check constantly.
func RebindAllowed(name string, localDomain string, allowlist []string) bool {
	n := strings.ToLower(strings.TrimSuffix(name, "."))
	if localDomain != "" {
		d := strings.ToLower(strings.TrimSuffix(localDomain, "."))
		if n == d || strings.HasSuffix(n, "."+d) {
			return true
		}
	}
	// Reverse lookups and service discovery are local by definition.
	for _, suffix := range []string{"in-addr.arpa", "ip6.arpa", "local", "home.arpa", "internal", "lan"} {
		if n == suffix || strings.HasSuffix(n, "."+suffix) {
			return true
		}
	}
	for _, a := range allowlist {
		if domainMatches(n, strings.ToLower(strings.TrimSuffix(a, "."))) {
			return true
		}
	}
	return false
}

// StripRebind removes A/AAAA records pointing into local space and reports how
// many it dropped. The rest of the answer is preserved: a legitimate record set
// that happens to include one bad address should lose that address, not the
// whole response.
func StripRebind(m *dns.Msg) int {
	if m == nil {
		return 0
	}
	dropped := 0
	filter := func(in []dns.RR) []dns.RR {
		out := in[:0]
		for _, rr := range in {
			var addr netip.Addr
			switch v := rr.(type) {
			case *dns.A:
				addr, _ = netip.AddrFromSlice(v.A)
			case *dns.AAAA:
				addr, _ = netip.AddrFromSlice(v.AAAA)
			default:
				out = append(out, rr)
				continue
			}
			if addr.IsValid() && IsRebindAddr(addr) {
				dropped++
				continue
			}
			out = append(out, rr)
		}
		return out
	}
	m.Answer = filter(m.Answer)
	m.Extra = filter(m.Extra)
	return dropped
}
