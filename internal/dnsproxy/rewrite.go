package dnsproxy

import (
	"net/netip"
	"strings"

	"github.com/Neoo-Blue/orbis/internal/config"
	"github.com/miekg/dns"
)

// Rewrites answer a name locally instead of forwarding it. They cover the
// cases a hosts file used to: pinning an internal service to an internal
// address, forcing a name to a sinkhole, or aliasing one name onto another.
//
// A rewrite is checked before the cache and before blocking, because it is an
// explicit operator instruction and should not be second-guessed by a list.

// ApplyRewrite builds an answer for name from the first matching rewrite rule,
// or returns nil when none match. A rule whose Answer is a bare address
// produces an A or AAAA; anything else is treated as a CNAME target.
func ApplyRewrite(rules []config.DNSRewrite, r *dns.Msg, q dns.Question, name string) *dns.Msg {
	for _, rule := range rules {
		if rule.Domain == "" || rule.Answer == "" {
			continue
		}
		if !domainMatches(name, strings.ToLower(strings.TrimSuffix(rule.Domain, "."))) {
			continue
		}
		m := new(dns.Msg)
		m.SetReply(r)
		m.Authoritative = true

		// "#" is the conventional shorthand for "answer with nothing", which
		// is how a rewrite expresses a block without inventing an address.
		if rule.Answer == "#" {
			m.Rcode = dns.RcodeNameError
			return m
		}

		if addr, err := netip.ParseAddr(rule.Answer); err == nil {
			ttl := uint32(rule.TTL)
			if ttl == 0 {
				ttl = 300
			}
			hdr := dns.RR_Header{Name: q.Name, Class: dns.ClassINET, Ttl: ttl}
			switch {
			case addr.Is4() && q.Qtype == dns.TypeA:
				hdr.Rrtype = dns.TypeA
				m.Answer = append(m.Answer, &dns.A{Hdr: hdr, A: addr.AsSlice()})
			case addr.Is6() && !addr.Is4In6() && q.Qtype == dns.TypeAAAA:
				hdr.Rrtype = dns.TypeAAAA
				m.Answer = append(m.Answer, &dns.AAAA{Hdr: hdr, AAAA: addr.AsSlice()})
			}
			// A matching rule with the wrong family still answers, with an
			// empty NOERROR. Falling through to the upstream would leak the
			// real address for the other record type and defeat the rewrite.
			return m
		}

		ttl := uint32(rule.TTL)
		if ttl == 0 {
			ttl = 300
		}
		target := dns.Fqdn(rule.Answer)
		m.Answer = append(m.Answer, &dns.CNAME{
			Hdr:    dns.RR_Header{Name: q.Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: ttl},
			Target: target,
		})
		return m
	}
	return nil
}

// MatchForwardZone returns the normalised domain of the most specific
// conditional-forward zone covering name, or "" when none match.
//
// Most specific wins so that a general rule for "internal.example" and a
// narrower one for "db.internal.example" can coexist, which is the usual
// reason to configure this at all. The domain is the key into the resolver's
// pre-parsed upstream pools.
func MatchForwardZone(zones []config.ForwardZone, name string) string {
	n := strings.ToLower(strings.TrimSuffix(name, "."))
	best := ""
	for _, z := range zones {
		if len(z.Upstreams) == 0 {
			continue
		}
		d := strings.ToLower(strings.TrimSuffix(z.Domain, "."))
		if d == "" {
			continue
		}
		if n != d && !strings.HasSuffix(n, "."+d) {
			continue
		}
		if len(d) > len(best) {
			best = d
		}
	}
	return best
}
