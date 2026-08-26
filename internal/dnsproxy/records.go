package dnsproxy

import (
	"net/netip"
	"strings"

	"github.com/miekg/dns"
)

// Local DNS records. This is what turns Orbis from a filtering resolver into a
// resolver that is also authoritative for your own names: nas.home, the
// printer, a CNAME alias, an MX for a local mail box.
//
// It sits ahead of the DHCP-derived records and the upstream, because an
// operator-defined record is an explicit instruction and must win over both a
// lease that happens to share a name and whatever the internet would say.

// LocalRecord is one operator-defined record. Kept transport-neutral (no
// dependency on the config or store packages) so it can be built from either.
type LocalRecord struct {
	Name  string // fully-qualified or bare; matched case-insensitively
	Type  string // A, AAAA, CNAME, TXT, MX, SRV, NS, PTR
	Value string
	TTL   uint32
	// Priority/Weight/Port carry the numeric fields MX and SRV need. Zero when
	// the type does not use them.
	Priority uint16
	Weight   uint16
	Port     uint16
}

// RecordSet is an indexed, lookup-ready view of the records, rebuilt whenever
// the operator changes them. A map keyed on the lower-cased name keeps a query
// to one hash lookup regardless of how many records exist.
type RecordSet struct {
	byName map[string][]LocalRecord
	// wildcards holds records whose name begins with "*." , checked only when
	// an exact match misses so the common path stays fast.
	wildcards []LocalRecord
}

// BuildRecordSet indexes records for lookup. A name is stored without its
// trailing dot and lower-cased so matching does not care about either.
func BuildRecordSet(records []LocalRecord) *RecordSet {
	rs := &RecordSet{byName: map[string][]LocalRecord{}}
	for _, r := range records {
		r.Name = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(r.Name), "."))
		r.Type = strings.ToUpper(strings.TrimSpace(r.Type))
		if r.Name == "" || r.Type == "" || r.Value == "" {
			continue
		}
		if r.TTL == 0 {
			r.TTL = 300
		}
		if strings.HasPrefix(r.Name, "*.") {
			rs.wildcards = append(rs.wildcards, r)
			continue
		}
		rs.byName[r.Name] = append(rs.byName[r.Name], r)
	}
	return rs
}

// Lookup answers a question from the local records, or returns nil. A CNAME is
// returned for any query type (the client re-queries the target), matching how
// every resolver handles an alias.
func (rs *RecordSet) Lookup(qname string, qtype uint16) []dns.RR {
	if rs == nil {
		return nil
	}
	name := strings.ToLower(strings.TrimSuffix(qname, "."))
	recs := rs.byName[name]
	if len(recs) == 0 {
		recs = rs.matchWildcard(name)
	}
	if len(recs) == 0 {
		return nil
	}

	var out []dns.RR
	// A CNAME shadows every other type for a name, so if one exists it is the
	// only answer, whatever was asked for.
	for _, r := range recs {
		if r.Type == "CNAME" {
			if rr := toRR(qname, r); rr != nil {
				return []dns.RR{rr}
			}
		}
	}
	want := dns.TypeToString[qtype]
	for _, r := range recs {
		if r.Type != want {
			continue
		}
		if rr := toRR(qname, r); rr != nil {
			out = append(out, rr)
		}
	}
	return out
}

// Has reports whether a name has any local record at all, so the resolver can
// answer NODATA (empty NOERROR) rather than leaking the query upstream for a
// name it owns but has no record of the requested type for.
func (rs *RecordSet) Has(qname string) bool {
	if rs == nil {
		return false
	}
	name := strings.ToLower(strings.TrimSuffix(qname, "."))
	if len(rs.byName[name]) > 0 {
		return true
	}
	return len(rs.matchWildcard(name)) > 0
}

func (rs *RecordSet) matchWildcard(name string) []LocalRecord {
	var out []LocalRecord
	for _, r := range rs.wildcards {
		base := r.Name[2:] // strip "*."
		if name == base || strings.HasSuffix(name, "."+base) {
			out = append(out, r)
		}
	}
	return out
}

// toRR converts one local record into a miekg/dns resource record. An entry
// that cannot be represented (a bad address, say) yields nil rather than a
// malformed answer.
func toRR(qname string, r LocalRecord) dns.RR {
	hdr := func(t uint16) dns.RR_Header {
		return dns.RR_Header{Name: qname, Rrtype: t, Class: dns.ClassINET, Ttl: r.TTL}
	}
	switch r.Type {
	case "A":
		addr, err := netip.ParseAddr(r.Value)
		if err != nil || !addr.Is4() {
			return nil
		}
		return &dns.A{Hdr: hdr(dns.TypeA), A: addr.AsSlice()}
	case "AAAA":
		addr, err := netip.ParseAddr(r.Value)
		if err != nil || !addr.Is6() || addr.Is4In6() {
			return nil
		}
		return &dns.AAAA{Hdr: hdr(dns.TypeAAAA), AAAA: addr.AsSlice()}
	case "CNAME":
		return &dns.CNAME{Hdr: hdr(dns.TypeCNAME), Target: dns.Fqdn(r.Value)}
	case "TXT":
		return &dns.TXT{Hdr: hdr(dns.TypeTXT), Txt: chunkTXT(r.Value)}
	case "MX":
		return &dns.MX{Hdr: hdr(dns.TypeMX), Preference: r.Priority, Mx: dns.Fqdn(r.Value)}
	case "NS":
		return &dns.NS{Hdr: hdr(dns.TypeNS), Ns: dns.Fqdn(r.Value)}
	case "SRV":
		return &dns.SRV{
			Hdr: hdr(dns.TypeSRV), Priority: r.Priority, Weight: r.Weight,
			Port: r.Port, Target: dns.Fqdn(r.Value),
		}
	case "PTR":
		return &dns.PTR{Hdr: hdr(dns.TypePTR), Ptr: dns.Fqdn(r.Value)}
	}
	return nil
}

// chunkTXT splits a long string into the 255-byte segments a TXT record stores,
// so a DKIM key or a long verification token is served correctly rather than
// truncated.
func chunkTXT(s string) []string {
	const max = 255
	if len(s) <= max {
		return []string{s}
	}
	var out []string
	for len(s) > max {
		out = append(out, s[:max])
		s = s[max:]
	}
	if len(s) > 0 {
		out = append(out, s)
	}
	return out
}

// ValidateRecord checks a record before it is stored, returning a human message
// on failure. Catching a bad address here means the operator sees it in the UI
// rather than wondering why a lookup silently returns nothing.
func ValidateRecord(r LocalRecord) string {
	name := strings.TrimSpace(r.Name)
	if name == "" {
		return "name is required"
	}
	if strings.TrimSpace(r.Value) == "" {
		return "value is required"
	}
	switch strings.ToUpper(strings.TrimSpace(r.Type)) {
	case "A":
		if a, err := netip.ParseAddr(r.Value); err != nil || !a.Is4() {
			return "A record needs an IPv4 address"
		}
	case "AAAA":
		if a, err := netip.ParseAddr(r.Value); err != nil || !a.Is6() || a.Is4In6() {
			return "AAAA record needs an IPv6 address"
		}
	case "CNAME", "NS", "PTR", "TXT":
		// A hostname or free text; nothing to reject beyond emptiness.
	case "MX":
		if r.Priority == 0 {
			// 0 is legal but almost always a mistake left unset.
		}
	case "SRV":
		if r.Port == 0 {
			return "SRV record needs a port"
		}
	default:
		return "unsupported type " + r.Type + " (use A, AAAA, CNAME, TXT, MX, NS, SRV or PTR)"
	}
	return ""
}

