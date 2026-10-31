package dnsproxy

import (
	"testing"
	"time"

	"github.com/miekg/dns"
)

func aQuestion(name string) dns.Question {
	return dns.Question{Name: name, Qtype: dns.TypeA, Qclass: dns.ClassINET}
}

func aAnswer(q dns.Question, ttl uint32) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(q.Name, q.Qtype)
	m.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl}, A: []byte{1, 2, 3, 4}}}
	return m
}

func negativeAnswer(q dns.Question, rcode int, soaTTL, minimum uint32) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(q.Name, q.Qtype)
	m.Rcode = rcode
	m.Ns = []dns.RR{&dns.SOA{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: soaTTL},
		Ns: "ns.example.com.", Mbox: "h.example.com.", Minttl: minimum}}
	return m
}

func entryOf(t *testing.T, c *Cache, q dns.Question) *cacheEntry {
	t.Helper()
	el, ok := c.entries[cacheKey(q, false)]
	if !ok {
		t.Fatalf("%s is not cached", q.Name)
	}
	return el.Value.(*cacheEntry)
}

func TestCacheKeepsAnAnswerExactlyAsLongAsItsTTL(t *testing.T) {
	c := NewCache(10)
	q := aQuestion("example.com.")
	c.Put(q, false, aAnswer(q, 60), 86400)
	if got := time.Until(entryOf(t, c, q).expires); got < 59*time.Second || got > 60*time.Second {
		t.Fatalf("a 60 s record lives %v", got)
	}
	if _, ok := c.Get(q, false); !ok {
		t.Fatal("a fresh answer must be served")
	}
	entryOf(t, c, q).expires = time.Now().Add(-time.Millisecond)
	if _, ok := c.Get(q, false); ok {
		t.Fatal("an answer past its TTL must never be served")
	}
	if len(c.entries) != 0 {
		t.Fatal("an expired answer must be dropped")
	}
}

func TestCacheDoesNotStoreTTLZeroOrFailures(t *testing.T) {
	c := NewCache(10)
	q := aQuestion("example.com.")
	c.Put(q, false, aAnswer(q, 0), 86400)
	if len(c.entries) != 0 {
		t.Fatal("TTL 0 means do not cache")
	}

	// A zero anywhere in a chain governs the whole answer.
	chain := aAnswer(q, 300)
	chain.Answer = append(chain.Answer,
		&dns.A{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 0}, A: []byte{1, 2, 3, 5}},
		&dns.A{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: []byte{1, 2, 3, 6}})
	c.Put(q, false, chain, 86400)
	if len(c.entries) != 0 {
		t.Fatal("a TTL 0 record in the middle of an answer was forgotten")
	}

	for _, rcode := range []int{dns.RcodeServerFailure, dns.RcodeRefused} {
		c.Put(q, false, negativeAnswer(q, rcode, 300, 300), 86400)
		if len(c.entries) != 0 {
			t.Fatalf("%s must never be cached", dns.RcodeToString[rcode])
		}
	}
}

func TestCacheNegativeAnswersAreBriefAndClientsAreHeldToIt(t *testing.T) {
	c := NewCache(10)
	q := aQuestion("new.example.com.")
	for _, m := range []*dns.Msg{negativeAnswer(q, dns.RcodeNameError, 1800, 3600), negativeAnswer(q, dns.RcodeSuccess, 1800, 3600)} {
		c.Put(q, false, m, 86400)
		if got := time.Until(entryOf(t, c, q).expires); got > maxNegativeTTL*time.Second {
			t.Fatalf("rcode %d kept for %v", m.Rcode, got)
		}
		if got := m.Ns[0].Header().Ttl; got > maxNegativeTTL {
			t.Fatalf("the client was handed a negative TTL of %d", got)
		}
	}

	// RFC 2308: the SOA minimum applies when it is lower.
	c.Put(q, false, negativeAnswer(q, dns.RcodeNameError, 1800, 5), 86400)
	if got := time.Until(entryOf(t, c, q).expires); got > 5*time.Second {
		t.Fatalf("SOA minimum 5 kept for %v", got)
	}

	// No SOA says nothing about how long the name stays absent.
	bare := new(dns.Msg)
	bare.Rcode = dns.RcodeNameError
	fresh := aQuestion("bare.example.com.")
	c.Put(fresh, false, bare, 86400)
	if _, ok := c.entries[cacheKey(fresh, false)]; ok {
		t.Fatal("a negative answer with no SOA must not be cached")
	}
}

func TestCacheMaxTTLBoundsTheClientToo(t *testing.T) {
	c := NewCache(10)
	q := aQuestion("example.com.")
	m := aAnswer(q, 604800)
	c.Put(q, false, m, 86400)
	if got := m.Answer[0].Header().Ttl; got != 86400 {
		t.Fatalf("client TTL = %d, want 86400", got)
	}
}

func TestAdjustTTLLeavesEDNSFlagsAlone(t *testing.T) {
	m := new(dns.Msg)
	m.SetEdns0(4096, true)
	before := m.IsEdns0().Hdr.Ttl
	adjustTTL(m, 100)
	capTTLs(m, 5)
	if got := m.IsEdns0(); got.Hdr.Ttl != before || !got.Do() {
		t.Fatalf("OPT flags changed: %#x -> %#x", before, got.Hdr.Ttl)
	}
}

func TestDueRefreshOnlyTouchesNamesInUse(t *testing.T) {
	c := NewCache(10)
	q := aQuestion("example.com.")
	now := time.Now()
	c.Put(q, false, aAnswer(q, 300), 86400)

	if len(c.DueRefresh(now, 10)) != 0 {
		t.Fatal("a fresh answer is not due")
	}
	// Age the entry into its last tenth: 300 s life, 20 s left.
	e := entryOf(t, c, q)
	e.inserted, e.expires = now.Add(-280*time.Second), now.Add(20*time.Second)
	if len(c.DueRefresh(now, 10)) != 1 {
		t.Fatal("an answer with a tenth of its life left is due")
	}
	if len(c.DueRefresh(now, 10)) != 0 {
		t.Fatal("a second sweep must not start a second refresh")
	}
	if got := c.Stats()["prefetches"]; got != int64(1) {
		t.Fatalf("prefetches = %v, want 1", got)
	}

	// The refresh replaces the entry without counting as a client asking.
	hit := now.Add(-time.Minute)
	e.lastHit = hit
	c.Put(q, false, aAnswer(q, 300), 86400)
	if got := entryOf(t, c, q); got.lastHit != hit || got.refreshing {
		t.Fatalf("refresh kept lastHit=%v refreshing=%v", got.lastHit, got.refreshing)
	}

	// Nobody has asked for a while: it is left to expire.
	e = entryOf(t, c, q)
	e.inserted, e.expires = now.Add(-280*time.Second), now.Add(20*time.Second)
	e.lastHit = now.Add(-refreshWindow - time.Second)
	if len(c.DueRefresh(now, 10)) != 0 {
		t.Fatal("a name no client wants must go cold")
	}

	// Short-lived answers are never refreshed.
	c.Put(q, false, aAnswer(q, 5), 86400)
	e = entryOf(t, c, q)
	e.lastHit, e.expires = now, now.Add(time.Second)
	if len(c.DueRefresh(now, 10)) != 0 {
		t.Fatal("a 5 s answer must not be refreshed")
	}
}
