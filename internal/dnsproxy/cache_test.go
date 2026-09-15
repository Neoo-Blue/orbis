package dnsproxy

import (
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestPrefetchableOncePerEntryNearExpiry(t *testing.T) {
	c := NewCache(10)
	q := dns.Question{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	m := new(dns.Msg)
	m.SetQuestion(q.Name, q.Qtype)
	m.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: []byte{1, 2, 3, 4}}}
	c.Put(q, false, m, 0, 0)

	if c.Prefetchable(q, false) {
		t.Fatal("a freshly inserted 300s answer must not be prefetchable")
	}
	// Age the entry into its last tenth: 300s life, 20s left.
	e := c.entries[cacheKey(q, false)].Value.(*cacheEntry)
	e.inserted = time.Now().Add(-280 * time.Second)
	e.expires = time.Now().Add(20 * time.Second)
	if !c.Prefetchable(q, false) {
		t.Fatal("an answer with a tenth of its life left must be prefetchable")
	}
	if c.Prefetchable(q, false) {
		t.Fatal("a second call must not start a second refresh")
	}
	// A refresh replaces the entry and re-arms it.
	c.Put(q, false, m, 0, 0)
	if c.Prefetchable(q, false) {
		t.Fatal("the refreshed entry is young again")
	}
	if got := c.Stats()["prefetches"]; got != int64(1) {
		t.Fatalf("prefetches = %v, want 1", got)
	}

	// Short-lived answers are never prefetched.
	short := m.Copy()
	short.Answer[0].Header().Ttl = 5
	c.Put(q, false, short, 0, 0)
	e = c.entries[cacheKey(q, false)].Value.(*cacheEntry)
	e.expires = time.Now().Add(100 * time.Millisecond)
	if c.Prefetchable(q, false) {
		t.Fatal("a 5s answer must not be prefetched")
	}
}
