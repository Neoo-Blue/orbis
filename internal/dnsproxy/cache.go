package dnsproxy

import (
	"container/list"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

const (
	// maxNegativeTTL caps how long "this name does not exist" is believed. A
	// record created a minute ago must not stay invisible for the 30 minutes
	// a zone's SOA asks for.
	maxNegativeTTL = 30
	// refreshWindow is how long a name stays warm after a client last asked
	// for it. Past that it is left to expire.
	refreshWindow = 15 * time.Minute
	// minRefreshLife leaves short-lived answers alone: refreshing a 5-second
	// record every 3 seconds is query volume, not a saving.
	minRefreshLife = 10 * time.Second
	// minRefreshMargin is the least time left when a refresh starts, so a
	// 20-second answer is not racing its own expiry.
	minRefreshMargin = 2 * time.Second
)

// Cache is a TTL-aware LRU over DNS responses. Keying includes the qtype and
// the DO bit because a DNSSEC-aware answer is not interchangeable with a
// stripped one.
//
// An entry never outlives the TTL its source gave it. Nothing here raises a
// TTL, and an expired answer is dropped rather than served: speed comes from
// refreshing names clients use before they expire, not from keeping old
// answers around.
type Cache struct {
	mu sync.Mutex
	// order runs from the name a client asked for most recently to the
	// least; a refresh does not move an entry, so DueRefresh can stop at the
	// first name nobody has wanted for a while.
	entries  map[string]*list.Element
	order    *list.List
	capacity int

	hits   int64
	misses int64
	// prefetches counts answers refreshed ahead of expiry.
	prefetches int64
}

type cacheEntry struct {
	key      string
	q        dns.Question
	dnssecOK bool
	msg      *dns.Msg
	expires  time.Time
	inserted time.Time
	// lastHit is when a client last used this name. A refresh carries it
	// over, so a name nobody asks for again goes cold on its own.
	lastHit time.Time
	// refreshing is set once a refresh has been started for this entry.
	refreshing bool
}

// refreshJob names one answer that should be fetched again.
type refreshJob struct {
	q        dns.Question
	dnssecOK bool
}

func NewCache(capacity int) *Cache {
	if capacity <= 0 {
		capacity = 10000
	}
	return &Cache{
		entries:  make(map[string]*list.Element, capacity),
		order:    list.New(),
		capacity: capacity,
	}
}

func cacheKey(q dns.Question, dnssecOK bool) string {
	var b strings.Builder
	b.Grow(len(q.Name) + 12)
	b.WriteString(strings.ToLower(q.Name))
	b.WriteByte('|')
	b.WriteString(dns.TypeToString[q.Qtype])
	b.WriteByte('|')
	b.WriteString(dns.ClassToString[q.Qclass])
	if dnssecOK {
		b.WriteString("|do")
	}
	return b.String()
}

// Get returns a cached answer with TTLs decremented to reflect elapsed time.
// An expired entry is dropped, so everything returned is inside its TTL.
func (c *Cache) Get(q dns.Question, dnssecOK bool) (*dns.Msg, bool) {
	key := cacheKey(q, dnssecOK)
	now := time.Now()

	c.mu.Lock()
	el, ok := c.entries[key]
	if !ok {
		c.misses++
		c.mu.Unlock()
		return nil, false
	}
	e := el.Value.(*cacheEntry)
	if !now.Before(e.expires) {
		c.order.Remove(el)
		delete(c.entries, key)
		c.misses++
		c.mu.Unlock()
		return nil, false
	}
	c.order.MoveToFront(el)
	e.lastHit = now
	c.hits++
	// The stored message is immutable after Put; Copy and TTL rewrite are
	// the expensive part, so they run after unlock rather than serialising
	// every concurrent lookup behind one deep copy.
	src := e.msg
	elapsed := uint32(now.Sub(e.inserted).Seconds())
	c.mu.Unlock()

	msg := src.Copy()
	adjustTTL(msg, elapsed)
	return msg, true
}

// DueRefresh claims up to limit answers that a client used recently and that
// are in the last tenth of their life. The caller fetches them again in the
// background, so a name the network keeps asking for is always answered from
// cache, with an answer that is never older than its TTL.
func (c *Cache) DueRefresh(now time.Time, limit int) []refreshJob {
	cutoff := now.Add(-refreshWindow)
	c.mu.Lock()
	defer c.mu.Unlock()
	var due []refreshJob
	for el := c.order.Front(); el != nil && len(due) < limit; el = el.Next() {
		e := el.Value.(*cacheEntry)
		if e.lastHit.Before(cutoff) {
			break
		}
		life := e.expires.Sub(e.inserted)
		margin := life / 10
		if margin < minRefreshMargin {
			margin = minRefreshMargin
		}
		if e.refreshing || life < minRefreshLife || !now.Before(e.expires) || e.expires.Sub(now) > margin {
			continue
		}
		e.refreshing = true
		c.prefetches++
		due = append(due, refreshJob{q: e.q, dnssecOK: e.dnssecOK})
	}
	return due
}

// adjustTTL walks every section so a client caching downstream does not hold
// the record longer than the authoritative TTL allows. An OPT record's TTL
// field holds the EDNS flags, so it is left alone.
func adjustTTL(m *dns.Msg, elapsed uint32) {
	dec := func(rrs []dns.RR) {
		for _, rr := range rrs {
			h := rr.Header()
			if h.Rrtype == dns.TypeOPT {
				continue
			}
			if h.Ttl > elapsed {
				h.Ttl -= elapsed
			} else {
				h.Ttl = 1
			}
		}
	}
	dec(m.Answer)
	dec(m.Ns)
	dec(m.Extra)
}

// hasData reports whether an answer actually answers the question. A CNAME
// with nothing behind it does not.
func hasData(q dns.Question, m *dns.Msg) bool {
	for _, rr := range m.Answer {
		if t := rr.Header().Rrtype; t == q.Qtype || q.Qtype == dns.TypeANY {
			return true
		}
	}
	return false
}

// negativeLimit is the most a negative answer may be kept: RFC 2308's
// min(SOA TTL, SOA MINIMUM), capped so a new record shows up quickly.
func negativeLimit(m *dns.Msg) uint32 {
	limit := uint32(maxNegativeTTL)
	for _, rr := range m.Ns {
		if soa, ok := rr.(*dns.SOA); ok && soa.Minttl < limit {
			limit = soa.Minttl
		}
	}
	return limit
}

// capTTLs lowers every TTL to limit, in place, so a client downstream is held
// to the same bound as this cache.
func capTTLs(m *dns.Msg, limit uint32) {
	cap := func(rrs []dns.RR) {
		for _, rr := range rrs {
			if h := rr.Header(); h.Rrtype != dns.TypeOPT && h.Ttl > limit {
				h.Ttl = limit
			}
		}
	}
	cap(m.Answer)
	cap(m.Ns)
	cap(m.Extra)
}

// Put stores a response for as long as its records say and no longer. maxTTL
// lowers what upstreams claim: a 7-day TTL would make a changed record
// invisible for a week. TTLs in msg are capped in place, so the client that
// asked gets the same bound. A TTL of 0 means do not cache, and only NOERROR
// and NXDOMAIN are ever stored.
func (c *Cache) Put(q dns.Question, dnssecOK bool, msg *dns.Msg, maxTTL int) {
	if msg == nil {
		return
	}
	limit := ^uint32(0)
	if maxTTL > 0 {
		limit = uint32(maxTTL)
	}
	if !hasData(q, msg) {
		if n := negativeLimit(msg); n < limit {
			limit = n
		}
	}
	capTTLs(msg, limit)
	if msg.Rcode != dns.RcodeSuccess && msg.Rcode != dns.RcodeNameError {
		return
	}
	ttl := lowestTTL(msg)
	if ttl == 0 {
		return
	}
	now := time.Now()
	e := &cacheEntry{
		key:      cacheKey(q, dnssecOK),
		q:        q,
		dnssecOK: dnssecOK,
		msg:      msg.Copy(),
		expires:  now.Add(time.Duration(ttl) * time.Second),
		inserted: now,
		lastHit:  now,
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.entries[e.key]; ok {
		e.lastHit = el.Value.(*cacheEntry).lastHit
		el.Value = e
		return
	}
	c.entries[e.key] = c.order.PushFront(e)
	for c.order.Len() > c.capacity {
		back := c.order.Back()
		if back == nil {
			break
		}
		c.order.Remove(back)
		delete(c.entries, back.Value.(*cacheEntry).key)
	}
}

// lowestTTL is the shortest life of any record in the answer. No records at
// all reads as 0, which is not cacheable.
func lowestTTL(m *dns.Msg) uint32 {
	var lowest uint32
	seen := false
	scan := func(rrs []dns.RR) {
		for _, rr := range rrs {
			// OPT records carry flags in the TTL field, not a real TTL.
			if rr.Header().Rrtype == dns.TypeOPT {
				continue
			}
			if t := rr.Header().Ttl; !seen || t < lowest {
				lowest, seen = t, true
			}
		}
	}
	scan(m.Answer)
	scan(m.Ns)
	return lowest
}

// Flush drops everything, used after a policy change so a previously-allowed
// answer cannot keep being served.
func (c *Cache) Flush() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := c.order.Len()
	c.entries = make(map[string]*list.Element, c.capacity)
	c.order.Init()
	return n
}

// FlushDomain removes only entries for a name and its subdomains.
func (c *Cache) FlushDomain(domain string) int {
	suffix := "." + strings.ToLower(strings.TrimSuffix(domain, ".")) + "."
	exact := strings.ToLower(strings.TrimSuffix(domain, ".")) + "."
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for key, el := range c.entries {
		name, _, _ := strings.Cut(key, "|")
		if name == exact || strings.HasSuffix(name, suffix) {
			c.order.Remove(el)
			delete(c.entries, key)
			n++
		}
	}
	return n
}

func (c *Cache) Stats() map[string]any {
	c.mu.Lock()
	defer c.mu.Unlock()
	total := c.hits + c.misses
	rate := 0.0
	if total > 0 {
		rate = float64(c.hits) / float64(total)
	}
	return map[string]any{
		"size": c.order.Len(), "capacity": c.capacity,
		"hits": c.hits, "misses": c.misses, "prefetches": c.prefetches,
		"hit_rate": rate,
	}
}
