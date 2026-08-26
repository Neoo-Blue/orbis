package dnsproxy

import (
	"container/list"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// Cache is a TTL-aware LRU over DNS responses. Keying includes the qtype and
// the DO bit because a DNSSEC-aware answer is not interchangeable with a
// stripped one.
type Cache struct {
	mu       sync.Mutex
	entries  map[string]*list.Element
	order    *list.List
	capacity int

	hits   int64
	misses int64
	// stale counts answers served past their TTL while a refresh was in
	// flight, which is a feature (serve-stale) and worth surfacing.
	stale int64
}

type cacheEntry struct {
	key     string
	msg     *dns.Msg
	expires time.Time
	// staleUntil allows serving an expired answer briefly when every
	// upstream is failing, which keeps a network usable during an outage.
	staleUntil time.Time
	inserted   time.Time
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
// The bool reports whether the entry was fresh; a stale hit is still returned
// so the caller can decide to serve it during an upstream outage.
func (c *Cache) Get(q dns.Question, dnssecOK bool) (*dns.Msg, bool, bool) {
	key := cacheKey(q, dnssecOK)
	now := time.Now()

	c.mu.Lock()
	el, ok := c.entries[key]
	if !ok {
		c.misses++
		c.mu.Unlock()
		return nil, false, false
	}
	e := el.Value.(*cacheEntry)
	if now.After(e.staleUntil) {
		c.order.Remove(el)
		delete(c.entries, key)
		c.misses++
		c.mu.Unlock()
		return nil, false, false
	}
	c.order.MoveToFront(el)
	fresh := now.Before(e.expires)
	if fresh {
		c.hits++
	} else {
		c.stale++
	}
	msg := e.msg.Copy()
	elapsed := uint32(now.Sub(e.inserted).Seconds())
	c.mu.Unlock()

	adjustTTL(msg, elapsed)
	return msg, true, fresh
}

// adjustTTL walks every section so a client caching downstream does not hold
// the record longer than the authoritative TTL allows.
func adjustTTL(m *dns.Msg, elapsed uint32) {
	dec := func(rrs []dns.RR) {
		for _, rr := range rrs {
			h := rr.Header()
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

// Put stores a response. minTTL/maxTTL clamp what upstreams claim: a 30-second
// TTL from a CDN produces needless query volume, and a 7-day TTL means a
// changed record is invisible for a week.
func (c *Cache) Put(q dns.Question, dnssecOK bool, msg *dns.Msg, minTTL, maxTTL int) {
	if msg == nil || len(msg.Answer)+len(msg.Ns) == 0 {
		// Cache negative answers briefly so an NXDOMAIN storm does not
		// hammer upstream, but never long.
		if msg == nil || msg.Rcode != dns.RcodeNameError {
			return
		}
	}
	ttl := lowestTTL(msg)
	if ttl == 0 {
		ttl = uint32(minTTL)
	}
	if minTTL > 0 && ttl < uint32(minTTL) {
		ttl = uint32(minTTL)
	}
	if maxTTL > 0 && ttl > uint32(maxTTL) {
		ttl = uint32(maxTTL)
	}
	if msg.Rcode == dns.RcodeNameError && ttl > 300 {
		ttl = 300
	}
	now := time.Now()
	e := &cacheEntry{
		key:        cacheKey(q, dnssecOK),
		msg:        msg.Copy(),
		expires:    now.Add(time.Duration(ttl) * time.Second),
		staleUntil: now.Add(time.Duration(ttl)*time.Second + 5*time.Minute),
		inserted:   now,
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.entries[e.key]; ok {
		el.Value = e
		c.order.MoveToFront(el)
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

func lowestTTL(m *dns.Msg) uint32 {
	var lowest uint32
	scan := func(rrs []dns.RR) {
		for _, rr := range rrs {
			// OPT records carry flags in the TTL field, not a real TTL.
			if rr.Header().Rrtype == dns.TypeOPT {
				continue
			}
			t := rr.Header().Ttl
			if lowest == 0 || t < lowest {
				lowest = t
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
		"hits": c.hits, "misses": c.misses, "stale_served": c.stale,
		"hit_rate": rate,
	}
}
