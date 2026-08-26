// Package adblock owns everything that decides "is this ad or tracking
// infrastructure": the subscribed blocklists, the operator's own overrides,
// per-client policies, and the smart-capture pipeline that discovers domains
// no list has caught yet.
package adblock

import (
	"strings"
	"sync"
	"sync/atomic"
)

// Match is the outcome of a lookup.
type Match struct {
	Blocked  bool
	Allowed  bool // an explicit allow that beat a block
	Source   string
	Category string
	// Rule is the specific pattern that matched, e.g. "*.doubleclick.net".
	Rule string
}

// Matcher is a lock-light domain matcher. Lookups happen on the DNS hot path
// (potentially thousands per second) so reads take an atomic pointer to an
// immutable index rather than a mutex; a list refresh builds a new index and
// swaps it in.
type Matcher struct {
	idx atomic.Pointer[index]

	// buildMu serialises rebuilds so two concurrent list refreshes cannot
	// interleave into a half-built index.
	buildMu sync.Mutex

	hits   atomic.Int64
	misses atomic.Int64
}

type index struct {
	// exact holds full-domain entries: "ads.example.com".
	exact map[string]entry
	// wildcard holds suffix entries: an entry for "doubleclick.net" matches
	// that name and every subdomain of it.
	wildcard map[string]entry
	// allowExact / allowWildcard always win over a block.
	allowExact    map[string]struct{}
	allowWildcard map[string]struct{}
	// regexes are the escape hatch for patterns a suffix cannot express.
	regexes []regexEntry
	count   int
}

type entry struct {
	source   string
	category string
}

type regexEntry struct {
	re       *compiledRegex
	source   string
	category string
}

func New() *Matcher {
	m := &Matcher{}
	m.idx.Store(&index{
		exact:         map[string]entry{},
		wildcard:      map[string]entry{},
		allowExact:    map[string]struct{}{},
		allowWildcard: map[string]struct{}{},
	})
	return m
}

// Builder accumulates entries for a new index.
type Builder struct {
	idx *index
}

func NewBuilder() *Builder {
	return &Builder{idx: &index{
		exact:         make(map[string]entry, 1<<17),
		wildcard:      make(map[string]entry, 1<<14),
		allowExact:    map[string]struct{}{},
		allowWildcard: map[string]struct{}{},
	}}
}

func (b *Builder) AddBlock(domain, source, category string, wildcard bool) {
	d := normalize(domain)
	if d == "" {
		return
	}
	e := entry{source: source, category: category}
	if wildcard {
		b.idx.wildcard[d] = e
	} else {
		b.idx.exact[d] = e
	}
	b.idx.count++
}

func (b *Builder) AddAllow(domain string, wildcard bool) {
	d := normalize(domain)
	if d == "" {
		return
	}
	if wildcard {
		b.idx.allowWildcard[d] = struct{}{}
	} else {
		b.idx.allowExact[d] = struct{}{}
	}
}

func (b *Builder) AddRegex(pattern, source, category string) error {
	re, err := compileRegex(pattern)
	if err != nil {
		return err
	}
	b.idx.regexes = append(b.idx.regexes, regexEntry{re: re, source: source, category: category})
	return nil
}

func (b *Builder) Count() int { return b.idx.count }

// Commit publishes the built index. Old readers finish against the previous
// index; there is never a window where the matcher is empty.
func (m *Matcher) Commit(b *Builder) {
	m.buildMu.Lock()
	m.idx.Store(b.idx)
	m.buildMu.Unlock()
}

// Lookup walks the label hierarchy from most to least specific:
// "a.b.doubleclick.net" tests a.b.doubleclick.net, b.doubleclick.net,
// doubleclick.net, net. Exact entries only match the full name; wildcard
// entries match at any level. Allows are checked first at every level so a
// narrow allow can carve a hole in a broad block.
func (m *Matcher) Lookup(domain string) Match {
	d := normalize(domain)
	if d == "" {
		return Match{}
	}
	idx := m.idx.Load()

	if _, ok := idx.allowExact[d]; ok {
		m.hits.Add(1)
		return Match{Allowed: true, Source: "allowlist", Rule: d}
	}

	name := d
	first := true
	for {
		if _, ok := idx.allowWildcard[name]; ok {
			m.hits.Add(1)
			return Match{Allowed: true, Source: "allowlist", Rule: "*." + name}
		}
		if first {
			if e, ok := idx.exact[name]; ok {
				m.hits.Add(1)
				return Match{Blocked: true, Source: e.source, Category: e.category, Rule: name}
			}
		}
		if e, ok := idx.wildcard[name]; ok {
			// A wildcard on a single label is a whole-TLD block. That is
			// occasionally what an operator wants (*.zip), but from a
			// subscribed list it is almost always a parse artefact, and
			// honouring it would take the network off the internet. Only
			// locally-authored rules are trusted at that level.
			if !strings.Contains(name, ".") && !isLocalSource(e.source) {
				m.misses.Add(1)
				return Match{}
			}
			m.hits.Add(1)
			return Match{Blocked: true, Source: e.source, Category: e.category, Rule: "*." + name}
		}
		first = false
		dot := strings.IndexByte(name, '.')
		if dot < 0 {
			break
		}
		name = name[dot+1:]
	}

	for _, r := range idx.regexes {
		if r.re.MatchString(d) {
			m.hits.Add(1)
			return Match{Blocked: true, Source: r.source, Category: r.category, Rule: r.re.pattern}
		}
	}
	m.misses.Add(1)
	return Match{}
}

// LookupChain applies the matcher to a full CNAME chain. First-party CNAME
// cloaking (analytics.example.com -> tracker.adtech.net) is invisible to a
// matcher that only sees the queried name, and it is now the dominant tracker
// evasion technique, so every hop gets checked.
func (m *Matcher) LookupChain(names []string) Match {
	for _, n := range names {
		if r := m.Lookup(n); r.Blocked || r.Allowed {
			if r.Blocked && len(names) > 1 && n != names[0] {
				r.Source = r.Source + " (via CNAME " + n + ")"
			}
			return r
		}
	}
	return Match{}
}

func (m *Matcher) Count() int {
	return m.idx.Load().count
}

func (m *Matcher) Stats() (hits, misses int64) {
	return m.hits.Load(), m.misses.Load()
}

// normalize lowercases, strips a trailing dot and any leading wildcard label,
// and rejects anything that is not plausibly a hostname.
func normalize(d string) string {
	d = strings.TrimSpace(strings.ToLower(d))
	d = strings.TrimSuffix(d, ".")
	d = strings.TrimPrefix(d, "*.")
	if d == "" || len(d) > 253 {
		return ""
	}
	// A bare IP is never a domain rule.
	if strings.Count(d, ".") == 3 && isAllDigitsAndDots(d) {
		return ""
	}
	for i := 0; i < len(d); i++ {
		c := d[i]
		if c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '.' || c == '-' || c == '_' {
			continue
		}
		// Allow IDN in punycode form only; raw unicode is normalized upstream.
		return ""
	}
	return d
}

// isLocalSource reports whether a rule came from the operator rather than a
// downloaded list.
func isLocalSource(source string) bool {
	return source == "config" || strings.HasPrefix(source, "local:") || strings.HasPrefix(source, "builtin:")
}

func isAllDigitsAndDots(s string) bool {
	for i := 0; i < len(s); i++ {
		if (s[i] < '0' || s[i] > '9') && s[i] != '.' {
			return false
		}
	}
	return true
}
