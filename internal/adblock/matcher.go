// Package adblock owns everything that decides "is this ad or tracking
// infrastructure": the subscribed blocklists, the operator's own overrides,
// per-client policies, and the smart-capture pipeline that discovers domains
// no list has caught yet.
package adblock

import (
	"fmt"
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
	// Important marks an AdGuard $important block, which beats exceptions
	// from lists (never the operator's own).
	Important bool `json:"important,omitempty"`
}

// Matcher is a lock-light domain matcher. Lookups happen on the DNS hot path
// (potentially thousands per second) so reads take an atomic pointer to an
// immutable index rather than a mutex; a list refresh builds a new index and
// swaps it in.
type Matcher struct {
	idx atomic.Pointer[index]
	// overlay holds the operator's own rules and the configuration's
	// overrides. It is tiny and rebuilt in microseconds, so a rule change
	// never touches the millions of list entries in idx.
	overlay atomic.Pointer[index]

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
	// allowExact / allowWildcard win over a block, except that an exception
	// that came from a list yields to a block marked important, which is
	// AdGuard's rule and what its lists are written against.
	allowExact    map[string]allowEntry
	allowWildcard map[string]allowEntry
	allowRegexes  []allowRegex
	// regexes are the escape hatch for patterns a suffix cannot express.
	regexes []regexEntry
	count   int
}

type entry struct {
	source    string
	category  string
	important bool
}

type regexEntry struct {
	re        *compiledRegex
	source    string
	category  string
	important bool
}

// allowEntry records whether the exception is the operator's own (local)
// or came from a subscribed list.
type allowEntry struct {
	local  bool
	source string // the list the exception came from; empty for the operator's own
}

type allowRegex struct {
	re     *compiledRegex
	local  bool
	source string
}

func New() *Matcher {
	m := &Matcher{}
	m.idx.Store(newIndex())
	m.overlay.Store(newIndex())
	return m
}

func newIndex() *index {
	return &index{
		exact:         map[string]entry{},
		wildcard:      map[string]entry{},
		allowExact:    map[string]allowEntry{},
		allowWildcard: map[string]allowEntry{},
	}
}

// Builder accumulates entries for a new index.
type Builder struct {
	idx *index
}

func NewBuilder() *Builder {
	return &Builder{idx: newIndex()}
}

func (b *Builder) AddBlock(domain, source, category string, wildcard bool) {
	b.AddBlockImportant(domain, source, category, wildcard, false)
}

// AddBlockImportant adds a block that also beats exceptions from lists.
func (b *Builder) AddBlockImportant(domain, source, category string, wildcard, important bool) {
	d := normalize(domain)
	if d == "" {
		return
	}
	e := entry{source: source, category: category, important: important}
	if wildcard {
		if old, ok := b.idx.wildcard[d]; ok && old.important {
			e.important = true
		}
		b.idx.wildcard[d] = e
	} else {
		if old, ok := b.idx.exact[d]; ok && old.important {
			e.important = true
		}
		b.idx.exact[d] = e
	}
	b.idx.count++
}

// AddAllow adds the operator's own exception, which beats everything.
func (b *Builder) AddAllow(domain string, wildcard bool) {
	b.AddAllowFrom(domain, wildcard, true, "")
}

// AddAllowFrom adds an exception; local false means it came from the named
// list and yields to blocks marked important.
func (b *Builder) AddAllowFrom(domain string, wildcard, local bool, source string) {
	d := normalize(domain)
	if d == "" {
		return
	}
	if wildcard {
		if old, ok := b.idx.allowWildcard[d]; !ok || !old.local {
			b.idx.allowWildcard[d] = allowEntry{local: local, source: source}
		}
	} else {
		if old, ok := b.idx.allowExact[d]; !ok || !old.local {
			b.idx.allowExact[d] = allowEntry{local: local, source: source}
		}
	}
}

func (b *Builder) AddRegex(pattern, source, category string) error {
	return b.AddRegexImportant(pattern, source, category, false)
}

func (b *Builder) AddRegexImportant(pattern, source, category string, important bool) error {
	re, err := compileRegex(pattern)
	if err != nil {
		return err
	}
	if !isLocalSource(source) && TooBroad(re) {
		return fmt.Errorf("pattern matches ordinary names")
	}
	b.idx.regexes = append(b.idx.regexes, regexEntry{re: re, source: source, category: category, important: important})
	b.idx.count++
	return nil
}

// AddAllowRegex adds an exception pattern.
func (b *Builder) AddAllowRegex(pattern string, local bool, source string) error {
	re, err := compileRegex(pattern)
	if err != nil {
		return err
	}
	if !local && TooBroad(re) {
		return fmt.Errorf("pattern matches ordinary names")
	}
	b.idx.allowRegexes = append(b.idx.allowRegexes, allowRegex{re: re, local: local, source: source})
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

// CommitOverlay publishes the operator's rules. Anything here is checked
// before the lists and is authoritative either way.
func (m *Matcher) CommitOverlay(b *Builder) {
	m.buildMu.Lock()
	m.overlay.Store(b.idx)
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
	// The operator's own rules first: an allow or a block there settles it.
	if r, ok := lookupIn(m.overlay.Load(), d); ok {
		m.hits.Add(1)
		return r
	}
	if r, ok := lookupIn(m.idx.Load(), d); ok {
		m.hits.Add(1)
		return r
	}
	m.misses.Add(1)
	return Match{}
}

// lookupIn resolves one name against one index; ok is false when nothing
// in it applies.
func lookupIn(idx *index, d string) (Match, bool) {
	var allow *Match
	var allowLocal bool
	if a, ok := idx.allowExact[d]; ok {
		allow, allowLocal = &Match{Allowed: true, Source: allowSource(a.local, a.source), Rule: d}, a.local
	}

	var block *Match
	name := d
	first := true
	for {
		if allow == nil {
			if a, ok := idx.allowWildcard[name]; ok {
				allow, allowLocal = &Match{Allowed: true, Source: allowSource(a.local, a.source), Rule: "*." + name}, a.local
			}
		}
		if block == nil && first {
			if e, ok := idx.exact[name]; ok {
				block = &Match{Blocked: true, Source: e.source, Category: e.category, Rule: name, Important: e.important}
			}
		}
		if block == nil {
			if e, ok := idx.wildcard[name]; ok {
				// A wildcard on a single label is a whole-TLD block. That is
				// occasionally what an operator wants (*.zip), but from a
				// subscribed list it is almost always a parse artefact, and
				// honouring it would take the network off the internet. Only
				// locally-authored rules are trusted at that level.
				if strings.Contains(name, ".") || isLocalSource(e.source) {
					block = &Match{Blocked: true, Source: e.source, Category: e.category, Rule: "*." + name, Important: e.important}
				}
			}
		}
		first = false
		dot := strings.IndexByte(name, '.')
		if dot < 0 {
			break
		}
		name = name[dot+1:]
	}
	if block == nil {
		for _, r := range idx.regexes {
			if r.re.MatchString(d) {
				block = &Match{Blocked: true, Source: r.source, Category: r.category, Rule: r.re.pattern, Important: r.important}
				break
			}
		}
	}
	if allow == nil {
		for _, r := range idx.allowRegexes {
			if r.re.MatchString(d) {
				allow, allowLocal = &Match{Allowed: true, Source: allowSource(r.local, r.source), Rule: "/" + r.re.pattern + "/"}, r.local
				break
			}
		}
	}

	switch {
	case allow != nil && (allowLocal || block == nil || !block.Important):
		return *allow, true
	case block != nil:
		return *block, true
	}
	return Match{}, false
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
	return m.idx.Load().count + m.overlay.Load().count
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

// allowSource names where an exception came from: the operator's own
// allowlist, or the list that carried it.
func allowSource(local bool, source string) string {
	if local || source == "" {
		return "allowlist"
	}
	return "exception:" + source
}
