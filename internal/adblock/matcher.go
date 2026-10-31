// Package adblock owns everything that decides "is this ad or tracking
// infrastructure": the subscribed blocklists, the operator's own overrides,
// per-client policies, and the smart-capture pipeline that discovers domains
// no list has caught yet.
package adblock

import (
	"fmt"
	"sort"
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
	exact domainSet
	// wildcard holds suffix entries: an entry for "doubleclick.net" matches
	// that name and every subdomain of it.
	wildcard domainSet
	// allowExact / allowWildcard win over a block, except that an exception
	// that came from a list yields to a block marked important, which is
	// AdGuard's rule and what its lists are written against.
	allowExact    domainSet
	allowWildcard domainSet
	allowRegexes  []allowRegex
	// regexes are the escape hatch for patterns a suffix cannot express.
	regexes []regexEntry
	count   int

	// entries holds each distinct attribution once; the sets store its index.
	// ids is only used while building.
	entries []entry
	ids     map[entry]uint32

	// memo remembers what the regexes said about a name; see regexVerdict.
	memoMu sync.RWMutex
	memo   map[string]regexVerdict
}

// entry says where a rule came from. local marks the operator's own
// exceptions, as opposed to ones from a subscribed list.
type entry struct {
	source    string
	category  string
	important bool
	local     bool
}

type regexEntry struct {
	re        *compiledRegex
	source    string
	category  string
	important bool
}

type allowRegex struct {
	re     *compiledRegex
	local  bool
	source string
}

// regexVerdict holds the index of the first block and allow pattern to match
// a name, or -1.
type regexVerdict struct{ block, allow int32 }

// regexMemoSize bounds the memo; a flood of random names just clears it.
const regexMemoSize = 1 << 16

// regexVerdict runs a name past the patterns once per index. There is no way
// to index a regex, so a linear scan of about 1,200 list patterns took 2.5 ms
// of every lookup on a Raspberry Pi, on what is otherwise a microsecond path.
// A home network asks for the same few thousand names all day.
func (idx *index) regexVerdict(d string) regexVerdict {
	if len(idx.regexes)+len(idx.allowRegexes) == 0 {
		return regexVerdict{-1, -1}
	}
	idx.memoMu.RLock()
	v, ok := idx.memo[d]
	idx.memoMu.RUnlock()
	if ok {
		return v
	}
	v = regexVerdict{-1, -1}
	for i, r := range idx.regexes {
		if r.re.MatchString(d) {
			v.block = int32(i)
			break
		}
	}
	for i, r := range idx.allowRegexes {
		if r.re.MatchString(d) {
			v.allow = int32(i)
			break
		}
	}
	idx.memoMu.Lock()
	if idx.memo == nil || len(idx.memo) >= regexMemoSize {
		idx.memo = make(map[string]regexVerdict, 256)
	}
	idx.memo[d] = v
	idx.memoMu.Unlock()
	return v
}

// domainSet is an open-addressing table from a domain's 64-bit hash to an
// entry. It keeps no strings and no pointers: millions of list entries cost
// about 25 bytes each rather than about 120 in Go maps, and the garbage
// collector never has to walk them, which is what made rebuilds freeze a
// Raspberry Pi.
//
// ponytail: a query matches a listed name it isn't only on a 64-bit hash
// collision, about one lookup in 4 trillion at 4 million entries.
type domainSet struct {
	keys []uint64 // 0 is an empty slot
	vals []uint32
	n    int
}

func hashDomain(d string) uint64 {
	h := uint64(14695981039346656037)
	for i := 0; i < len(d); i++ {
		h ^= uint64(d[i])
		h *= 1099511628211
	}
	h ^= h >> 32 // the table indexes by the low bits, FNV's weakest
	if h == 0 {
		return 1
	}
	return h
}

func (s *domainSet) find(h uint64) (uint32, bool) {
	if len(s.keys) == 0 {
		return 0, false
	}
	mask := uint64(len(s.keys) - 1)
	for i := h & mask; ; i = (i + 1) & mask {
		switch s.keys[i] {
		case h:
			return s.vals[i], true
		case 0:
			return 0, false
		}
	}
}

func (s *domainSet) set(h uint64, v uint32) {
	if (s.n+1)*3 >= len(s.keys)*2 {
		s.grow()
	}
	mask := uint64(len(s.keys) - 1)
	for i := h & mask; ; i = (i + 1) & mask {
		switch s.keys[i] {
		case 0:
			s.keys[i], s.vals[i] = h, v
			s.n++
			return
		case h:
			s.vals[i] = v
			return
		}
	}
}

func (s *domainSet) grow() {
	old := *s
	size := max(16, len(old.keys)*2)
	*s = domainSet{keys: make([]uint64, size), vals: make([]uint32, size)}
	for i, k := range old.keys {
		if k != 0 {
			s.set(k, old.vals[i])
		}
	}
}

func New() *Matcher {
	m := &Matcher{}
	m.idx.Store(newIndex())
	m.overlay.Store(newIndex())
	return m
}

func newIndex() *index {
	return &index{ids: map[entry]uint32{}}
}

// Builder accumulates entries for a new index.
type Builder struct {
	idx *index
}

func NewBuilder() *Builder {
	return &Builder{idx: newIndex()}
}

func (b *Builder) intern(e entry) uint32 {
	id, ok := b.idx.ids[e]
	if !ok {
		id = uint32(len(b.idx.entries))
		b.idx.entries = append(b.idx.entries, e)
		b.idx.ids[e] = id
	}
	return id
}

func (b *Builder) AddBlock(domain, source, category string, wildcard bool) {
	b.AddBlockImportant(domain, source, category, wildcard, false)
}

// AddBlockImportant adds a block that also beats exceptions from lists. When
// several lists carry a name the highest list name gets the credit, so the
// result does not depend on the order rows were read in; the operator's own
// and built-in rules always do.
func (b *Builder) AddBlockImportant(domain, source, category string, wildcard, important bool) {
	d := normalize(domain)
	if d == "" {
		return
	}
	set := &b.idx.exact
	if wildcard {
		set = &b.idx.wildcard
	}
	h := hashDomain(d)
	e := entry{source: source, category: category, important: important}
	if id, ok := set.find(h); ok {
		old := b.idx.entries[id]
		e.important = important || old.important
		if old.source > source && !isLocalSource(source) {
			e.source, e.category = old.source, old.category
		}
	}
	set.set(h, b.intern(e))
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
	set := &b.idx.allowExact
	if wildcard {
		set = &b.idx.allowWildcard
	}
	h := hashDomain(d)
	if id, ok := set.find(h); ok {
		if old := b.idx.entries[id]; old.local || (!local && old.source > source) {
			return
		}
	}
	set.set(h, b.intern(entry{source: source, local: local}))
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
	sort.SliceStable(b.idx.regexes, func(i, j int) bool { return b.idx.regexes[i].source < b.idx.regexes[j].source })
	sort.SliceStable(b.idx.allowRegexes, func(i, j int) bool { return b.idx.allowRegexes[i].source < b.idx.allowRegexes[j].source })
	b.idx.ids = nil
	m.buildMu.Lock()
	m.idx.Store(b.idx)
	m.buildMu.Unlock()
}

// CommitOverlay publishes the operator's rules. Anything here is checked
// before the lists and is authoritative either way.
func (m *Matcher) CommitOverlay(b *Builder) {
	b.idx.ids = nil
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
	h := hashDomain(d)
	if id, ok := idx.allowExact.find(h); ok {
		a := idx.entries[id]
		allow, allowLocal = &Match{Allowed: true, Source: allowSource(a.local, a.source), Rule: d}, a.local
	}

	var block *Match
	name := d
	first := true
	for {
		if allow == nil {
			if id, ok := idx.allowWildcard.find(h); ok {
				a := idx.entries[id]
				allow, allowLocal = &Match{Allowed: true, Source: allowSource(a.local, a.source), Rule: "*." + name}, a.local
			}
		}
		if block == nil && first {
			if id, ok := idx.exact.find(h); ok {
				e := idx.entries[id]
				block = &Match{Blocked: true, Source: e.source, Category: e.category, Rule: name, Important: e.important}
			}
		}
		if block == nil {
			if id, ok := idx.wildcard.find(h); ok {
				e := idx.entries[id]
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
		h = hashDomain(name)
	}
	if block == nil || allow == nil {
		v := idx.regexVerdict(d)
		if block == nil && v.block >= 0 {
			r := idx.regexes[v.block]
			block = &Match{Blocked: true, Source: r.source, Category: r.category, Rule: r.re.pattern, Important: r.important}
		}
		if allow == nil && v.allow >= 0 {
			r := idx.allowRegexes[v.allow]
			allow, allowLocal = &Match{Allowed: true, Source: allowSource(r.local, r.source), Rule: "/" + r.re.pattern + "/"}, r.local
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
