package adblock

import (
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Neoo-Blue/orbis/internal/config"
	"github.com/Neoo-Blue/orbis/internal/store"
)

// Manager downloads, parses and indexes subscription lists, then rebuilds the
// matcher. It is the boring-but-load-bearing part of ad blocking: the smart
// features only matter for what the lists miss.
type Manager struct {
	st      *store.Store
	matcher *Matcher
	cfg     *config.Config
	client  *http.Client
	log     func(string, ...any)

	mu           sync.Mutex
	updating     bool
	lastBuild    time.Time
	lastCount    int
	rebuilding   bool
	rebuildAgain bool
}

func NewManager(st *store.Store, m *Matcher, cfg *config.Config, log func(string, ...any)) *Manager {
	if log == nil {
		log = func(string, ...any) {}
	}
	return &Manager{
		st:      st,
		matcher: m,
		cfg:     cfg,
		log:     log,
		client: &http.Client{
			Timeout: 120 * time.Second,
			// Lists redirect constantly (raw.githubusercontent -> CDN); a
			// modest cap keeps a redirect loop from hanging the refresh.
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 5 {
					return fmt.Errorf("too many redirects")
				}
				return nil
			},
		},
	}
}

// SyncConfig reconciles the configured list set with what is in the database,
// so removing a list from the config actually drops its domains.
func (m *Manager) SyncConfig() error {
	cfg := m.cfg.Snapshot()
	want := map[string]bool{}
	for _, l := range cfg.AdBlock.Lists {
		want[l.Name] = true
		if err := m.st.UpsertListMeta(store.ListMeta{
			Name: l.Name, URL: l.URL, Category: l.Category, Enabled: l.Enabled,
		}); err != nil {
			return err
		}
	}
	existing, err := m.st.ListMetas()
	if err != nil {
		return err
	}
	for _, e := range existing {
		if !want[e.Name] {
			if err := m.st.DeleteList(e.Name); err != nil {
				return err
			}
			m.log("adblock: dropped list %q (no longer configured)", e.Name)
		}
	}
	return nil
}

// UpdateAll refreshes every enabled list, then rebuilds the index once. It is
// safe to call concurrently; the second caller returns immediately.
func (m *Manager) UpdateAll(ctx context.Context, force bool) error {
	m.mu.Lock()
	if m.updating {
		m.mu.Unlock()
		return fmt.Errorf("list update already in progress")
	}
	m.updating = true
	m.mu.Unlock()
	defer func() {
		m.mu.Lock()
		m.updating = false
		m.mu.Unlock()
	}()

	if err := m.SyncConfig(); err != nil {
		return err
	}
	metas, err := m.st.ListMetas()
	if err != nil {
		return err
	}
	interval := time.Duration(m.cfg.Snapshot().AdBlock.UpdateIntervalHours) * time.Hour
	if interval <= 0 {
		interval = 24 * time.Hour
	}

	// Lists are independent; fetching them in parallel turns a 9-list refresh
	// from minutes into seconds. Four at a time is polite to the mirrors.
	sem := make(chan struct{}, 4)
	var wg sync.WaitGroup
	var changed atomic.Int32
	for _, meta := range metas {
		if !meta.Enabled {
			continue
		}
		if !force && meta.LastUpdated != nil && time.Since(*meta.LastUpdated) < interval {
			continue
		}
		wg.Add(1)
		go func(meta store.ListMeta) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			did, err := m.updateOne(ctx, meta)
			if err != nil {
				m.log("adblock: list %q failed: %v", meta.Name, err)
				_ = m.st.SetListError(meta.Name, err.Error())
			}
			if did {
				changed.Add(1)
			}
		}(meta)
	}
	wg.Wait()
	// A refresh where every list came back unchanged has nothing to
	// rebuild, and a rebuild is the most expensive thing this process does.
	if changed.Load() == 0 && m.matcher.Count() > 0 {
		return nil
	}
	return m.Rebuild()
}

// updateOne fetches one list; it reports whether the stored entries changed.
func (m *Manager) updateOne(ctx context.Context, meta store.ListMeta) (bool, error) {
	reqCtx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, meta.URL, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("User-Agent", "orbis/1.0 (+https://github.com/Neoo-Blue/orbis)")
	req.Header.Set("Accept-Encoding", "gzip")
	if meta.ETag != "" {
		req.Header.Set("If-None-Match", meta.ETag)
	}
	resp, err := m.client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotModified {
		m.log("adblock: %s unchanged", meta.Name)
		return false, nil
	}
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	var reader io.Reader = io.LimitReader(resp.Body, 256<<20)
	if strings.EqualFold(resp.Header.Get("Content-Encoding"), "gzip") {
		gz, err := gzip.NewReader(reader)
		if err != nil {
			return false, fmt.Errorf("gzip: %w", err)
		}
		defer gz.Close()
		reader = gz
	}

	parsed, err := Parse(reader, m.parseOptions(meta.Name))
	if err != nil {
		return false, err
	}
	if parsed.Total() == 0 {
		return false, fmt.Errorf("list parsed to zero entries (format change?)")
	}
	if err := m.st.ReplaceListDomains(meta.Name, meta.Category, ToListEntries(parsed)); err != nil {
		return false, err
	}
	meta.ETag = resp.Header.Get("ETag")
	now := time.Now()
	meta.LastUpdated = &now
	meta.Entries = parsed.Total()
	_ = m.st.UpsertListMeta(meta)
	if len(parsed.Skipped) > 0 {
		m.log("adblock: %s -> %d entries (%d blocks, %d exceptions), skipped %s", meta.Name, meta.Entries, parsed.Blocks(), parsed.Allows(), skippedSummary(parsed.Skipped))
	} else {
		m.log("adblock: %s -> %d entries (%d blocks, %d exceptions)", meta.Name, meta.Entries, parsed.Blocks(), parsed.Allows())
	}
	return true, nil
}

// parseOptions reads a list's action and format from the configuration.
func (m *Manager) parseOptions(name string) ParseOptions {
	for _, l := range m.cfg.Snapshot().AdBlock.Lists {
		if l.Name == name {
			return ParseOptions{Format: l.Format, Allow: l.Action == "allow"}
		}
	}
	return ParseOptions{}
}

// ToListEntries converts a parse result for storage.
func ToListEntries(p *Entries) store.ListEntries {
	return store.ListEntries{
		Exact: p.Exact, Wildcard: p.Wildcard, Regex: p.Regex,
		AllowExact: p.AllowExact, AllowWildcard: p.AllowWildcard, AllowRegex: p.AllowRegex,
		Important: p.Important,
	}
}

func skippedSummary(sk map[string]int) string {
	parts := make([]string, 0, len(sk))
	for k, v := range sk {
		parts = append(parts, fmt.Sprintf("%d %s", v, k))
	}
	sort.Strings(parts)
	return strings.Join(parts, ", ")
}

// Rebuild reconstructs the list index from the database. It is the
// expensive path (millions of entries), so it is called only when the
// lists themselves change; a rule change goes through RebuildLocal. Calls
// that arrive while one is running are coalesced into a single follow-up.
func (m *Manager) Rebuild() error {
	m.mu.Lock()
	if m.rebuilding {
		m.rebuildAgain = true
		m.mu.Unlock()
		return nil
	}
	m.rebuilding = true
	m.mu.Unlock()
	for {
		err := m.rebuildLists()
		m.mu.Lock()
		again := m.rebuildAgain
		m.rebuildAgain = false
		if !again {
			m.rebuilding = false
			m.mu.Unlock()
			return err
		}
		m.mu.Unlock()
	}
}

func (m *Manager) rebuildLists() error {
	b := NewBuilder()
	badRegex := 0
	if err := m.st.AllBlockDomains(func(domain, source, category string, kind int, important bool) {
		switch kind {
		case store.EntryExact:
			b.AddBlockImportant(domain, source, category, false, important)
		case store.EntryWildcard:
			b.AddBlockImportant(domain, source, category, true, important)
		case store.EntryRegex:
			if err := b.AddRegexImportant(domain, source, category, important); err != nil {
				badRegex++
			}
		case store.EntryAllowExact:
			b.AddAllowFrom(domain, false, false, source)
		case store.EntryAllowWildcard:
			b.AddAllowFrom(domain, true, false, source)
		case store.EntryAllowRegex:
			if err := b.AddAllowRegex(domain, false, source); err != nil {
				badRegex++
			}
		}
	}); err != nil {
		return err
	}
	if badRegex > 0 {
		m.log("adblock: %d list regex entries were rejected (invalid or matching ordinary names)", badRegex)
	}

	cfg := m.cfg.Snapshot()
	if cfg.AdBlock.BlockDNSBypass {
		for _, d := range dohBypassDomains {
			b.AddBlock(d, "builtin:doh-bypass", "bypass", true)
		}
	}
	if cfg.AdBlock.StreamingAds {
		for _, d := range streamingAdDomains {
			b.AddBlock(d, "builtin:streaming-ads", "ads", true)
		}
	}

	m.matcher.Commit(b)
	m.mu.Lock()
	m.lastBuild = time.Now()
	m.lastCount = b.Count()
	m.mu.Unlock()
	m.log("adblock: index rebuilt, %d entries", b.Count())
	return m.RebuildLocal()
}

// RebuildLocal republishes the operator's rules and the configuration's
// overrides as the overlay. It reads a few hundred rows at most and is
// what every rule change calls; the lists are untouched.
func (m *Manager) RebuildLocal() error {
	b := NewBuilder()
	cfg := m.cfg.Snapshot()
	for _, d := range cfg.AdBlock.Denylist {
		b.AddBlock(d, "config", "manual", strings.HasPrefix(d, "*."))
	}
	for _, d := range cfg.AdBlock.Allowlist {
		b.AddAllow(d, strings.HasPrefix(d, "*."))
	}
	local, err := m.st.LocalRules()
	if err != nil {
		return err
	}
	for _, r := range local {
		switch {
		case r.Regex && r.Action == "allow":
			if err := b.AddAllowRegex(r.Domain, true, ""); err != nil {
				m.log("adblock: local allow pattern %q: %v", r.Domain, err)
			}
		case r.Regex:
			if err := b.AddRegex(r.Domain, "local:"+r.Origin, "manual"); err != nil {
				m.log("adblock: local block pattern %q: %v", r.Domain, err)
			}
		case r.Action == "allow":
			// An allow always covers subdomains: the operator allowed a
			// site, and a site is its hostnames.
			b.AddAllow(r.Domain, true)
		default:
			b.AddBlock(r.Domain, "local:"+r.Origin, "manual", r.Wildcard)
		}
	}
	m.matcher.CommitOverlay(b)
	return nil
}

// Busy reports whether lists are being refreshed or the index rebuilt, which
// keeps the database writer and the disk busy on their own.
func (m *Manager) Busy() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.updating || m.rebuilding
}

func (m *Manager) Status() map[string]any {
	m.mu.Lock()
	defer m.mu.Unlock()
	hits, misses := m.matcher.Stats()
	return map[string]any{
		"entries":    m.lastCount,
		"last_build": m.lastBuild,
		"updating":   m.updating,
		"hits":       hits,
		"misses":     misses,
	}
}

// Run keeps lists fresh in the background.
func (m *Manager) Run(ctx context.Context) {
	// Rebuild immediately from whatever is already stored so blocking works
	// as early as possible, then refresh from the network. Until this first
	// build lands the resolver answers unfiltered; the log line makes the
	// length of that window visible.
	m.mu.Lock()
	built := !m.lastBuild.IsZero()
	m.mu.Unlock()
	if !built {
		start := time.Now()
		if err := m.Rebuild(); err != nil {
			m.log("adblock: initial rebuild failed: %v", err)
		} else {
			m.log("adblock: initial index ready after %s; lookups before this were unfiltered", time.Since(start).Round(time.Millisecond))
		}
	}
	go func() {
		if err := m.UpdateAll(ctx, false); err != nil {
			m.log("adblock: initial update: %v", err)
		}
	}()
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := m.UpdateAll(ctx, false); err != nil {
				m.log("adblock: scheduled update: %v", err)
			}
		}
	}
}

// dohBypassDomains are the public DNS-over-HTTPS resolvers a browser or app
// will silently switch to, routing straight around this filter. Blocking the
// bootstrap names forces a fall back to the network resolver.
var dohBypassDomains = []string{
	"dns.google", "dns64.dns.google", "cloudflare-dns.com", "one.one.one.one",
	"mozilla.cloudflare-dns.com", "chrome.cloudflare-dns.com", "security.cloudflare-dns.com",
	"family.cloudflare-dns.com", "dns.quad9.net", "dns9.quad9.net", "dns10.quad9.net",
	"dns11.quad9.net", "doh.opendns.com", "doh.familyshield.opendns.com",
	"dns.nextdns.io", "doh.cleanbrowsing.org", "doh.dns.sb", "dns.adguard.com",
	"dns-family.adguard.com", "dns-unfiltered.adguard.com", "doh.mullvad.net",
	"adblock.doh.mullvad.net", "dns.controld.com", "freedns.controld.com",
	"doh.libredns.gr", "doh.tiar.app", "doh.360.cn", "doh.pub", "dns.alidns.com",
	"resolver.dnscrypt.info", "odoh.cloudflare-dns.com",
}
