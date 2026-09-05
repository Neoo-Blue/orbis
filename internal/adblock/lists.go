package adblock

import (
	"bufio"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
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

	mu        sync.Mutex
	updating  bool
	lastBuild time.Time
	lastCount int
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
			if err := m.updateOne(ctx, meta); err != nil {
				m.log("adblock: list %q failed: %v", meta.Name, err)
				_ = m.st.SetListError(meta.Name, err.Error())
			}
		}(meta)
	}
	wg.Wait()
	return m.Rebuild()
}

func (m *Manager) updateOne(ctx context.Context, meta store.ListMeta) error {
	reqCtx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, meta.URL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "orbis/1.0 (+https://github.com/Neoo-Blue/orbis)")
	req.Header.Set("Accept-Encoding", "gzip")
	if meta.ETag != "" {
		req.Header.Set("If-None-Match", meta.ETag)
	}
	resp, err := m.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotModified {
		m.log("adblock: %s unchanged", meta.Name)
		return nil
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	var reader io.Reader = io.LimitReader(resp.Body, 256<<20)
	if strings.EqualFold(resp.Header.Get("Content-Encoding"), "gzip") {
		gz, err := gzip.NewReader(reader)
		if err != nil {
			return fmt.Errorf("gzip: %w", err)
		}
		defer gz.Close()
		reader = gz
	}

	exact, wild, err := ParseList(reader)
	if err != nil {
		return err
	}
	if len(exact)+len(wild) == 0 {
		return fmt.Errorf("list parsed to zero entries (format change?)")
	}
	if err := m.st.ReplaceListDomains(meta.Name, meta.Category, exact, wild); err != nil {
		return err
	}
	meta.ETag = resp.Header.Get("ETag")
	now := time.Now()
	meta.LastUpdated = &now
	meta.Entries = len(exact) + len(wild)
	_ = m.st.UpsertListMeta(meta)
	m.log("adblock: %s -> %d entries", meta.Name, meta.Entries)
	return nil
}

// Rebuild reconstructs the in-memory index from the database. Called after a
// list refresh and whenever local rules change.
func (m *Manager) Rebuild() error {
	b := NewBuilder()
	if err := m.st.AllBlockDomains(func(domain, category string, wildcard bool) {
		b.AddBlock(domain, "list", category, wildcard)
	}); err != nil {
		return err
	}

	// Config-level overrides come next.
	cfg := m.cfg.Snapshot()
	for _, d := range cfg.AdBlock.Denylist {
		b.AddBlock(d, "config", "manual", strings.HasPrefix(d, "*."))
	}
	for _, d := range cfg.AdBlock.Allowlist {
		b.AddAllow(d, strings.HasPrefix(d, "*."))
	}

	// Local rules (UI, assistant, smart capture) are authoritative and are
	// applied last so they can override a subscribed list either way.
	local, err := m.st.LocalRules()
	if err != nil {
		return err
	}
	for _, r := range local {
		if r.Action == "allow" {
			b.AddAllow(r.Domain, r.Wildcard)
		} else {
			b.AddBlock(r.Domain, "local:"+r.Origin, "manual", r.Wildcard)
		}
	}

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
	return nil
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

// dnsrewriteBlocksAll reports whether an AdBlock rule's option modifiers
// amount to nothing more than a DNS rewrite: every modifier is either
// $dnsrewrite=... or $important. Filter lists use $dnsrewrite to point ads
// and trackers at a block page or a null address instead of NXDOMAIN, but a
// DNS-only blocker has no way to serve that rewritten answer, so the closest
// honest behaviour is to block the name outright. Any other modifier (for
// example $third-party or $domain=) changes when the rule applies in ways
// this parser cannot evaluate, so those rules are still skipped.
func dnsrewriteBlocksAll(modifiers string) bool {
	hasDNSRewrite := false
	for _, mod := range strings.Split(modifiers, ",") {
		mod = strings.TrimSpace(mod)
		switch {
		case mod == "":
			continue
		case mod == "important":
			continue
		case strings.HasPrefix(mod, "dnsrewrite"):
			hasDNSRewrite = true
		default:
			return false
		}
	}
	return hasDNSRewrite
}

// ParseList understands the formats real blocklists ship in:
//
//	hosts:      0.0.0.0 ads.example.com
//	plain:      ads.example.com
//	wildcard:   *.ads.example.com  |  .ads.example.com
//	AdBlock:    ||ads.example.com^
//	dnsmasq:    address=/ads.example.com/0.0.0.0
//
// Cosmetic AdBlock rules (##selector) and anything with a path component are
// skipped: a DNS-level blocker cannot honour them, and pretending otherwise
// produces overblocking.
func ParseList(r io.Reader) (exact []string, wildcard []string, err error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	seenExact := make(map[string]struct{}, 1<<16)
	seenWild := make(map[string]struct{}, 1<<12)

	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' || line[0] == '!' || strings.HasPrefix(line, "//") {
			continue
		}
		// Strip trailing comments.
		if i := strings.IndexAny(line, "#!"); i > 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line == "" {
			continue
		}

		switch {
		case strings.HasPrefix(line, "||"):
			// AdBlock network rule. Only host-anchored rules with no path
			// translate cleanly to DNS. A rule with option modifiers is kept
			// only when every modifier is a $dnsrewrite (or $important
			// alongside one): those rules redirect the request to a block
			// page or a null address, which is semantically a block at the
			// DNS layer even though the rewrite target itself is discarded.
			body := line[2:]
			if i := strings.Index(body, "/"); i >= 0 {
				continue
			}
			if i := strings.Index(body, "$"); i >= 0 {
				if !dnsrewriteBlocksAll(body[i+1:]) {
					continue
				}
				body = body[:i]
			}
			body = strings.TrimSuffix(body, "^")
			if strings.ContainsAny(body, "*^|") {
				continue
			}
			if d := normalize(body); d != "" {
				seenWild[d] = struct{}{}
			}

		case strings.HasPrefix(line, "@@"):
			// Exception rules are not applied here; they belong to the
			// allowlist path and blindly importing them inverts a list.
			continue

		case strings.HasPrefix(line, "address=/"):
			body := strings.TrimPrefix(line, "address=/")
			if i := strings.Index(body, "/"); i > 0 {
				if d := normalize(body[:i]); d != "" {
					seenWild[d] = struct{}{}
				}
			}

		case strings.HasPrefix(line, "server=/"):
			body := strings.TrimPrefix(line, "server=/")
			if i := strings.Index(body, "/"); i > 0 {
				if d := normalize(body[:i]); d != "" {
					seenWild[d] = struct{}{}
				}
			}

		default:
			fields := strings.Fields(line)
			var host string
			switch len(fields) {
			case 1:
				host = fields[0]
			default:
				// hosts format: an IP then one or more names.
				ip := fields[0]
				if ip == "0.0.0.0" || ip == "127.0.0.1" || ip == "::" || ip == "::1" || ip == "0.0.0.0.0" {
					for _, h := range fields[1:] {
						if h == "localhost" || h == "localhost.localdomain" ||
							h == "local" || h == "broadcasthost" || h == "ip6-localhost" ||
							h == "ip6-loopback" || h == "ip6-localnet" || h == "ip6-mcastprefix" ||
							h == "ip6-allnodes" || h == "ip6-allrouters" {
							continue
						}
						if d := normalize(h); d != "" {
							seenExact[d] = struct{}{}
						}
					}
					continue
				}
				host = fields[0]
			}
			isWild := strings.HasPrefix(host, "*.") || strings.HasPrefix(host, ".")
			if d := normalize(strings.TrimPrefix(host, ".")); d != "" {
				if isWild {
					seenWild[d] = struct{}{}
				} else {
					seenExact[d] = struct{}{}
				}
			}
		}
	}
	if err := sc.Err(); err != nil {
		return nil, nil, err
	}
	// A wildcard entry already covers the exact name, so drop the duplicate.
	exact = make([]string, 0, len(seenExact))
	for d := range seenExact {
		if _, ok := seenWild[d]; !ok {
			exact = append(exact, d)
		}
	}
	wildcard = make([]string, 0, len(seenWild))
	for d := range seenWild {
		wildcard = append(wildcard, d)
	}
	return exact, wildcard, nil
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
