package threat

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Neoo-Blue/orbis/internal/config"
	"github.com/Neoo-Blue/orbis/internal/geoip"
	"github.com/Neoo-Blue/orbis/internal/store"
	"github.com/google/uuid"
)

// Manager owns the feeds, the decisions and the merged table, and tells the
// enforcement points (the firewall's sets, the intercept table) whenever the
// set of listed addresses changes.
type Manager struct {
	cfg  *config.Config
	st   *store.Store
	geo  *geoip.Resolver
	log  func(string, ...any)
	ua   string
	http *http.Client

	mu        sync.RWMutex
	table     *Table
	feedSets  map[string][]netip.Prefix
	decisions map[string]store.ThreatDecision
	excluded  int
	lastBuild time.Time
	lastFeeds time.Time

	// Hooks the application wires in.
	onChange func(v4, v6 []string)
	emit     func(store.Event)
	enforced func(local netip.Addr, outbound bool) bool
	block    func(flowID, reason string) bool
	nameOf   func(clientID string) string

	coolMu   sync.Mutex
	cooldown map[string]time.Time
	hits     atomic.Int64

	kick chan struct{}

	csMu       sync.Mutex
	csLastPull time.Time
	csLastErr  string
	csStartup  bool
	csIgnored  int
	csURL      string
	csKey      string
}

func NewManager(cfg *config.Config, st *store.Store, geo *geoip.Resolver, version string, log func(string, ...any)) *Manager {
	if log == nil {
		log = func(string, ...any) {}
	}
	return &Manager{
		cfg: cfg, st: st, geo: geo, log: log,
		ua:        "orbis-bouncer/" + version + " (+https://github.com/Neoo-Blue/orbis)",
		http:      &http.Client{Timeout: 90 * time.Second},
		feedSets:  map[string][]netip.Prefix{},
		decisions: map[string]store.ThreatDecision{},
		cooldown:  map[string]time.Time{},
		kick:      make(chan struct{}, 1),
		csStartup: true,
	}
}

// SetOnChange receives the full element lists whenever the table changes.
func (m *Manager) SetOnChange(fn func(v4, v6 []string)) { m.onChange = fn }

// SetEmit receives the events hits produce.
func (m *Manager) SetEmit(fn func(store.Event)) { m.emit = fn }

// SetEnforced answers whether a connection for this local address, in this
// direction, is actually dropped by a ruleset (as opposed to only recorded).
func (m *Manager) SetEnforced(fn func(local netip.Addr, outbound bool) bool) { m.enforced = fn }

// SetBlocker is the flow tracker's kill switch, used to mark and end a flow
// that reached a listed address.
func (m *Manager) SetBlocker(fn func(flowID, reason string) bool) { m.block = fn }

// SetNamer turns a client id into the name events use.
func (m *Manager) SetNamer(fn func(clientID string) string) { m.nameOf = fn }

// Load restores feeds and decisions from the database so enforcement is in
// place before the first network fetch, and before the firewall renders.
func (m *Manager) Load() {
	entries, err := m.st.ThreatEntries()
	if err != nil {
		m.log("threat: load entries: %v", err)
	}
	decisions, err := m.st.ThreatDecisions(true)
	if err != nil {
		m.log("threat: load decisions: %v", err)
	}
	m.mu.Lock()
	for feed, list := range entries {
		out := make([]netip.Prefix, 0, len(list))
		for _, s := range list {
			if p, ok := ParsePrefix(s); ok {
				out = append(out, p)
			}
		}
		m.feedSets[feed] = out
	}
	for _, d := range decisions {
		m.decisions[d.ID] = d
	}
	m.mu.Unlock()
	m.rebuild()
}

// Run refreshes feeds on their interval, polls CrowdSec, expires decisions
// and prunes old hits until ctx ends.
func (m *Manager) Run(ctx context.Context) {
	first := time.NewTimer(15 * time.Second)
	defer first.Stop()
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	lastExpire, lastPrune, lastCS := time.Now(), time.Time{}, time.Time{}
	for {
		select {
		case <-ctx.Done():
			return
		case <-first.C:
			if err := m.Refresh(ctx, false); err != nil {
				m.log("threat: initial refresh: %v", err)
			}
		case <-m.kick:
			if err := m.Refresh(ctx, false); err != nil {
				m.log("threat: refresh: %v", err)
			}
		case now := <-tick.C:
			cfg := m.cfg.Snapshot().Threat
			if cfg.CrowdSec.Enabled {
				every := time.Duration(max(cfg.CrowdSec.PollSeconds, 10)) * time.Second
				if now.Sub(lastCS) >= every {
					lastCS = now
					m.pollCrowdSec(ctx)
				}
			}
			if now.Sub(lastExpire) >= time.Minute {
				lastExpire = now
				m.expire(now)
			}
			m.mu.RLock()
			due := now.Sub(m.lastFeeds) >= 30*time.Minute
			m.mu.RUnlock()
			if due {
				if err := m.Refresh(ctx, false); err != nil {
					m.log("threat: scheduled refresh: %v", err)
				}
			}
			if now.Sub(lastPrune) >= 24*time.Hour {
				lastPrune = now
				_ = m.st.PruneThreatHits(now.Add(-30 * 24 * time.Hour))
			}
		}
	}
}

// Reconfigure is called after the configuration changed: feeds added or
// removed, the feature toggled, the allow list edited. It rebuilds at once
// and schedules a fetch for anything new.
func (m *Manager) Reconfigure() {
	m.rebuild()
	select {
	case m.kick <- struct{}{}:
	default:
	}
}

// Refresh fetches feeds that are stale (or all of them when forced), stores
// what parsed, and rebuilds the table if anything changed.
func (m *Manager) Refresh(ctx context.Context, force bool) error {
	cfg := m.cfg.Snapshot().Threat
	interval := time.Duration(max(cfg.UpdateIntervalHours, 1)) * time.Hour
	stored, err := m.st.ThreatFeeds()
	if err != nil {
		return err
	}
	metas := map[string]store.ThreatFeedMeta{}
	for _, meta := range stored {
		metas[meta.Name] = meta
	}
	m.mu.Lock()
	m.lastFeeds = time.Now()
	m.mu.Unlock()

	changed := false
	configured := map[string]bool{}
	var firstErr error
	for _, f := range cfg.Feeds {
		if f.Name == "" || f.URL == "" {
			continue
		}
		configured[f.Name] = true
		meta := metas[f.Name]
		meta.Name, meta.URL, meta.Category, meta.Enabled = f.Name, f.URL, f.Category, f.Enabled
		if !f.Enabled {
			_ = m.st.UpsertThreatFeed(meta)
			continue
		}
		m.mu.RLock()
		have := len(m.feedSets[f.Name])
		m.mu.RUnlock()
		fresh := meta.FetchedAt != nil && time.Since(*meta.FetchedAt) < interval && have > 0
		if fresh && !force {
			_ = m.st.UpsertThreatFeed(meta)
			continue
		}
		prefixes, skipped, etag, unchanged, err := m.fetch(ctx, f.URL, meta.ETag)
		now := time.Now()
		if err != nil {
			meta.LastError = err.Error()
			_ = m.st.UpsertThreatFeed(meta)
			m.log("threat: feed %q: %v", f.Name, err)
			if firstErr == nil {
				firstErr = fmt.Errorf("%s: %w", f.Name, err)
			}
			continue
		}
		if unchanged && have > 0 {
			meta.FetchedAt, meta.LastError = &now, ""
			_ = m.st.UpsertThreatFeed(meta)
			continue
		}
		if len(prefixes) == 0 {
			meta.LastError = "feed parsed to zero usable entries (format change?)"
			_ = m.st.UpsertThreatFeed(meta)
			m.log("threat: feed %q parsed to zero entries", f.Name)
			continue
		}
		strs := make([]string, 0, len(prefixes))
		for _, p := range prefixes {
			strs = append(strs, p.String())
		}
		if err := m.st.ReplaceThreatEntries(f.Name, strs); err != nil {
			m.log("threat: feed %q: store: %v", f.Name, err)
		}
		meta.Entries, meta.Skipped, meta.FetchedAt, meta.LastError, meta.ETag = len(prefixes), skipped, &now, "", etag
		_ = m.st.UpsertThreatFeed(meta)
		m.mu.Lock()
		m.feedSets[f.Name] = prefixes
		m.mu.Unlock()
		changed = true
		m.log("threat: feed %q: %d entries (%d skipped)", f.Name, len(prefixes), skipped)
	}
	for name := range metas {
		if configured[name] {
			continue
		}
		_ = m.st.DeleteThreatFeed(name)
		m.mu.Lock()
		delete(m.feedSets, name)
		m.mu.Unlock()
		changed = true
	}
	if changed || force {
		m.rebuild()
	}
	return firstErr
}

func (m *Manager) fetch(ctx context.Context, url, etag string) (prefixes []netip.Prefix, skipped int, newETag string, unchanged bool, err error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, 0, "", false, err
	}
	req.Header.Set("User-Agent", m.ua)
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	resp, err := m.http.Do(req)
	if err != nil {
		return nil, 0, "", false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotModified {
		return nil, 0, etag, true, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, 0, "", false, fmt.Errorf("http %d", resp.StatusCode)
	}
	prefixes, skipped = ParseFeed(io.LimitReader(resp.Body, 32<<20))
	return prefixes, skipped, resp.Header.Get("ETag"), false, nil
}

// rebuild merges enabled feeds and active decisions into one table, applies
// the allow list, and pushes the result to the enforcement points.
func (m *Manager) rebuild() {
	cfg := m.cfg.Snapshot().Threat
	enabledFeed := map[string]config.ThreatFeed{}
	for _, f := range cfg.Feeds {
		if f.Enabled {
			enabledFeed[f.Name] = f
		}
	}
	var allow []netip.Prefix
	for _, s := range cfg.Allow {
		if p, ok := ParsePrefix(s); ok {
			allow = append(allow, p)
		}
	}
	m.mu.Lock()
	var entries []Entry
	// Decisions first so a ban's reason wins over a feed's category when the
	// same address is in both.
	for _, d := range m.decisions {
		if d.Until != nil && d.Until.Before(time.Now()) {
			continue
		}
		if p, ok := ParsePrefix(d.Value); ok {
			entries = append(entries, Entry{Prefix: p, Source: d.Source, Reason: d.Reason})
		}
	}
	names := make([]string, 0, len(m.feedSets))
	for name := range m.feedSets {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		f, on := enabledFeed[name]
		if !on {
			continue
		}
		for _, p := range m.feedSets[name] {
			entries = append(entries, Entry{Prefix: p, Source: name, Reason: f.Category})
		}
	}
	t, excluded := Build(entries, allow)
	m.table, m.excluded, m.lastBuild = t, excluded, time.Now()
	m.mu.Unlock()

	if m.onChange != nil {
		if cfg.Enabled {
			v4, v6 := t.Elements()
			m.onChange(v4, v6)
		} else {
			m.onChange(nil, nil)
		}
	}
}

func (m *Manager) expire(now time.Time) {
	ids, err := m.st.ExpireThreatDecisions(now)
	if err != nil {
		m.log("threat: expire: %v", err)
		return
	}
	if len(ids) == 0 {
		return
	}
	m.mu.Lock()
	for _, id := range ids {
		delete(m.decisions, id)
	}
	m.mu.Unlock()
	m.rebuild()
}

// Elements is the current set as nftables elements, empty when the feature
// is off so a rendered ruleset carries no stale drops.
func (m *Manager) Elements() (v4, v6 []string) {
	if !m.cfg.Snapshot().Threat.Enabled {
		return nil, nil
	}
	m.mu.RLock()
	t := m.table
	m.mu.RUnlock()
	return t.Elements()
}

// Lookup reports whether an address is listed, honouring the master switch.
func (m *Manager) Lookup(a netip.Addr) (Entry, bool) {
	if !m.cfg.Snapshot().Threat.Enabled {
		return Entry{}, false
	}
	m.mu.RLock()
	t := m.table
	m.mu.RUnlock()
	return t.Lookup(a)
}

// Describe is the assistant-facing view of one address.
func (m *Manager) Describe(a netip.Addr) map[string]any {
	e, ok := m.Lookup(a)
	if !ok {
		return map[string]any{"listed": false}
	}
	return map[string]any{"listed": true, "prefix": e.Prefix.String(), "source": e.Source, "reason": e.Reason}
}

// Observe is called for every new flow. A flow to or from a listed address
// becomes a hit (and an event, rate-limited per device and prefix), and is
// killed when this node is in a position to do so.
func (m *Manager) Observe(f *store.Flow) {
	cfg := m.cfg.Snapshot().Threat
	if !cfg.Enabled || f == nil {
		return
	}
	outbound := f.Direction != "in"
	if outbound && !cfg.BlockOutbound || !outbound && !cfg.BlockInbound {
		return
	}
	remoteS, localS := f.DstIP, f.SrcIP
	if !outbound {
		remoteS, localS = f.SrcIP, f.DstIP
	}
	remote, err := netip.ParseAddr(remoteS)
	if err != nil {
		return
	}
	e, ok := m.Lookup(remote)
	if !ok {
		return
	}
	local, _ := netip.ParseAddr(localS)
	enforced := m.enforced != nil && m.enforced(local, outbound)
	reason := "listed address: " + e.Source
	if e.Reason != "" {
		reason += " (" + e.Reason + ")"
	}
	if enforced && m.block != nil && f.ID != "" {
		id := f.ID
		go m.block(id, reason)
	}
	m.hits.Add(1)

	dir := "out"
	if !outbound {
		dir = "in"
	}
	key := localS + "|" + remoteS
	if !m.cool("hit:"+key, time.Minute) {
		return
	}
	var country, org string
	if m.geo != nil {
		loc := m.geo.LookupAddr(remote)
		country, org = loc.Country, loc.ASOrg
	}
	_ = m.st.AddThreatHit(store.ThreatHit{
		TS: time.Now(), ClientID: f.ClientID, LocalIP: localS, RemoteIP: remoteS, Prefix: e.Prefix.String(),
		Source: e.Source, Reason: e.Reason, Direction: dir, Port: f.DstPort, Proto: f.Proto,
		Enforced: enforced, FlowID: f.ID, Country: country, ASOrg: org,
	})

	if m.emit == nil || !m.cool("event:"+localS+"|"+e.Prefix.String(), time.Hour) {
		return
	}
	name := localS
	if m.nameOf != nil && f.ClientID != "" {
		if n := m.nameOf(f.ClientID); n != "" {
			name = n
		}
	}
	where := remoteS
	if org != "" {
		where += " (" + org
		if country != "" {
			where += ", " + country
		}
		where += ")"
	}
	listed := "is on the " + e.Source + " list"
	if e.Source == "manual" || e.Source == "assistant" || e.Source == "scan" || e.Source == crowdsecSource {
		listed = "is banned (" + e.Source + ")"
	}
	if e.Reason != "" {
		listed += ": " + e.Reason
	}
	var title, detail, sev string
	if outbound {
		sev = store.SevWarning
		title = fmt.Sprintf("%s reached a listed address", name)
		detail = fmt.Sprintf("%s connected to %s on port %d. That address %s.", name, where, f.DstPort, listed)
		if enforced {
			detail += " The connection was dropped."
		} else {
			detail += " Nothing was dropped: this node is not in the path for that device (observe mode, not intercepted). A device that keeps doing this may be compromised."
		}
	} else {
		sev = store.SevNotice
		title = fmt.Sprintf("Listed address tried to reach %s", name)
		detail = fmt.Sprintf("%s connected in to %s on port %d. That address %s.", where, name, f.DstPort, listed)
		if enforced {
			detail += " The connection was dropped."
		} else {
			detail += " It was recorded, not dropped: this node does not enforce for that device."
		}
	}
	m.emit(store.Event{
		ID: uuid.NewString(), TS: time.Now(), Severity: sev, Category: "threat", Title: title, Detail: detail,
		ClientID: f.ClientID, FlowID: f.ID,
		Data: map[string]any{
			"remote": remoteS, "local": localS, "prefix": e.Prefix.String(), "source": e.Source,
			"reason": e.Reason, "direction": dir, "enforced": enforced, "port": f.DstPort,
		},
	})
}

func (m *Manager) cool(key string, d time.Duration) bool {
	m.coolMu.Lock()
	defer m.coolMu.Unlock()
	now := time.Now()
	if t, ok := m.cooldown[key]; ok && now.Sub(t) < d {
		return false
	}
	if len(m.cooldown) > 20000 {
		for k, t := range m.cooldown {
			if now.Sub(t) > time.Hour {
				delete(m.cooldown, k)
			}
		}
	}
	m.cooldown[key] = now
	return true
}

// Ban records a timed decision against an address or range. A zero duration
// is permanent. Local and reserved addresses are refused: pausing a device
// is a different feature with a different blast radius.
func (m *Manager) Ban(value string, d time.Duration, reason, source, actor string) (*store.ThreatDecision, error) {
	p, ok := ParsePrefix(value)
	if !ok {
		return nil, fmt.Errorf("%q is not an address or a range", value)
	}
	if !Usable(p) {
		return nil, fmt.Errorf("%s is a local, reserved or too-wide range; bans are for internet addresses", p)
	}
	if source == "" {
		source = "manual"
	}
	dec := store.ThreatDecision{
		ID: uuid.NewString(), Value: p.String(), Source: source, Reason: strings.TrimSpace(reason),
		Actor: actor, Created: time.Now(),
	}
	if d > 0 {
		t := dec.Created.Add(d)
		dec.Until = &t
	}
	if err := m.st.PutThreatDecision(dec); err != nil {
		return nil, err
	}
	m.mu.Lock()
	m.decisions[dec.ID] = dec
	m.mu.Unlock()
	m.rebuild()
	return &dec, nil
}

// Unban lifts a decision by id, or every non-CrowdSec decision on a value.
// CrowdSec decisions belong to the engine; lift them there.
func (m *Manager) Unban(idOrValue string) (int, error) {
	m.mu.Lock()
	var ids []string
	if d, ok := m.decisions[idOrValue]; ok {
		ids = append(ids, d.ID)
	} else if p, ok := ParsePrefix(idOrValue); ok {
		for id, d := range m.decisions {
			if d.Value == p.String() && d.Source != crowdsecSource {
				ids = append(ids, id)
			}
		}
	}
	for _, id := range ids {
		delete(m.decisions, id)
	}
	m.mu.Unlock()
	if len(ids) == 0 {
		return 0, fmt.Errorf("no ban matches %q", idOrValue)
	}
	for _, id := range ids {
		if err := m.st.DeleteThreatDecision(id); err != nil {
			return 0, err
		}
	}
	m.rebuild()
	return len(ids), nil
}

// Decisions lists active bans, newest first.
func (m *Manager) Decisions() []store.ThreatDecision {
	m.mu.RLock()
	out := make([]store.ThreatDecision, 0, len(m.decisions))
	for _, d := range m.decisions {
		out = append(out, d)
	}
	m.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool { return out[i].Created.After(out[j].Created) })
	return out
}

// Feeds returns feed metadata in configuration order, with the in-memory
// entry count so a feed that failed to fetch still shows what it holds.
func (m *Manager) Feeds() []store.ThreatFeedMeta {
	cfg := m.cfg.Snapshot().Threat
	stored, _ := m.st.ThreatFeeds()
	byName := map[string]store.ThreatFeedMeta{}
	for _, s := range stored {
		byName[s.Name] = s
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]store.ThreatFeedMeta, 0, len(cfg.Feeds))
	for _, f := range cfg.Feeds {
		meta := byName[f.Name]
		meta.Name, meta.URL, meta.Category, meta.Enabled = f.Name, f.URL, f.Category, f.Enabled
		if n := len(m.feedSets[f.Name]); n > 0 {
			meta.Entries = n
		}
		out = append(out, meta)
	}
	return out
}

// Status is the page summary.
func (m *Manager) Status() map[string]any {
	cfg := m.cfg.Snapshot().Threat
	m.mu.RLock()
	entries := m.table.Len()
	excluded := m.excluded
	build := m.lastBuild
	bySource := map[string]int{}
	for _, d := range m.decisions {
		bySource[d.Source]++
	}
	active := len(m.decisions)
	m.mu.RUnlock()
	total, enforced, _ := m.st.ThreatHitCount(time.Now().Add(-24 * time.Hour))
	out := map[string]any{
		"enabled": cfg.Enabled, "block_outbound": cfg.BlockOutbound, "block_inbound": cfg.BlockInbound,
		"entries": entries, "excluded_by_allow": excluded, "decisions": active, "decisions_by_source": bySource,
		"hits_24h": total, "dropped_24h": enforced, "hits_since_start": m.hits.Load(),
		"auto_ban_scanners": cfg.AutoBanScanners, "update_interval_hours": cfg.UpdateIntervalHours,
		"allow": cfg.Allow, "crowdsec": m.crowdsecStatus(),
	}
	if !build.IsZero() {
		out["last_build"] = build
	}
	return out
}

// HitCount is how many hits (and drops) landed in a window.
func (m *Manager) HitCount(since time.Time) (total, enforced int) {
	total, enforced, _ = m.st.ThreatHitCount(since)
	return
}

// Hits lists recorded hits since a time.
func (m *Manager) Hits(since time.Time, limit int) ([]store.ThreatHit, error) {
	return m.st.ThreatHits(since, limit)
}

// Counts is the cheap summary the metrics endpoint scrapes.
func (m *Manager) Counts() (entries, decisions int) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.table.Len(), len(m.decisions)
}

// HitsSinceStart is a monotonic hit counter for metrics.
func (m *Manager) HitsSinceStart() int64 { return m.hits.Load() }
