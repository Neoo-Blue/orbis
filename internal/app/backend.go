package app

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"strings"
	"time"

	"github.com/Neoo-Blue/orbis/internal/alerts"
	"github.com/Neoo-Blue/orbis/internal/config"
	"github.com/Neoo-Blue/orbis/internal/consent"
	"github.com/Neoo-Blue/orbis/internal/dnsproxy"
	"github.com/Neoo-Blue/orbis/internal/firewall"
	"github.com/Neoo-Blue/orbis/internal/geoip"
	"github.com/Neoo-Blue/orbis/internal/intercept"
	"github.com/Neoo-Blue/orbis/internal/issues"
	"github.com/Neoo-Blue/orbis/internal/report"
	"github.com/Neoo-Blue/orbis/internal/store"
	"github.com/google/uuid"
)

// App implements ai.Backend. Every one of these methods is also what the REST
// layer calls, so the assistant and the UI operate on identical semantics —
// there is no "API-only" path that behaves differently from what the model
// was told it was doing.

func (a *App) Summary(since time.Time) (map[string]any, error) {
	out, err := a.Store.Summary(since)
	if err != nil {
		return nil, err
	}
	ts := a.Tracker.Stats()
	out["active_flows"] = ts.Active
	out["flows_seen"] = ts.Total
	out["sni_extracted"] = ts.SNIExtracted
	out["quic_decrypted"] = ts.QUICDecrypted
	out["mode"] = string(a.Cfg.Snapshot().Mode)
	out["uptime_seconds"] = int(a.Uptime().Seconds())
	return out, nil
}

func (a *App) Clients() []store.Client { return a.Registry.All() }

func (a *App) ActiveFlows(limit int) []store.Flow { return a.Tracker.Active(limit) }

func (a *App) QueryFlows(q store.FlowQuery) ([]store.Flow, error) { return a.Store.Flows(q) }

func (a *App) TopDestinations(since time.Time, clientID string, limit int) ([]map[string]any, error) {
	return a.Store.TopDestinations(since, clientID, limit)
}

func (a *App) DNSLog(since time.Time, clientID string, blockedOnly bool, search string, limit int) ([]store.DNSQuery, error) {
	return a.Store.DNSLog(since, clientID, blockedOnly, search, limit)
}

func (a *App) TopBlocked(since time.Time, limit int) ([]map[string]any, error) {
	return a.Store.TopBlocked(since, limit)
}

func (a *App) Events(since time.Time, severity string, unackOnly bool, limit int) ([]store.Event, error) {
	return a.Store.Events(since, severity, unackOnly, limit)
}

func (a *App) Rules() ([]store.Rule, error) { return a.Store.Rules() }

func (a *App) AdCandidates(status string, minScore float64, limit int) ([]store.AdCandidate, error) {
	return a.Store.Candidates(status, minScore, limit)
}

// LookupIP places an address for the assistant: where it is, whose network it
// is on, its reverse name, and whether it is one of our own devices.
func (a *App) LookupIP(ip string) (map[string]any, error) {
	addr, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil {
		return nil, fmt.Errorf("%q is not an IP address", ip)
	}
	out := map[string]any{"ip": addr.String(), "private": geoip.IsPrivate(addr)}
	if c := a.Registry.ByIP(addr); c != nil {
		name := c.Label
		if name == "" {
			name = c.Hostname
		}
		out["device"] = map[string]any{
			"id": c.ID, "name": name, "mac": c.MAC, "vendor": c.Vendor, "type": c.DeviceType, "online": c.Online,
		}
	}
	if !geoip.IsPrivate(addr) {
		loc := a.Geo.LookupAddr(addr)
		out["country"] = loc.Country
		out["country_name"] = loc.CountryName
		out["city"] = loc.City
		out["asn"] = loc.ASN
		out["network"] = loc.ASOrg
		out["anycast"] = loc.Anycast
		out["accuracy"] = loc.Accuracy
	}
	ctx, cancel := context.WithTimeout(a.ctx, 2*time.Second)
	defer cancel()
	if names, err := net.DefaultResolver.LookupAddr(ctx, addr.String()); err == nil && len(names) > 0 {
		for i := range names {
			names[i] = strings.TrimSuffix(names[i], ".")
		}
		out["reverse_dns"] = names
	}
	return out, nil
}

// YouTubeStatus is the Lounge engine's state, for the assistant.
func (a *App) YouTubeStatus() any {
	if a.Lounge == nil {
		return nil
	}
	return a.Lounge.Status()
}

// Series reads a per-minute metric, downsampled when buckets is set.
func (a *App) Series(metric string, since time.Time, buckets int) ([]map[string]any, error) {
	if buckets > 0 {
		return a.Store.SeriesDownsampled(metric, since, buckets)
	}
	return a.Store.Series(metric, since)
}

func (a *App) CountryTotals(since time.Time) ([]map[string]any, error) {
	return a.Store.CountryTotals(since)
}

func (a *App) Leases() ([]store.Lease, error) { return a.Store.Leases() }

func (a *App) AuditLog(limit int) ([]store.AuditEntry, error) { return a.Store.AuditLog(limit) }

// recordBrief persists an AI brief as an event and, when asked, pushes it
// through the notification sinks like any other event.
func (a *App) recordBrief(ev store.Event, notify bool) {
	_ = a.Store.AddEvent(ev)
	if notify && a.Notifier != nil {
		a.Notifier.Send(ev)
	}
	a.Bus.Publish(Event{Type: "event.new", Data: map[string]any{
		"severity": ev.Severity, "category": ev.Category, "title": ev.Title, "detail": ev.Detail,
	}})
	a.Bus.Publish(Event{Type: "ai.brief", Data: ev.Data})
}

// SystemStatus is the single call the dashboard and the assistant both use to
// answer "is everything working".
func (a *App) SystemStatus() map[string]any {
	cfg := a.Cfg.Snapshot()
	status := map[string]any{
		"mode":       string(cfg.Mode),
		"node":       cfg.Node.Name,
		"uptime_sec": int(a.Uptime().Seconds()),
		"capture":    a.captureStatus(),
		"dns":        a.DNS.Stats(),
		"dhcp":       a.DHCP.Stats(),
		"firewall":   a.Firewall.Status(),
		"vpn":        a.VPN.Status(),
		"tailscale":  a.Tailscale.Status(a.ctx),
		"adblock":    a.Lists.Status(),
		"geoip":      a.Geo.Source(),
		"self":       a.Self.Status(),
		"bus":        a.Bus.Stats(),
		"sysctl":     firewall.CheckSysctls(),
	}
	if a.MITM != nil {
		status["filter_proxy"] = a.MITM.Stats()
	} else {
		status["filter_proxy"] = map[string]any{"running": false, "error": "certificate authority unavailable"}
	}
	if a.CA != nil {
		status["ca"] = a.CA.Info()
	}
	aiStatus := map[string]any{
		"enabled":       cfg.AI.Enabled,
		"configured":    a.AI.Configured(),
		"provider":      cfg.AI.Provider,
		"model":         cfg.AI.Model,
		"fast_model":    cfg.AI.FastModel,
		"allow_write":   cfg.AI.AllowWrite,
		"anomaly":       cfg.AI.Anomaly.Enabled,
		"prefer_free":   cfg.AI.PreferFree,
		"brief_enabled": cfg.AI.Brief.Enabled,
	}
	if r := a.AI.Router(); r != nil {
		aiStatus["active_model"] = r.ActiveModel(cfg.AI)
		aiStatus["free_today"] = r.FreeRequestsToday()
		aiStatus["free_budget"] = cfg.AI.FreeDailyBudget
	}
	status["ai"] = aiStatus
	return status
}

func (a *App) captureStatus() map[string]any {
	s := a.Capture.Stats()
	t := a.Tracker.Stats()
	return map[string]any{
		"packets": s.Packets, "bytes": s.Bytes, "kernel_drops": s.KernelDrops,
		"parse_errors": s.ParseErrors, "interfaces": s.Interfaces,
		"filter_active": s.FilterActive, "truncated": s.Truncated,
		"active_flows": t.Active, "total_flows": t.Total,
		"capacity_drops": t.Dropped, "sni_extracted": t.SNIExtracted,
		"quic_decrypted": t.QUICDecrypted, "blocked": t.Blocked,
	}
}

// ---- mutating ----

func (a *App) AddRule(r *store.Rule) error {
	if err := a.Store.SaveRule(r); err != nil {
		return err
	}
	a.Store.Audit("api", "rule.create", r.ID, "", r.Name, "ok")
	a.Bus.Publish(Event{Type: "rule.changed", Data: r})
	return nil
}

func (a *App) DeleteRule(id string) error {
	if err := a.Store.DeleteRule(id); err != nil {
		return err
	}
	a.Store.Audit("api", "rule.delete", id, "", "", "ok")
	a.Bus.Publish(Event{Type: "rule.changed", Data: map[string]any{"id": id, "deleted": true}})
	return nil
}

func (a *App) SetRuleEnabled(id string, enabled bool) error {
	rules, err := a.Store.Rules()
	if err != nil {
		return err
	}
	for i := range rules {
		if rules[i].ID == id {
			rules[i].Enabled = enabled
			if err := a.Store.SaveRule(&rules[i]); err != nil {
				return err
			}
			a.Store.Audit("api", "rule.toggle", id, "", fmt.Sprint(enabled), "ok")
			a.Bus.Publish(Event{Type: "rule.changed", Data: rules[i]})
			return nil
		}
	}
	return fmt.Errorf("no rule with id %s", id)
}

func (a *App) BlockDomain(domain string, wildcard bool, note string) error {
	domain = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(domain, "*.")))
	if domain == "" || !strings.Contains(domain, ".") {
		return fmt.Errorf("%q is not a domain", domain)
	}
	if err := a.Store.SaveLocalRule(store.LocalRule{
		Domain: domain, Action: "block", Wildcard: wildcard, Origin: "user", Note: note,
	}); err != nil {
		return err
	}
	if err := a.Lists.Rebuild(); err != nil {
		return err
	}
	a.Store.Audit("api", "domain.block", domain, "", note, "ok")
	a.Bus.Publish(Event{Type: "adblock.changed", Data: map[string]any{"domain": domain, "action": "block"}})
	return nil
}

func (a *App) AllowDomain(domain, note string) error {
	domain = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(domain, "*.")))
	if domain == "" {
		return fmt.Errorf("domain is required")
	}
	if err := a.Store.SaveLocalRule(store.LocalRule{
		Domain: domain, Action: "allow", Wildcard: false, Origin: "user", Note: note,
	}); err != nil {
		return err
	}
	if err := a.Lists.Rebuild(); err != nil {
		return err
	}
	a.Store.Audit("api", "domain.allow", domain, "", note, "ok")
	a.Bus.Publish(Event{Type: "adblock.changed", Data: map[string]any{"domain": domain, "action": "allow"}})
	return nil
}

// SetClientBlocked quarantines a device. In inline mode this inserts its
// address into the nftables quarantine set; in observe mode it is recorded
// but cannot be enforced, and the UI says so.
func (a *App) SetClientBlocked(clientID string, blocked bool) error {
	c := a.Registry.ByID(clientID)
	if c == nil {
		return fmt.Errorf("no device with id %s", clientID)
	}
	if err := a.Store.SetClientFields(clientID, nil, nil, nil, nil, nil, &blocked); err != nil {
		return err
	}
	if addr, err := netip.ParseAddr(c.IP); err == nil && !blocked {
		_ = a.Firewall.UnblockAddress(addr)
	}
	if a.Cfg.Snapshot().Mode == config.ModeInline && blocked {
		if err := a.Firewall.Apply(a.ctx); err != nil {
			a.log("firewall: reapply after client block: %v", err)
		}
	}
	a.Store.Audit("api", "client.block", clientID, "", fmt.Sprint(blocked), "ok")
	a.Bus.Publish(Event{Type: "client.changed", Data: map[string]any{"id": clientID, "blocked": blocked}})
	return nil
}

func (a *App) SetClientLabel(clientID, label string) error {
	if err := a.Store.SetClientFields(clientID, &label, nil, nil, nil, nil, nil); err != nil {
		return err
	}
	a.Store.Audit("api", "client.label", clientID, "", label, "ok")
	a.Bus.Publish(Event{Type: "client.changed", Data: map[string]any{"id": clientID, "label": label}})
	return nil
}

func (a *App) ApplyFirewall(ctx context.Context) error {
	if err := a.Firewall.Apply(ctx); err != nil {
		a.Store.Audit("api", "firewall.apply", "", "", "", "error: "+err.Error())
		return err
	}
	a.Store.Audit("api", "firewall.apply", "", "", "", "ok")
	a.Bus.Publish(Event{Type: "firewall.applied", Data: a.Firewall.Status()})
	return nil
}

func (a *App) DecideCandidate(domain, decision, actor string) error {
	if err := a.Smart.Decide(domain, decision, actor); err != nil {
		return err
	}
	a.Store.Audit(actor, "candidate."+decision, domain, "", "", "ok")
	a.Bus.Publish(Event{Type: "adblock.candidate", Data: map[string]any{
		"domain": domain, "decision": decision,
	}})
	return nil
}

func (a *App) FlushDNSCache(domain string) int {
	if domain == "" {
		return a.DNS.Cache().Flush()
	}
	return a.DNS.Cache().FlushDomain(domain)
}

func (a *App) RefreshBlocklists(ctx context.Context) error {
	return a.Lists.UpdateAll(ctx, true)
}

// ReloadPolicies is exposed for the API layer after a policy edit.
func (a *App) ReloadPolicies() error { return a.reloadPolicies() }

// Log gives the API layer access to the daemon logger.
func (a *App) Log(format string, args ...any) { a.log(format, args...) }

// Context returns the app lifetime context.
func (a *App) Context() context.Context { return a.ctx }

// BackfillGeo re-resolves stored history against the current GeoIP database.
//
// Flows recorded before a database was installed keep whatever the coarse
// fallback guessed — frequently the wrong continent — and no amount of new
// traffic corrects the old rows. This is also what makes installing or
// updating a database take effect retroactively rather than only going
// forward.
func (a *App) BackfillGeo(ctx context.Context, limit int) (map[string]any, error) {
	// Anything not globally routable that picked up a position from an
	// earlier, coarser fallback gets it stripped.
	dests, err := a.Store.AllFlowDestinations(50000)
	if err != nil {
		return nil, err
	}
	var bogons []string
	for _, ip := range dests {
		if addr, err := netip.ParseAddr(ip); err != nil || geoip.IsPrivate(addr) {
			bogons = append(bogons, ip)
		}
	}
	cleared, err := a.Store.ClearFlowGeo(bogons)
	if err != nil {
		return nil, err
	}

	targets, err := a.Store.FlowsNeedingGeo(limit)
	if err != nil {
		return nil, err
	}

	updates := make([]store.GeoUpdate, 0, len(targets))
	unresolved := 0

	// Anycast rows need repairing even though they already carry a country and
	// an operator, because what they carry is the registry's country. A node
	// resolving over 1.1.1.1 accumulates tens of thousands of rows pointing at
	// Australia, which makes it the busiest country on the globe by an order of
	// magnitude. FlowsNeedingGeo will never revisit them: nothing is missing,
	// it is just wrong.
	anycastFixed := 0
	for _, ip := range dests {
		addr, err := netip.ParseAddr(ip)
		if err != nil {
			continue
		}
		loc, ok := geoip.LookupAnycast(addr)
		if !ok {
			continue
		}
		if enriched := a.Geo.LookupAddr(addr); enriched.ASN != 0 {
			loc.ASN = enriched.ASN
		}
		updates = append(updates, store.GeoUpdate{
			IP: ip, Country: loc.Country, City: loc.City,
			Lat: loc.Lat, Lon: loc.Lon, ASN: loc.ASN, ASOrg: loc.ASOrg,
		})
		anycastFixed++
	}
	for _, t := range targets {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		addr, err := netip.ParseAddr(t.IP)
		if err != nil || geoip.IsPrivate(addr) {
			continue
		}
		loc := a.Geo.LookupAddr(addr)
		// Only write back a real placement. Storing another region-level
		// guess would just relabel the same wrong answer.
		if loc.Accuracy != "city" && loc.Accuracy != "country" && loc.ASOrg == "" {
			unresolved++
			continue
		}
		updates = append(updates, store.GeoUpdate{
			IP: t.IP, Country: loc.Country, City: loc.City,
			Lat: loc.Lat, Lon: loc.Lon, ASN: loc.ASN, ASOrg: loc.ASOrg,
		})
	}

	rows, err := a.Store.ApplyGeoUpdates(updates)
	if err != nil {
		return nil, err
	}
	a.log("geoip: backfilled %d address(es) across %d row(s); corrected %d anycast address(es); cleared %d non-routable row(s), %d still unresolved",
		len(updates), rows, anycastFixed, cleared, unresolved)

	return map[string]any{
		"addresses_resolved": len(updates),
		"rows_updated":       rows,
		"anycast_corrected":  anycastFixed,
		"local_rows_cleared": cleared,
		"unresolved":         unresolved,
	}, nil
}

// ---- build / backup support ----

// SetBuild records the version string for the status surface and backups.
func (a *App) SetBuild(v string) {
	a.build = v
	if a.Issues != nil {
		a.Issues.SetVersion(v)
	}
}

// ---- memory and the specialist ----

func (a *App) Notes(limit int) ([]store.Note, error) { return a.Store.Notes(limit) }

func (a *App) SaveNote(note, source string) (*store.Note, error) {
	note = strings.TrimSpace(note)
	if note == "" {
		return nil, fmt.Errorf("note is empty")
	}
	if len(note) > 1000 {
		note = note[:1000]
	}
	n := store.Note{ID: uuid.NewString(), TS: time.Now(), Note: note, Source: source}
	if err := a.Store.SaveNote(n); err != nil {
		return nil, err
	}
	a.Store.Audit(source, "note.save", n.ID, "", note, "ok")
	return &n, nil
}

func (a *App) DeleteNote(id string) error {
	if err := a.Store.DeleteNote(id); err != nil {
		return err
	}
	a.Store.Audit("api", "note.delete", id, "", "", "ok")
	return nil
}

func (a *App) Recommendations(status string, limit int) ([]store.Recommendation, error) {
	return a.Store.Recommendations(status, limit)
}

// DecideRecommendation applies the operator's answer. Accepting an allow adds
// the domain to the allowlist; accepting a block adds a wildcard block. Both
// go through the same paths the UI uses, so they land in the audit log and
// the matcher is rebuilt immediately. Dismissals are remembered.
func (a *App) DecideRecommendation(id, decision, actor string) (*store.Recommendation, error) {
	rec, err := a.Store.Recommendation(id)
	if err != nil {
		return nil, err
	}
	if rec == nil {
		return nil, fmt.Errorf("no such recommendation")
	}
	switch decision {
	case "accept":
		note := "specialist: " + rec.Reason
		switch rec.Kind {
		case "allow":
			if err := a.AllowDomain(rec.Domain, note); err != nil {
				return nil, err
			}
			a.FlushDNSCache(rec.Domain)
		case "block":
			if err := a.BlockDomain(rec.Domain, true, note); err != nil {
				return nil, err
			}
			a.FlushDNSCache(rec.Domain)
		}
		if err := a.Store.DecideRecommendation(id, "accepted", actor); err != nil {
			return nil, err
		}
	case "dismiss":
		if err := a.Store.DecideRecommendation(id, "dismissed", actor); err != nil {
			return nil, err
		}
	case "reopen":
		if err := a.Store.DecideRecommendation(id, "open", actor); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("decision must be accept, dismiss or reopen")
	}
	a.Store.Audit(actor, "recommendation."+decision, rec.Kind+":"+rec.Domain, "", rec.Reason, "ok")
	a.Bus.Publish(Event{Type: "ai.recommendation", Data: map[string]any{"id": id, "decision": decision}})
	return a.Store.Recommendation(id)
}

// ReportIssue records a problem raised by a person (through the form or the
// assistant) and files it when reporting is enabled.
func (a *App) ReportIssue(ctx context.Context, title, detail, actor string) (*store.Issue, error) {
	if a.Issues == nil {
		return nil, fmt.Errorf("problem recording is unavailable")
	}
	source := "user"
	if strings.HasPrefix(actor, "assistant") {
		source = "assistant"
	}
	issue, err := a.Issues.Record(ctx, issues.Input{
		Severity: store.SevNotice, Category: "report", Title: title, Detail: detail, Source: source,
	})
	if err != nil || issue == nil {
		return issue, err
	}
	a.Store.Audit(actor, "issue.create", issue.ID, "", issue.Title, "ok")
	if a.Cfg.Snapshot().Issues.GitHub.Enabled {
		if filed, err := a.Issues.Report(ctx, issue.ID, false); err == nil && filed != nil {
			return filed, nil
		} else if err != nil {
			a.log("issues: report failed: %v", err)
		}
	}
	return issue, nil
}

// Build returns the version string this daemon was compiled as.
func (a *App) Build() string { return a.build }

// RedactedConfig returns a config whose secrets are masked, as a live-shaped
// *config.Config so callers that expect one can use it. It is NOT updatable:
// the returned value is a snapshot, and Update on it fails loudly by design.
func (a *App) RedactedConfig() *config.Config {
	red := a.Cfg.Redacted()
	return &red
}

// ReloadAfterRestore re-reads the configuration into the subsystems that cache
// it. A restore rewrites the file and the in-memory config, but a resolver
// holding parsed upstreams or a manager holding a device list would otherwise
// keep running the pre-restore setup until the next daemon restart.
func (a *App) ReloadAfterRestore() {
	if a.DNS != nil {
		if err := a.DNS.ReloadUpstreams(); err != nil {
			a.log("restore: dns upstreams: %v", err)
		}
		a.DNS.Cache().Flush()
	}
	if err := a.reloadPolicies(); err != nil {
		a.log("restore: policies: %v", err)
	}
	if a.Lounge != nil {
		a.Lounge.Apply()
	}
	a.log("restore: configuration reloaded")
}

// RestartWANMonitor re-reads the multi-WAN configuration and restarts probing,
// so a settings change takes effect immediately instead of at the next boot.
func (a *App) RestartWANMonitor() {
	cfg := a.Cfg.Snapshot()
	a.WAN.Stop()
	if cfg.Network.MultiWAN.Enabled {
		a.WAN.Start(a.ctx, cfg.Network.MultiWAN)
	}
}

// ---- ask-on-first-connection ----

// observeConsent feeds a newly-seen flow to the consent queue and enforces a
// standing deny by cutting the connection.
//
// The hostname is what a decision is keyed on, so a flow with no name yet is
// skipped: the tracker fills the name in from DNS or SNI shortly after, and
// deciding on a bare address would produce a rule that expires with the CDN.
func (a *App) observeConsent(f *store.Flow) {
	if f == nil {
		return
	}
	if a.Consent == nil || f.ClientID == "" {
		return
	}
	host := f.Hostname
	if host == "" {
		host = f.SNI
	}
	if host == "" {
		return
	}
	decision, known := a.Consent.Observe(consent.Request{
		ClientID: f.ClientID, ClientIP: f.SrcIP, Host: host,
		DstIP: f.DstIP, Port: f.DstPort, Proto: f.Proto, App: f.App,
		Country: f.Country, ASOrg: f.ASOrg, FirstSeen: f.StartedAt, LastSeen: f.LastSeen,
	})
	if known && decision == consent.Deny {
		// Terminate is the same enforcement path the flow tracker uses, so a
		// consent deny behaves exactly like any other block: drop set plus a
		// conntrack teardown, and a no-op in observe mode.
		dst, err1 := netip.ParseAddr(f.DstIP)
		src, err2 := netip.ParseAddr(f.SrcIP)
		if err1 != nil || err2 != nil {
			return
		}
		proto := uint8(6)
		if strings.EqualFold(f.Proto, "udp") {
			proto = 17
		}
		if err := a.Firewall.Terminate(f.ID, src, dst,
			uint16(f.SrcPort), uint16(f.DstPort), proto); err != nil {
			a.log("consent: could not block %s for %s: %v", host, f.ClientID, err)
		}
	}
}

// ConsentDecide answers a pending question and persists the rule.
func (a *App) ConsentDecide(id string, decision consent.Decision, scope string) (consent.Rule, error) {
	r, ok := a.Consent.Decide(id, decision, scope)
	if !ok {
		return consent.Rule{}, fmt.Errorf("no such pending request")
	}
	if err := a.Store.SaveConsentRule(store.ConsentRule{
		ClientID: r.ClientID, Host: r.Host, Decision: string(r.Decision),
		Scope: r.Scope, DecidedAt: r.DecidedAt,
	}); err != nil {
		return r, fmt.Errorf("rule applied but not saved: %w", err)
	}
	a.Store.Audit("api", "consent."+string(decision), r.Host, "", r.Scope, "ok")
	a.Bus.Publish(Event{Type: "consent.decided", Data: r})
	return r, nil
}

// ConsentForget removes a decision so the next connection asks again.
func (a *App) ConsentForget(clientID, host, scope string) error {
	if !a.Consent.Forget(clientID, host, scope) {
		return fmt.Errorf("no such rule")
	}
	return a.Store.DeleteConsentRule(clientID, host, scope)
}

// SetConsentEnrolled replaces the enrolled device set.
func (a *App) SetConsentEnrolled(ids []string) {
	a.Consent.SetEnrolled(ids)
	a.Store.Audit("api", "consent.enrol", fmt.Sprint(len(ids))+" device(s)", "", "", "ok")
}

// PolicyForClient resolves the policy attached to a device id, or nil. The DNS
// tooling needs this to explain a block that only applies to one device.
func (a *App) PolicyForClient(clientID string) *store.Policy {
	c, err := a.Store.Client(clientID)
	if err != nil || c == nil || c.PolicyID == "" {
		return nil
	}
	return a.policyByID(c.PolicyID)
}

// DefaultGateway reports the next hop this node routes through, which the
// topology map treats as a fact rather than an inference.
func (a *App) DefaultGateway() string {
	out, err := exec.Command("ip", "-4", "route", "show", "default").Output()
	if err != nil {
		return ""
	}
	fields := strings.Fields(string(out))
	for i, f := range fields {
		if f == "via" && i+1 < len(fields) {
			return fields[i+1]
		}
	}
	return ""
}

// SyncIntercept reconciles the ARP interception engine with configuration. It
// resolves the gateway from the default route when the config leaves it blank,
// and picks each enrolled device's MAC from the client registry when the config
// stored only an address.
func (a *App) SyncIntercept() error {
	cfg := a.Cfg.Snapshot().Network.Intercept
	gw := cfg.Gateway
	if gw == "" {
		gw = a.DefaultGateway()
	}
	gwAddr, err := netip.ParseAddr(gw)
	if err != nil {
		return fmt.Errorf("no usable gateway (%q): %w", gw, err)
	}

	lan := cfg.LANInterface
	if lan == "" {
		lan = a.Cfg.Snapshot().Firewall.WANInterface // the node's primary LAN nic
	}
	if lan == "" {
		lan = "eth0"
	}

	// Fill in any missing MACs from what the registry has observed, so the
	// operator can enrol a device by address alone.
	pairs := map[string]string{}
	for ip, mac := range cfg.Clients {
		if mac == "" {
			if addr, err := netip.ParseAddr(ip); err == nil {
				if c := a.Registry.ByIP(addr); c != nil {
					mac = c.MAC
				}
			}
		}
		if mac != "" {
			pairs[ip] = mac
		}
	}

	targets := intercept.ResolveTargets(pairs)

	// The web redirect is narrowed to the devices the proxy is allowed to
	// intercept (mitm.only_clients), when that list is set: those are the
	// ones with the certificate. Everyone else enrolled still gets DNS
	// filtering, and is spared a proxy hop that would only splice.
	mitmCfg := a.Cfg.Snapshot().MITM
	var webClients []netip.Addr
	scoped := cfg.RedirectHTTP && len(mitmCfg.OnlyClients) > 0
	if scoped {
		for _, t := range targets {
			for _, spec := range mitmCfg.OnlyClients {
				if pfx, err := netip.ParsePrefix(spec); err == nil && pfx.Contains(t.IP) {
					webClients = append(webClients, t.IP)
					break
				}
				if a, err := netip.ParseAddr(spec); err == nil && a == t.IP {
					webClients = append(webClients, t.IP)
					break
				}
			}
		}
	}

	return a.Intercept.Apply(a.ctx, intercept.Config{
		Enabled:      cfg.Enabled,
		LANInterface: lan,
		Gateway:      gwAddr,
		Clients:      targets,
		RedirectDNS:  cfg.RedirectDNS,
		DNSPort:      53,
		RedirectHTTP: cfg.RedirectHTTP,
		HTTPPort:     portOfAddr(mitmCfg.ListenHTTP),
		HTTPSPort:    portOfAddr(mitmCfg.ListenTLS),
		HTTPScoped:   scoped,
		HTTPClients:  webClients,
	})
}

// portOfAddr pulls the port off a listen address like "0.0.0.0:3128".
func portOfAddr(addr string) int {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return 0
	}
	n := 0
	for _, r := range port {
		if r < '0' || r > '9' {
			return 0
		}
		n = n*10 + int(r-'0')
	}
	return n
}

// ReloadRecords rebuilds the local DNS record index from configuration. Called
// at startup and after any change through the API.
func (a *App) ReloadRecords() {
	cfg := a.Cfg.Snapshot()
	recs := make([]dnsproxy.LocalRecord, 0, len(cfg.DNS.Records))
	for _, r := range cfg.DNS.Records {
		recs = append(recs, dnsproxy.LocalRecord{
			Name: r.Name, Type: r.Type, Value: r.Value, TTL: r.TTL,
			Priority: r.Priority, Weight: r.Weight, Port: r.Port,
		})
	}
	rs := dnsproxy.BuildRecordSet(recs)
	a.recordsMu.Lock()
	a.records = rs
	a.recordsMu.Unlock()
	if a.DNS != nil {
		a.DNS.Cache().Flush()
	}
}

// ---- alerts.Backend ----

func (a *App) AlertDevices() []alerts.DeviceSnapshot {
	out := []alerts.DeviceSnapshot{}
	cutoff := time.Now().Add(-5 * time.Minute)
	clients, _ := a.Store.Clients()
	for _, c := range clients {
		lbl := c.Label
		if lbl == "" {
			lbl = c.Hostname
		}
		out = append(out, alerts.DeviceSnapshot{
			ID: c.ID, IP: c.IP, Label: lbl,
			LastSeen: c.LastSeen, FirstSeen: c.FirstSeen, Online: c.LastSeen.After(cutoff),
		})
	}
	return out
}

func (a *App) ThroughputMbps() float64 {
	var in, out float64
	for _, r := range a.Tracker.ClientRates() {
		in += r[0]
		out += r[1]
	}
	return (in + out) * 8 / 1e6
}

func (a *App) RecentDomains(since time.Time) []string {
	rows, err := a.Store.DNSLog(since, "", false, "", 2000)
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(rows))
	for _, q := range rows {
		out = append(out, q.Name)
	}
	return out
}

func (a *App) BlockedPerMinute() float64 {
	pts, err := a.Store.Series("dns_blocked_total", time.Now().Add(-3*time.Minute))
	if err != nil || len(pts) < 2 {
		return 0
	}
	a0, _ := pts[len(pts)-2]["v"].(float64)
	b0, _ := pts[len(pts)-1]["v"].(float64)
	t0, _ := pts[len(pts)-2]["t"].(int64)
	t1, _ := pts[len(pts)-1]["t"].(int64)
	dt := float64(t1-t0) / 60
	if dt <= 0 {
		return 0
	}
	d := b0 - a0
	if d < 0 {
		d = 0
	}
	return d / dt
}

// ---- reports ----

// BuildReport assembles the network summary for a window.
func (a *App) BuildReport(window string, since time.Time) *report.Report {
	rep := &report.Report{
		Node: a.Cfg.Snapshot().Node.Name, GeneratedAt: time.Now(),
		Since: since, Window: window,
	}
	if rep.Node == "" {
		rep.Node = "orbis"
	}

	// DNS totals from the query log.
	if rows, err := a.Store.DNSLog(since, "", false, "", 100000); err == nil {
		rep.DNSQueries = int64(len(rows))
		for _, q := range rows {
			if q.Blocked {
				rep.DNSBlocked++
			}
		}
		if rep.DNSQueries > 0 {
			rep.BlockRate = 100 * float64(rep.DNSBlocked) / float64(rep.DNSQueries)
		}
	}

	// Devices + top talkers + new devices, from the client table.
	clients, _ := a.Store.Clients()
	rep.Devices = len(clients)
	var talkers []report.Row
	for _, c := range clients {
		if c.FirstSeen.After(since) {
			name := c.Label
			if name == "" {
				name = c.Hostname
			}
			if name == "" {
				name = c.IP
			}
			rep.NewDevices = append(rep.NewDevices, name)
		}
		total := c.RxBytes + c.TxBytes
		if total > 0 {
			name := c.Label
			if name == "" {
				name = c.Hostname
			}
			if name == "" {
				name = c.IP
			}
			talkers = append(talkers, report.Row{Label: name, Value: total})
			rep.BytesIn += c.RxBytes
			rep.BytesOut += c.TxBytes
		}
	}
	rep.TopTalkers = report.SortRows(talkers, 10)

	// Most-blocked domains.
	if tb, err := a.Store.TopBlocked(since, 10); err == nil {
		for _, row := range tb {
			name, _ := row["domain"].(string)
			var n int64
			switch v := row["count"].(type) {
			case int64:
				n = v
			case float64:
				n = int64(v)
			}
			if name != "" {
				rep.TopBlocked = append(rep.TopBlocked, report.Row{Label: name, Value: n})
			}
		}
	}

	// Top destination countries.
	if ct, err := a.Store.CountryTotals(since); err == nil {
		var rows []report.Row
		for _, row := range ct {
			name, _ := row["country"].(string)
			var n int64
			switch v := row["connections"].(type) {
			case int64:
				n = v
			case float64:
				n = int64(v)
			}
			if name != "" {
				rows = append(rows, report.Row{Label: name, Value: n})
			}
		}
		rep.TopCountries = report.SortRows(rows, 10)
	}
	return rep
}

// maybeSendReport emails the scheduled summary at most once per cadence period,
// at the configured hour. The last-sent day is remembered in memory; a restart
// can therefore re-send once if it happens to land in the same hour, which is a
// better failure than silently skipping a day.
func (a *App) maybeSendReport(now time.Time) {
	sched := a.Cfg.Snapshot().Notify.Report
	if !sched.Enabled || now.Hour() != sched.Hour {
		return
	}
	if sched.Cadence == "weekly" && now.Weekday() != time.Monday {
		return
	}
	day := now.Format("2006-01-02")
	a.reportMu.Lock()
	if a.lastReport == day {
		a.reportMu.Unlock()
		return
	}
	a.lastReport = day
	a.reportMu.Unlock()

	hours := 24
	window := "daily"
	if sched.Cadence == "weekly" {
		hours, window = 168, "weekly"
	}
	rep := a.BuildReport(window, now.Add(-time.Duration(hours)*time.Hour))
	a.Notifier.SendReport("Orbis "+window+" report", rep.TextSummary())
	a.log("report: sent %s summary", window)
}
