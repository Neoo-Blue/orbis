package app

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/Neoo-Blue/orbis/internal/config"
	"github.com/Neoo-Blue/orbis/internal/consent"
	"github.com/Neoo-Blue/orbis/internal/firewall"
	"github.com/Neoo-Blue/orbis/internal/geoip"
	"github.com/Neoo-Blue/orbis/internal/store"
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
	status["ai"] = map[string]any{
		"enabled":     cfg.AI.Enabled,
		"configured":  a.AI.Configured(),
		"provider":    cfg.AI.Provider,
		"model":       cfg.AI.Model,
		"fast_model":  cfg.AI.FastModel,
		"allow_write": cfg.AI.AllowWrite,
		"anomaly":     cfg.AI.Anomaly.Enabled,
	}
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
func (a *App) SetBuild(v string) { a.build = v }

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
