package api

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/Neoo-Blue/orbis/internal/adblock"
	"github.com/Neoo-Blue/orbis/internal/dnsproxy"
	"github.com/Neoo-Blue/orbis/internal/store"
	"github.com/go-chi/chi/v5"
	"github.com/miekg/dns"
)

// DNS tooling: answering "why is this domain not loading" without making the
// operator read a 480,000-line rule set.
//
// The existing check endpoint reports the matcher's verdict, which is only part
// of the story: a name can also be stopped by a per-client policy, by a blocked
// service bundle, by the DoH-bypass list, or by a CNAME that points into an ad
// network. Reporting only the first of those sends people hunting through
// blocklists for a rule that was never the cause.

func (s *Server) mountDNSTools(r chi.Router) {
	r.Route("/dnstools", func(r chi.Router) {
		r.Post("/diagnose", s.handleDiagnose)
		r.Post("/import", s.handleImportList)
		r.Post("/allow", s.handleQuickAllow)
		r.Post("/block", s.handleQuickBlock)
		r.Post("/unblock", s.handleQuickUnblock)
	})
}

// DiagnoseStep is one stage of the decision, in the order the resolver applies
// them, so the answer reads as a trace rather than a verdict.
type DiagnoseStep struct {
	Stage   string `json:"stage"`
	Hit     bool   `json:"hit"`
	Verdict string `json:"verdict"` // allow | block | none
	Detail  string `json:"detail"`
	Rule    string `json:"rule,omitempty"`
	Source  string `json:"source,omitempty"`
}

func (s *Server) handleDiagnose(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Domain   string `json:"domain"`
		ClientID string `json:"client_id"`
		Resolve  bool   `json:"resolve"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	name := strings.ToLower(strings.TrimSpace(strings.TrimSuffix(req.Domain, ".")))
	if name == "" {
		writeErr(w, http.StatusBadRequest, "domain is required")
		return
	}

	cfg := s.cfg.Snapshot()
	steps := []DiagnoseStep{}
	final := "allow"
	reason := "Nothing blocks this name."

	// 1. Operator rewrites.
	if len(cfg.DNS.Rewrites) > 0 {
		hit := false
		for _, rule := range cfg.DNS.Rewrites {
			if domainGlobMatch(name, rule.Domain) {
				hit = true
				verdict := "allow"
				detail := fmt.Sprintf("Answered locally as %s.", rule.Answer)
				if rule.Answer == "#" {
					verdict, final = "block", "block"
					detail = "Answered NXDOMAIN by a rewrite rule."
					reason = detail
				}
				steps = append(steps, DiagnoseStep{
					Stage: "Rewrite", Hit: true, Verdict: verdict,
					Detail: detail, Rule: rule.Domain, Source: "config",
				})
				break
			}
		}
		if !hit {
			steps = append(steps, DiagnoseStep{Stage: "Rewrite", Verdict: "none", Detail: "No rewrite matches."})
		}
	}

	// 2. Per-client policy, when one was named.
	var policy *store.Policy
	if req.ClientID != "" {
		if p := s.app.PolicyForClient(req.ClientID); p != nil {
			policy = p
		}
	}
	if policy != nil {
		active := dnsproxy.ScheduleActive(policy.Schedule, time.Now())
		if !active {
			steps = append(steps, DiagnoseStep{
				Stage: "Policy schedule", Verdict: "none",
				Detail: fmt.Sprintf("Policy %q is outside its window (%s), so its rules do not apply now.",
					policy.Name, policy.Schedule),
			})
		} else {
			if svc, hit := dnsproxy.MatchBlockedService(name, policy.BlockedServices); hit {
				steps = append(steps, DiagnoseStep{
					Stage: "Blocked service", Hit: true, Verdict: "block",
					Detail: fmt.Sprintf("%s is switched off for this device by policy %q.", svc, policy.Name),
					Rule:   svc, Source: "policy:" + policy.Name,
				})
				final, reason = "block", fmt.Sprintf("Blocked because the %s service bundle is off for this device.", svc)
			}
			if policy.BlockDoH && dnsproxy.IsDoHBypass(name) {
				steps = append(steps, DiagnoseStep{
					Stage: "DoH bypass", Hit: true, Verdict: "block",
					Detail: fmt.Sprintf("This is a public encrypted-DNS endpoint, refused for policy %q so the device cannot route around this resolver.", policy.Name),
					Source: "policy:" + policy.Name,
				})
				if final != "block" {
					final, reason = "block", "Blocked as a public DoH endpoint."
				}
			}
			for _, a := range policy.Allowlist {
				if domainGlobMatch(name, a) {
					steps = append(steps, DiagnoseStep{
						Stage: "Policy allowlist", Hit: true, Verdict: "allow",
						Detail: fmt.Sprintf("Explicitly allowed for this device by policy %q, overriding blocklists.", policy.Name),
						Rule:   a, Source: "policy:" + policy.Name,
					})
					final, reason = "allow", "Explicitly allowed by this device's policy."
				}
			}
		}
	}

	// 3. The global matcher: local rules and subscriptions.
	match := s.app.Matcher.Lookup(name)
	switch {
	case match.Allowed:
		steps = append(steps, DiagnoseStep{
			Stage: "Allowlist", Hit: true, Verdict: "allow",
			Detail: "On your allowlist, which wins over every subscription.",
			Rule:   match.Rule, Source: match.Source,
		})
		if final != "block" {
			final, reason = "allow", "Explicitly allowed by your own rule."
		}
	case match.Blocked:
		steps = append(steps, DiagnoseStep{
			Stage: "Blocklist", Hit: true, Verdict: "block",
			Detail: fmt.Sprintf("Matched %q from %s.", match.Rule, match.Source),
			Rule:   match.Rule, Source: match.Source,
		})
		if final != "block" {
			final = "block"
			reason = fmt.Sprintf("Blocked by %s, which matched the rule %q.", match.Source, match.Rule)
		}
	default:
		steps = append(steps, DiagnoseStep{
			Stage: "Blocklist", Verdict: "none",
			Detail: fmt.Sprintf("No match among %d indexed rules.", s.app.Matcher.Count()),
		})
	}

	// 4. CNAME uncloaking, which needs a real lookup to see the chain.
	var chain []string
	var answers []string
	if req.Resolve {
		chain, answers = s.resolveChain(r.Context(), name)
		if len(chain) > 0 && cfg.AdBlock.CNAMEUncloak {
			if cm := s.app.Matcher.LookupChain(chain); cm.Blocked {
				steps = append(steps, DiagnoseStep{
					Stage: "CNAME uncloak", Hit: true, Verdict: "block",
					Detail: fmt.Sprintf("The name itself is clean, but it is a CNAME into %q, which is blocked by %s.",
						cm.Rule, cm.Source),
					Rule: cm.Rule, Source: cm.Source,
				})
				if final != "block" {
					final = "block"
					reason = "Blocked by CNAME uncloaking: the name redirects into a blocked ad network."
				}
			} else {
				steps = append(steps, DiagnoseStep{
					Stage: "CNAME uncloak", Verdict: "none",
					Detail: "The CNAME chain is clean.",
				})
			}
		}
	}

	writeOK(w, map[string]any{
		"domain":      name,
		"verdict":     final,
		"reason":      reason,
		"steps":       steps,
		"cname_chain": chain,
		"answers":     answers,
		"policy":      policyName(policy),
	})
}

func policyName(p *store.Policy) string {
	if p == nil {
		return ""
	}
	return p.Name
}

// resolveChain asks the local resolver so the answer reflects what a client on
// this network actually gets, including any block this node applies.
func (s *Server) resolveChain(ctx context.Context, name string) ([]string, []string) {
	cctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), dns.TypeA)
	m.RecursionDesired = true

	client := &dns.Client{Timeout: 5 * time.Second}
	addr := "127.0.0.1:53"
	if listens := s.cfg.Snapshot().DNS.Listen; len(listens) > 0 {
		if _, port, ok := strings.Cut(listens[0], ":"); ok && port != "" {
			addr = "127.0.0.1:" + port
		}
	}
	resp, _, err := client.ExchangeContext(cctx, m, addr)
	if err != nil || resp == nil {
		return nil, nil
	}
	var chain, answers []string
	for _, rr := range resp.Answer {
		switch v := rr.(type) {
		case *dns.CNAME:
			chain = append(chain, strings.TrimSuffix(v.Target, "."))
			answers = append(answers, "CNAME "+strings.TrimSuffix(v.Target, "."))
		case *dns.A:
			answers = append(answers, "A "+v.A.String())
		case *dns.AAAA:
			answers = append(answers, "AAAA "+v.AAAA.String())
		}
	}
	return chain, answers
}

// domainGlobMatch mirrors the resolver's pattern matching for the trace.
func domainGlobMatch(name, pattern string) bool {
	p := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(pattern), "."))
	n := strings.ToLower(strings.TrimSuffix(name, "."))
	if p == "" {
		return false
	}
	if strings.HasPrefix(p, "*.") {
		base := p[2:]
		return n == base || strings.HasSuffix(n, "."+base)
	}
	return n == p
}

// ---- quick actions ----

func (s *Server) handleQuickAllow(w http.ResponseWriter, r *http.Request) {
	s.quickRule(w, r, "allow")
}

func (s *Server) handleQuickBlock(w http.ResponseWriter, r *http.Request) {
	s.quickRule(w, r, "block")
}

func (s *Server) quickRule(w http.ResponseWriter, r *http.Request, action string) {
	var req struct {
		Domain   string `json:"domain"`
		Wildcard bool   `json:"wildcard"`
		Note     string `json:"note"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	domain := strings.ToLower(strings.TrimSpace(strings.TrimSuffix(req.Domain, ".")))
	if domain == "" {
		writeErr(w, http.StatusBadRequest, "domain is required")
		return
	}
	note := req.Note
	if note == "" {
		note = "added from the domain tester"
	}

	// Reuse the app-level operations rather than writing the rule here: they
	// already reindex the matcher, audit, and publish the change, and a second
	// implementation would drift from them.
	var err error
	if action == "allow" {
		err = s.app.AllowDomain(domain, note)
	} else {
		err = s.app.BlockDomain(domain, req.Wildcard, note)
	}
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	// A cached answer would keep serving the old verdict for its whole TTL,
	// which reads as the button not having worked.
	s.app.DNS.Cache().FlushDomain(domain)
	writeOK(w, map[string]any{"ok": true, "verdict": s.app.Matcher.Lookup(domain)})
}

// handleQuickUnblock removes any local rule for a name and flushes the cache,
// which is the "let this through again" button.
func (s *Server) handleQuickUnblock(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Domain string `json:"domain"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	domain := strings.ToLower(strings.TrimSpace(req.Domain))
	if domain == "" {
		writeErr(w, http.StatusBadRequest, "domain is required")
		return
	}
	if err := s.app.Store.DeleteLocalRule(domain); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := s.app.Lists.Rebuild(); err != nil {
		writeErr(w, http.StatusInternalServerError, "removed but reindex failed: "+err.Error())
		return
	}
	s.app.DNS.Cache().FlushDomain(domain)
	s.app.Store.Audit(r.RemoteAddr, "adblock.unblock", domain, "", "", "ok")
	writeOK(w, map[string]any{"ok": true, "verdict": s.app.Matcher.Lookup(domain)})
}

// ---- list import ----

// handleImportList accepts a pasted or uploaded list in any of the formats
// ParseList understands, so a Pi-hole or AdGuard Home export can be moved over
// without converting it first.
func (s *Server) handleImportList(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Text     string `json:"text"`
		Action   string `json:"action"` // block | allow
		Note     string `json:"note"`
		DryRun   bool   `json:"dry_run"`
		Wildcard bool   `json:"wildcard_all"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if strings.TrimSpace(req.Text) == "" {
		writeErr(w, http.StatusBadRequest, "nothing to import")
		return
	}
	action := req.Action
	if action != "allow" {
		action = "block"
	}

	exact, wildcard, err := adblock.ParseList(strings.NewReader(req.Text))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "could not parse: "+err.Error())
		return
	}
	if len(exact) == 0 && len(wildcard) == 0 {
		writeErr(w, http.StatusBadRequest,
			"parsed successfully but found no usable domains. Cosmetic rules and rules with a URL path are skipped, because DNS cannot honour them.")
		return
	}

	// Report what would happen before touching anything: importing a list that
	// turns out to contain a whole-TLD wildcard takes a network offline, and
	// the time to notice is before it is applied.
	sample := make([]string, 0, 12)
	for _, d := range exact {
		if len(sample) >= 6 {
			break
		}
		sample = append(sample, d)
	}
	for _, d := range wildcard {
		if len(sample) >= 12 {
			break
		}
		sample = append(sample, "*."+d)
	}
	sort.Strings(sample)

	var risky []string
	for _, d := range wildcard {
		// A wildcard on a single label is a whole-TLD block. It is almost
		// always a parse artefact and honouring it is catastrophic.
		if !strings.Contains(d, ".") {
			risky = append(risky, "*."+d)
		}
	}

	result := map[string]any{
		"exact":     len(exact),
		"wildcard":  len(wildcard),
		"total":     len(exact) + len(wildcard),
		"sample":    sample,
		"risky":     risky,
		"action":    action,
		"dry_run":   req.DryRun,
		"imported":  0,
	}
	if req.DryRun {
		writeOK(w, result)
		return
	}
	if len(risky) > 0 {
		writeErr(w, http.StatusBadRequest, fmt.Sprintf(
			"refusing to import: %v would block an entire top-level domain and take the network offline. Remove those lines and try again.", risky))
		return
	}

	note := req.Note
	if note == "" {
		note = "imported"
	}
	now := time.Now()
	n := 0
	for _, d := range exact {
		if err := s.app.Store.SaveLocalRule(store.LocalRule{
			Domain: d, Action: action, Wildcard: req.Wildcard,
			Origin: "import", Note: note, CreatedAt: now,
		}); err == nil {
			n++
		}
	}
	for _, d := range wildcard {
		if err := s.app.Store.SaveLocalRule(store.LocalRule{
			Domain: d, Action: action, Wildcard: true,
			Origin: "import", Note: note, CreatedAt: now,
		}); err == nil {
			n++
		}
	}
	if err := s.app.Lists.Rebuild(); err != nil {
		writeErr(w, http.StatusInternalServerError, "imported but reindex failed: "+err.Error())
		return
	}
	result["imported"] = n
	s.app.Store.Audit(r.RemoteAddr, "adblock.import", note, "",
		fmt.Sprintf("%d rule(s) as %s", n, action), "ok")
	writeOK(w, result)
}
