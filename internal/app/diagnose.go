package app

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Neoo-Blue/orbis/internal/dnsproxy"
	"github.com/Neoo-Blue/orbis/internal/store"
	"github.com/miekg/dns"
)

// DNS diagnosis: answering "why is this domain not loading" without making the
// operator read a 480,000-line rule set.
//
// The matcher's verdict is only part of the story: a name can also be stopped
// by a per-client policy, by a blocked service bundle, by the DoH-bypass list,
// or by a CNAME that points into an ad network. Reporting only the first of
// those sends people hunting through blocklists for a rule that was never the
// cause. The REST endpoint and the assistant's explain_domain tool both call
// this, so they cannot disagree.

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

// DiagnoseDomain traces a name through every filtering stage.
func (a *App) DiagnoseDomain(ctx context.Context, domain, clientID string, resolve bool) (map[string]any, error) {
	name := strings.ToLower(strings.TrimSpace(strings.TrimSuffix(domain, ".")))
	if name == "" {
		return nil, fmt.Errorf("domain is required")
	}

	cfg := a.Cfg.Snapshot()
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
	if clientID != "" {
		if p := a.PolicyForClient(clientID); p != nil {
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
			for _, al := range policy.Allowlist {
				if domainGlobMatch(name, al) {
					steps = append(steps, DiagnoseStep{
						Stage: "Policy allowlist", Hit: true, Verdict: "allow",
						Detail: fmt.Sprintf("Explicitly allowed for this device by policy %q, overriding blocklists.", policy.Name),
						Rule:   al, Source: "policy:" + policy.Name,
					})
					final, reason = "allow", "Explicitly allowed by this device's policy."
				}
			}
		}
	}

	// 3. The global matcher: local rules and subscriptions.
	match := a.Matcher.Lookup(name)
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
			Detail: fmt.Sprintf("No match among %d indexed rules.", a.Matcher.Count()),
		})
	}

	// 4. CNAME uncloaking, which needs a real lookup to see the chain.
	var chain []string
	var answers []string
	if resolve {
		chain, answers = a.resolveChain(ctx, name)
		if len(chain) > 0 && cfg.AdBlock.CNAMEUncloak {
			if cm := a.Matcher.LookupChain(chain); cm.Blocked {
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

	policyLabel := ""
	if policy != nil {
		policyLabel = policy.Name
	}
	return map[string]any{
		"domain":      name,
		"verdict":     final,
		"reason":      reason,
		"steps":       steps,
		"cname_chain": chain,
		"answers":     answers,
		"policy":      policyLabel,
	}, nil
}

// resolveChain asks the local resolver so the answer reflects what a client on
// this network actually gets, including any block this node applies.
func (a *App) resolveChain(ctx context.Context, name string) ([]string, []string) {
	cctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), dns.TypeA)
	m.RecursionDesired = true

	client := &dns.Client{Timeout: 5 * time.Second}
	addr := "127.0.0.1:53"
	if listens := a.Cfg.Snapshot().DNS.Listen; len(listens) > 0 {
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
