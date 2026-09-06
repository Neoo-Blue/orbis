package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/Neoo-Blue/orbis/internal/adblock"
	"github.com/Neoo-Blue/orbis/internal/config"
	"github.com/Neoo-Blue/orbis/internal/store"
	"github.com/Neoo-Blue/orbis/internal/threat"
	"github.com/google/uuid"
)

// Intel is the threat-intelligence analyst. On a schedule, and on demand, it
// reads the window's attacks, threat-feed hits, anomalies, bans, blocked
// lookups and unusual destinations, and writes an assessment: a risk level,
// findings in plain words, and the actions it would take. Each action is a
// timed ban or a domain block. They wait for a click unless active blocking
// is on, in which case the confident ones are applied at once, within the
// limits in the configuration, and every one can be undone.
type Intel struct {
	cfg     *config.Config
	client  *Client
	backend Backend
	st      *store.Store
	record  func(store.Event, bool)
	log     func(string, ...any)

	mu      sync.Mutex
	running bool
	last    time.Time
	lastErr string
}

func NewIntel(cfg *config.Config, client *Client, backend Backend, st *store.Store,
	record func(store.Event, bool), log func(string, ...any)) *Intel {
	if log == nil {
		log = func(string, ...any) {}
	}
	if record == nil {
		record = func(store.Event, bool) {}
	}
	n := &Intel{cfg: cfg, client: client, backend: backend, st: st, record: record, log: log}
	if st != nil {
		if prev, err := st.AIIntels(1); err == nil && len(prev) > 0 {
			n.last = prev[0].TS
		}
	}
	return n
}

// Run checks once a minute whether an assessment is due.
func (n *Intel) Run(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			cfg := n.cfg.Snapshot().AI
			if !cfg.Enabled || !cfg.Intel.Enabled || !n.client.Configured() {
				continue
			}
			every := time.Duration(cfg.Intel.IntervalHours) * time.Hour
			if every <= 0 {
				every = 6 * time.Hour
			}
			n.mu.Lock()
			due := time.Since(n.last) >= every
			n.mu.Unlock()
			if !due {
				continue
			}
			if _, _, err := n.Assess(ctx, cfg.Intel.IntervalHours); err != nil {
				n.log("intel: %v", err)
				n.mu.Lock()
				n.lastErr = err.Error()
				// Back off rather than retrying every minute against a
				// provider that is down.
				n.last = time.Now().Add(-every).Add(30 * time.Minute)
				n.mu.Unlock()
			}
		}
	}
}

const intelPrompt = `You are the security analyst for a home or small-office network gateway called Orbis.
You are given evidence the gateway collected over a window: intrusion alerts (repeated login
failures, port scans, sweeps, floods), connections that touched threat-feed addresses, active
bans, anomaly findings (beaconing, large uploads, generated hostnames), blocked lookups, the
busiest destinations, countries, new devices, and the node's mode. You also get the actions
already open so you do not repeat them.

Write an assessment for the person who runs this network. They are not a security professional.
Be concrete about what happened and honest about what it means: most home networks see constant
background scanning that is not a targeted attack, and saying so is more useful than alarm.

Risk levels: "low" (background noise only), "guarded" (something worth watching), "elevated"
(a device or service is being actively probed or is misbehaving), "high" (evidence of a
compromise, data leaving the network, or an exposed service under attack).

Actions you may propose, each attached to one finding:
- ban_ip: a public internet address or range that attacked or is beaconed to. Never a private,
  LAN, gateway, DNS-resolver or CDN address. hours between 1 and 168.
- block_domain: a hostname that is malicious or exfiltrating. Never a first-party service the
  household uses, an update, certificate, time or push endpoint, a CDN, or a big brand's main
  domain; name the specific malicious host instead.
- none: when watching or a human step is the right answer.
confidence (0 to 1) is how sure you are the action is right AND harmless. Below 0.6 means the
finding should carry no action.

Answer with a JSON object and nothing else:
{"risk":"low|guarded|elevated|high",
 "headline":"one line, under 120 characters",
 "summary":"two to four sentences for a non-expert",
 "findings":[{"title":"short","severity":"info|notice|warning|critical","detail":"what the evidence shows, plainly",
   "indicators":["addresses, hosts or devices involved"],"recommendation":"what the person should do, one or two sentences",
   "action":{"kind":"ban_ip|block_domain|none","value":"","hours":24,"confidence":0.0}}]}
At most eight findings, most serious first. If nothing is wrong say so in one finding with severity info.`

type intelOut struct {
	Risk     string `json:"risk"`
	Headline string `json:"headline"`
	Summary  string `json:"summary"`
	Findings []struct {
		Title          string   `json:"title"`
		Severity       string   `json:"severity"`
		Detail         string   `json:"detail"`
		Indicators     []string `json:"indicators"`
		Recommendation string   `json:"recommendation"`
		Action         struct {
			Kind       string  `json:"kind"`
			Value      string  `json:"value"`
			Hours      int     `json:"hours"`
			Confidence float64 `json:"confidence"`
		} `json:"action"`
	} `json:"findings"`
}

// Assess runs one assessment over the last hours and files its actions.
func (n *Intel) Assess(ctx context.Context, hours int) (*store.AIIntel, []store.AIAction, error) {
	if !n.client.Configured() {
		return nil, nil, fmt.Errorf("the assistant is not configured")
	}
	n.mu.Lock()
	if n.running {
		n.mu.Unlock()
		return nil, nil, fmt.Errorf("an assessment is already running")
	}
	n.running = true
	n.mu.Unlock()
	defer func() {
		n.mu.Lock()
		n.running = false
		n.mu.Unlock()
	}()
	if hours <= 0 {
		hours = 6
	}
	if hours > 168 {
		hours = 168
	}
	since := time.Now().Add(-time.Duration(hours) * time.Hour)
	evidence := n.gather(ctx, since, hours)
	payload, err := jsonOf(evidence, nil)
	if err != nil {
		return nil, nil, err
	}

	cctx, cancel := context.WithTimeout(ctx, 4*time.Minute)
	defer cancel()
	validate := func(text string) error {
		var probe intelOut
		if err := parseJSONObject(text, &probe); err != nil {
			return err
		}
		if strings.TrimSpace(probe.Headline) == "" {
			return fmt.Errorf("headline missing")
		}
		return nil
	}
	resp, err := n.client.CompleteJSON(cctx, intelPrompt, []Message{{Role: RoleUser, Content: payload}}, false, validate)
	if err != nil {
		return nil, nil, err
	}
	var out intelOut
	if err := parseJSONObject(resp.Text, &out); err != nil {
		return nil, nil, fmt.Errorf("assessment unreadable: %w", err)
	}
	out.Risk = normalizeRisk(out.Risk)
	out.Headline = clip(strings.TrimSpace(out.Headline), 160)
	if len(out.Findings) > 12 {
		out.Findings = out.Findings[:12]
	}
	for i := range out.Findings {
		f := &out.Findings[i]
		switch f.Severity {
		case store.SevNotice, store.SevWarning, store.SevCritical:
		default:
			f.Severity = store.SevInfo
		}
		f.Action.Kind = strings.ToLower(strings.TrimSpace(f.Action.Kind))
		if f.Action.Kind != "ban_ip" && f.Action.Kind != "block_domain" {
			f.Action.Kind = "none"
		}
	}
	findings, _ := json.Marshal(out.Findings)
	in := &store.AIIntel{
		ID: uuid.NewString(), TS: time.Now(), Hours: hours, Model: resp.Model,
		Risk: out.Risk, Headline: out.Headline, Summary: strings.TrimSpace(out.Summary), Findings: findings,
	}
	if n.st != nil {
		if err := n.st.SaveAIIntel(*in); err != nil {
			return nil, nil, err
		}
		_ = n.st.PruneAIIntel(60)
	}

	cfg := n.cfg.Snapshot().AI.Intel
	actions := n.fileActions(in, out, cfg)

	sev := store.SevInfo
	switch out.Risk {
	case "guarded":
		sev = store.SevNotice
	case "elevated":
		sev = store.SevWarning
	case "high":
		sev = store.SevCritical
	}
	applied := 0
	for _, a := range actions {
		if a.Status == "applied" {
			applied++
		}
	}
	detail := in.Summary
	if applied > 0 {
		detail += fmt.Sprintf("\n\nActive blocking applied %d action(s); see Threats, AI intel, to undo any of them.", applied)
	} else if len(actions) > 0 {
		detail += fmt.Sprintf("\n\n%d proposed action(s) wait for a click on Threats, AI intel.", len(actions))
	}
	n.record(store.Event{
		ID: uuid.NewString(), TS: in.TS, Severity: sev, Category: "ai:intel",
		Title: "Threat check: " + in.Headline, Detail: detail,
		Data: map[string]any{"intel_id": in.ID, "risk": in.Risk, "hours": hours, "model": resp.Model, "actions": len(actions), "applied": applied},
	}, cfg.Notify)

	n.mu.Lock()
	n.last = in.TS
	n.lastErr = ""
	n.mu.Unlock()
	n.log("intel: %s risk, %q, %d finding(s), %d action(s), %d applied (%s)", in.Risk, in.Headline, len(out.Findings), len(actions), applied, resp.Model)
	return in, actions, nil
}

// fileActions turns the findings' actions into records, applying the ones
// active blocking allows.
func (n *Intel) fileActions(in *store.AIIntel, out intelOut, cfg config.IntelConfig) []store.AIAction {
	var actions []store.AIAction
	applied := 0
	for _, f := range out.Findings {
		if f.Action.Kind == "none" || strings.TrimSpace(f.Action.Value) == "" {
			continue
		}
		a := store.AIAction{
			ID: uuid.NewString(), IntelID: in.ID, TS: time.Now(), Kind: f.Action.Kind,
			Value: strings.TrimSpace(f.Action.Value), Hours: f.Action.Hours,
			Reason: clip(strings.TrimSpace(f.Title+". "+f.Detail), 300), Confidence: clamp01(f.Action.Confidence),
			Status: "suggested",
		}
		if a.Hours <= 0 {
			a.Hours = 24
		}
		if a.Hours > 168 {
			a.Hours = 168
		}
		if reason := n.refuse(a); reason != "" {
			a.Status, a.Ref = "refused", reason
		} else if n.st != nil {
			if open, _ := n.st.OpenAIAction(a.Kind, a.Value); open != nil {
				continue
			}
		}
		if a.Status == "suggested" && cfg.ActiveBlocking && a.Confidence >= cfg.MinConfidence && applied < cfg.MaxActionsPerRun && n.kindAllowed(a.Kind, cfg) {
			if err := n.apply(&a, "ai", cfg.MaxBanHours); err != nil {
				a.Status, a.Ref = "failed", err.Error()
			} else {
				applied++
			}
		}
		if n.st != nil {
			_ = n.st.SaveAIAction(a)
		}
		actions = append(actions, a)
	}
	return actions
}

func (n *Intel) kindAllowed(kind string, cfg config.IntelConfig) bool {
	switch kind {
	case "ban_ip":
		return cfg.BanAddresses
	case "block_domain":
		return cfg.BlockDomains
	}
	return false
}

// refuse is the guard rail: what no assessment may act on, however sure.
func (n *Intel) refuse(a store.AIAction) string {
	switch a.Kind {
	case "ban_ip":
		p, ok := threat.ParsePrefix(a.Value)
		if !ok {
			return "not an address"
		}
		if !threat.Usable(p) {
			return "local, reserved or too wide a range"
		}
		for _, ig := range n.cfg.Snapshot().IDS.Ignore {
			if q, ok := threat.ParsePrefix(ig); ok && (q.Overlaps(p)) {
				return "on the never-act-on list"
			}
		}
	case "block_domain":
		if protected, why := adblock.Protected(a.Value); protected {
			return why
		}
	default:
		return "unknown action"
	}
	return ""
}

// apply carries out one action through the same paths a person would use,
// so it is audited and enforced identically.
func (n *Intel) apply(a *store.AIAction, actor string, maxHours int) error {
	hours := a.Hours
	if maxHours > 0 && hours > maxHours && actor == "ai" {
		hours = maxHours
	}
	reason := "AI threat check: " + a.Reason
	switch a.Kind {
	case "ban_ip":
		dec, err := n.backend.BanAddress(a.Value, hours, reason, actor)
		if err != nil {
			return err
		}
		a.Ref = dec.ID
		a.Hours = hours
	case "block_domain":
		if err := n.backend.BlockDomain(a.Value, true, reason); err != nil {
			return err
		}
		a.Ref = a.Value
	default:
		return fmt.Errorf("unknown action %q", a.Kind)
	}
	a.Status, a.DecidedAt, a.DecidedBy = "applied", time.Now(), actor
	if n.st != nil {
		n.st.Audit(actor, "ai.intel."+a.Kind, a.Value, "", fmt.Sprintf("%dh", hours), "applied")
	}
	if actor == "ai" {
		what := "banned " + a.Value + fmt.Sprintf(" for %dh", hours)
		if a.Kind == "block_domain" {
			what = "blocked " + a.Value
		}
		n.record(store.Event{
			ID: uuid.NewString(), TS: time.Now(), Severity: store.SevNotice, Category: "ai:action",
			Title: "Active blocking " + what, Detail: a.Reason + "\n\nUndo from Threats, AI intel.",
			Data: map[string]any{"action_id": a.ID, "kind": a.Kind, "value": a.Value, "confidence": a.Confidence},
		}, false)
	}
	return nil
}

// Decide applies, dismisses or undoes an action on the operator's word.
func (n *Intel) Decide(id, decision, actor string) (*store.AIAction, error) {
	if n.st == nil {
		return nil, fmt.Errorf("no store")
	}
	a, err := n.st.AIAction(id)
	if err != nil {
		return nil, err
	}
	if a == nil {
		return nil, fmt.Errorf("no such action")
	}
	switch decision {
	case "apply":
		if a.Status == "applied" {
			return a, nil
		}
		if why := n.refuse(*a); why != "" {
			return nil, fmt.Errorf("refused: %s", why)
		}
		if err := n.apply(a, actor, 0); err != nil {
			return nil, err
		}
	case "dismiss":
		a.Status, a.DecidedAt, a.DecidedBy = "dismissed", time.Now(), actor
	case "undo":
		if a.Status != "applied" {
			return nil, fmt.Errorf("that action is not applied")
		}
		switch a.Kind {
		case "ban_ip":
			target := a.Ref
			if target == "" {
				target = a.Value
			}
			if _, err := n.backend.UnbanAddress(target, actor); err != nil && !strings.Contains(err.Error(), "no ban matches") {
				return nil, err
			}
		case "block_domain":
			if err := n.backend.UnblockDomain(a.Value); err != nil {
				return nil, err
			}
		}
		a.Status, a.DecidedAt, a.DecidedBy = "undone", time.Now(), actor
		n.st.Audit(actor, "ai.intel.undo", a.Value, a.Kind, "", "ok")
	default:
		return nil, fmt.Errorf("decision must be apply, dismiss or undo")
	}
	if err := n.st.SaveAIAction(*a); err != nil {
		return nil, err
	}
	return a, nil
}

// Status is the page's view: the latest assessments, the actions, and where
// the schedule stands.
func (n *Intel) Status(limit int) map[string]any {
	cfg := n.cfg.Snapshot().AI
	n.mu.Lock()
	running, last, lastErr := n.running, n.last, n.lastErr
	n.mu.Unlock()
	out := map[string]any{
		"enabled": cfg.Enabled && cfg.Intel.Enabled, "configured": n.client.Configured(), "running": running,
		"interval_hours": cfg.Intel.IntervalHours, "active_blocking": cfg.Intel.ActiveBlocking,
		"min_confidence": cfg.Intel.MinConfidence, "max_actions_per_run": cfg.Intel.MaxActionsPerRun,
		"max_ban_hours": cfg.Intel.MaxBanHours, "last_error": lastErr,
		"assessments": []store.AIIntel{}, "actions": []store.AIAction{},
	}
	if !last.IsZero() {
		out["last"] = last
		out["next"] = last.Add(time.Duration(cfg.Intel.IntervalHours) * time.Hour)
	}
	if n.st != nil {
		if list, err := n.st.AIIntels(limit); err == nil {
			out["assessments"] = list
		}
		if acts, err := n.st.AIActions("", 200); err == nil {
			out["actions"] = acts
		}
	}
	return out
}

// gather assembles the evidence from what the pages already show.
func (n *Intel) gather(ctx context.Context, since time.Time, hours int) map[string]any {
	ev := map[string]any{"window_hours": hours, "now": time.Now().Format(time.RFC3339)}
	if st := n.backend.SystemStatus(); st != nil {
		ev["node"] = map[string]any{"mode": st["mode"], "version": st["version"], "enforcement": st["threat_enforcement"]}
	}
	if m, err := n.backend.IntrusionStatus(since, 40); err == nil {
		ev["intrusion"] = pick(m, "enabled", "alerts", "alerts_24h", "bans_24h", "syslog_hosts")
	}
	if m, err := n.backend.ThreatStatus(since, 40); err == nil {
		ev["threat_feeds"] = pick(m, "enabled", "entries", "hits", "hits_24h", "dropped_24h", "decisions", "recent_decisions", "enforcement")
	}
	if evs, err := n.backend.Events(since, "", false, 200); err == nil {
		var keep []map[string]any
		for _, e := range evs {
			c := e.Category
			if strings.HasPrefix(c, "ai:") || c == "update" || c == "brief" {
				continue
			}
			if e.Severity == store.SevInfo && !strings.Contains(c, "anomaly") && !strings.Contains(c, "device") {
				continue
			}
			keep = append(keep, map[string]any{"ts": e.TS.Format(time.RFC3339), "severity": e.Severity, "category": c, "title": e.Title, "detail": clip(e.Detail, 280)})
			if len(keep) >= 60 {
				break
			}
		}
		ev["events"] = keep
	}
	if d, err := n.backend.TopDestinations(since, "", 25); err == nil {
		ev["top_destinations"] = d
	}
	if b, err := n.backend.TopBlocked(since, 15); err == nil {
		ev["top_blocked_lookups"] = b
	}
	if c, err := n.backend.CountryTotals(since); err == nil && len(c) > 0 {
		if len(c) > 12 {
			c = c[:12]
		}
		ev["countries"] = c
	}
	ev["devices_known"] = len(n.backend.Clients())
	if n.st != nil {
		if acts, err := n.st.AIActions("", 60); err == nil {
			var open []map[string]any
			for _, a := range acts {
				if a.Status == "suggested" || a.Status == "applied" || a.Status == "dismissed" {
					open = append(open, map[string]any{"kind": a.Kind, "value": a.Value, "status": a.Status, "reason": clip(a.Reason, 120)})
				}
			}
			ev["actions_already_open"] = open
		}
	}
	_ = ctx
	return ev
}

func pick(m map[string]any, keys ...string) map[string]any {
	out := map[string]any{}
	for _, k := range keys {
		if v, ok := m[k]; ok {
			out[k] = v
		}
	}
	return out
}

func normalizeRisk(r string) string {
	switch strings.ToLower(strings.TrimSpace(r)) {
	case "guarded", "moderate", "medium":
		return "guarded"
	case "elevated", "raised":
		return "elevated"
	case "high", "critical", "severe":
		return "high"
	}
	return "low"
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func clamp01(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}
