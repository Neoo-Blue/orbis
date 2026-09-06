package ai

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/Neoo-Blue/orbis/internal/adblock"
	"github.com/Neoo-Blue/orbis/internal/store"
)

// Explainer answers "what is this and should I worry" for one thing on a
// page: an event, an intrusion alert, an address or a hostname. It gathers
// what the node knows about the thing and asks the model for a plain
// explanation, a danger level and the steps to take. Answers are cached for
// an hour so a page that re-renders does not re-ask.
type Explainer struct {
	client  *Client
	backend Backend
	st      *store.Store
	judge   *Judge
	log     func(string, ...any)

	mu    sync.Mutex
	cache map[string]*Explanation
}

// Explanation is the answer.
type Explanation struct {
	Kind        string    `json:"kind"`
	Key         string    `json:"key"`
	Title       string    `json:"title"`
	Danger      string    `json:"danger"` // none | low | medium | high
	Explanation string    `json:"explanation"`
	Steps       []string  `json:"steps"`
	Model       string    `json:"model"`
	TS          time.Time `json:"ts"`
}

func NewExplainer(client *Client, backend Backend, st *store.Store, log func(string, ...any)) *Explainer {
	if log == nil {
		log = func(string, ...any) {}
	}
	return &Explainer{client: client, backend: backend, st: st, judge: NewJudge(client, log), log: log, cache: map[string]*Explanation{}}
}

const explainPrompt = `You explain one thing a home-network gateway noticed to the person who runs the network.
They are not a security professional. You get the record and whatever else the gateway knows
about the addresses, hosts and devices involved.

Say what it is in plain words, whether it is dangerous, and what to do. Most things a gateway
notices are routine: background scanning from the internet, a device checking for updates, an
ad server, a cloud service's telemetry. Say so when that is the case; do not invent threats.
When something does deserve action, be specific: which device, which setting, which page.

Danger levels: "none" (normal), "low" (worth knowing, no action), "medium" (do something when
convenient), "high" (act now).

Answer with a JSON object and nothing else:
{"title":"one line","danger":"none|low|medium|high","explanation":"two to five sentences","steps":["at most four short steps, or none"]}`

// Explain answers for kind "event" (id), "alert" (intrusion alert id),
// "ip" (address) or "domain" (hostname).
func (x *Explainer) Explain(ctx context.Context, kind, key string) (*Explanation, error) {
	if !x.client.Configured() {
		return nil, fmt.Errorf("the assistant is not configured")
	}
	kind = strings.ToLower(strings.TrimSpace(kind))
	key = strings.TrimSpace(key)
	if key == "" {
		return nil, fmt.Errorf("nothing to explain")
	}
	ck := kind + ":" + strings.ToLower(key)
	x.mu.Lock()
	if c, ok := x.cache[ck]; ok && time.Since(c.TS) < time.Hour {
		x.mu.Unlock()
		return c, nil
	}
	x.mu.Unlock()

	subject, err := x.subject(ctx, kind, key)
	if err != nil {
		return nil, err
	}
	payload, err := jsonOf(subject, nil)
	if err != nil {
		return nil, err
	}
	cctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	type out struct {
		Title       string   `json:"title"`
		Danger      string   `json:"danger"`
		Explanation string   `json:"explanation"`
		Steps       []string `json:"steps"`
	}
	validate := func(text string) error {
		var probe out
		if err := parseJSONObject(text, &probe); err != nil {
			return err
		}
		if strings.TrimSpace(probe.Explanation) == "" {
			return fmt.Errorf("explanation missing")
		}
		return nil
	}
	resp, err := x.client.CompleteJSON(cctx, explainPrompt, []Message{{Role: RoleUser, Content: payload}}, false, validate)
	if err != nil {
		return nil, err
	}
	var o out
	if err := parseJSONObject(resp.Text, &o); err != nil {
		return nil, fmt.Errorf("explanation unreadable: %w", err)
	}
	switch strings.ToLower(o.Danger) {
	case "low", "medium", "high":
		o.Danger = strings.ToLower(o.Danger)
	default:
		o.Danger = "none"
	}
	if len(o.Steps) > 4 {
		o.Steps = o.Steps[:4]
	}
	e := &Explanation{Kind: kind, Key: key, Title: clip(strings.TrimSpace(o.Title), 140), Danger: o.Danger,
		Explanation: strings.TrimSpace(o.Explanation), Steps: o.Steps, Model: resp.Model, TS: time.Now()}
	x.mu.Lock()
	if len(x.cache) > 300 {
		x.cache = map[string]*Explanation{}
	}
	x.cache[ck] = e
	x.mu.Unlock()
	return e, nil
}

// subject collects what the node knows about the thing.
func (x *Explainer) subject(ctx context.Context, kind, key string) (map[string]any, error) {
	since := time.Now().Add(-7 * 24 * time.Hour)
	out := map[string]any{"kind": kind}
	switch kind {
	case "event":
		if x.st == nil {
			return nil, fmt.Errorf("no store")
		}
		ev, err := x.st.EventByID(key)
		if err != nil {
			return nil, err
		}
		if ev == nil {
			return nil, fmt.Errorf("no such event")
		}
		out["event"] = ev
		// Pull in the address or host the event names, if any.
		for _, k := range []string{"ip", "address", "src", "source", "value"} {
			if v, ok := ev.Data[k].(string); ok && v != "" {
				if info, err := x.backend.LookupIP(v); err == nil {
					out["address"] = info
				}
				break
			}
		}
		if d, ok := ev.Data["domain"].(string); ok && d != "" {
			if diag, err := x.backend.DiagnoseDomain(ctx, d, "", false); err == nil {
				out["domain"] = diag
			}
		}
	case "alert":
		if x.st == nil {
			return nil, fmt.Errorf("no store")
		}
		alerts, err := x.st.IDSAlerts(since, 500)
		if err != nil {
			return nil, err
		}
		var found *store.IDSAlert
		for i := range alerts {
			if fmt.Sprint(alerts[i].ID) == key {
				found = &alerts[i]
				break
			}
		}
		if found == nil {
			return nil, fmt.Errorf("no such alert")
		}
		out["alert"] = found
		if info, err := x.backend.LookupIP(found.IP); err == nil {
			out["address"] = info
		}
		var same []store.IDSAlert
		for _, a := range alerts {
			if a.IP == found.IP && a.ID != found.ID && len(same) < 10 {
				same = append(same, a)
			}
		}
		out["other_alerts_from_same_address"] = same
	case "ip":
		info, err := x.backend.LookupIP(key)
		if err != nil {
			return nil, err
		}
		out["address"] = info
		if m, err := x.backend.ThreatStatus(since, 200); err == nil {
			out["threat_status"] = pick(m, "hits", "recent_decisions")
		}
		if x.st != nil {
			if alerts, err := x.st.IDSAlerts(since, 500); err == nil {
				var mine []store.IDSAlert
				for _, a := range alerts {
					if a.IP == key && len(mine) < 10 {
						mine = append(mine, a)
					}
				}
				out["intrusion_alerts"] = mine
			}
		}
	case "domain":
		diag, err := x.backend.DiagnoseDomain(ctx, key, "", true)
		if err != nil {
			return nil, err
		}
		out["domain"] = diag
		if log, err := x.backend.DNSLog(since, "", false, key, 50); err == nil {
			out["recent_lookups"] = len(log)
			devices := map[string]bool{}
			for _, q := range log {
				devices[q.ClientID] = true
			}
			out["devices_asking"] = len(devices)
		}
		if protected, why := adblock.Protected(key); protected {
			out["protected_from_automatic_blocking"] = why
		}
	default:
		return nil, fmt.Errorf("kind must be event, alert, ip or domain")
	}
	return out, nil
}

// JudgeDomain asks the ad-and-tracker classifier about one hostname, with
// what the DNS log shows about it, for the domain tester.
func (x *Explainer) JudgeDomain(ctx context.Context, domain string) (map[string]any, error) {
	if !x.client.Configured() {
		return nil, fmt.Errorf("the assistant is not configured")
	}
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" || !strings.Contains(domain, ".") {
		return nil, fmt.Errorf("that is not a hostname")
	}
	ev := adblock.DomainEvidence{Domain: domain, SubdomainDepth: strings.Count(domain, ".")}
	since := time.Now().Add(-7 * 24 * time.Hour)
	if log, err := x.backend.DNSLog(since, "", false, domain, 500); err == nil {
		devices := map[string]bool{}
		for _, q := range log {
			if strings.EqualFold(q.Name, domain) {
				ev.Observations++
				devices[q.ClientID] = true
			}
		}
		ev.DistinctClients = len(devices)
	}
	ev.HeuristicScore = adblock.Heuristic(ev)
	verdicts, err := x.judge.JudgeDomains(ctx, []adblock.DomainEvidence{ev})
	if err != nil {
		return nil, err
	}
	if len(verdicts) == 0 {
		return nil, fmt.Errorf("the model gave no verdict")
	}
	out := map[string]any{"domain": domain, "verdict": verdicts[0], "evidence": ev}
	if protected, why := adblock.Protected(domain); protected {
		out["protected"] = why
	}
	return out, nil
}
