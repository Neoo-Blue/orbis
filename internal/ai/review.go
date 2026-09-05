package ai

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Neoo-Blue/orbis/internal/config"
	"github.com/Neoo-Blue/orbis/internal/store"
	"github.com/google/uuid"
)

// Reviewer is the ad-blocking specialist. On a schedule it reads what was
// blocked, for whom, and by which list, plus what the smart-capture pipeline
// wants blocked, and suggests: names that look like collateral damage and
// should be allowed, names that should be blocked, and things worth a look.
// Suggestions are remembered with the operator's decision, so a dismissed
// idea does not come back the next morning.
type Reviewer struct {
	cfg     *config.Config
	client  *Client
	backend Backend
	st      *store.Store
	log     func(string, ...any)
	record  func(e store.Event, notify bool)

	mu      sync.Mutex
	running bool
	last    time.Time
}

func NewReviewer(cfg *config.Config, client *Client, backend Backend, st *store.Store,
	record func(e store.Event, notify bool), log func(string, ...any)) *Reviewer {
	if log == nil {
		log = func(string, ...any) {}
	}
	if record == nil {
		record = func(store.Event, bool) {}
	}
	rv := &Reviewer{cfg: cfg, client: client, backend: backend, st: st, log: log, record: record}
	if st != nil {
		if recs, err := st.Recommendations("", 1); err == nil && len(recs) > 0 {
			rv.last = recs[0].TS
		}
	}
	return rv
}

func (rv *Reviewer) Run(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		cfg := rv.cfg.Snapshot().AI
		if !cfg.Enabled || !cfg.Review.Enabled || !rv.client.Configured() {
			continue
		}
		interval := time.Duration(cfg.Review.IntervalHours) * time.Hour
		if interval < time.Hour {
			interval = 24 * time.Hour
		}
		rv.mu.Lock()
		due := time.Since(rv.last) >= interval
		rv.mu.Unlock()
		if !due {
			continue
		}
		if _, err := rv.Review(ctx, int(interval/time.Hour)); err != nil && ctx.Err() == nil {
			rv.log("review: %v", err)
			rv.mu.Lock()
			rv.last = time.Now().Add(-interval + 30*time.Minute)
			rv.mu.Unlock()
		}
	}
}

const reviewPrompt = `You are the ad-blocking specialist inside Orbis, a home/small-office DNS filter.
Once a day you review what the filter did and tell the operator what to change. You are careful:
blocking the wrong thing breaks something someone uses, and the operator will stop trusting you.

You are given JSON from the node:
- blocked: names the filter stopped in the window, with how many lookups, how many distinct devices
  asked, and which list caused it. Most are exactly what the lists are for. Some are collateral:
  a CDN that also serves a site's assets, a first-party API or login endpoint, a push-notification
  or update service, an OCSP responder, a smart-TV app's content host, a service the operator
  clearly uses (see notes). Those deserve an "allow" suggestion.
- candidates: names the smart-capture heuristics scored as probable ad or tracking infrastructure
  that no list has yet. Where the evidence is convincing (third-party ratio near 1, many referring
  sites, tiny beacon responses), suggest "block". Where it is a CDN shard or unclear, do not.
- already_decided: kinds and names the operator already accepted or dismissed. Never suggest these.
- allowlist / denylist: what is already in place. Never suggest what is already done.
- notes: facts the operator asked to be remembered about this network. Respect them.

Answer with a JSON array and nothing else, at most MAX items, best first:
[{"kind":"allow|block|investigate","domain":"...","reason":"one sentence naming the evidence","confidence":0.0-1.0}]

Rules: "allow" needs a concrete reason the block plausibly breaks something. "block" needs
behavioural evidence, not just a name that sounds like tracking. "investigate" is for a device
doing something the operator should look at, with the specific domain. An empty array is a fine
answer on a quiet day.`

// Review runs one pass over the last hours and stores what survives.
func (rv *Reviewer) Review(ctx context.Context, hours int) ([]store.Recommendation, error) {
	if !rv.client.Configured() {
		return nil, fmt.Errorf("the assistant is not configured")
	}
	rv.mu.Lock()
	if rv.running {
		rv.mu.Unlock()
		return nil, fmt.Errorf("a review is already running")
	}
	rv.running = true
	rv.mu.Unlock()
	defer func() {
		rv.mu.Lock()
		rv.running = false
		rv.mu.Unlock()
	}()

	if hours <= 0 {
		hours = 24
	}
	if hours > 336 {
		hours = 336
	}
	cfg := rv.cfg.Snapshot()
	maxItems := cfg.AI.Review.MaxSuggestions
	if maxItems <= 0 {
		maxItems = 8
	}
	since := time.Now().Add(-time.Duration(hours) * time.Hour)
	evidence, blockedSet := rv.gather(cfg, since, hours)
	payload, err := jsonOf(evidence, nil)
	if err != nil {
		return nil, err
	}
	prompt := strings.Replace(reviewPrompt, "MAX", fmt.Sprint(maxItems), 1)

	type rec struct {
		Kind       string  `json:"kind"`
		Domain     string  `json:"domain"`
		Reason     string  `json:"reason"`
		Confidence float64 `json:"confidence"`
	}
	cctx, cancel := context.WithTimeout(ctx, 4*time.Minute)
	defer cancel()
	resp, err := rv.client.CompleteJSON(cctx, prompt, []Message{{Role: RoleUser, Content: payload}}, false,
		func(text string) error {
			var probe []rec
			return parseJSONArray(text, &probe)
		})
	if err != nil {
		return nil, err
	}
	var recs []rec
	if err := parseJSONArray(resp.Text, &recs); err != nil {
		return nil, err
	}

	if rv.st != nil {
		_ = rv.st.ExpireRecommendations(time.Now().Add(-14 * 24 * time.Hour))
	}
	decided := rv.decidedSet()
	allowed := toSet(cfg.AdBlock.Allowlist)
	denied := toSet(cfg.AdBlock.Denylist)
	var out []store.Recommendation
	for _, r := range recs {
		d := strings.ToLower(strings.TrimSpace(strings.TrimPrefix(r.Domain, "*.")))
		kind := strings.ToLower(strings.TrimSpace(r.Kind))
		if d == "" || !strings.Contains(d, ".") {
			continue
		}
		if kind != "allow" && kind != "block" && kind != "investigate" {
			continue
		}
		// The model may only speak about what it was shown; a name it made up
		// must never reach a block or allow list.
		if kind != "investigate" && !blockedSet[d] && !evidence.candidateSet[d] {
			rv.log("review: ignoring %s suggestion for %q (not in evidence)", kind, d)
			continue
		}
		if decided[kind+"|"+d] || (kind == "allow" && allowed[d]) || (kind == "block" && denied[d]) {
			continue
		}
		if r.Confidence < 0 {
			r.Confidence = 0
		}
		if r.Confidence > 1 {
			r.Confidence = 1
		}
		saved, err := rv.st.UpsertRecommendation(store.Recommendation{
			ID: uuid.NewString(), TS: time.Now(), Kind: kind, Domain: d, Reason: strings.TrimSpace(r.Reason),
			Confidence: r.Confidence, Evidence: evidence.evidenceFor(d), Model: resp.Model,
		})
		if err != nil {
			return nil, err
		}
		if saved.Status == "open" {
			out = append(out, *saved)
		}
		if len(out) >= maxItems {
			break
		}
	}

	rv.mu.Lock()
	rv.last = time.Now()
	rv.mu.Unlock()

	allow, block, look := 0, 0, 0
	for _, r := range out {
		switch r.Kind {
		case "allow":
			allow++
		case "block":
			block++
		default:
			look++
		}
	}
	rv.log("review: %d suggestion(s) (%d allow, %d block, %d investigate) from %s", len(out), allow, block, look, resp.Model)
	if len(out) > 0 {
		sev := store.SevInfo
		if look > 0 {
			sev = store.SevNotice
		}
		rv.record(store.Event{
			ID: uuid.NewString(), TS: time.Now(), Severity: sev, Category: "ai:review",
			Title:  fmt.Sprintf("Blocklist review: %d suggestion(s) waiting", len(out)),
			Detail: fmt.Sprintf("%d to allow, %d to block, %d to look at. Decide on the Assistant page.", allow, block, look),
			Data:   map[string]any{"allow": allow, "block": block, "investigate": look, "model": resp.Model},
		}, false)
	}
	return out, nil
}

type reviewEvidence struct {
	payload      map[string]any
	blocked      map[string]map[string]any
	candidateSet map[string]bool
}

func (e reviewEvidence) evidenceFor(domain string) map[string]any {
	if b, ok := e.blocked[domain]; ok {
		return b
	}
	if e.candidateSet[domain] {
		return map[string]any{"source": "smart_capture"}
	}
	return nil
}

func (rv *Reviewer) gather(cfg config.Config, since time.Time, hours int) (reviewEvidence, map[string]bool) {
	ev := reviewEvidence{blocked: map[string]map[string]any{}, candidateSet: map[string]bool{}}

	// Blocked names, aggregated from the query log so we know how many
	// devices asked, which is the strongest collateral-damage signal.
	type agg struct {
		count   int
		clients map[string]bool
		source  string
		rcode   string
	}
	aggs := map[string]*agg{}
	if queries, err := rv.backend.DNSLog(since, "", true, "", 4000); err == nil {
		for _, q := range queries {
			name := strings.ToLower(q.Name)
			a := aggs[name]
			if a == nil {
				a = &agg{clients: map[string]bool{}}
				aggs[name] = a
			}
			a.count++
			a.clients[q.ClientIP] = true
			if q.BlockSource != "" {
				a.source = q.BlockSource
			}
		}
	}
	type row struct {
		Domain  string `json:"domain"`
		Lookups int    `json:"lookups"`
		Devices int    `json:"devices"`
		Source  string `json:"blocked_by"`
	}
	rows := make([]row, 0, len(aggs))
	for d, a := range aggs {
		rows = append(rows, row{Domain: d, Lookups: a.count, Devices: len(a.clients), Source: a.source})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Devices != rows[j].Devices {
			return rows[i].Devices > rows[j].Devices
		}
		return rows[i].Lookups > rows[j].Lookups
	})
	if len(rows) > 60 {
		rows = rows[:60]
	}
	blockedSet := map[string]bool{}
	for _, r := range rows {
		blockedSet[r.Domain] = true
		ev.blocked[r.Domain] = map[string]any{"lookups": r.Lookups, "devices": r.Devices, "blocked_by": r.Source}
	}

	// Smart-capture candidates with their behavioural evidence.
	var cands []map[string]any
	for _, status := range []string{"review", "candidate"} {
		list, err := rv.backend.AdCandidates(status, 0.5, 25)
		if err != nil {
			continue
		}
		for _, c := range list {
			d := strings.ToLower(c.Domain)
			ev.candidateSet[d] = true
			entry := map[string]any{
				"domain": d, "status": c.Status, "score": c.FinalScore, "heuristic": c.HeuristicScore,
				"clients": c.DistinctClients, "referrers": c.DistinctReferrers, "observations": c.Observations,
			}
			if c.AIReason != "" {
				entry["earlier_assessment"] = c.AIReason
			}
			cands = append(cands, entry)
		}
	}

	var decided []string
	for k := range rv.decidedSet() {
		decided = append(decided, k)
	}
	sort.Strings(decided)

	var notes []string
	if rv.st != nil {
		if ns, err := rv.st.Notes(40); err == nil {
			for _, n := range ns {
				notes = append(notes, n.Note)
			}
		}
	}

	ev.payload = map[string]any{
		"window_hours":    hours,
		"blocked":         rows,
		"candidates":      cands,
		"already_decided": decided,
		"allowlist":       cfg.AdBlock.Allowlist,
		"denylist":        cfg.AdBlock.Denylist,
		"notes":           notes,
	}
	return ev, blockedSet
}

// decidedSet is the memory: every accepted or dismissed suggestion as
// "kind|domain". Expired open ones are not decisions and may return.
func (rv *Reviewer) decidedSet() map[string]bool {
	out := map[string]bool{}
	if rv.st == nil {
		return out
	}
	recs, err := rv.st.Recommendations("", 500)
	if err != nil {
		return out
	}
	for _, r := range recs {
		if r.Status == "accepted" || r.Status == "dismissed" {
			out[r.Kind+"|"+r.Domain] = true
		}
	}
	return out
}

func toSet(items []string) map[string]bool {
	out := make(map[string]bool, len(items))
	for _, it := range items {
		out[strings.ToLower(strings.TrimPrefix(strings.TrimSpace(it), "*."))] = true
	}
	return out
}
