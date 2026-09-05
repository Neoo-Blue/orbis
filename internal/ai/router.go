package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Neoo-Blue/orbis/internal/config"
	"github.com/Neoo-Blue/orbis/internal/store"
)

// The router decides which model answers a request. On OpenRouter a credited
// account may use every ":free" model at no charge, subject to a daily cap and
// to the free tier's weather: models come and go, get rate-limited upstream
// for minutes at a time, and occasionally reject a parameter. Rather than pin
// one model id in a config file and discover it stopped working weeks later,
// the router fetches the catalogue, probes what is actually there with the
// same shape of request production sends, ranks the survivors, and walks that
// ranking at call time with short per-model cooldowns. The operator's pinned
// model is the guaranteed last link.

type family int

const (
	familyChat family = iota // tool-using conversation and briefs
	familyFast               // high-volume JSON classification
)

func (f family) String() string {
	if f == familyFast {
		return "fast"
	}
	return "chat"
}

// ProviderError is an error the provider returned, with enough structure for
// the router to decide whether the next model should be tried.
type ProviderError struct {
	Status  int // HTTP status, 200 when the error rode inside a 200 body
	Code    int // upstream code carried in the body, when present
	Message string
}

func (e *ProviderError) Error() string {
	code := e.Status
	if e.Code != 0 && e.Code != e.Status {
		code = e.Code
	}
	return fmt.Sprintf("provider returned %d: %s", code, e.Message)
}

func (e *ProviderError) status() int {
	if e.Code != 0 && (e.Status == 200 || e.Status == 0) {
		return e.Code
	}
	return e.Status
}

// Router state is small: the catalogue with probe results, per-model
// cooldowns, and today's usage. Everything it needs to answer "which model
// next" is in memory; the store is the crash-safe copy.
type Router struct {
	cfg  *config.Config
	st   *store.Store
	http *http.Client
	log  func(string, ...any)

	mu        sync.Mutex
	models    map[string]*store.AIModel
	chatRank  []string
	fastRank  []string
	cooldown  map[string]time.Time
	locked    map[string]bool // models that refuse reasoning:{enabled:false}
	usageDay  string
	usage     map[string]*store.AIUsage
	lastProbe time.Time
	probing   bool
	probeErr  string

	probeReq chan struct{}
	now      func() time.Time
	// pace is the minimum gap between probe request starts; tests shorten it.
	pace time.Duration
}

func NewRouter(cfg *config.Config, st *store.Store, httpc *http.Client, log func(string, ...any)) *Router {
	if log == nil {
		log = func(string, ...any) {}
	}
	if httpc == nil {
		httpc = &http.Client{Timeout: 60 * time.Second}
	}
	r := &Router{
		cfg: cfg, st: st, http: httpc, log: log,
		models:   map[string]*store.AIModel{},
		cooldown: map[string]time.Time{},
		locked:   map[string]bool{},
		usage:    map[string]*store.AIUsage{},
		probeReq: make(chan struct{}, 1),
		now:      time.Now,
		pace:     3500 * time.Millisecond,
	}
	r.load()
	return r
}

// load restores the last ranking and today's counters from the store.
func (r *Router) load() {
	if r.st == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if models, err := r.st.AIModels(); err == nil {
		for i := range models {
			m := models[i]
			r.models[m.ID] = &m
			if m.LastProbe.After(r.lastProbe) {
				r.lastProbe = m.LastProbe
			}
		}
		r.rebuildRanksLocked()
	}
	r.usageDay = r.today()
	if rows, err := r.st.AIUsage(r.usageDay); err == nil {
		for i := range rows {
			u := rows[i]
			r.usage[u.Model] = &u
		}
	}
}

func (r *Router) today() string { return r.now().UTC().Format("2006-01-02") }

func isFree(model string) bool { return strings.HasSuffix(model, ":free") }

func isOpenRouter(cfg config.AIConfig) bool {
	return strings.EqualFold(cfg.Provider, "openrouter") ||
		strings.Contains(strings.ToLower(cfg.BaseURL), "openrouter")
}

// Candidates returns the ordered list of models to try for a request. The
// list is short on purpose: a chat turn that walks six models before failing
// is a worse experience than one that fails after three.
func (r *Router) Candidates(cfg config.AIConfig, fam family) []string {
	pinned := cfg.Model
	if fam == familyFast && cfg.FastModel != "" {
		pinned = cfg.FastModel
	}
	if !isOpenRouter(cfg) || !cfg.PreferFree {
		if pinned == "" {
			return nil
		}
		return []string{pinned}
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	r.rolloverLocked()

	// Past the daily budget, free candidates are not offered; the pinned
	// model carries the rest of the day (and if it is itself free, it will
	// simply fail with the provider's own message when the cap is hit).
	budget := cfg.FreeDailyBudget
	if budget <= 0 {
		budget = 900
	}
	if r.freeRequestsTodayLocked() >= budget && pinned != "" && !isFree(pinned) {
		return []string{pinned}
	}

	chain := cfg.ModelChain
	if fam == familyFast && len(cfg.FastModelChain) > 0 {
		chain = cfg.FastModelChain
	}
	if len(chain) == 0 {
		chain = r.chatRank
		if fam == familyFast {
			chain = r.fastRank
		}
	}

	now := r.now()
	out := make([]string, 0, 5)
	seen := map[string]bool{}
	add := func(id string) {
		if id == "" || seen[id] {
			return
		}
		seen[id] = true
		out = append(out, id)
	}
	const maxFree = 4
	for _, id := range chain {
		if len(out) >= maxFree {
			break
		}
		if until, ok := r.cooldown[id]; ok && until.After(now) {
			continue
		}
		add(id)
	}
	// Everything cooling down at once usually means the free tier is having
	// a bad minute rather than every model being broken; offer the best one
	// anyway so the request is not refused without a single attempt.
	if len(out) == 0 && len(chain) > 0 {
		add(chain[0])
	}
	add(pinned)
	return out
}

// requestOptions are the per-model request tweaks the OpenAI-shaped path
// applies: whether to switch reasoning off, and how much output budget to
// grant on top of the configured maximum.
type requestOptions struct {
	reasoningOff bool
	maxTokens    int
}

func (r *Router) options(cfg config.AIConfig, model string, fam family) requestOptions {
	opts := requestOptions{maxTokens: orDefault(cfg.MaxTokens, 4096)}
	if !isOpenRouter(cfg) {
		return opts
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	m := r.models[model]
	if m == nil {
		return opts
	}
	if m.Reasoning {
		// Reasoning tokens count against max_tokens. Several strong free
		// models think for thousands of tokens before the first visible one
		// and return finish_reason=length with no content at the nominal
		// budget. The headroom is additive, not a multiplier.
		opts.maxTokens += 6000
		// Label work does not need a chain of thought and the tokens are
		// most of the bill. Chat keeps the model's default.
		if fam == familyFast && !r.locked[model] {
			opts.reasoningOff = true
		}
	}
	if m.MaxOutput > 0 && opts.maxTokens > m.MaxOutput {
		opts.maxTokens = m.MaxOutput
	}
	return opts
}

// noteReasoningLocked remembers that a model rejects reasoning:{enabled:false}
// so the next request does not pay a round-trip to be told again.
func (r *Router) noteReasoningLocked(model string) {
	r.mu.Lock()
	r.locked[model] = true
	r.mu.Unlock()
}

func (r *Router) isLocked(model string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.locked[model]
}

// Report records the outcome of one request and updates cooldowns.
func (r *Router) Report(model string, err error, resp *Response) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.rolloverLocked()
	u := r.usage[model]
	if u == nil {
		u = &store.AIUsage{Day: r.usageDay, Model: model}
		r.usage[model] = u
	}
	u.Requests++
	var in, out int
	if resp != nil {
		in, out = resp.TokensIn, resp.TokensOut
		u.TokensIn += in
		u.TokensOut += out
	}
	if err == nil {
		delete(r.cooldown, model)
	} else {
		u.Failures++
		if d, _ := classify(err); d > 0 {
			r.cooldown[model] = r.now().Add(d)
		}
		if m := r.models[model]; m != nil {
			m.LastError = trimErr(err.Error())
		}
	}
	if r.st != nil {
		_ = r.st.RecordAIUsage(r.usageDay, model, err != nil, in, out)
	}
}

// classify maps a failure to a cooldown and to whether the caller should move
// on to the next model. Free-tier 429s are weather, not an outage: a short
// cooldown and the next candidate, never a provider-wide breaker.
func classify(err error) (cooldown time.Duration, retriable bool) {
	if err == nil {
		return 0, false
	}
	if err == context.Canceled {
		return 0, false
	}
	msg := strings.ToLower(err.Error())
	if pe, ok := err.(*ProviderError); ok {
		switch pe.status() {
		case 429:
			return 2 * time.Minute, true
		case 401, 402:
			// Bad key or no credit: the same for every model. Do not burn
			// the chain finding that out four times.
			return 0, false
		case 403:
			// "only available on agentic harnesses" and similar gating.
			return 24 * time.Hour, true
		case 404:
			return 6 * time.Hour, true
		case 400:
			if strings.Contains(msg, "reasoning") {
				return 0, true
			}
			if strings.Contains(msg, "context length") || strings.Contains(msg, "too long") ||
				strings.Contains(msg, "maximum context") {
				// The prompt is too big for this model; a bigger one may fit.
				return 0, true
			}
			return time.Hour, true
		case 408, 500, 502, 503, 504, 520, 522, 524:
			return 5 * time.Minute, true
		case 200:
			// Empty completion, no choices: the model is up but unhelpful
			// right now; try another and come back later.
			return 3 * time.Minute, true
		}
		return 5 * time.Minute, true
	}
	if strings.Contains(msg, "deadline exceeded") || strings.Contains(msg, "timeout") ||
		strings.Contains(msg, "connection reset") || strings.Contains(msg, "eof") {
		return 3 * time.Minute, true
	}
	if strings.Contains(msg, "decode response") {
		return 3 * time.Minute, true
	}
	return time.Minute, true
}

func trimErr(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 240 {
		s = s[:240] + "…"
	}
	return s
}

func (r *Router) rolloverLocked() {
	day := r.today()
	if day != r.usageDay {
		r.usageDay = day
		r.usage = map[string]*store.AIUsage{}
	}
}

func (r *Router) freeRequestsTodayLocked() int {
	n := 0
	for id, u := range r.usage {
		if isFree(id) {
			n += u.Requests
		}
	}
	return n
}

// ---- probe ----

// Run keeps the catalogue fresh. It probes shortly after start (so a node
// that has never probed gets a ranking within a minute of booting) and then
// on the configured interval, or when the API asks.
func (r *Router) Run(ctx context.Context) {
	first := time.NewTimer(20 * time.Second)
	defer first.Stop()
	for {
		cfg := r.cfg.Snapshot().AI
		interval := time.Duration(cfg.ProbeIntervalHours) * time.Hour
		if interval < time.Hour {
			interval = 6 * time.Hour
		}
		var due <-chan time.Time
		r.mu.Lock()
		last := r.lastProbe
		r.mu.Unlock()
		if last.IsZero() {
			due = first.C
		} else {
			wait := time.Until(last.Add(interval))
			if wait < time.Minute {
				wait = time.Minute
			}
			t := time.NewTimer(wait)
			due = t.C
			defer t.Stop()
		}
		select {
		case <-ctx.Done():
			return
		case <-due:
		case <-r.probeReq:
		}
		cfg = r.cfg.Snapshot().AI
		if !cfg.Enabled || !cfg.AutoDiscover || !isOpenRouter(cfg) || cfg.APIKey == "" {
			// Nothing to do; wait for the next tick or request rather than
			// spinning. Mark a probe time so the loop sleeps a full interval.
			r.mu.Lock()
			if r.lastProbe.IsZero() {
				r.lastProbe = r.now()
			}
			r.mu.Unlock()
			continue
		}
		if err := r.Probe(ctx); err != nil && ctx.Err() == nil {
			r.log("ai: probe failed: %v", err)
		}
	}
}

// RequestProbe asks the run loop to probe now. Non-blocking; a probe that
// is already queued or running absorbs the request.
func (r *Router) RequestProbe() {
	select {
	case r.probeReq <- struct{}{}:
	default:
	}
}

type catalogueEntry struct {
	ID            string   `json:"id"`
	Name          string   `json:"name"`
	ContextLength int      `json:"context_length"`
	Supported     []string `json:"supported_parameters"`
	Architecture  struct {
		Modality         string   `json:"modality"`
		OutputModalities []string `json:"output_modalities"`
	} `json:"architecture"`
	TopProvider struct {
		MaxCompletionTokens int `json:"max_completion_tokens"`
	} `json:"top_provider"`
}

func (r *Router) fetchCatalogue(ctx context.Context, cfg config.AIConfig) ([]catalogueEntry, error) {
	base := cfg.BaseURL
	if base == "" {
		base = "https://openrouter.ai/api/v1"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimSuffix(base, "/")+"/models", nil)
	if err != nil {
		return nil, err
	}
	if cfg.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+cfg.APIKey)
	}
	resp, err := r.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, &ProviderError{Status: resp.StatusCode, Message: trimErr(string(raw))}
	}
	var parsed struct {
		Data []catalogueEntry `json:"data"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, fmt.Errorf("decode catalogue: %w", err)
	}
	return parsed.Data, nil
}

func (e catalogueEntry) has(param string) bool {
	for _, p := range e.Supported {
		if p == param {
			return true
		}
	}
	return false
}

func (e catalogueEntry) textOut() bool {
	if len(e.Architecture.OutputModalities) > 0 {
		for _, m := range e.Architecture.OutputModalities {
			if m == "text" {
				return true
			}
		}
		return false
	}
	return e.Architecture.Modality == "" || strings.HasSuffix(e.Architecture.Modality, "->text")
}

// Probe refreshes the catalogue and re-tests every free tool-capable model.
// Requests are paced under the free tier's per-minute limit so the probe does
// not itself trip the 429s it is trying to route around.
func (r *Router) Probe(ctx context.Context) error {
	r.mu.Lock()
	if r.probing {
		r.mu.Unlock()
		return nil
	}
	r.probing = true
	r.probeErr = ""
	r.mu.Unlock()
	defer func() {
		r.mu.Lock()
		r.probing = false
		r.mu.Unlock()
	}()

	cfg := r.cfg.Snapshot().AI
	entries, err := r.fetchCatalogue(ctx, cfg)
	if err != nil {
		r.mu.Lock()
		r.probeErr = trimErr(err.Error())
		r.mu.Unlock()
		return err
	}

	prior := map[string]store.AIModel{}
	r.mu.Lock()
	for id, m := range r.models {
		prior[id] = *m
	}
	r.mu.Unlock()

	pinned := map[string]bool{cfg.Model: true, cfg.FastModel: true}
	var models []store.AIModel
	var toProbe []store.AIModel
	for _, e := range entries {
		free := isFree(e.ID)
		if !free && !pinned[e.ID] {
			continue
		}
		m := store.AIModel{
			ID: e.ID, Name: e.Name, Free: free,
			Context: e.ContextLength, MaxOutput: e.TopProvider.MaxCompletionTokens,
			Tools: e.has("tools"), Reasoning: e.has("reasoning"), Structured: e.has("response_format"),
		}
		if p, ok := prior[e.ID]; ok {
			m.ToolOK, m.JSONOK, m.LatencyMS = p.ToolOK, p.JSONOK, p.LatencyMS
			m.LastProbe, m.LastError = p.LastProbe, p.LastError
		}
		if free && m.Tools && e.textOut() {
			// A model gated behind a 403 yesterday is not worth two more
			// requests today; the next probe after the cooldown asks again.
			if strings.Contains(m.LastError, "403") && r.now().Sub(m.LastProbe) < 24*time.Hour {
				models = append(models, m)
				continue
			}
			toProbe = append(toProbe, m)
		}
		models = append(models, m)
	}
	sort.Slice(toProbe, func(i, j int) bool { return toProbe[i].ID < toProbe[j].ID })
	if len(toProbe) > 16 {
		toProbe = toProbe[:16]
	}

	// Pace: one request start every 3.5s keeps a 16-model probe (two
	// requests each, plus a follow-up on the chat test) under 20 a minute.
	pace := time.NewTicker(r.pace)
	defer pace.Stop()
	wait := func() bool {
		select {
		case <-ctx.Done():
			return false
		case <-pace.C:
			return true
		}
	}

	results := map[string]store.AIModel{}
	var wg sync.WaitGroup
	var rmu sync.Mutex
	sem := make(chan struct{}, 2)
	for _, m := range toProbe {
		if !wait() {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(m store.AIModel) {
			defer wg.Done()
			defer func() { <-sem }()
			r.probeOne(ctx, cfg, &m, wait)
			rmu.Lock()
			results[m.ID] = m
			rmu.Unlock()
		}(m)
	}
	wg.Wait()

	for i := range models {
		if res, ok := results[models[i].ID]; ok {
			models[i] = res
		}
	}
	r.rank(models)

	r.mu.Lock()
	r.models = map[string]*store.AIModel{}
	for i := range models {
		m := models[i]
		r.models[m.ID] = &m
	}
	r.rebuildRanksLocked()
	r.lastProbe = r.now()
	chat, fast := len(r.chatRank), len(r.fastRank)
	r.mu.Unlock()

	if r.st != nil {
		if err := r.st.ReplaceAIModels(models); err != nil {
			r.log("ai: could not persist model catalogue: %v", err)
		}
	}
	r.log("ai: probed %d free models: %d usable for chat, %d for classification", len(toProbe), chat, fast)
	return ctx.Err()
}

// probeOne runs the two production-shaped tests against one model. A 429
// leaves the previous verdicts alone: "busy right now" is not "cannot".
func (r *Router) probeOne(ctx context.Context, cfg config.AIConfig, m *store.AIModel, wait func() bool) {
	pctx, cancel := context.WithTimeout(ctx, 4*time.Minute)
	defer cancel()
	c := &Client{cfg: r.cfg, http: r.http, router: r, log: r.log}

	m.LastProbe = r.now()
	m.LastError = ""
	var latency time.Duration

	// Test 1: chat shape. Ask a question that needs a tool, expect the call;
	// feed a tiny result back, expect the answer to carry the number in it.
	toolOK := false
	start := r.now()
	resp, err := c.completeOnce(pctx, cfg, m.ID, familyChat, false, probeSystem,
		[]Message{{Role: RoleUser, Content: "How many devices are online right now?"}}, probeTools)
	r.Report(m.ID, err, resp)
	if err != nil {
		m.LastError = trimErr(err.Error())
		if pe, ok := err.(*ProviderError); ok && pe.status() == 429 {
			return // keep prior verdicts
		}
		f := false
		m.ToolOK, m.JSONOK = &f, &f
		return
	}
	var call *ToolCall
	for i := range resp.ToolCalls {
		if resp.ToolCalls[i].Name == "list_clients" {
			call = &resp.ToolCalls[i]
			break
		}
	}
	if call != nil && wait() {
		msgs := []Message{
			{Role: RoleUser, Content: "How many devices are online right now?"},
			{Role: RoleAssistant, Content: resp.Text, ToolCalls: resp.ToolCalls},
		}
		for _, tc := range resp.ToolCalls {
			result := `{"count":3,"clients":[{"name":"Living room TV","online":true},{"name":"Laptop","online":true},{"name":"Phone","online":true}]}`
			msgs = append(msgs, Message{Role: RoleTool, ToolCallID: tc.ID, Name: tc.Name, Content: result})
		}
		resp2, err2 := c.completeOnce(pctx, cfg, m.ID, familyChat, false, probeSystem, msgs, probeTools)
		r.Report(m.ID, err2, resp2)
		if err2 == nil {
			t := strings.ToLower(resp2.Text)
			toolOK = strings.Contains(t, "3") || strings.Contains(t, "three")
		} else {
			m.LastError = trimErr(err2.Error())
		}
	}
	latency = r.now().Sub(start)
	m.ToolOK = &toolOK

	// Test 2: the judge's exact shape, with one obvious tracker and one CDN
	// that must not be called an ad. Getting the CDN wrong is disqualifying:
	// this verdict path can auto-block.
	if !wait() {
		return
	}
	jsonOK := false
	start = r.now()
	resp, err = c.completeOnce(pctx, cfg, m.ID, familyFast, true, judgePrompt,
		[]Message{{Role: RoleUser, Content: probeJudgeInput}}, nil)
	r.Report(m.ID, err, resp)
	if err != nil {
		m.LastError = trimErr(err.Error())
		if pe, ok := err.(*ProviderError); ok && pe.status() == 429 {
			m.LatencyMS = int(latency.Milliseconds())
			return
		}
		m.JSONOK = &jsonOK
		m.LatencyMS = int(latency.Milliseconds())
		return
	}
	if verdicts, perr := parseVerdicts(resp.Text); perr == nil && len(verdicts) == 2 {
		byDomain := map[string]bool{}
		for _, v := range verdicts {
			byDomain[strings.ToLower(v.Domain)] = v.IsAdTech
		}
		ad, okA := byDomain["px.ads-twitter.com"]
		cdn, okC := byDomain["cdn.jsdelivr.net"]
		jsonOK = okA && okC && ad && !cdn
	} else if perr != nil {
		m.LastError = "classification output was not JSON"
	}
	latency += r.now().Sub(start)
	m.JSONOK = &jsonOK
	m.LatencyMS = int(latency.Milliseconds())
}

const probeSystem = "You are the assistant built into Orbis, a network firewall. " +
	"Reach for tools rather than guessing. Answer with real numbers from tool results."

var probeTools = []ToolDef{{
	Name:        "list_clients",
	Description: "Every device known to the network, with whether it is online.",
	Schema:      objSchema(map[string]any{"online_only": boolProp("Only devices seen in the last five minutes")}, nil),
}}

const probeJudgeInput = `Classify these 2 hostnames.

[
  {"domain": "px.ads-twitter.com", "third_party_ratio": 0.98, "referring_sites": 41, "avg_response_bytes": 43, "request_count": 1204, "name_keywords": ["ads"]},
  {"domain": "cdn.jsdelivr.net", "third_party_ratio": 0.95, "referring_sites": 120, "avg_response_bytes": 48211, "request_count": 3310, "name_keywords": ["cdn"]}
]`

// rank assigns chat and fast positions. Chat needs the tool round-trip to
// work; the JSON test is a tie-breaker there. Fast needs the JSON test.
// Among the qualified, lower latency wins, then more context.
func (r *Router) rank(models []store.AIModel) {
	ok := func(b *bool) bool { return b != nil && *b }
	var chat, fast []int
	for i := range models {
		if !models[i].Free {
			continue
		}
		if ok(models[i].ToolOK) {
			chat = append(chat, i)
		}
		if ok(models[i].JSONOK) {
			fast = append(fast, i)
		}
	}
	sort.SliceStable(chat, func(a, b int) bool {
		ma, mb := models[chat[a]], models[chat[b]]
		if ok(ma.JSONOK) != ok(mb.JSONOK) {
			return ok(ma.JSONOK)
		}
		// Latency buckets of two seconds: a 1.1s and a 1.9s model are the
		// same to a person, and a 1M-token context is not.
		ba, bb := ma.LatencyMS/2000, mb.LatencyMS/2000
		if ba != bb {
			return ba < bb
		}
		return ma.Context > mb.Context
	})
	sort.SliceStable(fast, func(a, b int) bool {
		ma, mb := models[fast[a]], models[fast[b]]
		if ma.LatencyMS != mb.LatencyMS {
			return ma.LatencyMS < mb.LatencyMS
		}
		return ma.Context > mb.Context
	})
	for i := range models {
		models[i].ChatRank, models[i].FastRank = 0, 0
	}
	for pos, i := range chat {
		models[i].ChatRank = pos + 1
	}
	for pos, i := range fast {
		models[i].FastRank = pos + 1
	}
}

func (r *Router) rebuildRanksLocked() {
	type ranked struct {
		id   string
		rank int
	}
	var chat, fast []ranked
	for id, m := range r.models {
		if m.ChatRank > 0 {
			chat = append(chat, ranked{id, m.ChatRank})
		}
		if m.FastRank > 0 {
			fast = append(fast, ranked{id, m.FastRank})
		}
	}
	sort.Slice(chat, func(i, j int) bool { return chat[i].rank < chat[j].rank })
	sort.Slice(fast, func(i, j int) bool { return fast[i].rank < fast[j].rank })
	r.chatRank = r.chatRank[:0]
	for _, c := range chat {
		r.chatRank = append(r.chatRank, c.id)
	}
	r.fastRank = r.fastRank[:0]
	for _, f := range fast {
		r.fastRank = append(r.fastRank, f.id)
	}
}

// Status is what the UI shows: the catalogue with verdicts, the chains in
// effect right now, and how much of the free day is spent.
func (r *Router) Status(cfg config.AIConfig) map[string]any {
	chat := r.Candidates(cfg, familyChat)
	fast := r.Candidates(cfg, familyFast)

	r.mu.Lock()
	defer r.mu.Unlock()
	r.rolloverLocked()

	now := r.now()
	models := make([]map[string]any, 0, len(r.models))
	for _, m := range r.models {
		entry := map[string]any{
			"id": m.ID, "name": m.Name, "free": m.Free, "context": m.Context,
			"max_output": m.MaxOutput, "tools": m.Tools, "reasoning": m.Reasoning,
			"structured": m.Structured, "tool_ok": m.ToolOK, "json_ok": m.JSONOK,
			"latency_ms": m.LatencyMS, "chat_rank": m.ChatRank, "fast_rank": m.FastRank,
			"last_error": m.LastError,
		}
		if !m.LastProbe.IsZero() {
			entry["last_probe"] = m.LastProbe
		}
		if until, ok := r.cooldown[m.ID]; ok && until.After(now) {
			entry["cooldown_until"] = until
		}
		if u := r.usage[m.ID]; u != nil {
			entry["requests_today"] = u.Requests
			entry["failures_today"] = u.Failures
			entry["tokens_out_today"] = u.TokensOut
		}
		if r.locked[m.ID] {
			entry["reasoning_locked"] = true
		}
		models = append(models, entry)
	}
	sort.Slice(models, func(i, j int) bool {
		ri, rj := models[i]["chat_rank"].(int), models[j]["chat_rank"].(int)
		if (ri == 0) != (rj == 0) {
			return ri != 0
		}
		if ri != rj {
			return ri < rj
		}
		return models[i]["id"].(string) < models[j]["id"].(string)
	})

	// Usage for models no longer in the catalogue still counts.
	usage := make([]map[string]any, 0, len(r.usage))
	total, free := 0, 0
	for id, u := range r.usage {
		total += u.Requests
		if isFree(id) {
			free += u.Requests
		}
		usage = append(usage, map[string]any{
			"model": id, "requests": u.Requests, "failures": u.Failures,
			"tokens_in": u.TokensIn, "tokens_out": u.TokensOut,
		})
	}
	sort.Slice(usage, func(i, j int) bool { return usage[i]["requests"].(int) > usage[j]["requests"].(int) })

	budget := cfg.FreeDailyBudget
	if budget <= 0 {
		budget = 900
	}
	out := map[string]any{
		"provider":       cfg.Provider,
		"openrouter":     isOpenRouter(cfg),
		"prefer_free":    cfg.PreferFree,
		"auto_discover":  cfg.AutoDiscover,
		"models":         models,
		"chat_chain":     chat,
		"fast_chain":     fast,
		"usage":          usage,
		"requests_today": total,
		"free_today":     free,
		"free_budget":    budget,
		"free_cap":       1000,
		"probing":        r.probing,
		"probe_error":    r.probeErr,
		"day":            r.usageDay,
	}
	if !r.lastProbe.IsZero() {
		out["last_probe"] = r.lastProbe
	}
	return out
}

// ActiveModel is the model a chat request would reach first right now.
func (r *Router) ActiveModel(cfg config.AIConfig) string {
	c := r.Candidates(cfg, familyChat)
	if len(c) == 0 {
		return ""
	}
	return c[0]
}

// FreeRequestsToday is exposed for metrics.
func (r *Router) FreeRequestsToday() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.rolloverLocked()
	return r.freeRequestsTodayLocked()
}
