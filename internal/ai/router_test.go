package ai

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Neoo-Blue/orbis/internal/config"
	"github.com/Neoo-Blue/orbis/internal/store"
)

func testConfig(base string) *config.Config {
	c := config.Default()
	c.AI.Enabled = true
	c.AI.Provider = "openrouter"
	c.AI.BaseURL = base
	c.AI.APIKey = "sk-or-test"
	c.AI.Model = "paid/pinned"
	c.AI.FastModel = "paid/pinned-fast"
	c.AI.PreferFree = true
	c.AI.MaxTokens = 1000
	return c
}

func ptr(b bool) *bool { return &b }

// fakeRouter builds a router with a ready ranking and no store.
func fakeRouter(cfg *config.Config) *Router {
	r := NewRouter(cfg, nil, nil, nil)
	r.models = map[string]*store.AIModel{
		"a/one:free":   {ID: "a/one:free", Free: true, Tools: true, Reasoning: true, ToolOK: ptr(true), JSONOK: ptr(true), LatencyMS: 900, ChatRank: 1, FastRank: 2},
		"b/two:free":   {ID: "b/two:free", Free: true, Tools: true, ToolOK: ptr(true), JSONOK: ptr(true), LatencyMS: 1200, ChatRank: 2, FastRank: 1},
		"c/three:free": {ID: "c/three:free", Free: true, Tools: true, ToolOK: ptr(true), JSONOK: ptr(false), LatencyMS: 300, ChatRank: 3},
	}
	r.rebuildRanksLocked()
	return r
}

func TestCandidatesWalkRankingThenPinned(t *testing.T) {
	cfg := testConfig("http://unused")
	r := fakeRouter(cfg)
	got := r.Candidates(cfg.AI, familyChat)
	want := []string{"a/one:free", "b/two:free", "c/three:free", "paid/pinned"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("chat chain = %v, want %v", got, want)
	}
	got = r.Candidates(cfg.AI, familyFast)
	want = []string{"b/two:free", "a/one:free", "paid/pinned-fast"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("fast chain = %v, want %v", got, want)
	}
}

func TestCandidatesSkipCooldownAndHonourPins(t *testing.T) {
	cfg := testConfig("http://unused")
	r := fakeRouter(cfg)
	r.Report("a/one:free", &ProviderError{Status: 429, Message: "rate-limited upstream"}, nil)
	got := r.Candidates(cfg.AI, familyChat)
	if got[0] != "b/two:free" {
		t.Fatalf("rate-limited model should be skipped, chain = %v", got)
	}
	// A pinned chain wins over the probe ranking.
	cfg.AI.ModelChain = []string{"c/three:free", "a/one:free"}
	got = r.Candidates(cfg.AI, familyChat)
	if got[0] != "c/three:free" || got[len(got)-1] != "paid/pinned" {
		t.Fatalf("pinned chain not honoured: %v", got)
	}
	// Prefer-free off: only the pinned model.
	cfg.AI.PreferFree = false
	if got := r.Candidates(cfg.AI, familyChat); len(got) != 1 || got[0] != "paid/pinned" {
		t.Fatalf("prefer_free=false should give the pinned model only, got %v", got)
	}
}

func TestEverythingCoolingStillOffersBest(t *testing.T) {
	cfg := testConfig("http://unused")
	r := fakeRouter(cfg)
	for _, id := range []string{"a/one:free", "b/two:free", "c/three:free"} {
		r.Report(id, &ProviderError{Status: 502, Message: "bad gateway"}, nil)
	}
	got := r.Candidates(cfg.AI, familyChat)
	if len(got) != 2 || got[0] != "a/one:free" || got[1] != "paid/pinned" {
		t.Fatalf("expected best free + pinned, got %v", got)
	}
}

func TestFreeBudgetExhaustedGoesToPinned(t *testing.T) {
	cfg := testConfig("http://unused")
	cfg.AI.FreeDailyBudget = 3
	r := fakeRouter(cfg)
	for i := 0; i < 3; i++ {
		r.Report("a/one:free", nil, &Response{})
	}
	got := r.Candidates(cfg.AI, familyChat)
	if len(got) != 1 || got[0] != "paid/pinned" {
		t.Fatalf("budget spent should leave only the pinned model, got %v", got)
	}
	// A free pinned model cannot be budget-protected; the chain is offered.
	cfg.AI.Model = "z/free-pin:free"
	if got := r.Candidates(cfg.AI, familyChat); len(got) < 2 {
		t.Fatalf("free pinned model should still get the chain, got %v", got)
	}
}

func TestUsageRollsOverAtMidnightUTC(t *testing.T) {
	cfg := testConfig("http://unused")
	r := fakeRouter(cfg)
	day := time.Date(2026, 9, 5, 23, 59, 0, 0, time.UTC)
	r.now = func() time.Time { return day }
	r.Report("a/one:free", nil, &Response{TokensOut: 10})
	if r.FreeRequestsToday() != 1 {
		t.Fatal("expected one free request today")
	}
	r.now = func() time.Time { return day.Add(2 * time.Minute) }
	if r.FreeRequestsToday() != 0 {
		t.Fatal("usage should reset on the new UTC day")
	}
}

func TestClassify(t *testing.T) {
	cases := []struct {
		err       error
		retriable bool
		cooldown  bool
	}{
		{&ProviderError{Status: 429}, true, true},
		{&ProviderError{Status: 200, Code: 429}, true, true},
		{&ProviderError{Status: 401}, false, false},
		{&ProviderError{Status: 402}, false, false},
		{&ProviderError{Status: 403, Message: "only available on agentic harnesses"}, true, true},
		{&ProviderError{Status: 400, Message: "Reasoning is mandatory"}, true, false},
		{&ProviderError{Status: 200, Message: "empty completion (finish_reason=length)"}, true, true},
		{&ProviderError{Status: 503}, true, true},
		{errors.New("Post: context deadline exceeded"), true, true},
		{context.Canceled, false, false},
	}
	for _, c := range cases {
		d, ok := classify(c.err)
		if ok != c.retriable || (d > 0) != c.cooldown {
			t.Errorf("classify(%v) = (%v, %v), want retriable=%v cooldown=%v", c.err, d, ok, c.retriable, c.cooldown)
		}
	}
}

func TestOptionsHeadroomAndReasoning(t *testing.T) {
	cfg := testConfig("http://unused")
	r := fakeRouter(cfg)
	r.models["a/one:free"].MaxOutput = 5000
	opts := r.options(cfg.AI, "a/one:free", familyFast)
	if !opts.reasoningOff {
		t.Fatal("fast family on a reasoning model should switch reasoning off")
	}
	if opts.maxTokens != 5000 {
		t.Fatalf("headroom should be capped by the model's max output, got %d", opts.maxTokens)
	}
	opts = r.options(cfg.AI, "a/one:free", familyChat)
	if opts.reasoningOff {
		t.Fatal("chat keeps the model's default reasoning")
	}
	r.noteReasoningLocked("a/one:free")
	if r.options(cfg.AI, "a/one:free", familyFast).reasoningOff {
		t.Fatal("a locked model must not be sent reasoning:false again")
	}
	// A model without reasoning support gets the plain budget.
	if got := r.options(cfg.AI, "b/two:free", familyChat).maxTokens; got != 1000 {
		t.Fatalf("plain model budget = %d, want 1000", got)
	}
}

// fakeOpenRouter is just enough of the API for the router: a catalogue, and
// a chat endpoint whose behaviour is scripted per model.
type fakeOpenRouter struct {
	mu      sync.Mutex
	calls   map[string]int
	bodies  []map[string]any
	handler func(model string, body map[string]any) (int, any)
}

func newFake() *fakeOpenRouter { return &fakeOpenRouter{calls: map[string]int{}} }

func (f *fakeOpenRouter) server(t *testing.T) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/models":
			json.NewEncoder(w).Encode(map[string]any{"data": []map[string]any{
				{"id": "busy/one:free", "name": "Busy", "context_length": 100000, "supported_parameters": []string{"tools", "reasoning"}, "architecture": map[string]any{"modality": "text->text"}},
				{"id": "good/two:free", "name": "Good", "context_length": 200000, "supported_parameters": []string{"tools", "reasoning", "response_format"}, "architecture": map[string]any{"modality": "text->text"}, "top_provider": map[string]any{"max_completion_tokens": 8000}},
				{"id": "gated/three:free", "name": "Gated", "context_length": 100000, "supported_parameters": []string{"tools"}, "architecture": map[string]any{"modality": "text->text"}},
				{"id": "notools/four:free", "name": "No tools", "context_length": 100000, "supported_parameters": []string{"temperature"}, "architecture": map[string]any{"modality": "text->text"}},
				{"id": "paid/pinned", "name": "Pinned", "context_length": 100000, "supported_parameters": []string{"tools"}, "architecture": map[string]any{"modality": "text->text"}},
			}})
		case "/chat/completions":
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			model, _ := body["model"].(string)
			f.mu.Lock()
			f.calls[model]++
			f.bodies = append(f.bodies, body)
			f.mu.Unlock()
			status, payload := f.handler(model, body)
			w.WriteHeader(status)
			json.NewEncoder(w).Encode(payload)
		default:
			http.NotFound(w, r)
		}
	}))
}

func okText(model, text string) map[string]any {
	return map[string]any{
		"model":   model,
		"choices": []map[string]any{{"message": map[string]any{"content": text}, "finish_reason": "stop"}},
		"usage":   map[string]any{"prompt_tokens": 10, "completion_tokens": 5},
	}
}

func okToolCall(model, name, args string) map[string]any {
	return map[string]any{
		"model": model,
		"choices": []map[string]any{{"message": map[string]any{
			"content": "",
			"tool_calls": []map[string]any{{"id": "call_1", "type": "function",
				"function": map[string]any{"name": name, "arguments": args}}},
		}, "finish_reason": "tool_calls"}},
		"usage": map[string]any{"prompt_tokens": 10, "completion_tokens": 5},
	}
}

func rateLimited(model string) map[string]any {
	return map[string]any{"error": map[string]any{"message": "Provider returned error", "code": 429,
		"metadata": map[string]any{"raw": model + " is temporarily rate-limited upstream"}}}
}

func TestCompleteFallsThroughRateLimitedModel(t *testing.T) {
	f := newFake()
	f.handler = func(model string, body map[string]any) (int, any) {
		if model == "busy/one:free" {
			return 429, rateLimited(model)
		}
		return 200, okText(model, "hello from "+model)
	}
	srv := f.server(t)
	defer srv.Close()

	cfg := testConfig(srv.URL)
	c := NewClient(cfg, nil, nil)
	c.router.models = map[string]*store.AIModel{
		"busy/one:free": {ID: "busy/one:free", Free: true, Tools: true, ChatRank: 1},
		"good/two:free": {ID: "good/two:free", Free: true, Tools: true, ChatRank: 2},
	}
	c.router.rebuildRanksLocked()

	resp, err := c.Complete(context.Background(), "sys", []Message{{Role: RoleUser, Content: "hi"}}, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Model != "good/two:free" || resp.Attempts != 2 {
		t.Fatalf("expected the second model to answer on attempt 2, got %s attempt %d", resp.Model, resp.Attempts)
	}
	// The busy model is now cooling down and the next call skips it.
	resp, err = c.Complete(context.Background(), "sys", []Message{{Role: RoleUser, Content: "hi"}}, nil, false)
	if err != nil || resp.Attempts != 1 {
		t.Fatalf("second call should skip the cooling model: attempts=%d err=%v", resp.Attempts, err)
	}
	if f.calls["busy/one:free"] != 1 {
		t.Fatalf("busy model should have been tried once, got %d", f.calls["busy/one:free"])
	}
	st := c.router.Status(cfg.AI)
	if st["free_today"].(int) != 3 {
		t.Fatalf("usage should count every attempt, got %v", st["free_today"])
	}
}

func TestCompleteStopsOnAuthFailure(t *testing.T) {
	f := newFake()
	f.handler = func(model string, body map[string]any) (int, any) {
		return 401, map[string]any{"error": map[string]any{"message": "No auth credentials found", "code": 401}}
	}
	srv := f.server(t)
	defer srv.Close()
	cfg := testConfig(srv.URL)
	c := NewClient(cfg, nil, nil)
	c.router.models = map[string]*store.AIModel{
		"busy/one:free": {ID: "busy/one:free", Free: true, Tools: true, ChatRank: 1},
		"good/two:free": {ID: "good/two:free", Free: true, Tools: true, ChatRank: 2},
	}
	c.router.rebuildRanksLocked()
	_, err := c.Complete(context.Background(), "sys", []Message{{Role: RoleUser, Content: "hi"}}, nil, false)
	if err == nil {
		t.Fatal("expected an error")
	}
	if len(f.calls) != 1 {
		t.Fatalf("a bad key must not be retried across models, got calls=%v", f.calls)
	}
}

func TestReasoningLockedRetriesWithoutParameter(t *testing.T) {
	f := newFake()
	f.handler = func(model string, body map[string]any) (int, any) {
		if _, has := body["reasoning"]; has {
			return 400, map[string]any{"error": map[string]any{"message": "Reasoning is mandatory for this endpoint and cannot be disabled.", "code": 400}}
		}
		return 200, okText(model, `[{"domain":"x.com","is_ad_or_tracking":false,"confidence":0.9,"reason":"","breakage_risk":"low"}]`)
	}
	srv := f.server(t)
	defer srv.Close()
	cfg := testConfig(srv.URL)
	c := NewClient(cfg, nil, nil)
	c.router.models = map[string]*store.AIModel{
		"good/two:free": {ID: "good/two:free", Free: true, Tools: true, Reasoning: true, FastRank: 1},
	}
	c.router.rebuildRanksLocked()

	resp, err := c.Complete(context.Background(), judgePrompt, []Message{{Role: RoleUser, Content: "x"}}, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Model != "good/two:free" || f.calls["good/two:free"] != 2 {
		t.Fatalf("expected one retry without reasoning, got calls=%v", f.calls)
	}
	// Second call: no round-trip wasted.
	if _, err := c.Complete(context.Background(), judgePrompt, []Message{{Role: RoleUser, Content: "x"}}, nil, true); err != nil {
		t.Fatal(err)
	}
	if f.calls["good/two:free"] != 3 {
		t.Fatalf("locked model should be called once per request afterwards, got %d", f.calls["good/two:free"])
	}
	if _, has := f.bodies[len(f.bodies)-1]["reasoning"]; has {
		t.Fatal("reasoning parameter still sent after lock")
	}
}

func TestEmptyCompletionMovesOn(t *testing.T) {
	f := newFake()
	f.handler = func(model string, body map[string]any) (int, any) {
		if model == "busy/one:free" {
			return 200, map[string]any{"model": model, "choices": []map[string]any{{"message": map[string]any{"content": ""}, "finish_reason": "length"}}}
		}
		return 200, okText(model, "answer")
	}
	srv := f.server(t)
	defer srv.Close()
	cfg := testConfig(srv.URL)
	c := NewClient(cfg, nil, nil)
	c.router.models = map[string]*store.AIModel{
		"busy/one:free": {ID: "busy/one:free", Free: true, Tools: true, ChatRank: 1},
		"good/two:free": {ID: "good/two:free", Free: true, Tools: true, ChatRank: 2},
	}
	c.router.rebuildRanksLocked()
	resp, err := c.Complete(context.Background(), "sys", []Message{{Role: RoleUser, Content: "hi"}}, nil, false)
	if err != nil || resp.Model != "good/two:free" {
		t.Fatalf("empty completion should fall through: resp=%+v err=%v", resp, err)
	}
}

func TestProbeRanksWhatWorks(t *testing.T) {
	var step int32
	f := newFake()
	f.handler = func(model string, body map[string]any) (int, any) {
		atomic.AddInt32(&step, 1)
		switch model {
		case "busy/one:free":
			return 429, rateLimited(model)
		case "gated/three:free":
			return 403, map[string]any{"error": map[string]any{"message": model + " is only available on agentic harnesses", "code": 403}}
		}
		// good/two:free: tool call on the first chat turn, "3" on the second,
		// and a correct JSON classification.
		msgs, _ := body["messages"].([]any)
		last, _ := msgs[len(msgs)-1].(map[string]any)
		if _, hasTools := body["tools"]; hasTools {
			if last["role"] == "tool" {
				return 200, okText(model, "There are 3 devices online right now.")
			}
			return 200, okToolCall(model, "list_clients", `{"online_only":true}`)
		}
		return 200, okText(model, "```json\n[{\"domain\":\"px.ads-twitter.com\",\"is_ad_or_tracking\":true,\"confidence\":0.95,\"reason\":\"beacon\",\"breakage_risk\":\"low\"},{\"domain\":\"cdn.jsdelivr.net\",\"is_ad_or_tracking\":false,\"confidence\":0.9,\"reason\":\"cdn\",\"breakage_risk\":\"high\"}]\n```")
	}
	srv := f.server(t)
	defer srv.Close()

	cfg := testConfig(srv.URL)
	r := NewRouter(cfg, nil, srv.Client(), nil)
	r.pace = 5 * time.Millisecond // the real pacing exists for the provider, not the test
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if err := r.Probe(ctx); err != nil {
		t.Fatal(err)
	}
	st := r.Status(cfg.AI)
	chain := st["chat_chain"].([]string)
	if len(chain) < 2 || chain[0] != "good/two:free" {
		t.Fatalf("chat chain = %v, want good/two:free first", chain)
	}
	fast := st["fast_chain"].([]string)
	if fast[0] != "good/two:free" {
		t.Fatalf("fast chain = %v", fast)
	}
	m := r.models["gated/three:free"]
	if m.ToolOK == nil || *m.ToolOK || m.ChatRank != 0 || !strings.Contains(m.LastError, "403") {
		t.Fatalf("gated model should be ranked out with its 403 recorded: %+v", m)
	}
	if m := r.models["busy/one:free"]; m.ToolOK != nil {
		t.Fatalf("a rate-limited probe must not record a verdict: %+v", m)
	}
	if _, ok := r.models["notools/four:free"]; !ok {
		t.Fatal("catalogue entries without tools are kept for display")
	}
	if r.models["notools/four:free"].ChatRank != 0 {
		t.Fatal("a model without tools cannot be ranked for chat")
	}
	if f.calls["notools/four:free"] != 0 {
		t.Fatal("models without tool support must not be probed")
	}
}

func TestProviderErrorTextIncludesUpstreamRaw(t *testing.T) {
	b := &providerErrorBody{Message: "Provider returned error", Code: json.RawMessage(`429`)}
	b.Metadata.Raw = "x:free is temporarily rate-limited upstream. Please retry shortly"
	if b.code() != 429 || !strings.Contains(b.text(), "rate-limited upstream") {
		t.Fatalf("code=%d text=%q", b.code(), b.text())
	}
	s := &providerErrorBody{Message: "nope", Code: json.RawMessage(`"402"`)}
	if s.code() != 402 {
		t.Fatalf("string code should parse, got %d", s.code())
	}
}

func TestCompleteJSONFallsOverOnBadOutput(t *testing.T) {
	f := newFake()
	f.handler = func(model string, body map[string]any) (int, any) {
		if _, has := body["reasoning"]; !has {
			t.Errorf("structured call to %s should switch reasoning off", model)
		}
		if model == "busy/one:free" {
			return 200, okText(model, "Here's a thinking process: first I will consider the network...")
		}
		return 200, okText(model, `{"headline":"Quiet","severity":"info","body":"- nothing"}`)
	}
	srv := f.server(t)
	defer srv.Close()
	cfg := testConfig(srv.URL)
	c := NewClient(cfg, nil, nil)
	c.router.models = map[string]*store.AIModel{
		"busy/one:free": {ID: "busy/one:free", Free: true, Tools: true, Reasoning: true, ChatRank: 1},
		"good/two:free": {ID: "good/two:free", Free: true, Tools: true, Reasoning: true, ChatRank: 2},
	}
	c.router.rebuildRanksLocked()
	resp, err := c.CompleteJSON(context.Background(), "sys", []Message{{Role: RoleUser, Content: "x"}}, false,
		func(text string) error {
			var out map[string]any
			return parseJSONObject(text, &out)
		})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Model != "good/two:free" || resp.Attempts != 2 {
		t.Fatalf("non-JSON output should fail over: model=%s attempts=%d", resp.Model, resp.Attempts)
	}
	if got := c.router.Candidates(cfg.AI, familyChat)[0]; got != "good/two:free" {
		t.Fatalf("the model that returned prose should be cooling down, chain starts with %s", got)
	}
}
