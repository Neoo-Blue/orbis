// Package ai provides the assistant: a chat interface that can actually
// inspect and change the firewall, a classifier for ambiguous ad domains, a
// background analyser that looks for behaviour worth waking someone up for,
// and a periodic brief that says what happened while nobody was looking.
//
// Two provider shapes are supported — Anthropic's Messages API and the
// OpenAI-compatible chat-completions shape used by OpenAI, OpenRouter and
// Ollama — because an operator running this on their own hardware should not
// be forced to send their network's traffic metadata to a specific vendor.
//
// On OpenRouter the client routes through free models by preference (see
// router.go): the catalogue is probed on a timer, ranked, and walked at call
// time with per-model cooldowns, so a busy or withdrawn free model costs one
// failed attempt rather than a broken assistant.
package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/Neoo-Blue/orbis/internal/config"
	"github.com/Neoo-Blue/orbis/internal/store"
)

type Role string

const (
	RoleUser      Role = "user"
	RoleAssistant Role = "assistant"
	RoleSystem    Role = "system"
	RoleTool      Role = "tool"
)

// Message is the provider-neutral conversation unit.
type Message struct {
	Role    Role   `json:"role"`
	Content string `json:"content"`
	// ToolCalls is set on assistant turns that want to invoke tools.
	ToolCalls []ToolCall `json:"tool_calls,omitempty"`
	// ToolCallID / Name are set on tool-result turns.
	ToolCallID string `json:"tool_call_id,omitempty"`
	Name       string `json:"name,omitempty"`
	IsError    bool   `json:"is_error,omitempty"`
}

type ToolCall struct {
	ID    string          `json:"id"`
	Name  string          `json:"name"`
	Input json.RawMessage `json:"input"`
}

// ToolDef describes a callable tool to the model.
type ToolDef struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Schema      map[string]any `json:"input_schema"`
	// Mutating tools are withheld entirely when write access is off, rather
	// than being offered and then refused — a model that is told it can do
	// something and then blocked produces a worse conversation than one that
	// was never offered the capability.
	Mutating bool `json:"-"`
}

type Response struct {
	Text       string
	ToolCalls  []ToolCall
	StopReason string
	TokensIn   int
	TokensOut  int
	Model      string
	// Attempts is how many models were tried before this one answered.
	Attempts int
}

type Client struct {
	cfg    *config.Config
	http   *http.Client
	router *Router
	log    func(string, ...any)
}

// NewClient builds the client and its router. The store may be nil (tests);
// the ranking and usage counters then live only in memory.
func NewClient(cfg *config.Config, st *store.Store, log func(string, ...any)) *Client {
	if log == nil {
		log = func(string, ...any) {}
	}
	httpc := &http.Client{
		// Long enough for a slow local model, short enough that a hung
		// provider does not wedge a background sweep forever.
		Timeout: 180 * time.Second,
	}
	c := &Client{cfg: cfg, http: httpc, log: log}
	c.router = NewRouter(cfg, st, httpc, log)
	return c
}

// Router exposes the model router for the API and metrics.
func (c *Client) Router() *Router { return c.router }

func (c *Client) Configured() bool {
	cfg := c.cfg.Snapshot().AI
	if !cfg.Enabled {
		return false
	}
	if cfg.Provider == "ollama" {
		return cfg.BaseURL != ""
	}
	return cfg.APIKey != "" || cfg.BaseURL != ""
}

// Complete runs one model turn, walking the router's candidate list until a
// model answers. A failure that is the same for every model (bad key, no
// credit, caller went away) stops the walk immediately.
func (c *Client) Complete(ctx context.Context, system string, msgs []Message, tools []ToolDef, useFast bool) (*Response, error) {
	return c.complete(ctx, system, msgs, tools, useFast, false, nil)
}

// CompleteJSON is Complete for callers that need machine-readable output.
// Reasoning is switched off where the model allows it (several free models
// otherwise leak their chain of thought into the content and spend the whole
// budget on it), and an answer that fails validate counts as a failed attempt
// so the next candidate gets a turn instead of the caller getting garbage.
func (c *Client) CompleteJSON(ctx context.Context, system string, msgs []Message, useFast bool, validate func(text string) error) (*Response, error) {
	return c.complete(ctx, system, msgs, nil, useFast, true, validate)
}

func (c *Client) complete(ctx context.Context, system string, msgs []Message, tools []ToolDef, useFast, structured bool, validate func(string) error) (*Response, error) {
	cfg := c.cfg.Snapshot().AI
	if !cfg.Enabled {
		return nil, fmt.Errorf("AI is disabled in configuration")
	}
	fam := familyChat
	if useFast {
		fam = familyFast
	}
	candidates := c.router.Candidates(cfg, fam)
	if len(candidates) == 0 {
		return nil, fmt.Errorf("no model configured")
	}

	var lastErr error
	for i, model := range candidates {
		resp, err := c.completeOnce(ctx, cfg, model, fam, structured, system, msgs, tools)
		if err == nil && validate != nil {
			if verr := validate(resp.Text); verr != nil {
				err = &ProviderError{Status: 200, Message: "output was not the expected JSON: " + trimErr(verr.Error())}
				resp = nil
			}
		}
		c.router.Report(model, err, resp)
		if err == nil {
			if resp.Model == "" {
				resp.Model = model
			}
			resp.Attempts = i + 1
			return resp, nil
		}
		lastErr = err
		if ctx.Err() != nil {
			return nil, err
		}
		if _, retriable := classify(err); !retriable {
			return nil, err
		}
		if i+1 < len(candidates) {
			c.log("ai: %s: %s; trying %s", model, trimErr(err.Error()), candidates[i+1])
		}
	}
	if len(candidates) > 1 {
		return nil, fmt.Errorf("all %d models failed, last (%s): %w", len(candidates), candidates[len(candidates)-1], lastErr)
	}
	return nil, lastErr
}

// completeOnce sends one request to one model. structured asks for reasoning
// to be switched off regardless of family, for callers that parse the output.
func (c *Client) completeOnce(ctx context.Context, cfg config.AIConfig, model string, fam family, structured bool, system string, msgs []Message, tools []ToolDef) (*Response, error) {
	if model == "" {
		return nil, fmt.Errorf("no model configured")
	}
	switch strings.ToLower(cfg.Provider) {
	case "", "anthropic":
		return c.completeAnthropic(ctx, cfg, model, system, msgs, tools)
	default:
		opts := requestOptions{maxTokens: orDefault(cfg.MaxTokens, 4096)}
		if c.router != nil {
			opts = c.router.options(cfg, model, fam)
			if structured && !c.router.isLocked(model) && isOpenRouter(cfg) {
				opts.reasoningOff = true
			}
		}
		resp, err := c.completeOpenAI(ctx, cfg, model, opts, system, msgs, tools)
		if err != nil && opts.reasoningOff && isReasoningLocked(err) {
			// The model insists on thinking. Remember that and ask again
			// plainly; this costs one round-trip once, not on every call.
			if c.router != nil {
				c.router.noteReasoningLocked(model)
			}
			opts.reasoningOff = false
			return c.completeOpenAI(ctx, cfg, model, opts, system, msgs, tools)
		}
		return resp, err
	}
}

func isReasoningLocked(err error) bool {
	pe, ok := err.(*ProviderError)
	if !ok || pe.status() != 400 {
		return false
	}
	m := strings.ToLower(pe.Message)
	return strings.Contains(m, "reasoning")
}

// ---- Anthropic ----

func (c *Client) completeAnthropic(ctx context.Context, cfg config.AIConfig, model, system string, msgs []Message, tools []ToolDef) (*Response, error) {
	base := cfg.BaseURL
	if base == "" {
		base = "https://api.anthropic.com"
	}
	type content map[string]any
	body := map[string]any{
		"model":      model,
		"max_tokens": orDefault(cfg.MaxTokens, 4096),
	}
	if system != "" {
		body["system"] = system
	}

	apiMsgs := make([]map[string]any, 0, len(msgs))
	for _, m := range msgs {
		switch m.Role {
		case RoleTool:
			// Anthropic carries tool results as a user turn containing a
			// tool_result block, not a distinct role.
			apiMsgs = append(apiMsgs, map[string]any{
				"role": "user",
				"content": []content{{
					"type":        "tool_result",
					"tool_use_id": m.ToolCallID,
					"content":     m.Content,
					"is_error":    m.IsError,
				}},
			})
		case RoleAssistant:
			blocks := []content{}
			if m.Content != "" {
				blocks = append(blocks, content{"type": "text", "text": m.Content})
			}
			for _, tc := range m.ToolCalls {
				var input any
				_ = json.Unmarshal(tc.Input, &input)
				if input == nil {
					input = map[string]any{}
				}
				blocks = append(blocks, content{
					"type": "tool_use", "id": tc.ID, "name": tc.Name, "input": input,
				})
			}
			if len(blocks) == 0 {
				continue
			}
			apiMsgs = append(apiMsgs, map[string]any{"role": "assistant", "content": blocks})
		default:
			apiMsgs = append(apiMsgs, map[string]any{"role": "user", "content": m.Content})
		}
	}
	body["messages"] = apiMsgs

	if len(tools) > 0 {
		apiTools := make([]map[string]any, 0, len(tools))
		for _, t := range tools {
			apiTools = append(apiTools, map[string]any{
				"name": t.Name, "description": t.Description, "input_schema": t.Schema,
			})
		}
		body["tools"] = apiTools
	}

	raw, err := c.post(ctx, strings.TrimSuffix(base, "/")+"/v1/messages", body, map[string]string{
		"x-api-key":         cfg.APIKey,
		"anthropic-version": "2023-06-01",
	})
	if err != nil {
		return nil, err
	}

	var parsed struct {
		Content []struct {
			Type  string          `json:"type"`
			Text  string          `json:"text"`
			ID    string          `json:"id"`
			Name  string          `json:"name"`
			Input json.RawMessage `json:"input"`
		} `json:"content"`
		StopReason string `json:"stop_reason"`
		Model      string `json:"model"`
		Usage      struct {
			InputTokens  int `json:"input_tokens"`
			OutputTokens int `json:"output_tokens"`
		} `json:"usage"`
		Error *struct {
			Type    string `json:"type"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	if parsed.Error != nil {
		return nil, &ProviderError{Status: 200, Message: parsed.Error.Type + ": " + parsed.Error.Message}
	}

	out := &Response{
		StopReason: parsed.StopReason,
		Model:      parsed.Model,
		TokensIn:   parsed.Usage.InputTokens,
		TokensOut:  parsed.Usage.OutputTokens,
	}
	var textParts []string
	for _, blk := range parsed.Content {
		switch blk.Type {
		case "text":
			textParts = append(textParts, blk.Text)
		case "tool_use":
			out.ToolCalls = append(out.ToolCalls, ToolCall{ID: blk.ID, Name: blk.Name, Input: blk.Input})
		}
	}
	out.Text = strings.Join(textParts, "\n")
	return out, nil
}

// ---- OpenAI-compatible ----

func (c *Client) completeOpenAI(ctx context.Context, cfg config.AIConfig, model string, opts requestOptions, system string, msgs []Message, tools []ToolDef) (*Response, error) {
	base := cfg.BaseURL
	if base == "" {
		switch strings.ToLower(cfg.Provider) {
		case "openrouter":
			base = "https://openrouter.ai/api/v1"
		case "ollama":
			base = "http://127.0.0.1:11434/v1"
		default:
			base = "https://api.openai.com/v1"
		}
	}

	apiMsgs := make([]map[string]any, 0, len(msgs)+1)
	if system != "" {
		apiMsgs = append(apiMsgs, map[string]any{"role": "system", "content": system})
	}
	for _, m := range msgs {
		switch m.Role {
		case RoleTool:
			apiMsgs = append(apiMsgs, map[string]any{
				"role": "tool", "tool_call_id": m.ToolCallID, "content": m.Content,
			})
		case RoleAssistant:
			entry := map[string]any{"role": "assistant"}
			if m.Content != "" {
				entry["content"] = m.Content
			}
			if len(m.ToolCalls) > 0 {
				calls := make([]map[string]any, 0, len(m.ToolCalls))
				for _, tc := range m.ToolCalls {
					calls = append(calls, map[string]any{
						"id": tc.ID, "type": "function",
						"function": map[string]any{"name": tc.Name, "arguments": string(tc.Input)},
					})
				}
				entry["tool_calls"] = calls
			}
			if entry["content"] == nil && len(m.ToolCalls) == 0 {
				continue
			}
			apiMsgs = append(apiMsgs, entry)
		default:
			apiMsgs = append(apiMsgs, map[string]any{"role": "user", "content": m.Content})
		}
	}

	maxTokens := opts.maxTokens
	if maxTokens <= 0 {
		maxTokens = orDefault(cfg.MaxTokens, 4096)
	}
	body := map[string]any{
		"model":      model,
		"messages":   apiMsgs,
		"max_tokens": maxTokens,
	}
	if opts.reasoningOff {
		body["reasoning"] = map[string]any{"enabled": false}
	}
	if len(tools) > 0 {
		apiTools := make([]map[string]any, 0, len(tools))
		for _, t := range tools {
			apiTools = append(apiTools, map[string]any{
				"type": "function",
				"function": map[string]any{
					"name": t.Name, "description": t.Description, "parameters": t.Schema,
				},
			})
		}
		body["tools"] = apiTools
	}

	headers := map[string]string{}
	if cfg.APIKey != "" {
		headers["Authorization"] = "Bearer " + cfg.APIKey
	}
	if strings.Contains(base, "openrouter") {
		headers["HTTP-Referer"] = "https://github.com/Neoo-Blue/orbis"
		headers["X-Title"] = "Orbis"
	}

	raw, err := c.post(ctx, strings.TrimSuffix(base, "/")+"/chat/completions", body, headers)
	if err != nil {
		return nil, err
	}

	var parsed struct {
		Choices []struct {
			Message struct {
				Content   string `json:"content"`
				ToolCalls []struct {
					ID       string `json:"id"`
					Function struct {
						Name      string `json:"name"`
						Arguments string `json:"arguments"`
					} `json:"function"`
				} `json:"tool_calls"`
			} `json:"message"`
			FinishReason string `json:"finish_reason"`
		} `json:"choices"`
		Model string `json:"model"`
		Usage struct {
			PromptTokens     int `json:"prompt_tokens"`
			CompletionTokens int `json:"completion_tokens"`
		} `json:"usage"`
		Error *providerErrorBody `json:"error"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	if parsed.Error != nil {
		// OpenRouter delivers upstream failures inside an HTTP 200 body.
		// Surface the upstream code so the router can tell a rate limit
		// from a broken model.
		return nil, &ProviderError{Status: 200, Code: parsed.Error.code(), Message: parsed.Error.text()}
	}
	if len(parsed.Choices) == 0 {
		return nil, &ProviderError{Status: 200, Message: "model returned no choices"}
	}
	choice := parsed.Choices[0]
	out := &Response{
		Text:       choice.Message.Content,
		StopReason: choice.FinishReason,
		Model:      parsed.Model,
		TokensIn:   parsed.Usage.PromptTokens,
		TokensOut:  parsed.Usage.CompletionTokens,
	}
	for _, tc := range choice.Message.ToolCalls {
		args := tc.Function.Arguments
		if args == "" {
			args = "{}"
		}
		out.ToolCalls = append(out.ToolCalls, ToolCall{
			ID: tc.ID, Name: tc.Function.Name, Input: json.RawMessage(args),
		})
	}
	if len(out.ToolCalls) == 0 && strings.TrimSpace(out.Text) == "" {
		// A reasoning model that spent the whole budget thinking, or a
		// provider hiccup. Either way there is nothing to show; the next
		// candidate gets a turn.
		return nil, &ProviderError{Status: 200, Message: fmt.Sprintf("empty completion (finish_reason=%s)", orDefaultStr(choice.FinishReason, "unknown"))}
	}
	return out, nil
}

// providerErrorBody is the error object OpenAI-shaped providers return. The
// code arrives as a number from OpenRouter and as a string from others.
type providerErrorBody struct {
	Message  string          `json:"message"`
	Code     json.RawMessage `json:"code"`
	Metadata struct {
		Raw          string `json:"raw"`
		ProviderName string `json:"provider_name"`
	} `json:"metadata"`
}

func (e *providerErrorBody) code() int {
	if len(e.Code) == 0 {
		return 0
	}
	var n int
	if err := json.Unmarshal(e.Code, &n); err == nil {
		return n
	}
	var s string
	if err := json.Unmarshal(e.Code, &s); err == nil {
		fmt.Sscanf(s, "%d", &n)
	}
	return n
}

func (e *providerErrorBody) text() string {
	msg := strings.TrimSpace(e.Message)
	if raw := strings.TrimSpace(e.Metadata.Raw); raw != "" && !strings.Contains(msg, raw) {
		// "Provider returned error" alone says nothing; the raw upstream
		// text ("temporarily rate-limited upstream") is the useful part.
		if len(raw) > 200 {
			raw = raw[:200] + "…"
		}
		msg = msg + " (" + raw + ")"
	}
	if msg == "" {
		msg = "unknown provider error"
	}
	return msg
}

func (c *Client) post(ctx context.Context, url string, body any, headers map[string]string) ([]byte, error) {
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		if v != "" {
			req.Header.Set(k, v)
		}
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		// Surface the provider's own message: "insufficient credit" and
		// "model not found" need different fixes and a generic 4xx hides that.
		msg := strings.TrimSpace(string(raw))
		var wrapped struct {
			Error *providerErrorBody `json:"error"`
		}
		code := 0
		if json.Unmarshal(raw, &wrapped) == nil && wrapped.Error != nil {
			msg = wrapped.Error.text()
			code = wrapped.Error.code()
		}
		if len(msg) > 500 {
			msg = msg[:500]
		}
		return nil, &ProviderError{Status: resp.StatusCode, Code: code, Message: msg}
	}
	return raw, nil
}

func orDefault(v, def int) int {
	if v <= 0 {
		return def
	}
	return v
}

func orDefaultStr(v, def string) string {
	if v == "" {
		return def
	}
	return v
}
