// Package ai provides the assistant: a chat interface that can actually
// inspect and change the firewall, a classifier for ambiguous ad domains, and
// a background analyser that looks for behaviour worth waking someone up for.
//
// Two provider shapes are supported — Anthropic's Messages API and the
// OpenAI-compatible chat-completions shape used by OpenAI, OpenRouter and
// Ollama — because an operator running this on their own hardware should not
// be forced to send their network's traffic metadata to a specific vendor.
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
}

type Client struct {
	cfg  *config.Config
	http *http.Client
}

func NewClient(cfg *config.Config) *Client {
	return &Client{
		cfg: cfg,
		http: &http.Client{
			// Long enough for a slow local model, short enough that a hung
			// provider does not wedge a background sweep forever.
			Timeout: 180 * time.Second,
		},
	}
}

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

// Complete runs one model turn.
func (c *Client) Complete(ctx context.Context, system string, msgs []Message, tools []ToolDef, useFast bool) (*Response, error) {
	cfg := c.cfg.Snapshot().AI
	if !cfg.Enabled {
		return nil, fmt.Errorf("AI is disabled in configuration")
	}
	model := cfg.Model
	if useFast && cfg.FastModel != "" {
		model = cfg.FastModel
	}
	if model == "" {
		return nil, fmt.Errorf("no model configured")
	}

	switch strings.ToLower(cfg.Provider) {
	case "", "anthropic":
		return c.completeAnthropic(ctx, cfg, model, system, msgs, tools)
	default:
		return c.completeOpenAI(ctx, cfg, model, system, msgs, tools)
	}
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
		return nil, fmt.Errorf("%s: %s", parsed.Error.Type, parsed.Error.Message)
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

func (c *Client) completeOpenAI(ctx context.Context, cfg config.AIConfig, model, system string, msgs []Message, tools []ToolDef) (*Response, error) {
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
			apiMsgs = append(apiMsgs, entry)
		default:
			apiMsgs = append(apiMsgs, map[string]any{"role": "user", "content": m.Content})
		}
	}

	body := map[string]any{
		"model":      model,
		"messages":   apiMsgs,
		"max_tokens": orDefault(cfg.MaxTokens, 4096),
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
		Error *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	if parsed.Error != nil {
		return nil, fmt.Errorf("%s", parsed.Error.Message)
	}
	if len(parsed.Choices) == 0 {
		return nil, fmt.Errorf("model returned no choices")
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
	return out, nil
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
		if len(msg) > 500 {
			msg = msg[:500]
		}
		return nil, fmt.Errorf("provider returned %d: %s", resp.StatusCode, msg)
	}
	return raw, nil
}

func orDefault(v, def int) int {
	if v <= 0 {
		return def
	}
	return v
}
