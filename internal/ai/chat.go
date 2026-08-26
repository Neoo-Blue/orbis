package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/Neoo-Blue/orbis/internal/config"
	"github.com/Neoo-Blue/orbis/internal/store"
	"github.com/google/uuid"
)

// Assistant runs the chat loop: model turn, tool calls, tool results, repeat
// until the model produces a final answer.
type Assistant struct {
	client  *Client
	backend Backend
	st      *store.Store
	cfg     *config.Config
	log     func(string, ...any)
}

func NewAssistant(cfg *config.Config, client *Client, backend Backend, st *store.Store, log func(string, ...any)) *Assistant {
	if log == nil {
		log = func(string, ...any) {}
	}
	return &Assistant{client: client, backend: backend, st: st, cfg: cfg, log: log}
}

// Turn is one step of the loop, streamed to the UI so the operator can watch
// the assistant work rather than staring at a spinner.
type Turn struct {
	Kind    string `json:"kind"` // "text" | "tool_call" | "tool_result" | "error" | "done"
	Text    string `json:"text,omitempty"`
	Tool    string `json:"tool,omitempty"`
	Input   any    `json:"input,omitempty"`
	Result  string `json:"result,omitempty"`
	IsError bool   `json:"is_error,omitempty"`
}

const systemPrompt = `You are the assistant built into Orbis, a network firewall and traffic
analysis appliance. You are talking to the person who administers this network, in their own
firewall's UI.

What you are looking at:
- Orbis sits on the network watching connections. It resolves DNS, blocks ads and trackers,
  runs a stateful firewall, hands out DHCP leases, and can run WireGuard in both directions.
- "observe" mode means Orbis watches but does not route or enforce. "inline" mode means it is
  a real gateway. Check system_status before claiming something is or is not being enforced —
  in observe mode a "block" verdict means "would have blocked".
- Every device is a "client" with a stable id. Connections are "flows".

How to work:
- Reach for tools rather than guessing. If you are asked why something is slow, or who a device
  is talking to, go look. Several tool calls in a row to build a picture is normal and expected.
- Answer at the altitude the question was asked. "Is anything weird happening?" wants a short
  read on the network, not a table of every connection. "What did the TV do last night?" wants
  specifics.
- Give real numbers. "142 connections to 3 hosts in Ireland, 2.1 GB" beats "quite a lot of
  traffic".
- When something looks suspicious, say what it is and what would confirm or rule it out. Do not
  manufacture alarm; most unexpected traffic is a CDN or a telemetry endpoint, and saying so is
  more useful than a warning.

Making changes:
- Making a change is what you are here for; do it when asked. Explain what you changed in one
  line afterwards.
- Firewall rule changes are not live until apply_firewall runs. Call it after any rule change,
  in the same turn, unless the operator asked you to stage the change.
- Blocking a domain or a device affects real people using this network right now. For anything
  broad — a whole TLD, a device someone is actively using, a rule that could cut off the
  network — say what you are about to do and let the operator confirm, rather than acting first.
- If write access is off, the mutating tools are not available to you. Explain what you would
  change and where to click, instead of pretending you cannot help.

Formatting: plain prose and short lists. Markdown tables only when comparing several things
across the same columns. No preamble, no restating the question.`

// Ask runs a full turn, emitting incremental updates through onTurn.
func (a *Assistant) Ask(ctx context.Context, conversationID, userMessage, actor string, onTurn func(Turn)) error {
	if !a.client.Configured() {
		return fmt.Errorf("the assistant is not configured — add a provider and API key in Settings → AI")
	}
	emit := func(t Turn) {
		if onTurn != nil {
			onTurn(t)
		}
	}

	history, err := a.st.ChatHistory(conversationID, 40)
	if err != nil {
		return err
	}
	msgs := rehydrate(history)
	msgs = append(msgs, Message{Role: RoleUser, Content: userMessage})

	if err := a.st.SaveChatMessage(store.ChatMessage{
		ID: uuid.NewString(), Conversation: conversationID, TS: time.Now(),
		Role: string(RoleUser), Content: userMessage,
	}); err != nil {
		return err
	}

	allowWrite := a.cfg.Snapshot().AI.AllowWrite
	tools := Tools(allowWrite)
	system := systemPrompt + "\n\n" + a.contextBlock(allowWrite)

	// Bounded: a model that keeps calling tools without converging should
	// stop and say so rather than run up a bill.
	const maxIterations = 12
	for i := 0; i < maxIterations; i++ {
		resp, err := a.client.Complete(ctx, system, msgs, tools, false)
		if err != nil {
			emit(Turn{Kind: "error", Text: err.Error()})
			return err
		}

		if resp.Text != "" {
			emit(Turn{Kind: "text", Text: resp.Text})
		}

		if len(resp.ToolCalls) == 0 {
			return a.st.SaveChatMessage(store.ChatMessage{
				ID: uuid.NewString(), Conversation: conversationID, TS: time.Now(),
				Role: string(RoleAssistant), Content: resp.Text, Model: resp.Model,
				TokensIn: resp.TokensIn, TokensOut: resp.TokensOut,
			})
		}

		callsJSON, _ := json.Marshal(resp.ToolCalls)
		if err := a.st.SaveChatMessage(store.ChatMessage{
			ID: uuid.NewString(), Conversation: conversationID, TS: time.Now(),
			Role: string(RoleAssistant), Content: resp.Text, ToolCalls: string(callsJSON),
			Model: resp.Model, TokensIn: resp.TokensIn, TokensOut: resp.TokensOut,
		}); err != nil {
			return err
		}
		msgs = append(msgs, Message{Role: RoleAssistant, Content: resp.Text, ToolCalls: resp.ToolCalls})

		for _, call := range resp.ToolCalls {
			var input any
			_ = json.Unmarshal(call.Input, &input)
			emit(Turn{Kind: "tool_call", Tool: call.Name, Input: input})

			result, execErr := Execute(ctx, a.backend, call, allowWrite, actor)
			isErr := execErr != nil
			if isErr {
				result = "Error: " + execErr.Error()
			}
			a.st.Audit(actor+" (assistant)", "tool:"+call.Name, "", string(call.Input),
				truncate(result, 500), resultWord(isErr))

			emit(Turn{Kind: "tool_result", Tool: call.Name, Result: truncate(result, 2000), IsError: isErr})

			_ = a.st.SaveChatMessage(store.ChatMessage{
				ID: uuid.NewString(), Conversation: conversationID, TS: time.Now(),
				Role: string(RoleTool), Content: result, ToolResult: call.Name,
			})
			msgs = append(msgs, Message{
				Role: RoleTool, ToolCallID: call.ID, Name: call.Name,
				Content: result, IsError: isErr,
			})
		}
	}

	msg := "I ran out of steps working on that. Ask me for a narrower slice and I will get there."
	emit(Turn{Kind: "text", Text: msg})
	return a.st.SaveChatMessage(store.ChatMessage{
		ID: uuid.NewString(), Conversation: conversationID, TS: time.Now(),
		Role: string(RoleAssistant), Content: msg,
	})
}

// contextBlock gives the model the current state up front, so simple
// questions ("what mode am I in") do not cost a tool round-trip.
func (a *Assistant) contextBlock(allowWrite bool) string {
	cfg := a.cfg.Snapshot()
	var b strings.Builder
	b.WriteString("Current node state:\n")
	fmt.Fprintf(&b, "- Mode: %s\n", cfg.Mode)
	fmt.Fprintf(&b, "- Time now: %s\n", time.Now().Format(time.RFC3339))
	fmt.Fprintf(&b, "- Subsystems: dns=%v adblock=%v smart_capture=%v filter_proxy=%v firewall=%v dhcp=%v vpn_server=%v\n",
		cfg.DNS.Enabled, cfg.AdBlock.Enabled, cfg.AdBlock.SmartCapture.Enabled,
		cfg.MITM.Enabled, cfg.Firewall.Enabled, cfg.DHCP.Enabled, cfg.VPN.Server.Enabled)
	if allowWrite {
		b.WriteString("- You have write access: mutating tools will take effect on the live network.\n")
	} else {
		b.WriteString("- Write access is OFF: you can inspect but not change anything. Say what should change and where.\n")
	}
	if cfg.Mode != config.ModeInline {
		b.WriteString("- Note: in observe mode, block verdicts are recorded but not enforced on traffic that does not pass through this node.\n")
	}
	if len(cfg.Firewall.Zones) > 0 {
		b.WriteString("- Zones: ")
		names := make([]string, 0, len(cfg.Firewall.Zones))
		for _, z := range cfg.Firewall.Zones {
			names = append(names, fmt.Sprintf("%s(%s)", z.Name, z.Trust))
		}
		b.WriteString(strings.Join(names, ", ") + "\n")
	}
	return b.String()
}

// rehydrate turns persisted rows back into a provider-neutral history.
func rehydrate(history []store.ChatMessage) []Message {
	out := make([]Message, 0, len(history))
	for _, h := range history {
		m := Message{Role: Role(h.Role), Content: h.Content}
		if h.ToolCalls != "" {
			var calls []ToolCall
			if err := json.Unmarshal([]byte(h.ToolCalls), &calls); err == nil {
				m.ToolCalls = calls
			}
		}
		if h.Role == string(RoleTool) {
			m.Name = h.ToolResult
			// The tool_call_id is recoverable from the preceding assistant
			// turn; providers that require it are matched by position.
			if len(out) > 0 {
				prev := out[len(out)-1]
				for _, c := range prev.ToolCalls {
					if c.Name == h.ToolResult {
						m.ToolCallID = c.ID
						break
					}
				}
			}
		}
		out = append(out, m)
	}
	return out
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func resultWord(isErr bool) string {
	if isErr {
		return "error"
	}
	return "ok"
}
