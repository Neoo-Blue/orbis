// Package mcp exposes Orbis over the Model Context Protocol, so an assistant
// running outside the node can inspect the network and, when permitted, change
// it.
//
// The tools are not defined here. They are the same catalogue the built-in
// assistant uses, executed through the same Backend, because two independently
// maintained tool surfaces drift: the copy that is used less gets stale
// descriptions, loses a parameter, and eventually lies about what it does. This
// package is a transport, nothing more.
package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sync"

	"github.com/Neoo-Blue/orbis/internal/ai"
)

// protocolVersion is the MCP revision this server implements.
const protocolVersion = "2025-06-18"

// Server speaks JSON-RPC 2.0 over a byte stream, newline-delimited.
type Server struct {
	backend    ai.Backend
	allowWrite bool
	log        func(string, ...any)

	// writeMu serialises responses. Notifications can be emitted from other
	// goroutines, and two interleaved writes produce a stream no client can
	// parse.
	writeMu sync.Mutex
	out     io.Writer
}

func New(backend ai.Backend, allowWrite bool, log func(string, ...any)) *Server {
	if log == nil {
		log = func(string, ...any) {}
	}
	return &Server{backend: backend, allowWrite: allowWrite, log: log}
}

// ---- JSON-RPC envelopes ----

type request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

const (
	codeParseError     = -32700
	codeInvalidRequest = -32600
	codeMethodNotFound = -32601
	codeInvalidParams  = -32602
	codeInternalError  = -32603
)

// Serve reads requests until the stream closes.
func (s *Server) Serve(ctx context.Context, in io.Reader, out io.Writer) error {
	s.out = out
	sc := bufio.NewScanner(in)
	// Tool results can be large (a flow dump, a DNS log); the default 64KB
	// token limit would truncate a request mid-object.
	sc.Buffer(make([]byte, 0, 64*1024), 8<<20)

	for sc.Scan() {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var req request
		if err := json.Unmarshal(line, &req); err != nil {
			s.send(response{JSONRPC: "2.0", Error: &rpcError{codeParseError, "invalid JSON"}})
			continue
		}
		s.dispatch(ctx, req)
	}
	return sc.Err()
}

func (s *Server) dispatch(ctx context.Context, req request) {
	// A request without an id is a notification: the protocol forbids
	// answering it, and clients send "notifications/initialized" routinely.
	notification := len(req.ID) == 0

	switch req.Method {
	case "initialize":
		s.reply(req, map[string]any{
			"protocolVersion": protocolVersion,
			"capabilities": map[string]any{
				// Tools are fixed for the life of the process, so no
				// listChanged subscription is offered.
				"tools": map[string]any{"listChanged": false},
			},
			"serverInfo": map[string]any{
				"name":    "orbis",
				"version": Version,
			},
			"instructions": instructions(s.allowWrite),
		})

	case "notifications/initialized", "notifications/cancelled":
		// Nothing to do, and nothing to answer.

	case "ping":
		s.reply(req, map[string]any{})

	case "tools/list":
		s.reply(req, map[string]any{"tools": s.toolList()})

	case "tools/call":
		s.callTool(ctx, req)

	default:
		if !notification {
			s.fail(req, codeMethodNotFound, "unknown method "+req.Method)
		}
	}
}

func instructions(allowWrite bool) string {
	base := "Orbis is a network firewall, filtering resolver and traffic analyser. " +
		"These tools read live state from one node: connections with the device that " +
		"opened them, DNS history with the reason anything was blocked, firewall rules " +
		"with hit counters, and the ad-blocking review queue.\n\n" +
		"A caveat worth knowing before drawing conclusions: a node that is not on the " +
		"traffic path records only its own traffic and broadcast noise. If flows look " +
		"sparse or every source is the node itself, check placement before assuming the " +
		"network is quiet."
	if !allowWrite {
		return base + "\n\nThis node is read-only. Mutating tools are not offered."
	}
	return base + "\n\nWrite access is on. Changes take effect immediately and are recorded " +
		"in the audit log."
}

// toolList converts the assistant catalogue into MCP tool descriptors.
func (s *Server) toolList() []map[string]any {
	defs := ai.Tools(s.allowWrite)
	out := make([]map[string]any, 0, len(defs))
	for _, d := range defs {
		schema := d.Schema
		if schema == nil {
			// MCP requires an object schema even for a tool that takes
			// nothing; omitting it makes some clients refuse the tool.
			schema = map[string]any{"type": "object", "properties": map[string]any{}}
		}
		entry := map[string]any{
			"name":        d.Name,
			"description": d.Description,
			"inputSchema": schema,
		}
		if d.Mutating {
			// Advertise the side effect rather than leaving a caller to infer
			// it from the name.
			entry["annotations"] = map[string]any{
				"readOnlyHint":    false,
				"destructiveHint": true,
			}
		} else {
			entry["annotations"] = map[string]any{"readOnlyHint": true}
		}
		out = append(out, entry)
	}
	return out
}

func (s *Server) callTool(ctx context.Context, req request) {
	var params struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal(req.Params, &params); err != nil {
		s.fail(req, codeInvalidParams, "params must be {name, arguments}")
		return
	}
	if params.Name == "" {
		s.fail(req, codeInvalidParams, "tool name is required")
		return
	}
	args := params.Arguments
	if len(args) == 0 {
		args = json.RawMessage(`{}`)
	}

	result, err := ai.Execute(ctx, s.backend, ai.ToolCall{
		Name:  params.Name,
		Input: args,
	}, s.allowWrite, "mcp")

	if err != nil {
		// A tool that fails is reported inside the result with isError, not as
		// a protocol error: the model is meant to see the message and adapt,
		// and a JSON-RPC error would be swallowed by the client instead.
		s.reply(req, map[string]any{
			"content": []map[string]any{{"type": "text", "text": err.Error()}},
			"isError": true,
		})
		return
	}
	s.reply(req, map[string]any{
		"content": []map[string]any{{"type": "text", "text": result}},
	})
}

// ---- transport helpers ----

func (s *Server) reply(req request, result any) {
	if len(req.ID) == 0 {
		return // notification
	}
	s.send(response{JSONRPC: "2.0", ID: req.ID, Result: result})
}

func (s *Server) fail(req request, code int, msg string) {
	if len(req.ID) == 0 {
		return
	}
	s.send(response{JSONRPC: "2.0", ID: req.ID, Error: &rpcError{code, msg}})
}

func (s *Server) send(r response) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	b, err := json.Marshal(r)
	if err != nil {
		s.log("mcp: could not encode response: %v", err)
		return
	}
	if _, err := fmt.Fprintf(s.out, "%s\n", b); err != nil {
		s.log("mcp: write failed: %v", err)
	}
}

// Version is set from the daemon so serverInfo matches the binary.
var Version = "dev"
