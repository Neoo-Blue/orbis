package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/Neoo-Blue/orbis/internal/ai"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

func (s *Server) handleConversations(w http.ResponseWriter, r *http.Request) {
	convs, err := s.app.Store.Conversations()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeOK(w, map[string]any{"conversations": convs})
}

func (s *Server) handleConversation(w http.ResponseWriter, r *http.Request) {
	msgs, err := s.app.Store.ChatHistory(chi.URLParam(r, "id"), queryInt(r, "limit", 100, 500))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeOK(w, map[string]any{"messages": msgs})
}

func (s *Server) handleDeleteConversation(w http.ResponseWriter, r *http.Request) {
	if err := s.app.Store.DeleteConversation(chi.URLParam(r, "id")); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeOK(w, map[string]any{"ok": true})
}

// handleAsk streams the assistant's turn as Server-Sent Events. SSE rather
// than WebSocket because the response is one-directional and SSE reconnects
// and buffers correctly through proxies without any extra work.
func (s *Server) handleAsk(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Conversation string `json:"conversation"`
		Message      string `json:"message"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.Message == "" {
		writeErr(w, http.StatusBadRequest, "message is required")
		return
	}
	if req.Conversation == "" {
		req.Conversation = uuid.NewString()
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		writeErr(w, http.StatusInternalServerError, "streaming is not supported by this server")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	// Nginx and friends buffer SSE into uselessness without this.
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	send := func(event string, payload any) {
		data, err := json.Marshal(payload)
		if err != nil {
			return
		}
		fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, data)
		flusher.Flush()
	}
	send("start", map[string]any{"conversation": req.Conversation})

	// The request context is cancelled when the browser navigates away; the
	// assistant should stop working the moment nobody is listening.
	ctx := r.Context()
	done := make(chan struct{})
	go func() {
		defer close(done)
		err := s.app.Assistant.Ask(ctx, req.Conversation, req.Message, "ui", func(t ai.Turn) {
			send("turn", t)
		})
		if err != nil {
			send("error", map[string]any{"error": err.Error()})
		}
		send("done", map[string]any{"conversation": req.Conversation})
	}()

	// Keepalive comments stop intermediaries timing the stream out during a
	// long tool call.
	keepalive := time.NewTicker(15 * time.Second)
	defer keepalive.Stop()
	for {
		select {
		case <-done:
			return
		case <-ctx.Done():
			return
		case <-keepalive.C:
			fmt.Fprint(w, ": keepalive\n\n")
			flusher.Flush()
		}
	}
}
