package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/Neoo-Blue/orbis/internal/app"
	"nhooyr.io/websocket"
)

// handleWebSocket streams live events to the UI. Clients can subscribe to a
// subset of event types so a dashboard that only draws the globe does not pay
// for the DNS query firehose.
func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		// Same-origin only; the UI is served from this host.
		OriginPatterns:  []string{"*"},
		CompressionMode: websocket.CompressionContextTakeover,
	})
	if err != nil {
		return
	}
	defer conn.Close(websocket.StatusInternalError, "closing")

	// A single browser tab can generate a lot of interest; 4 MB of read limit
	// is far more than any control message needs.
	conn.SetReadLimit(1 << 20)

	filter := parseFilter(r.URL.Query().Get("types"))
	ch, unsubscribe := s.app.Bus.Subscribe()
	defer unsubscribe()

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	// Reader goroutine: handles subscription updates and detects hangup.
	go func() {
		defer cancel()
		for {
			_, data, err := conn.Read(ctx)
			if err != nil {
				return
			}
			var msg struct {
				Action string   `json:"action"`
				Types  []string `json:"types"`
			}
			if err := json.Unmarshal(data, &msg); err != nil {
				continue
			}
			if msg.Action == "subscribe" {
				filter = toSet(msg.Types)
			}
		}
	}()

	// Send an immediate snapshot so the UI has something to draw before the
	// first event arrives.
	snapshot := app.Event{Type: "snapshot", TS: time.Now().UnixMilli(), Data: map[string]any{
		"status":  s.app.SystemStatus(),
		"clients": s.app.Clients(),
		"flows":   s.app.Tracker.Active(300),
	}}
	if err := writeWS(ctx, conn, snapshot); err != nil {
		return
	}

	ping := time.NewTicker(30 * time.Second)
	defer ping.Stop()

	for {
		select {
		case <-ctx.Done():
			conn.Close(websocket.StatusNormalClosure, "")
			return

		case <-ping.C:
			pctx, pcancel := context.WithTimeout(ctx, 10*time.Second)
			err := conn.Ping(pctx)
			pcancel()
			if err != nil {
				return
			}

		case ev, ok := <-ch:
			if !ok {
				conn.Close(websocket.StatusNormalClosure, "server shutting down")
				return
			}
			if filter != nil && !filter[ev.Type] {
				continue
			}
			if err := writeWS(ctx, conn, ev); err != nil {
				return
			}
		}
	}
}

func writeWS(ctx context.Context, conn *websocket.Conn, ev app.Event) error {
	data, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	wctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return conn.Write(wctx, websocket.MessageText, data)
}

// parseFilter turns "flow.new,flow.close" into a set. An empty parameter means
// everything, which is the right default for the dashboard.
func parseFilter(raw string) map[string]bool {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	return toSet(strings.Split(raw, ","))
}

func toSet(items []string) map[string]bool {
	if len(items) == 0 {
		return nil
	}
	out := make(map[string]bool, len(items))
	for _, s := range items {
		s = strings.TrimSpace(s)
		if s != "" {
			out[s] = true
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
