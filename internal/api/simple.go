package api

import (
	"net/http"
	"time"

	"github.com/Neoo-Blue/orbis/internal/dnsproxy"
	"github.com/go-chi/chi/v5"
)

// Endpoints the simple interface leans on. Everything here is a plain-language
// reading of data the advanced pages already expose.

func (s *Server) mountSimple(r chi.Router) {
	r.Get("/health", s.handleHealth)
	r.Get("/dns/services", s.handleServiceBundles)
	// Plain routes, not a mounted sub-router: a router mounted at
	// /clients/{id} carries its own catch-all, which swallowed every other
	// device path (/clients/{id}, /flows, /destinations, /dns) and answered
	// them with the interface's HTML page.
	r.Post("/clients/{id}/pause", s.handleClientPause)
	r.Post("/clients/{id}/resume", s.handleClientResume)
	r.Get("/pauses", s.handlePauses)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeOK(w, s.app.Health())
}

// handleServiceBundles lists the blocked-service catalogue (TikTok, Roblox,
// ...) so a profile editor can offer switches instead of hostnames.
func (s *Server) handleServiceBundles(w http.ResponseWriter, r *http.Request) {
	out := make([]map[string]any, 0, len(dnsproxy.BlockedServices))
	for _, b := range dnsproxy.BlockedServices {
		out = append(out, map[string]any{"id": b.ID, "name": b.Name, "domains": len(b.Domains)})
	}
	writeOK(w, map[string]any{"services": out})
}

func (s *Server) handleClientPause(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Minutes int `json:"minutes"`
	}
	_ = decodeJSON(r, &req)
	until, err := s.app.PauseClient(chi.URLParam(r, "id"), req.Minutes, r.RemoteAddr)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	resp := map[string]any{"ok": true}
	if !until.IsZero() {
		resp["until"] = until.Format(time.RFC3339)
	}
	writeOK(w, resp)
}

func (s *Server) handleClientResume(w http.ResponseWriter, r *http.Request) {
	if err := s.app.ResumeClient(chi.URLParam(r, "id"), r.RemoteAddr); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeOK(w, map[string]any{"ok": true})
}

func (s *Server) handlePauses(w http.ResponseWriter, r *http.Request) {
	pauses, err := s.app.Store.Pauses()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := map[string]string{}
	for id, until := range pauses {
		out[id] = until.Format(time.RFC3339)
	}
	writeOK(w, map[string]any{"pauses": out})
}
