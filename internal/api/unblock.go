package api

import (
	"errors"
	"net/http"
	"time"

	"github.com/Neoo-Blue/orbis/internal/app"
	"github.com/Neoo-Blue/orbis/internal/blockpage"
	"github.com/Neoo-Blue/orbis/internal/unblock"
	"github.com/go-chi/chi/v5"
)

// mountUnblock registers the owner's side of "ask to unblock".
func (s *Server) mountUnblock(r chi.Router) {
	r.Route("/unblock", func(r chi.Router) {
		r.Get("/", s.handleUnblockList)
		r.Post("/trust", s.handleUnblockTrust)
		r.Post("/{id}/decide", s.handleUnblockDecide)
		r.Post("/{id}/revoke", s.handleUnblockRevoke)
	})
}

func (s *Server) handleUnblockList(w http.ResponseWriter, r *http.Request) {
	pending, grants, past := s.app.Unblock.List(time.Now())
	if len(past) > 30 {
		past = past[:30]
	}
	writeOK(w, map[string]any{"pending": pending, "grants": grants, "past": past, "trusted": s.app.Unblock.TrustedDevices()})
}

func (s *Server) handleUnblockDecide(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Allow    bool `json:"allow"`
		Minutes  int  `json:"minutes"`
		Everyone bool `json:"everyone"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.writeDecision(w, chi.URLParam(r, "id"), req.Allow, req.Minutes, req.Everyone, r.RemoteAddr)
}

func (s *Server) writeDecision(w http.ResponseWriter, id string, allow bool, minutes int, everyone bool, by string) {
	got, err := s.app.DecideUnblock(id, allow, minutes, everyone, by)
	switch {
	case errors.Is(err, unblock.ErrNotFound):
		writeErr(w, http.StatusNotFound, err.Error())
	case errors.Is(err, app.ErrTooBroad):
		writeErr(w, http.StatusBadRequest, err.Error())
	case err != nil:
		writeErr(w, http.StatusInternalServerError, err.Error())
	default:
		writeOK(w, got)
	}
}

func (s *Server) handleUnblockRevoke(w http.ResponseWriter, r *http.Request) {
	if err := s.app.Unblock.Revoke(chi.URLParam(r, "id"), time.Now()); err != nil {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}
	writeOK(w, map[string]any{"ok": true})
}

func (s *Server) handleUnblockTrust(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ClientID string `json:"client_id"`
		Trusted  bool   `json:"trusted"`
	}
	if err := decodeJSON(r, &req); err != nil || req.ClientID == "" {
		writeErr(w, http.StatusBadRequest, "client_id is required")
		return
	}
	if err := s.app.Unblock.Trust(req.ClientID, req.Trusted); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.app.Store.Audit(r.RemoteAddr, "unblock.trust", req.ClientID, "", "", "ok")
	writeOK(w, map[string]any{"ok": true})
}

// handleApproval is the page behind the link in a notification. The token is
// the owner's authority for this one request, so a tap on a phone needs no
// sign-in, and it grants nothing beyond answering this request once.
func (s *Server) handleApproval(w http.ResponseWriter, r *http.Request) {
	id, token := chi.URLParam(r, "id"), r.FormValue("t")
	if !s.app.Unblock.ValidToken(id, token) {
		http.Error(w, "This link is not valid.", http.StatusForbidden)
		return
	}
	req, ok := s.app.Unblock.Get(id)
	if !ok {
		http.Error(w, "This request is gone.", http.StatusNotFound)
		return
	}
	if r.Method == http.MethodPost {
		minutes := map[string]int{"hour": 60, "day": 1440}[r.FormValue("for")]
		got, err := s.app.DecideUnblock(id, r.FormValue("answer") == "allow", minutes, false, "notification link")
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		req = got
	}
	blockpage.WriteApproval(w, blockpage.Approval{
		Host: req.Host, Device: req.Device, Note: req.Note, Why: req.Why, Risky: req.Risky,
		State: string(req.State), Token: token,
	})
}
