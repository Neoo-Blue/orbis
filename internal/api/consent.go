package api

import (
	"net/http"

	"github.com/Neoo-Blue/orbis/internal/consent"
	"github.com/go-chi/chi/v5"
)

// mountConsent registers ask-on-first-connection.
func (s *Server) mountConsent(r chi.Router) {
	r.Route("/consent", func(r chi.Router) {
		r.Get("/", s.handleConsentStatus)
		r.Post("/decide", s.handleConsentDecide)
		r.Post("/enrol", s.handleConsentEnrol)
		r.Post("/forget", s.handleConsentForget)
		r.Post("/clear", s.handleConsentClear)
	})
}

func (s *Server) handleConsentStatus(w http.ResponseWriter, r *http.Request) {
	writeOK(w, map[string]any{
		"enrolled": s.app.Consent.Enrolled(),
		"pending":  s.app.Consent.Pending(),
		"rules":    s.app.Consent.Rules(),
	})
}

func (s *Server) handleConsentDecide(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID       string `json:"id"`
		Decision string `json:"decision"`
		Scope    string `json:"scope"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	d := consent.Decision(req.Decision)
	if d != consent.Allow && d != consent.Deny {
		writeErr(w, http.StatusBadRequest, "decision must be allow or deny")
		return
	}
	rule, err := s.app.ConsentDecide(req.ID, d, req.Scope)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeOK(w, rule)
}

func (s *Server) handleConsentEnrol(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ClientIDs []string `json:"client_ids"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.app.SetConsentEnrolled(req.ClientIDs)
	writeOK(w, map[string]any{"enrolled": s.app.Consent.Enrolled()})
}

func (s *Server) handleConsentForget(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ClientID string `json:"client_id"`
		Host     string `json:"host"`
		Scope    string `json:"scope"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.app.ConsentForget(req.ClientID, req.Host, req.Scope); err != nil {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}
	writeOK(w, map[string]any{"ok": true})
}

func (s *Server) handleConsentClear(w http.ResponseWriter, r *http.Request) {
	writeOK(w, map[string]any{"cleared": s.app.Consent.Clear()})
}
