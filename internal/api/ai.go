package api

import (
	"fmt"
	"net/http"

	"github.com/go-chi/chi/v5"
)

// The assistant's plumbing: which models are in play, how much of the free
// day is spent, and the periodic briefs. Chat itself lives in chat.go.

func (s *Server) mountAI(r chi.Router) {
	r.Route("/ai", func(r chi.Router) {
		r.Get("/models", s.handleAIModels)
		r.Post("/probe", s.handleAIProbe)
		r.Get("/briefs", s.handleAIBriefs)
		r.Post("/briefs/run", s.handleAIBriefRun)
		r.Get("/recommendations", s.handleRecommendations)
		r.Post("/recommendations/{id}", s.handleRecommendationDecide)
		r.Post("/review/run", s.handleReviewRun)
		r.Get("/notes", s.handleNotes)
		r.Post("/notes", s.handleNoteCreate)
		r.Delete("/notes/{id}", s.handleNoteDelete)
	})
}

func (s *Server) handleRecommendations(w http.ResponseWriter, r *http.Request) {
	recs, err := s.app.Store.Recommendations(r.URL.Query().Get("status"), queryInt(r, "limit", 100, 500))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	cfg := s.cfg.Snapshot().AI.Review
	writeOK(w, map[string]any{"recommendations": recs, "review": map[string]any{
		"enabled": cfg.Enabled, "interval_hours": cfg.IntervalHours,
	}})
}

func (s *Server) handleRecommendationDecide(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Decision string `json:"decision"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	rec, err := s.app.DecideRecommendation(chi.URLParam(r, "id"), req.Decision, "ui")
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeOK(w, map[string]any{"recommendation": rec})
}

// handleReviewRun runs the specialist now. Synchronous like the brief: one
// model round-trip, and the caller wants the list.
func (s *Server) handleReviewRun(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Hours int `json:"hours"`
	}
	_ = decodeJSON(r, &req)
	if req.Hours <= 0 {
		req.Hours = s.cfg.Snapshot().AI.Review.IntervalHours
	}
	recs, err := s.app.Reviewer.Review(r.Context(), req.Hours)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	s.app.Store.Audit(r.RemoteAddr, "ai.review", "", "", fmt.Sprint(len(recs)), "ok")
	writeOK(w, map[string]any{"added": recs})
}

func (s *Server) handleNotes(w http.ResponseWriter, r *http.Request) {
	notes, err := s.app.Store.Notes(queryInt(r, "limit", 200, 500))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeOK(w, map[string]any{"notes": notes})
}

func (s *Server) handleNoteCreate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Note string `json:"note"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	n, err := s.app.SaveNote(req.Note, "operator")
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"note": n})
}

func (s *Server) handleNoteDelete(w http.ResponseWriter, r *http.Request) {
	if err := s.app.Store.DeleteNote(chi.URLParam(r, "id")); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeOK(w, map[string]any{"ok": true})
}

// handleAIModels returns the router's view: catalogue with probe verdicts,
// the chains a request would walk right now, and today's usage.
func (s *Server) handleAIModels(w http.ResponseWriter, r *http.Request) {
	cfg := s.cfg.Snapshot().AI
	out := s.app.AI.Router().Status(cfg)
	out["configured"] = s.app.AI.Configured()
	out["enabled"] = cfg.Enabled
	out["model"] = cfg.Model
	out["fast_model"] = cfg.FastModel
	writeOK(w, out)
}

// handleAIProbe asks the router to refresh the catalogue and re-probe now.
// The probe takes a minute or two (it is paced under the free tier's
// per-minute limit), so this returns immediately and the UI polls.
func (s *Server) handleAIProbe(w http.ResponseWriter, r *http.Request) {
	cfg := s.cfg.Snapshot().AI
	if !cfg.Enabled || cfg.APIKey == "" {
		writeErr(w, http.StatusBadRequest, "enable the assistant and set an API key first")
		return
	}
	s.app.AI.Router().RequestProbe()
	s.app.Store.Audit(r.RemoteAddr, "ai.probe", "", "", "", "ok")
	writeJSON(w, http.StatusAccepted, map[string]any{"started": true})
}

func (s *Server) handleAIBriefs(w http.ResponseWriter, r *http.Request) {
	briefs, err := s.app.Store.AIBriefs(queryInt(r, "limit", 10, 100))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeOK(w, map[string]any{"briefs": briefs})
}

// handleAIBriefRun writes a brief now. Synchronous: the caller wants the
// text, and a brief is a single model round-trip.
func (s *Server) handleAIBriefRun(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Hours int `json:"hours"`
	}
	_ = decodeJSON(r, &req)
	if req.Hours <= 0 {
		req.Hours = s.cfg.Snapshot().AI.Brief.IntervalHours
	}
	brief, err := s.app.Briefer.Generate(r.Context(), req.Hours)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	s.app.Store.Audit(r.RemoteAddr, "ai.brief", "", "", brief.Headline, "ok")
	writeOK(w, brief)
}
