package api

import (
	"net/http"

	"github.com/Neoo-Blue/orbis/internal/ids"
	"github.com/go-chi/chi/v5"
)

// Intrusion detection: sources, rules, alerts, and a line tester.

func (s *Server) mountIDS(r chi.Router) {
	r.Route("/ids", func(r chi.Router) {
		r.Get("/", s.handleIDS)
		r.Post("/test", s.handleIDSTest)
	})
}

func (s *Server) handleIDS(w http.ResponseWriter, r *http.Request) {
	out, err := s.app.IntrusionStatus(querySince(r, 24), queryInt(r, "limit", 200, 2000))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeOK(w, out)
}

func (s *Server) handleIDSTest(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Line string `json:"line"`
	}
	if err := decodeJSON(r, &req); err != nil || req.Line == "" {
		writeErr(w, http.StatusBadRequest, "a log line is required")
		return
	}
	writeOK(w, ids.Test(req.Line))
}
