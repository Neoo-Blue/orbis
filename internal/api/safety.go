package api

import (
	"net/http"

	"github.com/go-chi/chi/v5"
)

// The safety net: what keeps the network up when Orbis is down.

func (s *Server) mountSafety(r chi.Router) {
	r.Route("/safety", func(r chi.Router) {
		r.Get("/", s.handleSafety)
		r.Post("/install", s.handleSafetyInstall)
	})
}

func (s *Server) handleSafety(w http.ResponseWriter, r *http.Request) {
	out, err := s.app.SafetyStatus(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeOK(w, out)
}

func (s *Server) handleSafetyInstall(w http.ResponseWriter, r *http.Request) {
	out, err := s.app.InstallSafetyNet(r.Context(), r.RemoteAddr)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeOK(w, out)
}
