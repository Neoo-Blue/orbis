package api

import (
	"context"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
)

// Updates: the latest release on GitHub and one-click install.

func (s *Server) mountUpdate(r chi.Router) {
	r.Route("/update", func(r chi.Router) {
		r.Get("/", s.handleUpdate)
		r.Post("/check", s.handleUpdateCheck)
		r.Post("/apply", s.handleUpdateApply)
	})
}

func (s *Server) handleUpdate(w http.ResponseWriter, r *http.Request) {
	writeOK(w, s.app.UpdateStatus())
}

func (s *Server) handleUpdateCheck(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	out, err := s.app.CheckUpdate(ctx)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	writeOK(w, out)
}

func (s *Server) handleUpdateApply(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	out, err := s.app.ApplyUpdate(ctx, r.RemoteAddr)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeOK(w, out)
}
