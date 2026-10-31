package api

import (
	"net/http"

	"github.com/Neoo-Blue/orbis/internal/netwatch"
	"github.com/go-chi/chi/v5"
)

func (s *Server) mountNetwatch(r chi.Router) {
	r.Route("/netwatch", func(r chi.Router) {
		r.Get("/status", s.handleNetwatchStatus)
		r.Get("/history", s.handleNetwatchHistory)
	})
}

func (s *Server) handleNetwatchStatus(w http.ResponseWriter, r *http.Request) {
	if s.app == nil || s.app.Netwatch == nil {
		writeOK(w, netwatch.NewManager(nil, nil, nil).Status())
		return
	}
	writeOK(w, s.app.Netwatch.Status())
}

func (s *Server) handleNetwatchHistory(w http.ResponseWriter, r *http.Request) {
	hours := queryInt(r, "hours", 6, 24)
	if s.app == nil || s.app.Netwatch == nil {
		writeOK(w, netwatch.NewManager(nil, nil, nil).History(hours))
		return
	}
	writeOK(w, s.app.Netwatch.History(hours))
}
