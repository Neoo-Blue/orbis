package api

import (
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
)

// Country rules: block or allow by where an address is.

func (s *Server) mountCountry(r chi.Router) {
	r.Route("/country", func(r chi.Router) {
		r.Get("/", s.handleCountry)
		r.Post("/rules", s.handleCountryRule)
	})
}

func (s *Server) handleCountry(w http.ResponseWriter, r *http.Request) {
	out, err := s.app.CountryRules()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeOK(w, out)
}

func (s *Server) handleCountryRule(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Code   string `json:"code"`
		Action string `json:"action"` // add | remove | mode_block | mode_allow | enable | disable
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	out, err := s.app.SetCountryRule(req.Code, strings.TrimSpace(req.Action), r.RemoteAddr)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeOK(w, out)
}
