package api

import (
	"context"
	"net/http"
	"time"

	"github.com/Neoo-Blue/orbis/internal/config"
	"github.com/go-chi/chi/v5"
)

// mountYouTube registers the native YouTube ad-control surface: the Lounge
// engine (no CA) plus device pairing and discovery.
func (s *Server) mountYouTube(r chi.Router) {
	r.Route("/youtube", func(r chi.Router) {
		r.Get("/status", s.handleYouTubeStatus)
		r.Post("/discover", s.handleYouTubeDiscover)
		r.Post("/pair", s.handleYouTubePair)
		r.Post("/adopt", s.handleYouTubeAdopt)
		r.Post("/forget", s.handleYouTubeForget)
		r.Post("/settings", s.handleYouTubeSettings)
	})
}

func (s *Server) handleYouTubeStatus(w http.ResponseWriter, r *http.Request) {
	writeOK(w, s.app.Lounge.Status())
}

func (s *Server) handleYouTubeDiscover(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()
	screens, err := s.app.Lounge.Discover(ctx, 3*time.Second)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeOK(w, screens)
}

func (s *Server) handleYouTubePair(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Code string `json:"code"`
		Name string `json:"name"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if body.Code == "" {
		writeErr(w, http.StatusBadRequest, "code is required")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	dev, err := s.app.Lounge.PairCode(ctx, body.Code, body.Name)
	if err != nil {
		// Pairing failures are almost always user-fixable (expired code), so
		// they are a 400 with the real message, not an opaque 500.
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.app.Store.Audit(r.RemoteAddr, "youtube.pair", dev.Name, "", "", "ok")
	writeOK(w, dev)
}

func (s *Server) handleYouTubeAdopt(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ScreenID string  `json:"screen_id"`
		Name     string  `json:"name"`
		Offset   float64 `json:"offset"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if body.ScreenID == "" {
		writeErr(w, http.StatusBadRequest, "screen_id is required")
		return
	}
	if err := s.app.Lounge.Adopt(body.ScreenID, body.Name, body.Offset); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.app.Store.Audit(r.RemoteAddr, "youtube.adopt", body.Name, "", "", "ok")
	writeOK(w, s.app.Lounge.Status())
}

func (s *Server) handleYouTubeForget(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ScreenID string `json:"screen_id"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if body.ScreenID == "" {
		writeErr(w, http.StatusBadRequest, "screen_id is required")
		return
	}
	if err := s.app.Lounge.Forget(body.ScreenID); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.app.Store.Audit(r.RemoteAddr, "youtube.forget", body.ScreenID, "", "", "ok")
	writeOK(w, s.app.Lounge.Status())
}

func (s *Server) handleYouTubeSettings(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Enabled       *bool     `json:"enabled"`
		AutoDiscover  *bool     `json:"auto_discover"`
		SkipAds       *bool     `json:"skip_ads"`
		MuteAds       *bool     `json:"mute_ads"`
		Categories    *[]string `json:"categories"`
		MinSkipLength *float64  `json:"min_skip_length"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	err := s.cfg.Update(func(c *config.Config) {
		lc := &c.YouTube.Lounge
		if body.Enabled != nil {
			lc.Enabled = *body.Enabled
		}
		if body.AutoDiscover != nil {
			lc.AutoDiscover = *body.AutoDiscover
		}
		if body.SkipAds != nil {
			lc.SkipAds = *body.SkipAds
		}
		if body.MuteAds != nil {
			lc.MuteAds = *body.MuteAds
		}
		if body.Categories != nil {
			lc.SkipCategories = *body.Categories
		}
		if body.MinSkipLength != nil {
			lc.MinSkipLength = *body.MinSkipLength
		}
	})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.app.Lounge.Apply()
	s.app.Store.Audit(r.RemoteAddr, "youtube.settings", "", "", "", "ok")
	writeOK(w, s.app.Lounge.Status())
}
