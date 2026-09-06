package api

import (
	"context"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/Neoo-Blue/orbis/internal/config"
	"github.com/go-chi/chi/v5"
)

// Threat intelligence: address feeds, bans, hits, and the CrowdSec bouncer.

func (s *Server) mountThreat(r chi.Router) {
	r.Route("/threat", func(r chi.Router) {
		r.Get("/status", s.handleThreatStatus)
		r.Get("/feeds", s.handleThreatFeeds)
		r.Post("/feeds", s.handleThreatSaveFeed)
		r.Delete("/feeds/{name}", s.handleThreatDeleteFeed)
		r.Post("/refresh", s.handleThreatRefresh)
		r.Get("/decisions", s.handleThreatDecisions)
		r.Post("/decisions", s.handleThreatBan)
		r.Delete("/decisions/{id}", s.handleThreatUnban)
		r.Get("/hits", s.handleThreatHits)
		r.Get("/lookup", s.handleThreatLookup)
		r.Post("/crowdsec/test", s.handleThreatCrowdSecTest)
	})
}

func (s *Server) handleThreatStatus(w http.ResponseWriter, r *http.Request) {
	out := s.app.Threat.Status()
	out["enforcement"] = s.app.ThreatEnforcement()
	writeOK(w, out)
}

func (s *Server) handleThreatFeeds(w http.ResponseWriter, r *http.Request) {
	writeOK(w, map[string]any{"feeds": s.app.Threat.Feeds()})
}

func (s *Server) handleThreatSaveFeed(w http.ResponseWriter, r *http.Request) {
	var req config.ThreatFeed
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	req.URL = strings.TrimSpace(req.URL)
	if req.Name == "" || req.URL == "" {
		writeErr(w, http.StatusBadRequest, "name and url are required")
		return
	}
	if !strings.HasPrefix(req.URL, "http://") && !strings.HasPrefix(req.URL, "https://") {
		writeErr(w, http.StatusBadRequest, "url must be http or https")
		return
	}
	err := s.cfg.Update(func(c *config.Config) {
		for i := range c.Threat.Feeds {
			if c.Threat.Feeds[i].Name == req.Name {
				c.Threat.Feeds[i] = req
				return
			}
		}
		c.Threat.Feeds = append(c.Threat.Feeds, req)
	})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.app.Store.Audit(r.RemoteAddr, "threat.feed", req.Name, "", req.URL, "ok")
	s.app.Threat.Reconfigure()
	writeOK(w, map[string]any{"ok": true})
}

func (s *Server) handleThreatDeleteFeed(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	err := s.cfg.Update(func(c *config.Config) {
		out := c.Threat.Feeds[:0]
		for _, f := range c.Threat.Feeds {
			if f.Name != name {
				out = append(out, f)
			}
		}
		c.Threat.Feeds = out
	})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.app.Store.Audit(r.RemoteAddr, "threat.feed.delete", name, "", "", "ok")
	s.app.Threat.Reconfigure()
	writeOK(w, map[string]any{"ok": true})
}

func (s *Server) handleThreatRefresh(w http.ResponseWriter, r *http.Request) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()
		if err := s.app.Threat.Refresh(ctx, true); err != nil {
			s.app.Log("threat: manual refresh: %v", err)
		}
	}()
	writeOK(w, map[string]any{"started": true})
}

func (s *Server) handleThreatDecisions(w http.ResponseWriter, r *http.Request) {
	writeOK(w, map[string]any{"decisions": s.app.Threat.Decisions()})
}

func (s *Server) handleThreatBan(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Value  string  `json:"value"`
		Hours  float64 `json:"hours"`
		Reason string  `json:"reason"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if strings.TrimSpace(req.Value) == "" {
		writeErr(w, http.StatusBadRequest, "an address or range is required")
		return
	}
	var d time.Duration
	if req.Hours > 0 {
		d = time.Duration(req.Hours * float64(time.Hour))
	}
	dec, err := s.app.Threat.Ban(req.Value, d, req.Reason, "manual", r.RemoteAddr)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.app.Store.Audit(r.RemoteAddr, "threat.ban", dec.Value, "", req.Reason, "ok")
	writeOK(w, map[string]any{"decision": dec})
}

func (s *Server) handleThreatUnban(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	n, err := s.app.Threat.Unban(id)
	if err != nil {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}
	s.app.Store.Audit(r.RemoteAddr, "threat.unban", id, "", "", "ok")
	writeOK(w, map[string]any{"lifted": n})
}

func (s *Server) handleThreatHits(w http.ResponseWriter, r *http.Request) {
	since := querySince(r, 24)
	limit := queryInt(r, "limit", 200, 2000)
	hits, err := s.app.Threat.Hits(since, limit)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeOK(w, map[string]any{"since": since, "hits": hits, "devices": s.deviceLabels()})
}

func (s *Server) handleThreatLookup(w http.ResponseWriter, r *http.Request) {
	addr, err := netip.ParseAddr(strings.TrimSpace(r.URL.Query().Get("ip")))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "ip must be an address")
		return
	}
	out := s.app.Threat.Describe(addr)
	out["ip"] = addr.String()
	if s.app.Geo != nil {
		loc := s.app.Geo.LookupAddr(addr)
		out["country"] = loc.Country
		out["network"] = loc.ASOrg
	}
	writeOK(w, out)
}

func (s *Server) handleThreatCrowdSecTest(w http.ResponseWriter, r *http.Request) {
	var req struct {
		URL    string `json:"url"`
		APIKey string `json:"api_key"`
	}
	_ = decodeJSON(r, &req)
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	out, err := s.app.Threat.TestCrowdSec(ctx, strings.TrimSpace(req.URL), strings.TrimSpace(req.APIKey))
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	writeOK(w, out)
}
