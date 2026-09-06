package api

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Neoo-Blue/orbis/internal/config"
	"github.com/Neoo-Blue/orbis/internal/discover"
	"github.com/go-chi/chi/v5"
)

// Hosted apps: what the network runs, the storage on it, and port forwards.

func (s *Server) mountHosted(r chi.Router) {
	r.Route("/hosted", func(r chi.Router) {
		r.Get("/", s.handleHosted)
		r.Post("/scan", s.handleHostedScan)
		r.Get("/storage", s.handleHostedStorage)
		r.Get("/forwards", s.handleForwards)
		r.Post("/forwards", s.handleForwardCreate)
		r.Delete("/forwards/{id}", s.handleForwardDelete)
		r.Delete("/router/{proto}/{port}", s.handleRouterMappingDelete)
		r.Post("/docker", s.handleDockerSave)
		r.Delete("/docker/{name}", s.handleDockerDelete)
		r.Post("/docker/test", s.handleDockerTest)
	})
}

func (s *Server) handleHosted(w http.ResponseWriter, r *http.Request) {
	hosts, err := s.app.Discover.Hosts()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := s.app.Discover.Status()
	cfg := s.cfg.Snapshot()
	out["hosts"] = hosts
	out["docker"] = cfg.Discover.Docker
	out["enabled"] = cfg.Discover.Enabled
	out["interval_hours"] = cfg.Discover.IntervalHours
	inline := cfg.Mode == config.ModeInline && cfg.Firewall.Enabled && s.app.Firewall.Available()
	out["forwarding"] = map[string]any{"inline": inline, "upnp": cfg.Discover.UPnP}
	writeOK(w, out)
}

func (s *Server) handleHostedScan(w http.ResponseWriter, r *http.Request) {
	s.app.Discover.RequestScan()
	s.app.Store.Audit(r.RemoteAddr, "hosted.scan", "", "", "", "ok")
	writeOK(w, map[string]any{"started": true})
}

func (s *Server) handleHostedStorage(w http.ResponseWriter, r *http.Request) {
	storage, err := s.app.Discover.Storage()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeOK(w, map[string]any{"storage": storage})
}

func (s *Server) handleForwards(w http.ResponseWriter, r *http.Request) {
	forwards, err := s.app.Discover.Forwards()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
	defer cancel()
	cfg := s.cfg.Snapshot()
	inline := cfg.Mode == config.ModeInline && cfg.Firewall.Enabled && s.app.Firewall.Available()
	writeOK(w, map[string]any{
		"forwards": forwards, "router": s.app.Discover.Router(ctx),
		"forwarding": map[string]any{"inline": inline, "upnp": cfg.Discover.UPnP},
	})
}

func (s *Server) handleForwardCreate(w http.ResponseWriter, r *http.Request) {
	var req discover.ForwardRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	fw, err := s.app.ForwardPort(ctx, req, r.RemoteAddr)
	if err != nil {
		var se *discover.SensitiveError
		if errors.As(err, &se) {
			writeJSON(w, http.StatusConflict, map[string]any{"error": err.Error(), "needs_confirm": true, "service": se.Service})
			return
		}
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"forward": fw})
}

func (s *Server) handleForwardDelete(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	if err := s.app.RemoveForward(ctx, chi.URLParam(r, "id"), r.RemoteAddr); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeOK(w, map[string]any{"ok": true})
}

func (s *Server) handleRouterMappingDelete(w http.ResponseWriter, r *http.Request) {
	port, err := strconv.Atoi(chi.URLParam(r, "port"))
	if err != nil || port <= 0 || port > 65535 {
		writeErr(w, http.StatusBadRequest, "port must be 1 to 65535")
		return
	}
	proto := strings.ToLower(chi.URLParam(r, "proto"))
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	if err := s.app.Discover.RemoveRouterMapping(ctx, port, proto); err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	s.app.Store.Audit(r.RemoteAddr, "router.mapping.delete", strconv.Itoa(port)+"/"+proto, "", "", "ok")
	writeOK(w, map[string]any{"ok": true})
}

func (s *Server) handleDockerSave(w http.ResponseWriter, r *http.Request) {
	var req config.DockerHost
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	req.Name, req.URL = strings.TrimSpace(req.Name), strings.TrimSpace(req.URL)
	if req.Name == "" || req.URL == "" {
		writeErr(w, http.StatusBadRequest, "name and url are required")
		return
	}
	err := s.cfg.Update(func(c *config.Config) {
		for i := range c.Discover.Docker {
			if c.Discover.Docker[i].Name == req.Name {
				c.Discover.Docker[i] = req
				return
			}
		}
		c.Discover.Docker = append(c.Discover.Docker, req)
	})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.app.Store.Audit(r.RemoteAddr, "docker.host", req.Name, "", req.URL, "ok")
	s.app.Discover.RequestScan()
	writeOK(w, map[string]any{"ok": true})
}

func (s *Server) handleDockerDelete(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	err := s.cfg.Update(func(c *config.Config) {
		out := c.Discover.Docker[:0]
		for _, d := range c.Discover.Docker {
			if d.Name != name {
				out = append(out, d)
			}
		}
		c.Discover.Docker = out
	})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeOK(w, map[string]any{"ok": true})
}

func (s *Server) handleDockerTest(w http.ResponseWriter, r *http.Request) {
	var req struct {
		URL string `json:"url"`
	}
	if err := decodeJSON(r, &req); err != nil || strings.TrimSpace(req.URL) == "" {
		writeErr(w, http.StatusBadRequest, "url is required")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	out, err := discover.DockerVersion(ctx, strings.TrimSpace(req.URL))
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	writeOK(w, out)
}
