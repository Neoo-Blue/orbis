package api

import (
	"net/http"

	"github.com/Neoo-Blue/orbis/internal/config"
	"github.com/go-chi/chi/v5"
)

// mountIntercept exposes ARP interception: the way a node that is not the
// gateway still gets selected devices' traffic.
func (s *Server) mountIntercept(r chi.Router) {
	r.Route("/intercept", func(r chi.Router) {
		r.Get("/", s.handleInterceptStatus)
		r.Post("/settings", s.handleInterceptSettings)
		r.Post("/enroll", s.handleInterceptEnroll)
		r.Post("/remove", s.handleInterceptRemove)
	})
}

func (s *Server) handleInterceptStatus(w http.ResponseWriter, r *http.Request) {
	cfg := s.cfg.Snapshot().Network.Intercept
	// Present the enrolled set alongside what the registry knows, so the UI can
	// show a name and online state rather than a bare address.
	writeOK(w, map[string]any{
		"config":  cfg,
		"stats":   s.app.Intercept.Stats(),
		"gateway": s.app.DefaultGateway(),
	})
}

func (s *Server) handleInterceptSettings(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Enabled      *bool   `json:"enabled"`
		LANInterface *string `json:"lan_interface"`
		Gateway      *string `json:"gateway"`
		RedirectDNS  *bool   `json:"redirect_dns"`
		RedirectHTTP *bool   `json:"redirect_http"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	err := s.cfg.Update(func(c *config.Config) {
		ic := &c.Network.Intercept
		if body.Enabled != nil {
			ic.Enabled = *body.Enabled
		}
		if body.LANInterface != nil {
			ic.LANInterface = *body.LANInterface
		}
		if body.Gateway != nil {
			ic.Gateway = *body.Gateway
		}
		if body.RedirectDNS != nil {
			ic.RedirectDNS = *body.RedirectDNS
		}
		if body.RedirectHTTP != nil {
			ic.RedirectHTTP = *body.RedirectHTTP
		}
	})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := s.app.SyncIntercept(); err != nil {
		writeErr(w, http.StatusInternalServerError, "saved but could not apply: "+err.Error())
		return
	}
	s.app.Store.Audit(r.RemoteAddr, "intercept.settings", "", "", "", "ok")
	writeOK(w, map[string]any{"config": s.cfg.Snapshot().Network.Intercept, "stats": s.app.Intercept.Stats()})
}

func (s *Server) handleInterceptEnroll(w http.ResponseWriter, r *http.Request) {
	var body struct {
		IP  string `json:"ip"`
		MAC string `json:"mac"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if body.IP == "" {
		writeErr(w, http.StatusBadRequest, "ip is required")
		return
	}
	err := s.cfg.Update(func(c *config.Config) {
		if c.Network.Intercept.Clients == nil {
			c.Network.Intercept.Clients = map[string]string{}
		}
		c.Network.Intercept.Clients[body.IP] = body.MAC
	})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := s.app.SyncIntercept(); err != nil {
		writeErr(w, http.StatusInternalServerError, "enrolled but could not apply: "+err.Error())
		return
	}
	s.app.Store.Audit(r.RemoteAddr, "intercept.enroll", body.IP, "", body.MAC, "ok")
	writeOK(w, map[string]any{"config": s.cfg.Snapshot().Network.Intercept, "stats": s.app.Intercept.Stats()})
}

func (s *Server) handleInterceptRemove(w http.ResponseWriter, r *http.Request) {
	var body struct {
		IP string `json:"ip"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	err := s.cfg.Update(func(c *config.Config) {
		delete(c.Network.Intercept.Clients, body.IP)
	})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	// SyncIntercept sees the shorter client list and the manager restores the
	// removed device's ARP cache before dropping it.
	if err := s.app.SyncIntercept(); err != nil {
		writeErr(w, http.StatusInternalServerError, "removed but could not apply: "+err.Error())
		return
	}
	s.app.Store.Audit(r.RemoteAddr, "intercept.remove", body.IP, "", "", "ok")
	writeOK(w, map[string]any{"config": s.cfg.Snapshot().Network.Intercept, "stats": s.app.Intercept.Stats()})
}
