package api

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/Neoo-Blue/orbis/internal/links"
	"github.com/Neoo-Blue/orbis/internal/wifi"
	"github.com/go-chi/chi/v5"
)

// Cables and Wi-Fi: which interface is what, and the access point.

func (s *Server) mountLinks(r chi.Router) {
	r.Route("/links", func(r chi.Router) {
		r.Get("/", s.handleLinks)
		r.Post("/apply", s.handleLinksApply)
	})
	r.Route("/wifi", func(r chi.Router) {
		r.Get("/status", s.handleWiFiStatus)
		r.Post("/enable", s.handleWiFiEnable)
		r.Post("/disable", s.handleWiFiDisable)
		r.Post("/passphrase", s.handleWiFiPassphrase)
		r.Get("/qr.png", s.handleWiFiQR)
	})
}

func (s *Server) handleLinks(w http.ResponseWriter, r *http.Request) {
	ls, sug := s.app.Links.Refresh()
	cfg := s.cfg.Snapshot()
	writeOK(w, map[string]any{
		"links": ls, "suggestion": sug, "auto_assign": cfg.Network.Links.AutoAssign,
		"mode": string(cfg.Mode), "wan_interface": cfg.Firewall.WANInterface, "zones": cfg.Firewall.Zones,
	})
}

// handleLinksApply writes the suggestion, or an explicit assignment.
func (s *Server) handleLinksApply(w http.ResponseWriter, r *http.Request) {
	var req struct {
		WAN  string   `json:"wan"`
		LAN  []string `json:"lan"`
		WiFi []string `json:"wifi"`
	}
	_ = decodeJSON(r, &req)
	_, sug := s.app.Links.Refresh()
	if req.WAN != "" || len(req.LAN) > 0 {
		sug = links.Suggestion{WAN: req.WAN, LAN: req.LAN, WiFi: req.WiFi}
	}
	if err := links.Apply(s.cfg, sug); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.app.Store.Audit(r.RemoteAddr, "links.apply", sug.WAN, "", strings.Join(append(sug.LAN, sug.WiFi...), ","), "ok")
	s.app.ReapplyThreatEnforcement()
	ls, sug2 := s.app.Links.Refresh()
	writeOK(w, map[string]any{"links": ls, "suggestion": sug2, "applied": sug})
}

func (s *Server) handleWiFiStatus(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()
	st := s.app.WiFi.Status(ctx)
	cfg := s.cfg.Snapshot().WiFi
	// The operator needs the passphrase to join; it is shown here, behind
	// the admin session, and masked everywhere else.
	st["passphrase"] = cfg.Passphrase
	st["config"] = map[string]any{
		"band": cfg.Band, "channel": cfg.Channel, "country": cfg.Country, "hidden": cfg.Hidden,
		"isolate_clients": cfg.IsolateClients, "bridge": cfg.Bridge, "lan_access": cfg.LANAccess, "wpa3": cfg.WPA3,
		"interface": cfg.Interface,
	}
	writeOK(w, st)
}

func (s *Server) handleWiFiEnable(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SSID       string `json:"ssid"`
		Passphrase string `json:"passphrase"`
		Band       string `json:"band"`
	}
	_ = decodeJSON(r, &req)
	on := true
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	st, err := s.app.ConfigureWiFi(ctx, &on, strings.TrimSpace(req.SSID), strings.TrimSpace(req.Passphrase), strings.TrimSpace(req.Band), r.RemoteAddr)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeOK(w, st)
}

func (s *Server) handleWiFiDisable(w http.ResponseWriter, r *http.Request) {
	off := false
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	st, err := s.app.ConfigureWiFi(ctx, &off, "", "", "", r.RemoteAddr)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeOK(w, st)
}

// handleWiFiPassphrase sets a new passphrase, or generates one when the
// body is empty, and restarts the access point.
func (s *Server) handleWiFiPassphrase(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Passphrase string `json:"passphrase"`
	}
	_ = decodeJSON(r, &req)
	p := strings.TrimSpace(req.Passphrase)
	if p == "" {
		p = wifi.GeneratePassphrase()
	}
	if len(p) < 8 || len(p) > 63 {
		writeErr(w, http.StatusBadRequest, "the passphrase must be 8 to 63 characters")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	st, err := s.app.ConfigureWiFi(ctx, nil, "", p, "", r.RemoteAddr)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeOK(w, st)
}

// wifiQRPayload is the string phones understand when they scan a Wi-Fi
// code: WIFI:T:WPA;S:name;P:passphrase;H:true;; with the special characters
// escaped.
func wifiQRPayload(ssid, passphrase string, hidden bool) string {
	esc := func(v string) string {
		r := strings.NewReplacer("\\", "\\\\", ";", "\\;", ",", "\\,", ":", "\\:", "\"", "\\\"")
		return r.Replace(v)
	}
	h := ""
	if hidden {
		h = "H:true;"
	}
	return "WIFI:T:WPA;S:" + esc(ssid) + ";P:" + esc(passphrase) + ";" + h + ";"
}

// handleWiFiQR renders the join code as a PNG, behind the admin session
// like the passphrase itself.
func (s *Server) handleWiFiQR(w http.ResponseWriter, r *http.Request) {
	cfg := s.cfg.Snapshot().WiFi
	if !cfg.Enabled || cfg.SSID == "" || cfg.Passphrase == "" {
		writeErr(w, http.StatusNotFound, "wi-fi is not configured")
		return
	}
	png, err := qrPNG(wifiQRPayload(cfg.SSID, cfg.Passphrase, cfg.Hidden))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(png)
}
