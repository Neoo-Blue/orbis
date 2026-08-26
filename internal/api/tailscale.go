package api

import (
	"net/http"
	"strings"

	"github.com/Neoo-Blue/orbis/internal/config"
	"github.com/Neoo-Blue/orbis/internal/vpn"
	"github.com/go-chi/chi/v5"
)

func (s *Server) mountTailscale(r chi.Router) {
	r.Route("/tailscale", func(r chi.Router) {
		r.Get("/status", s.handleTSStatus)
		r.Post("/up", s.handleTSUp)
		r.Post("/down", s.handleTSDown)
		r.Post("/login", s.handleTSLogin)
		r.Post("/logout", s.handleTSLogout)
		r.Post("/exit-node", s.handleTSSetExitNode)
		r.Post("/advertise-exit-node", s.handleTSAdvertiseExitNode)
		r.Post("/routes", s.handleTSRoutes)
		r.Post("/steer", s.handleTSSteer)
		r.Post("/accept-routes", s.handleTSAcceptRoutes)
	})
}

func (s *Server) handleTSStatus(w http.ResponseWriter, r *http.Request) {
	st := s.app.Tailscale.Status(r.Context())
	cfg := s.cfg.Snapshot().Tailscale
	out := map[string]any{
		"status": st,
		"config": map[string]any{
			"enabled":             cfg.Enabled,
			"hostname":            cfg.Hostname,
			"advertise_exit_node": cfg.AdvertiseExitNode,
			"exit_node":           cfg.ExitNode,
			"exit_node_allow_lan": cfg.ExitNodeAllowLAN,
			"steer_clients":       cfg.SteerClients,
			"advertise_routes":    cfg.AdvertiseRoutes,
			"accept_routes":       cfg.AcceptRoutes,
			"accept_dns":          cfg.AcceptDNS,
			"ssh":                 cfg.SSH,
			"login_server":        cfg.LoginServer,
		},
		"steering_active":    s.app.Tailscale.SteeringActive(r.Context()),
		"overlapping_routes": s.app.Tailscale.OverlappingRoutes(r.Context()),
		// The gateway block is what tells an operator whether an approved
		// exit node can actually move traffic, rather than only whether
		// Tailscale thinks it is one.
		"gateway": s.app.Firewall.TunnelStatus(),
	}
	if !st.Available {
		out["install_hint"] = vpn.InstallHint()
	}
	// Surface the two conditions that make a correctly-configured exit node
	// silently not work, rather than leaving the operator to discover them.
	var warnings []string
	if st.AdvertisingExitNode && !st.ExitNodeApproved {
		warnings = append(warnings,
			"This node is advertising itself as an exit node but has not been approved yet. "+
				"Approve it under Machines → this node → Edit route settings in the Tailscale admin console.")
	}
	if len(st.PendingRoutes) > 0 {
		warnings = append(warnings,
			"Subnet routes "+strings.Join(st.PendingRoutes, ", ")+" are advertised but not approved in the admin console.")
	}
	if gw := s.app.Firewall.TunnelStatus(); len(gw.Blockers) > 0 {
		for _, b := range gw.Blockers {
			warnings = append(warnings, b)
		}
	}
	if cfg.ExitNode != "" && len(cfg.SteerClients) == 0 {
		warnings = append(warnings,
			"An exit node is selected, but no LAN clients are steered through it — only this node's own traffic uses it.")
	}
	if cfg.AcceptDNS {
		warnings = append(warnings,
			"accept_dns is on, so the tailnet's DNS overrides this node's filtering resolver for its own lookups.")
	}
	if overlap := s.app.Tailscale.OverlappingRoutes(r.Context()); len(overlap) > 0 {
		warnings = append(warnings,
			"A tailnet peer advertises "+strings.Join(overlap, ", ")+", which covers this node's own "+
				"network. Accepting routes while that is true would send local traffic into the "+
				"tunnel and take this node off the LAN, so route acceptance is being held off.")
	}
	// Exit-node clients resolve through MagicDNS on the client itself, so
	// their queries never reach the nftables redirect. Their traffic is
	// filtered; their DNS is not. Saying so beats letting an operator believe
	// otherwise.
	if st.AdvertisingExitNode && st.ExitNodeApproved && st.Self != nil && len(st.Self.Addresses) > 0 {
		warnings = append(warnings,
			"Devices using this node as an exit node have their connections captured and filtered "+
				"here, but their DNS goes through Tailscale's MagicDNS and bypasses this resolver. "+
				"To filter that too, set "+st.Self.Addresses[0]+" as the tailnet's global nameserver "+
				"under DNS \u2192 Nameservers in the Tailscale admin console, with \"Override local "+
				"DNS\" turned on.")
	}
	for _, b := range s.app.Firewall.TunnelStatus().Blockers {
		warnings = append(warnings, b)
	}
	out["warnings"] = warnings
	writeOK(w, out)
}

func (s *Server) handleTSUp(w http.ResponseWriter, r *http.Request) {
	var req struct {
		AuthKey     string   `json:"auth_key"`
		Hostname    string   `json:"hostname"`
		LoginServer string   `json:"login_server"`
		Routes      []string `json:"advertise_routes"`
		ExitNode    bool     `json:"advertise_exit_node"`
	}
	// A bodyless POST just re-applies the stored settings.
	_ = decodeJSON(r, &req)

	err := s.cfg.Update(func(c *config.Config) {
		c.Tailscale.Enabled = true
		if req.AuthKey != "" && !strings.Contains(req.AuthKey, "•") {
			c.Tailscale.AuthKey = req.AuthKey
		}
		if req.Hostname != "" {
			c.Tailscale.Hostname = req.Hostname
		}
		if req.LoginServer != "" {
			c.Tailscale.LoginServer = req.LoginServer
		}
		if req.Routes != nil {
			c.Tailscale.AdvertiseRoutes = req.Routes
		}
		if req.ExitNode {
			c.Tailscale.AdvertiseExitNode = true
		}
	})
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.app.Tailscale.Up(r.Context()); err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	if err := s.app.Tailscale.ApplySteering(r.Context()); err != nil {
		s.app.Log("tailscale: steering: %v", err)
	}
	s.app.SyncTunnelRules()
	s.app.Store.Audit(r.RemoteAddr, "tailscale.up", "", "", "", "ok")
	writeOK(w, s.app.Tailscale.Status(r.Context()))
}

func (s *Server) handleTSDown(w http.ResponseWriter, r *http.Request) {
	if err := s.app.Tailscale.Down(r.Context()); err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	_ = s.cfg.Update(func(c *config.Config) { c.Tailscale.Enabled = false })
	s.app.SyncTunnelRules()
	s.app.Store.Audit(r.RemoteAddr, "tailscale.down", "", "", "", "ok")
	writeOK(w, s.app.Tailscale.Status(r.Context()))
}

func (s *Server) handleTSLogin(w http.ResponseWriter, r *http.Request) {
	url, err := s.app.Tailscale.LoginURL(r.Context())
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	writeOK(w, map[string]any{"auth_url": url})
}

func (s *Server) handleTSLogout(w http.ResponseWriter, r *http.Request) {
	if err := s.app.Tailscale.Logout(r.Context()); err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	s.app.Store.Audit(r.RemoteAddr, "tailscale.logout", "", "", "", "ok")
	writeOK(w, map[string]any{"ok": true})
}

// handleTSSetExitNode selects (or clears) the peer this network egresses
// through, and re-applies client steering so the change reaches LAN devices.
func (s *Server) handleTSSetExitNode(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Node     string `json:"node"`
		AllowLAN *bool  `json:"allow_lan"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.AllowLAN != nil {
		if err := s.cfg.Update(func(c *config.Config) {
			c.Tailscale.ExitNodeAllowLAN = *req.AllowLAN
		}); err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	if err := s.app.Tailscale.SetExitNode(r.Context(), req.Node); err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	if err := s.app.Tailscale.ApplySteering(r.Context()); err != nil {
		s.app.Log("tailscale: steering: %v", err)
	}
	s.app.SyncTunnelRules()
	s.app.Store.Audit(r.RemoteAddr, "tailscale.exit_node", req.Node, "", "", "ok")
	writeOK(w, s.app.Tailscale.Status(r.Context()))
}

// handleTSAdvertiseExitNode toggles offering this network as an exit node.
func (s *Server) handleTSAdvertiseExitNode(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.app.Tailscale.SetAdvertiseExitNode(r.Context(), req.Enabled); err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	s.app.SyncTunnelRules()
	s.app.Store.Audit(r.RemoteAddr, "tailscale.advertise_exit_node", "", "", boolWord(req.Enabled), "ok")
	st := s.app.Tailscale.Status(r.Context())
	out := map[string]any{"status": st}
	if req.Enabled && !st.ExitNodeApproved {
		out["next_step"] = "Approve this node as an exit node in the Tailscale admin console " +
			"(Machines → this node → Edit route settings). Until then it will not carry traffic."
	}
	writeOK(w, out)
}

func (s *Server) handleTSRoutes(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Routes []string `json:"routes"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.app.Tailscale.SetAdvertiseRoutes(r.Context(), req.Routes); err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	s.app.SyncTunnelRules()
	s.app.Store.Audit(r.RemoteAddr, "tailscale.routes", strings.Join(req.Routes, ","), "", "", "ok")
	writeOK(w, s.app.Tailscale.Status(r.Context()))
}

// handleTSSteer sets which LAN sources are policy-routed through the exit node.
func (s *Server) handleTSSteer(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Clients []string `json:"clients"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.cfg.Update(func(c *config.Config) { c.Tailscale.SteerClients = req.Clients }); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.app.Tailscale.ApplySteering(r.Context()); err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	s.app.SyncTunnelRules()
	s.app.Store.Audit(r.RemoteAddr, "tailscale.steer", strings.Join(req.Clients, ","), "", "", "ok")
	writeOK(w, map[string]any{
		"steering_active":    s.app.Tailscale.SteeringActive(r.Context()),
		"overlapping_routes": s.app.Tailscale.OverlappingRoutes(r.Context()),
	})
}

// handleTSAcceptRoutes toggles route acceptance through the guarded setter,
// which refuses when a peer's advertised prefix covers this node's own LAN.
func (s *Server) handleTSAcceptRoutes(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.app.Tailscale.SetAcceptRoutes(r.Context(), req.Enabled); err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	s.app.Store.Audit(r.RemoteAddr, "tailscale.accept_routes", "", "", boolWord(req.Enabled), "ok")
	writeOK(w, s.app.Tailscale.Status(r.Context()))
}

func boolWord(b bool) string {
	if b {
		return "enabled"
	}
	return "disabled"
}
