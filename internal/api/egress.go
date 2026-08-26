package api

import (
	"net/http"
	"strings"

	"github.com/Neoo-Blue/orbis/internal/config"
	"github.com/Neoo-Blue/orbis/internal/vpn"
	"github.com/go-chi/chi/v5"
)

func (s *Server) mountEgress(r chi.Router) {
	r.Route("/vpn/out", func(r chi.Router) {
		r.Get("/", s.handleEgressStatus)
		r.Post("/tunnels", s.handleCreateTunnel)
		r.Post("/tunnels/import", s.handleImportTunnel)
		r.Put("/tunnels/{name}", s.handleUpdateTunnel)
		r.Delete("/tunnels/{name}", s.handleDeleteTunnel)
		r.Post("/tunnels/{name}/{action}", s.handleTunnelAction)
		r.Post("/assign", s.handleAssignEgress)
		r.Post("/assign-all", s.handleAssignAll)
	})
}

// handleEgressStatus is the single call the outbound-VPN page makes: the
// tunnels, everywhere traffic can go, and what is routed where.
func (s *Server) handleEgressStatus(w http.ResponseWriter, r *http.Request) {
	cfg := s.cfg.Snapshot()
	targets := s.app.EgressTargets(r.Context())

	// Which device sits behind each route, so the UI can show names rather
	// than addresses after a restart.
	byIP := map[string]string{}
	for _, c := range s.app.Clients() {
		byIP[c.IP] = c.ID
	}
	routes := make([]map[string]any, 0, len(cfg.VPN.Routes))
	for _, rt := range cfg.VPN.Routes {
		routes = append(routes, map[string]any{
			"source": rt.Source, "target": rt.TargetID,
			"label": rt.Label, "client_id": byIP[rt.Source],
		})
	}

	writeOK(w, map[string]any{
		"tunnels":  redactTunnels(cfg.VPN.Tunnels),
		"targets":  targets,
		"routes":   routes,
		"status":   s.app.Egress.Status(r.Context()),
		"lan":      s.app.LANPrefixes(),
		"warnings": egressWarnings(cfg, targets),
	})
}

// egressWarnings names the conditions under which routing looks configured
// but does not work.
func egressWarnings(cfg config.Config, targets []vpn.EgressTarget) []string {
	var out []string
	if len(cfg.VPN.Routes) > 0 && cfg.Firewall.WANInterface == "" {
		out = append(out,
			"No WAN interface is set, so traffic steered into a tunnel cannot be NATed and will not return.")
	}
	for _, t := range targets {
		if t.Kind != "wireguard" || t.Up {
			continue
		}
		routed := 0
		for _, r := range cfg.VPN.Routes {
			if r.TargetID == t.ID {
				routed++
			}
		}
		if routed == 0 {
			continue
		}
		if t.KillSwitch {
			out = append(out,
				t.Name+" is not connected and its kill switch is on, so the "+
					plural(routed, "device", "devices")+" routed through it "+
					"currently ha"+verb(routed)+" no internet. That is the kill switch working, not a fault.")
		} else {
			out = append(out,
				t.Name+" is not connected, so the "+plural(routed, "device", "devices")+
					" routed through it "+verbIs(routed)+" going out over the plain WAN unprotected. "+
					"Turn on its kill switch if that is not acceptable.")
		}
	}
	return out
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return itoa(n) + " " + many
}
func verb(n int) string {
	if n == 1 {
		return "s"
	}
	return "ve"
}
func verbIs(n int) string {
	if n == 1 {
		return "is"
	}
	return "are"
}
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

func redactTunnels(in []config.TunnelConfig) []map[string]any {
	out := make([]map[string]any, 0, len(in))
	for _, t := range in {
		out = append(out, map[string]any{
			"name": t.Name, "enabled": t.Enabled, "interface": t.Interface,
			"addresses": t.Addresses, "dns": t.DNS, "mtu": t.MTU,
			"peer_public_key": t.PeerPublicKey, "endpoint": t.Endpoint,
			"allowed_ips": t.AllowedIPs, "keepalive": t.Keepalive,
			"route_table": t.RouteTable, "kill_switch": t.KillSwitch,
			"note": t.Note,
			// The private and preshared keys never leave the node.
			"has_preshared_key": t.PresharedKey != "",
		})
	}
	return out
}

// handleImportTunnel accepts a pasted wg-quick config, which is how every
// provider distributes one. Retyping five base64 fields into a form is how
// people end up with a tunnel that will not handshake for reasons they cannot
// see.
func (s *Server) handleImportTunnel(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name       string `json:"name"`
		Config     string `json:"config"`
		KillSwitch bool   `json:"kill_switch"`
		Enable     bool   `json:"enable"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if strings.TrimSpace(req.Config) == "" {
		writeErr(w, http.StatusBadRequest, "paste the .conf file contents")
		return
	}
	parsed, err := vpn.ParseWGQuick(req.Config)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.Name == "" {
		req.Name = "tunnel"
	}

	tunnel := config.TunnelConfig{
		Name: req.Name, Enabled: req.Enable, PrivateKey: parsed.PrivateKey,
		Addresses: parsed.Addresses, DNS: parsed.DNS, MTU: parsed.MTU,
		PeerPublicKey: parsed.PeerPublicKey, PresharedKey: parsed.PresharedKey,
		Endpoint: parsed.Endpoint, AllowedIPs: parsed.AllowedIPs,
		Keepalive: parsed.Keepalive, KillSwitch: req.KillSwitch,
	}
	if err := s.saveTunnel(tunnel, true); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.app.SyncEgress(r.Context()); err != nil {
		// The tunnel is saved either way; report the failure rather than
		// discarding a config the operator just pasted.
		writeJSON(w, http.StatusAccepted, map[string]any{
			"saved": true, "warning": err.Error(), "ignored": parsed.Ignored,
		})
		return
	}
	s.app.Store.Audit(r.RemoteAddr, "vpn.tunnel.import", req.Name, "", "", "ok")
	writeJSON(w, http.StatusCreated, map[string]any{
		"saved": true, "ignored": parsed.Ignored,
	})
}

func (s *Server) handleCreateTunnel(w http.ResponseWriter, r *http.Request) {
	var t config.TunnelConfig
	if err := decodeJSON(r, &t); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if t.Name == "" || t.PrivateKey == "" || t.PeerPublicKey == "" || t.Endpoint == "" {
		writeErr(w, http.StatusBadRequest, "name, private key, peer public key and endpoint are all required")
		return
	}
	if err := s.saveTunnel(t, true); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.app.SyncEgress(r.Context()); err != nil {
		writeJSON(w, http.StatusAccepted, map[string]any{"saved": true, "warning": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"saved": true})
}

func (s *Server) handleUpdateTunnel(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	var req struct {
		Enabled    *bool    `json:"enabled"`
		KillSwitch *bool    `json:"kill_switch"`
		DNS        []string `json:"dns"`
		MTU        *int     `json:"mtu"`
		AllowedIPs []string `json:"allowed_ips"`
		Note       *string  `json:"note"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	err := s.cfg.Update(func(c *config.Config) {
		for i := range c.VPN.Tunnels {
			if c.VPN.Tunnels[i].Name != name {
				continue
			}
			if req.Enabled != nil {
				c.VPN.Tunnels[i].Enabled = *req.Enabled
			}
			if req.KillSwitch != nil {
				c.VPN.Tunnels[i].KillSwitch = *req.KillSwitch
			}
			if req.DNS != nil {
				c.VPN.Tunnels[i].DNS = req.DNS
			}
			if req.MTU != nil {
				c.VPN.Tunnels[i].MTU = *req.MTU
			}
			if req.AllowedIPs != nil {
				c.VPN.Tunnels[i].AllowedIPs = req.AllowedIPs
			}
			if req.Note != nil {
				c.VPN.Tunnels[i].Note = *req.Note
			}
		}
	})
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.app.SyncEgress(r.Context()); err != nil {
		writeJSON(w, http.StatusAccepted, map[string]any{"saved": true, "warning": err.Error()})
		return
	}
	s.app.Store.Audit(r.RemoteAddr, "vpn.tunnel.update", name, "", "", "ok")
	writeOK(w, map[string]any{"ok": true})
}

func (s *Server) handleDeleteTunnel(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	err := s.cfg.Update(func(c *config.Config) {
		out := c.VPN.Tunnels[:0]
		for _, t := range c.VPN.Tunnels {
			if t.Name != name {
				out = append(out, t)
			}
		}
		c.VPN.Tunnels = out
		// Devices routed through a tunnel that no longer exists would
		// otherwise be left with a rule pointing at an empty table, which
		// blackholes them.
		routes := c.VPN.Routes[:0]
		for _, rt := range c.VPN.Routes {
			if rt.TargetID != name {
				routes = append(routes, rt)
			}
		}
		c.VPN.Routes = routes
	})
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.app.SyncEgress(r.Context()); err != nil {
		s.app.Log("vpn: resync after deleting %s: %v", name, err)
	}
	s.app.Store.Audit(r.RemoteAddr, "vpn.tunnel.delete", name, "", "", "ok")
	writeOK(w, map[string]any{"ok": true})
}

func (s *Server) handleTunnelAction(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	action := chi.URLParam(r, "action")
	enable := action == "start"
	if action != "start" && action != "stop" {
		writeErr(w, http.StatusBadRequest, "action must be start or stop")
		return
	}
	err := s.cfg.Update(func(c *config.Config) {
		for i := range c.VPN.Tunnels {
			if c.VPN.Tunnels[i].Name == name {
				c.VPN.Tunnels[i].Enabled = enable
			}
		}
	})
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.app.SyncEgress(r.Context()); err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	s.app.Store.Audit(r.RemoteAddr, "vpn.tunnel."+action, name, "", "", "ok")
	writeOK(w, map[string]any{"targets": s.app.EgressTargets(r.Context())})
}

func (s *Server) handleAssignEgress(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ClientID string `json:"client_id"`
		Target   string `json:"target"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.app.AssignDeviceEgress(r.Context(), req.ClientID, req.Target); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeOK(w, map[string]any{"ok": true, "status": s.app.Egress.Status(r.Context())})
}

func (s *Server) handleAssignAll(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Target string `json:"target"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.app.SetAllDevicesEgress(r.Context(), req.Target); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeOK(w, map[string]any{"ok": true, "status": s.app.Egress.Status(r.Context())})
}

// saveTunnel adds or replaces a tunnel, allocating a routing table id.
func (s *Server) saveTunnel(t config.TunnelConfig, replace bool) error {
	return s.cfg.Update(func(c *config.Config) {
		var tables []int
		for _, existing := range c.VPN.Tunnels {
			tables = append(tables, existing.RouteTable)
		}
		if t.RouteTable == 0 {
			t.RouteTable = s.app.Egress.AllocateTable(tables)
		}
		if t.Interface == "" {
			t.Interface = "wgc-" + strings.ToLower(sanitizeFilename(t.Name))
			if len(t.Interface) > 15 {
				t.Interface = t.Interface[:15]
			}
		}
		for i := range c.VPN.Tunnels {
			if c.VPN.Tunnels[i].Name == t.Name {
				if !replace {
					return
				}
				// Keep the table already allocated, or every save would
				// orphan the rules pointing at the old one.
				t.RouteTable = c.VPN.Tunnels[i].RouteTable
				c.VPN.Tunnels[i] = t
				return
			}
		}
		c.VPN.Tunnels = append(c.VPN.Tunnels, t)
	})
}
