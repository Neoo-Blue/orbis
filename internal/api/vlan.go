package api

import (
	"net/http"

	"github.com/Neoo-Blue/orbis/internal/config"
	"github.com/Neoo-Blue/orbis/internal/netconf"
	"github.com/go-chi/chi/v5"
)

func (s *Server) mountNetwork(r chi.Router) {
	r.Route("/network/vlans", func(r chi.Router) {
		r.Get("/", s.handleListVLANs)
		r.Post("/", s.handleSaveVLAN)
		r.Put("/{name}", s.handleSaveVLAN)
		r.Delete("/{name}", s.handleDeleteVLAN)
	})
	r.Get("/proxy/readiness", s.handleProxyReadiness)
}

func (s *Server) handleListVLANs(w http.ResponseWriter, r *http.Request) {
	available, why := s.app.Net.Available()
	writeOK(w, map[string]any{
		"vlans":      s.app.VLANStates(),
		"available":  available,
		"reason":     why,
		"last_error": s.app.Net.LastError(),
		"parents":    physicalInterfaces(),
	})
}

// physicalInterfaces lists the interfaces a VLAN can be built on: real
// devices, not tunnels or other VLANs, since stacking tags is almost never
// what someone means.
func physicalInterfaces() []string {
	var out []string
	for _, i := range listInterfaces() {
		if i.loopbackOrVirtual() {
			continue
		}
		out = append(out, i.Name)
	}
	return out
}

func (s *Server) handleSaveVLAN(w http.ResponseWriter, r *http.Request) {
	var v netconf.VLAN
	if err := decodeJSON(r, &v); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := v.Validate(); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	target := chi.URLParam(r, "name")

	err := s.cfg.Update(func(c *config.Config) {
		name := v.DefaultName()
		for i := range c.Network.VLANs {
			existing := c.Network.VLANs[i].DefaultName()
			if existing == name || (target != "" && existing == target) {
				c.Network.VLANs[i] = v
				return
			}
		}
		c.Network.VLANs = append(c.Network.VLANs, v)
	})
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.app.SyncVLANs(); err != nil {
		// The configuration is saved either way; report what could not be
		// applied rather than discarding it.
		writeJSON(w, http.StatusAccepted, map[string]any{"saved": true, "warning": err.Error()})
		return
	}
	s.app.Store.Audit(r.RemoteAddr, "network.vlan.save", v.DefaultName(), "", "", "ok")
	writeJSON(w, http.StatusCreated, map[string]any{"saved": true, "vlans": s.app.VLANStates()})
}

func (s *Server) handleDeleteVLAN(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	err := s.cfg.Update(func(c *config.Config) {
		out := c.Network.VLANs[:0]
		for _, v := range c.Network.VLANs {
			if v.DefaultName() != name {
				out = append(out, v)
			}
		}
		c.Network.VLANs = out
		// A zone left pointing at a deleted interface would produce a
		// ruleset nft rejects, taking the whole firewall down with it.
		for i := range c.Firewall.Zones {
			ifaces := c.Firewall.Zones[i].Interfaces[:0]
			for _, iface := range c.Firewall.Zones[i].Interfaces {
				if iface != name {
					ifaces = append(ifaces, iface)
				}
			}
			c.Firewall.Zones[i].Interfaces = ifaces
		}
	})
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.app.SyncVLANs(); err != nil {
		s.app.Log("network: resync after deleting %s: %v", name, err)
	}
	s.app.Store.Audit(r.RemoteAddr, "network.vlan.delete", name, "", "", "ok")
	writeOK(w, map[string]any{"ok": true, "vlans": s.app.VLANStates()})
}

// handleProxyReadiness answers "why am I still seeing ads". Each check is a
// thing that has to be true for in-stream filtering to work, and the failure
// of any one of them looks identical from the sofa.
func (s *Server) handleProxyReadiness(w http.ResponseWriter, r *http.Request) {
	cfg := s.cfg.Snapshot()
	stats := map[string]any{}
	if s.app.MITM != nil {
		stats = s.app.MITM.Stats()
	}
	tunnel := s.app.Firewall.TunnelStatus()

	accepted := toInt(stats["accepted"])
	intercepted := toInt(stats["intercepted"])
	stripped := toInt(stats["ads_stripped"])

	type check struct {
		Name   string `json:"name"`
		OK     bool   `json:"ok"`
		Detail string `json:"detail"`
		Fix    string `json:"fix,omitempty"`
	}
	checks := []check{
		{
			Name: "Filter proxy running", OK: cfg.MITM.Enabled && toBool(stats["running"]),
			Detail: pick(cfg.MITM.Enabled && toBool(stats["running"]), "listening", "stopped"),
			Fix:    "Turn on the in-stream filter under Ad blocking → In-stream ads.",
		},
		{
			Name: "Traffic redirected to it", OK: tunnel.Applied && accepted > 0,
			Detail: pick(accepted > 0,
				itoa(accepted)+" connections seen",
				"no connection has ever reached the proxy"),
			Fix: "Traffic only reaches the proxy if this node is inline for the LAN, or the device " +
				"comes in over the VPN. In observe mode nothing on the LAN passes through here.",
		},
		{
			Name: "TLS being decrypted", OK: intercepted > 0,
			Detail: pick(intercepted > 0,
				itoa(intercepted)+" connections decrypted",
				"connections arrive but none are being decrypted"),
			Fix: "The device has to trust the Orbis CA. Until it does, its connections are passed " +
				"through untouched rather than broken — which is why nothing changes.",
		},
		{
			Name: "Ads being stripped", OK: stripped > 0,
			Detail: pick(stripped > 0,
				itoa(stripped)+" ad structures removed",
				"no ads have been removed yet"),
			Fix: "If the checks above are green and this is not, the ads you are seeing are " +
				"server-side stitched into the video stream, which nothing on a network can remove.",
		},
	}

	// A single-homed node has no LAN side to redirect: its one interface is
	// the WAN. Only tunnel clients can be filtered there, and saying so beats
	// leaving someone to wonder why their laptop is unaffected.
	lanRedirect := len(tunnel.Interfaces) > 0
	hasLANSide := false
	for _, z := range cfg.Firewall.Zones {
		if z.Trust != "wan" && len(z.Interfaces) > 0 {
			hasLANSide = true
		}
	}
	if cfg.MITM.Enabled && !hasLANSide {
		checks = append(checks, check{
			Name: "LAN devices covered", OK: false,
			Detail: pick(lanRedirect,
				"only devices arriving over the VPN are filtered",
				"no interface is carrying LAN traffic through this node"),
			Fix: "This node has no LAN-side interface in a zone, so LAN traffic does not pass " +
				"through it and cannot be redirected. Devices reaching the network over WireGuard " +
				"or a Tailscale exit node are filtered; anything on the LAN is not.",
		})
	}

	var firstProblem string
	for _, c := range checks {
		if !c.OK {
			firstProblem = c.Fix
			break
		}
	}

	writeOK(w, map[string]any{
		"checks":          checks,
		"next_step":       firstProblem,
		"stats":           stats,
		"intercept_hosts": cfg.MITM.InterceptHosts,
		"only_clients":    cfg.MITM.OnlyClients,
		"mode":            string(cfg.Mode),
	})
}

func pick(ok bool, yes, no string) string {
	if ok {
		return yes
	}
	return no
}

func toInt(v any) int {
	switch n := v.(type) {
	case int:
		return n
	case int64:
		return int(n)
	case float64:
		return int(n)
	}
	return 0
}

func toBool(v any) bool {
	b, _ := v.(bool)
	return b
}
