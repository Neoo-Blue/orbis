package api

import (
	"net/http"
	"strings"

	"github.com/Neoo-Blue/orbis/internal/config"
	"github.com/go-chi/chi/v5"
)

// First-run onboarding.
//
// The thing a new node most needs to tell you is not which features exist, it
// is whether it can see anything at all. A node that is not on the traffic path
// records its own DNS lookups and some broadcast noise, and every screen then
// looks plausibly populated while being empty of the network. So the wizard's
// job is to establish placement first and features second, and to say plainly
// when the answer is "this node will see almost nothing".

func (s *Server) mountOnboarding(r chi.Router) {
	r.Route("/onboarding", func(r chi.Router) {
		r.Get("/", s.handleOnboardingState)
		r.Post("/apply", s.handleOnboardingApply)
		r.Post("/reset", s.handleOnboardingReset)
	})
}

// PlacementCheck is one observation about where this node sits.
type PlacementCheck struct {
	Name   string `json:"name"`
	Status string `json:"status"` // ok | warn | fail
	Detail string `json:"detail"`
	Fix    string `json:"fix,omitempty"`
}

func (s *Server) handleOnboardingState(w http.ResponseWriter, r *http.Request) {
	cfg := s.cfg.Snapshot()
	writeOK(w, map[string]any{
		"onboarded":      cfg.Node.Onboarded,
		"mode":           cfg.Node.OnboardedMode,
		"password_set":   cfg.API.AdminHash != "",
		"node_name":      cfg.Node.Name,
		"current_mode":   string(cfg.Mode),
		"placement":      s.placementChecks(cfg),
		"interfaces":     listInterfaces(),
		"dns_enabled":    cfg.DNS.Enabled,
		"dhcp_enabled":   cfg.DHCP.Enabled,
		"adblock":        cfg.AdBlock.Enabled,
		"lounge_enabled": cfg.YouTube.Lounge.Enabled,
	})
}

// placementChecks answers "will this node actually see the network", which is
// the question every other screen silently depends on.
func (s *Server) placementChecks(cfg config.Config) []PlacementCheck {
	out := []PlacementCheck{}

	// 1. Is anything other than this node using it as a resolver?
	clients := 0
	if rows, err := s.app.Store.DNSClientCount(); err == nil {
		clients = rows
	}
	switch {
	case clients > 1:
		out = append(out, PlacementCheck{
			Name: "Devices using this resolver", Status: "ok",
			Detail: pluralDevices(clients) + " have sent DNS queries here.",
		})
	default:
		out = append(out, PlacementCheck{
			Name: "Devices using this resolver", Status: "fail",
			Detail: "Nothing but this node has queried it. DNS filtering is doing nothing for the network.",
			Fix:    "Point your router's DHCP at this node's address as the DNS server, or enable DHCP here and let it hand itself out.",
		})
	}

	// 2. Does the capture path see traffic from anyone else?
	foreign, total := 0, 0
	if f, t, err := s.app.Store.ForeignFlowShare(); err == nil {
		foreign, total = f, t
	}
	switch {
	case total == 0:
		out = append(out, PlacementCheck{
			Name: "Traffic visible to capture", Status: "warn",
			Detail: "No flows recorded yet. Give it a minute after enabling capture.",
		})
	case foreign == 0:
		out = append(out, PlacementCheck{
			Name: "Traffic visible to capture", Status: "fail",
			Detail: "Every recorded flow is this node's own traffic or broadcast noise. On a switched network a node that is not the gateway never sees what other devices send.",
			Fix:    "Put this node in the traffic path: bridge your router and make Orbis the gateway, or route selected devices through it.",
		})
	default:
		out = append(out, PlacementCheck{
			Name: "Traffic visible to capture", Status: "ok",
			Detail: pctDetail(foreign, total),
		})
	}

	// 3. Inline mode that does not actually route.
	if cfg.Mode == config.ModeInline && !cfg.Firewall.Enabled {
		out = append(out, PlacementCheck{
			Name: "Gateway rules", Status: "warn",
			Detail: "Mode is inline but the firewall is off, so no NAT or forwarding rules are installed. Traffic sent here is forwarded without being translated, and replies come back around this node.",
			Fix:    "Enable the firewall to install the gateway ruleset, or set the mode back to observe so the UI stops claiming to be a gateway.",
		})
	}

	// 4. Interception without a certificate anyone trusts.
	if cfg.MITM.Enabled && cfg.Mode == config.ModeInline {
		out = append(out, PlacementCheck{
			Name: "TLS interception", Status: "warn",
			Detail: "The filter proxy is on. Any device whose traffic is redirected into it and which has not installed the Orbis certificate will fail TLS and show sites as unreachable.",
			Fix:    "Install the CA on the devices you intend to filter, or narrow mitm.only_clients to just those devices.",
		})
	}

	return out
}

func pluralDevices(n int) string {
	if n == 1 {
		return "1 device"
	}
	return itoa(n) + " devices"
}

func pctDetail(foreign, total int) string {
	p := 100 * foreign / total
	return itoa(foreign) + " of " + itoa(total) + " recent flows (" + itoa(p) + "%) came from other devices."
}


// handleOnboardingApply writes the wizard's choices in one transaction, so a
// half-applied setup cannot leave the node in a state nobody chose.
func (s *Server) handleOnboardingApply(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Mode        string `json:"mode"` // simple | advanced
		NodeName    string `json:"node_name"`
		Placement   string `json:"placement"` // observe | inline
		EnableDNS   *bool  `json:"enable_dns"`
		EnableAds   *bool  `json:"enable_adblock"`
		EnableDHCP  *bool  `json:"enable_dhcp"`
		EnableYT    *bool  `json:"enable_youtube"`
		WANIface    string `json:"wan_interface"`
		Upstreams   []string `json:"upstreams"`
		Finish      bool   `json:"finish"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}

	err := s.cfg.Update(func(c *config.Config) {
		if n := strings.TrimSpace(req.NodeName); n != "" {
			c.Node.Name = n
		}
		switch req.Placement {
		case "inline":
			c.Mode = config.ModeInline
			// Inline without the firewall installs no NAT, which is the trap
			// the placement check warns about. Turning it on together is the
			// only combination that produces a working gateway.
			c.Firewall.Enabled = true
			if req.WANIface != "" {
				c.Firewall.WANInterface = req.WANIface
			}
		case "observe":
			c.Mode = config.ModeObserve
		}
		if req.EnableDNS != nil {
			c.DNS.Enabled = *req.EnableDNS
		}
		if req.EnableAds != nil {
			c.AdBlock.Enabled = *req.EnableAds
		}
		if req.EnableDHCP != nil {
			c.DHCP.Enabled = *req.EnableDHCP
		}
		if req.EnableYT != nil {
			c.YouTube.Lounge.Enabled = *req.EnableYT
		}
		if len(req.Upstreams) > 0 {
			c.DNS.Upstreams = req.Upstreams
		}
		if req.Mode != "" {
			c.Node.OnboardedMode = req.Mode
			// The wizard's choice is also the interface default, so a
			// household that picked "simple" lands on the simple screens.
			if req.Mode == "simple" || req.Mode == "advanced" {
				c.Node.UIMode = req.Mode
			}
		}
		if req.Finish {
			c.Node.Onboarded = true
		}
	})
	if err != nil {
		// Validation rejects impossible combinations (inline with no WAN
		// interface, for one), and the message says which.
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}

	// Bring the affected subsystems in line with what was just chosen, or the
	// wizard reports success while the node keeps running the old setup.
	s.app.ReloadAfterRestore()
	s.app.Store.Audit(r.RemoteAddr, "onboarding.apply", req.Placement, "", req.Mode, "ok")

	cfg := s.cfg.Snapshot()
	writeOK(w, map[string]any{
		"ok":        true,
		"onboarded": cfg.Node.Onboarded,
		"placement": s.placementChecks(cfg),
	})
}

// handleOnboardingReset re-opens the wizard without touching configuration, so
// re-running it is safe to do out of curiosity.
func (s *Server) handleOnboardingReset(w http.ResponseWriter, r *http.Request) {
	if err := s.cfg.Update(func(c *config.Config) { c.Node.Onboarded = false }); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.app.Store.Audit(r.RemoteAddr, "onboarding.reset", "", "", "", "ok")
	writeOK(w, map[string]any{"ok": true, "onboarded": false})
}
