package api

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/Neoo-Blue/orbis/internal/config"
	"github.com/Neoo-Blue/orbis/internal/flows"
	"github.com/Neoo-Blue/orbis/internal/netconf"
	"github.com/go-chi/chi/v5"
)

// mountGateway registers routing, multi-WAN, shaping, port mapping and the
// live diagnostic tools.
func (s *Server) mountGateway(r chi.Router) {
	r.Route("/routes", func(r chi.Router) {
		r.Get("/", s.handleRoutesList)
		r.Post("/", s.handleRouteSave)
		r.Delete("/{name}", s.handleRouteDelete)
		r.Post("/apply", s.handleRoutesApply)
	})

	r.Route("/wan", func(r chi.Router) {
		r.Get("/", s.handleWANStatus)
		r.Post("/settings", s.handleWANSettings)
	})

	r.Route("/shaping", func(r chi.Router) {
		r.Get("/", s.handleShapingStatus)
		r.Post("/", s.handleShapingApply)
	})

	r.Route("/portmap", func(r chi.Router) {
		r.Get("/", s.handlePortMapList)
		r.Delete("/{proto}/{port}", s.handlePortMapDelete)
	})

	r.Route("/tools", func(r chi.Router) {
		r.Post("/ping", s.handleToolPing)
		r.Post("/traceroute", s.handleToolTraceroute)
		r.Post("/wol", s.handleToolWOL)
		r.Post("/speedtest", s.handleToolSpeedtest)
		r.Post("/capture", s.handleToolCapture)
	})
}

// ---- static routes ----

func (s *Server) handleRoutesList(w http.ResponseWriter, r *http.Request) {
	cfg := s.cfg.Snapshot()
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	kernel, _ := s.app.Net.KernelRoutes(ctx, queryBool(r, "ipv6"))
	writeOK(w, map[string]any{
		"configured": orEmptyRoutes(cfg.Network.Routes),
		"kernel":     kernel,
	})
}

func (s *Server) handleRouteSave(w http.ResponseWriter, r *http.Request) {
	var route netconf.StaticRoute
	if err := decodeJSON(r, &route); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if route.Name == "" {
		writeErr(w, http.StatusBadRequest, "name is required")
		return
	}
	if err := route.Validate(); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	err := s.cfg.Update(func(c *config.Config) {
		for i := range c.Network.Routes {
			if c.Network.Routes[i].Name == route.Name {
				c.Network.Routes[i] = route
				return
			}
		}
		c.Network.Routes = append(c.Network.Routes, route)
	})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.applyRoutes(r)
	s.app.Store.Audit(r.RemoteAddr, "route.save", route.Name, "", route.Destination, "ok")
	writeOK(w, route)
}

func (s *Server) handleRouteDelete(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	var removed *netconf.StaticRoute
	err := s.cfg.Update(func(c *config.Config) {
		out := c.Network.Routes[:0]
		for _, rt := range c.Network.Routes {
			if rt.Name == name {
				cp := rt
				removed = &cp
				continue
			}
			out = append(out, rt)
		}
		c.Network.Routes = out
	})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	// Take the route out of the kernel too, or deleting it from the config
	// leaves it installed until the next reboot.
	if removed != nil {
		removed.Enabled = false
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		_ = s.app.Net.ApplyRoutes(ctx, []netconf.StaticRoute{*removed})
		cancel()
	}
	s.app.Store.Audit(r.RemoteAddr, "route.delete", name, "", "", "ok")
	writeOK(w, map[string]any{"ok": true})
}

func (s *Server) handleRoutesApply(w http.ResponseWriter, r *http.Request) {
	if err := s.applyRoutes(r); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeOK(w, map[string]any{"ok": true})
}

func (s *Server) applyRoutes(r *http.Request) error {
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	return s.app.Net.ApplyRoutes(ctx, s.cfg.Snapshot().Network.Routes)
}

func orEmptyRoutes(in []netconf.StaticRoute) []netconf.StaticRoute {
	if in == nil {
		return []netconf.StaticRoute{}
	}
	return in
}

// ---- multi-WAN ----

func (s *Server) handleWANStatus(w http.ResponseWriter, r *http.Request) {
	cfg := s.cfg.Snapshot().Network.MultiWAN
	writeOK(w, map[string]any{
		"config":  cfg,
		"running": s.app.WAN.Running(),
		"active":  s.app.WAN.Active(),
		"links":   s.app.WAN.States(),
	})
}

func (s *Server) handleWANSettings(w http.ResponseWriter, r *http.Request) {
	var incoming netconf.MultiWANConfig
	if err := decodeJSON(r, &incoming); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	for _, l := range incoming.Links {
		if l.Enabled && l.Interface == "" {
			writeErr(w, http.StatusBadRequest,
				fmt.Sprintf("uplink %q needs an interface", l.Name))
			return
		}
	}
	if err := s.cfg.Update(func(c *config.Config) { c.Network.MultiWAN = incoming }); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	// Restart the monitor so a changed probe list or interval takes effect now
	// rather than at the next daemon restart.
	s.app.RestartWANMonitor()
	s.app.Store.Audit(r.RemoteAddr, "wan.settings", "", "", "", "ok")
	writeOK(w, map[string]any{
		"config": incoming, "running": s.app.WAN.Running(), "links": s.app.WAN.States(),
	})
}

// ---- shaping ----

func (s *Server) handleShapingStatus(w http.ResponseWriter, r *http.Request) {
	cfg := s.cfg.Snapshot().Network.Shaping
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	writeOK(w, map[string]any{
		"config": cfg,
		"status": s.app.Net.ShapingStatusFor(ctx, cfg.Interface),
	})
}

func (s *Server) handleShapingApply(w http.ResponseWriter, r *http.Request) {
	var incoming netconf.ShapingConfig
	if err := decodeJSON(r, &incoming); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.cfg.Update(func(c *config.Config) { c.Network.Shaping = incoming }); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	st, err := s.app.Net.ApplyShaping(ctx, incoming)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.app.Store.Audit(r.RemoteAddr, "shaping.apply", incoming.Interface, "", "", "ok")
	writeOK(w, map[string]any{"config": incoming, "status": st})
}

// ---- NAT-PMP ----

func (s *Server) handlePortMapList(w http.ResponseWriter, r *http.Request) {
	writeOK(w, map[string]any{
		"config":   s.cfg.Snapshot().Network.PortMap,
		"running":  s.app.PortMap.Running(),
		"mappings": s.app.PortMap.Mappings(),
	})
}

func (s *Server) handlePortMapDelete(w http.ResponseWriter, r *http.Request) {
	proto := chi.URLParam(r, "proto")
	port, err := parseUint16(chi.URLParam(r, "port"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad port")
		return
	}
	if !s.app.PortMap.Delete(proto, port) {
		writeErr(w, http.StatusNotFound, "no such mapping")
		return
	}
	s.app.Store.Audit(r.RemoteAddr, "portmap.delete", fmt.Sprintf("%s/%d", proto, port), "", "", "ok")
	writeOK(w, map[string]any{"ok": true})
}

func parseUint16(s string) (uint16, error) {
	var n int
	if _, err := fmt.Sscanf(s, "%d", &n); err != nil {
		return 0, err
	}
	if n < 0 || n > 65535 {
		return 0, fmt.Errorf("out of range")
	}
	return uint16(n), nil
}

// ---- live tools ----

func (s *Server) handleToolPing(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Target string `json:"target"`
		Count  int    `json:"count"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	res, err := netconf.Ping(r.Context(), req.Target, req.Count)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeOK(w, res)
}

func (s *Server) handleToolTraceroute(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Target  string `json:"target"`
		MaxHops int    `json:"max_hops"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	hops, raw, err := netconf.Traceroute(r.Context(), req.Target, req.MaxHops)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeOK(w, map[string]any{"hops": hops, "raw": raw})
}

func (s *Server) handleToolWOL(w http.ResponseWriter, r *http.Request) {
	var req struct {
		MAC       string `json:"mac"`
		Broadcast string `json:"broadcast"`
		Port      int    `json:"port"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	// When no broadcast is given, derive one from the DHCP scope so waking a
	// device on a tagged VLAN reaches the right segment.
	if req.Broadcast == "" {
		for _, sc := range s.cfg.Snapshot().DHCP.Scopes {
			if b := netconf.BroadcastFor(sc.Subnet); b != "" {
				req.Broadcast = b
				break
			}
		}
	}
	if err := netconf.WakeOnLAN(req.MAC, req.Broadcast, req.Port); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.app.Store.Audit(r.RemoteAddr, "tools.wol", req.MAC, "", req.Broadcast, "ok")
	writeOK(w, map[string]any{"ok": true, "broadcast": req.Broadcast})
}

func (s *Server) handleToolSpeedtest(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 120*time.Second)
	defer cancel()
	res, err := netconf.RunSpeedTest(ctx)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	s.app.Store.Audit(r.RemoteAddr, "tools.speedtest", "", "",
		fmt.Sprintf("%.1f/%.1f Mbps", res.DownloadMbps, res.UploadMbps), "ok")
	writeOK(w, res)
}

// handleToolCapture streams a pcap file. It writes directly to the response so
// a large capture never has to be buffered in memory on the node.
func (s *Server) handleToolCapture(w http.ResponseWriter, r *http.Request) {
	var req flows.CaptureRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.Interface == "" {
		writeErr(w, http.StatusBadRequest, "interface is required")
		return
	}
	name := fmt.Sprintf("orbis-%s-%s.pcap", req.Interface, time.Now().Format("150405"))
	w.Header().Set("Content-Type", "application/vnd.tcpdump.pcap")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)

	res, err := flows.CaptureToWriter(r.Context(), w, req)
	if err != nil {
		// The header is already sent if any bytes were written, so an error
		// here can only be reported when nothing has gone out yet.
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.app.Store.Audit(r.RemoteAddr, "tools.capture", req.Interface, req.Filter,
		fmt.Sprintf("%d bytes", res.Bytes), "ok")
}
