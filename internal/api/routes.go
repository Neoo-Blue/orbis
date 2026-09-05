package api

import (
	"context"
	"fmt"
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/Neoo-Blue/orbis/internal/adblock"
	"github.com/Neoo-Blue/orbis/internal/config"
	"github.com/Neoo-Blue/orbis/internal/firewall"
	"github.com/Neoo-Blue/orbis/internal/flows"
	"github.com/Neoo-Blue/orbis/internal/geoip"
	"github.com/Neoo-Blue/orbis/internal/mitm"
	"github.com/Neoo-Blue/orbis/internal/store"
	"github.com/Neoo-Blue/orbis/internal/vpn"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

func (s *Server) mount(r chi.Router) {
	r.Route("/auth", func(r chi.Router) {
		r.Get("/status", s.handleAuthStatus)
		r.Post("/login", s.handleLogin)
		r.Post("/logout", s.handleLogout)
		r.Post("/password", s.handleSetPassword)
	})

	r.Get("/status", s.handleStatus)
	r.Get("/summary", s.handleSummary)
	r.Get("/series/{metric}", s.handleSeries)
	r.Get("/stream", s.handleWebSocket)

	r.Route("/clients", func(r chi.Router) {
		r.Get("/", s.handleClients)
		r.Get("/{id}", s.handleClient)
		r.Patch("/{id}", s.handleClientUpdate)
		r.Delete("/{id}", s.handleClientDelete)
		r.Get("/{id}/flows", s.handleClientFlows)
		r.Get("/{id}/destinations", s.handleClientDestinations)
		r.Get("/{id}/dns", s.handleClientDNS)
	})

	r.Route("/flows", func(r chi.Router) {
		r.Get("/", s.handleFlows)
		r.Get("/active", s.handleActiveFlows)
		r.Get("/globe", s.handleGlobe)
		r.Post("/{id}/block", s.handleBlockFlow)
	})

	r.Route("/dns", func(r chi.Router) {
		r.Get("/log", s.handleDNSLog)
		r.Get("/stats", s.handleDNSStats)
		r.Post("/flush", s.handleDNSFlush)
	})

	r.Route("/adblock", func(r chi.Router) {
		r.Get("/status", s.handleAdblockStatus)
		r.Get("/lists", s.handleLists)
		r.Post("/lists", s.handleAddList)
		r.Delete("/lists/{name}", s.handleDeleteList)
		r.Post("/refresh", s.handleRefreshLists)
		r.Get("/top-blocked", s.handleTopBlocked)
		r.Get("/rules", s.handleLocalRules)
		r.Post("/rules", s.handleAddLocalRule)
		r.Delete("/rules/{domain}", s.handleDeleteLocalRule)
		r.Get("/candidates", s.handleCandidates)
		r.Post("/candidates/{domain}", s.handleDecideCandidate)
		r.Post("/scan", s.handleSmartScan)
		r.Get("/check/{domain}", s.handleCheckDomain)
	})

	r.Route("/firewall", func(r chi.Router) {
		r.Get("/rules", s.handleRules)
		r.Post("/rules", s.handleCreateRule)
		r.Put("/rules/{id}", s.handleUpdateRule)
		r.Delete("/rules/{id}", s.handleDeleteRule)
		r.Post("/rules/reorder", s.handleReorderRules)
		r.Get("/preview", s.handlePreviewRuleset)
		r.Post("/apply", s.handleApplyFirewall)
		r.Post("/flush", s.handleFlushFirewall)
		r.Get("/sysctl", s.handleSysctl)
		r.Post("/sysctl", s.handleApplySysctl)
	})

	r.Route("/policies", func(r chi.Router) {
		r.Get("/", s.handlePolicies)
		r.Post("/", s.handleSavePolicy)
		r.Put("/{id}", s.handleSavePolicy)
		r.Delete("/{id}", s.handleDeletePolicy)
	})

	r.Route("/dhcp", func(r chi.Router) {
		r.Get("/leases", s.handleLeases)
		r.Delete("/leases/{mac}", s.handleDeleteLease)
		r.Get("/stats", s.handleDHCPStats)
	})

	r.Route("/vpn", func(r chi.Router) {
		r.Get("/status", s.handleVPNStatus)
		r.Get("/peers", s.handlePeers)
		r.Post("/peers", s.handleAddPeer)
		r.Delete("/peers/{id}", s.handleDeletePeer)
		r.Get("/peers/{id}/config", s.handlePeerConfig)
		r.Get("/peers/{id}/qr", s.handlePeerQR)
		r.Post("/server/{action}", s.handleVPNServerAction)
		r.Post("/clients/{name}/{action}", s.handleVPNClientAction)
	})

	s.mountTailscale(r)
	s.mountEgress(r)
	s.mountNetwork(r)

	r.Route("/proxy", func(r chi.Router) {
		r.Get("/status", s.handleProxyStatus)
		r.Get("/ca", s.handleCAInfo)
		r.Post("/{action}", s.handleProxyAction)
	})

	s.mountYouTube(r)
	s.mountOps(r)
	s.mountGateway(r)
	s.mountConsent(r)
	s.mountDNSTools(r)
	s.mountDNSRecords(r)
	s.mountReport(r)
	s.mountOnboarding(r)
	s.mountTopology(r)
	s.mountIntercept(r)

	r.Route("/events", func(r chi.Router) {
		r.Get("/", s.handleEvents)
		r.Post("/{id}/ack", s.handleAckEvent)
	})

	s.mountAI(r)
	s.mountIssues(r)

	r.Route("/chat", func(r chi.Router) {
		r.Get("/conversations", s.handleConversations)
		r.Get("/conversations/{id}", s.handleConversation)
		r.Delete("/conversations/{id}", s.handleDeleteConversation)
		r.Post("/ask", s.handleAsk)
	})

	r.Route("/config", func(r chi.Router) {
		r.Get("/", s.handleGetConfig)
		r.Patch("/", s.handlePatchConfig)
		r.Get("/interfaces", s.handleInterfaces)
	})

	r.Post("/geoip/locate", s.handleLocateSelf)
	r.Post("/geoip/backfill", s.handleGeoBackfill)
	r.Get("/audit", s.handleAudit)
	r.Get("/geoip/{ip}", s.handleGeoIP)
}

// ---- status ----

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	writeOK(w, s.app.SystemStatus())
}

func (s *Server) handleSummary(w http.ResponseWriter, r *http.Request) {
	sum, err := s.app.Summary(querySince(r, 24))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeOK(w, sum)
}

func (s *Server) handleSeries(w http.ResponseWriter, r *http.Request) {
	metric := chi.URLParam(r, "metric")
	buckets := queryInt(r, "points", 0, 1000)
	var points []map[string]any
	var err error
	if buckets > 0 {
		points, err = s.app.Store.SeriesDownsampled(metric, querySince(r, 6), buckets)
	} else {
		points, err = s.app.Store.Series(metric, querySince(r, 6))
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeOK(w, map[string]any{"metric": metric, "points": points})
}

// ---- clients ----

func (s *Server) handleClients(w http.ResponseWriter, r *http.Request) {
	clients := s.app.Clients()
	if queryBool(r, "online_only") {
		filtered := clients[:0]
		for _, c := range clients {
			if c.Online {
				filtered = append(filtered, c)
			}
		}
		clients = filtered
	}
	if q := strings.ToLower(r.URL.Query().Get("q")); q != "" {
		filtered := clients[:0]
		for _, c := range clients {
			hay := strings.ToLower(c.Label + " " + c.Hostname + " " + c.IP + " " + c.MAC + " " + c.Vendor)
			if strings.Contains(hay, q) {
				filtered = append(filtered, c)
			}
		}
		clients = filtered
	}
	sort.Slice(clients, func(i, j int) bool {
		if clients[i].Online != clients[j].Online {
			return clients[i].Online
		}
		return clients[i].LastSeen.After(clients[j].LastSeen)
	})
	writeOK(w, map[string]any{"count": len(clients), "clients": clients})
}

func (s *Server) handleClient(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	for _, c := range s.app.Clients() {
		if c.ID == id {
			writeOK(w, c)
			return
		}
	}
	writeErr(w, http.StatusNotFound, "no such device")
}

func (s *Server) handleClientUpdate(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var req struct {
		Label    *string `json:"label"`
		Zone     *string `json:"zone"`
		PolicyID *string `json:"policy_id"`
		VPNRoute *string `json:"vpn_route"`
		Notes    *string `json:"notes"`
		Blocked  *bool   `json:"blocked"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.Blocked != nil {
		if err := s.app.SetClientBlocked(id, *req.Blocked); err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	if err := s.app.Store.SetClientFields(id, req.Label, req.Zone, req.PolicyID, req.VPNRoute, req.Notes, nil); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.app.Store.Audit(r.RemoteAddr, "client.update", id, "", "", "ok")
	writeOK(w, map[string]any{"ok": true})
}

func (s *Server) handleClientDelete(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := s.app.Store.DeleteClient(id); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeOK(w, map[string]any{"ok": true})
}

func (s *Server) handleClientFlows(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if queryBool(r, "active") {
		writeOK(w, map[string]any{"flows": s.app.Tracker.ActiveForClient(id)})
		return
	}
	since := querySince(r, 24)
	flows, err := s.app.Store.Flows(store.FlowQuery{
		Since: &since, ClientID: id, Limit: queryInt(r, "limit", 200, 2000),
		Search: r.URL.Query().Get("q"), Verdict: r.URL.Query().Get("verdict"),
	})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeOK(w, map[string]any{"count": len(flows), "flows": flows})
}

func (s *Server) handleClientDestinations(w http.ResponseWriter, r *http.Request) {
	dests, err := s.app.Store.TopDestinations(querySince(r, 24), chi.URLParam(r, "id"),
		queryInt(r, "limit", 50, 300))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeOK(w, map[string]any{"destinations": dests})
}

func (s *Server) handleClientDNS(w http.ResponseWriter, r *http.Request) {
	queries, err := s.app.Store.DNSLog(querySince(r, 6), chi.URLParam(r, "id"),
		queryBool(r, "blocked_only"), r.URL.Query().Get("q"), queryInt(r, "limit", 200, 2000))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeOK(w, map[string]any{"count": len(queries), "queries": queries})
}

// ---- flows ----

func (s *Server) handleFlows(w http.ResponseWriter, r *http.Request) {
	since := querySince(r, 24)
	q := store.FlowQuery{
		Since:      &since,
		ClientID:   r.URL.Query().Get("client_id"),
		Verdict:    r.URL.Query().Get("verdict"),
		Search:     r.URL.Query().Get("q"),
		Country:    strings.ToUpper(r.URL.Query().Get("country")),
		Proto:      r.URL.Query().Get("proto"),
		Port:       queryInt(r, "port", 0, 65535),
		MinBytes:   int64(queryInt(r, "min_bytes", 0, 1<<30)),
		ActiveOnly: queryBool(r, "active"),
		Limit:      queryInt(r, "limit", 200, 5000),
		Offset:     queryInt(r, "offset", 0, 1<<20),
		OrderBy:    r.URL.Query().Get("order"),
	}
	flows, err := s.app.Store.Flows(q)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeOK(w, map[string]any{"count": len(flows), "flows": flows})
}

func (s *Server) handleActiveFlows(w http.ResponseWriter, r *http.Request) {
	flows := s.app.Tracker.Active(queryInt(r, "limit", 500, 5000))
	writeOK(w, map[string]any{"count": len(flows), "flows": flows})
}

// handleGlobe returns the arcs and points the 3D view renders: live flows
// with coordinates, plus per-country aggregates for the heat layer.
func (s *Server) handleGlobe(w http.ResponseWriter, r *http.Request) {
	mode := r.URL.Query().Get("mode")
	limit := queryInt(r, "limit", 400, 2000)

	var flows []store.Flow
	if mode == "history" {
		since := querySince(r, 24)
		var err error
		flows, err = s.app.Store.Flows(store.FlowQuery{
			Since: &since, Limit: limit, OrderBy: "bytes",
			ClientID: r.URL.Query().Get("client_id"),
		})
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
	} else {
		flows = s.app.Tracker.Active(limit)
		if cid := r.URL.Query().Get("client_id"); cid != "" {
			flows = s.app.Tracker.ActiveForClient(cid)
		}
	}

	// The globe needs a home point. Without a real geolocation for the node
	// itself, arcs would all originate from (0,0) in the Atlantic.
	home := s.homePoint()

	arcs := make([]map[string]any, 0, len(flows))
	for _, f := range flows {
		if f.Lat == 0 && f.Lon == 0 {
			continue
		}
		label := f.Hostname
		if label == "" {
			label = f.SNI
		}
		if label == "" {
			label = f.DstIP
		}
		// The arc is always drawn between this network and the remote end;
		// direction says which way the traffic actually initiated, which the
		// renderer uses to run the marker the right way. Without it every
		// connection looks outbound, and an unsolicited inbound connection —
		// the one worth noticing — is indistinguishable from a web request.
		arcs = append(arcs, map[string]any{
			"id": f.ID, "client_id": f.ClientID,
			"start_lat": home[0], "start_lng": home[1],
			"end_lat": f.Lat, "end_lng": f.Lon,
			"direction": f.Direction,
			"bytes_in":  f.BytesIn,
			"bytes_out": f.BytesOut,
			"label":     label, "app": f.App, "country": f.Country, "city": f.City,
			"org": f.ASOrg, "verdict": f.Verdict, "bytes": f.BytesIn + f.BytesOut,
			"port": f.DstPort, "proto": f.Proto, "risk": f.Risk,
			"started": f.StartedAt.Unix(), "active": f.Active(),
			"src": f.SrcIP, "dst": f.DstIP,
		})
	}
	countries, err := s.app.Store.CountryTotals(querySince(r, 24))
	if err != nil {
		countries = nil
	}
	writeOK(w, map[string]any{
		"home": map[string]any{"lat": home[0], "lng": home[1], "label": s.cfg.Snapshot().Node.Name},
		"arcs": arcs, "countries": countries, "mode": orDefault(mode, "live"),
	})
}

// homePoint places the node on the globe, in descending order of honesty:
// an explicit setting, then geolocating the node's own public address, then
// the configured timezone's centroid. No external service is consulted.
func (s *Server) homePoint() [2]float64 {
	cfg := s.cfg.Snapshot()
	if cfg.Node.Latitude != 0 || cfg.Node.Longitude != 0 {
		return [2]float64{cfg.Node.Latitude, cfg.Node.Longitude}
	}
	// A node behind NAT has no public address on any interface, so the
	// discovered one is the answer that actually works for most installs.
	if loc, ok := s.app.Self.Location(); ok {
		return [2]float64{loc.Lat, loc.Lon}
	}
	if loc, ok := s.publicSelfLocation(); ok {
		return loc
	}
	if cfg.Node.Timezone != "" {
		if c, ok := timezoneCentroid[cfg.Node.Timezone]; ok {
			return c
		}
	}
	return [2]float64{39.0, -98.0}
}

// publicSelfLocation geolocates the first globally-routable address on this
// host. On a node behind NAT there will not be one, which is why this is a
// preference rather than the only strategy.
func (s *Server) publicSelfLocation() ([2]float64, bool) {
	var addrs []netip.Addr
	for _, cidr := range flows.LocalPrefixes() {
		if p, err := netip.ParsePrefix(cidr); err == nil {
			addrs = append(addrs, p.Addr())
		}
	}
	pub, ok := geoip.PublicAddrOf(addrs)
	if !ok {
		return [2]float64{}, false
	}
	loc := s.app.Geo.LookupAddr(pub)
	if loc.Lat == 0 && loc.Lon == 0 {
		return [2]float64{}, false
	}
	return [2]float64{loc.Lat, loc.Lon}, true
}

func (s *Server) handleBlockFlow(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if !s.app.Tracker.BlockFlow(id, "blocked from UI") {
		writeErr(w, http.StatusNotFound, "connection is no longer active")
		return
	}
	s.app.Store.Audit(r.RemoteAddr, "flow.block", id, "", "", "ok")
	writeOK(w, map[string]any{"ok": true})
}

// ---- DNS ----

func (s *Server) handleDNSLog(w http.ResponseWriter, r *http.Request) {
	queries, err := s.app.Store.DNSLog(querySince(r, 1), r.URL.Query().Get("client_id"),
		queryBool(r, "blocked_only"), r.URL.Query().Get("q"), queryInt(r, "limit", 200, 2000))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeOK(w, map[string]any{"count": len(queries), "queries": queries})
}

func (s *Server) handleDNSStats(w http.ResponseWriter, r *http.Request) {
	writeOK(w, s.app.DNS.Stats())
}

func (s *Server) handleDNSFlush(w http.ResponseWriter, r *http.Request) {
	domain := r.URL.Query().Get("domain")
	n := s.app.FlushDNSCache(domain)
	writeOK(w, map[string]any{"flushed": n})
}

// ---- adblock ----

func (s *Server) handleAdblockStatus(w http.ResponseWriter, r *http.Request) {
	writeOK(w, s.app.Lists.Status())
}

func (s *Server) handleLists(w http.ResponseWriter, r *http.Request) {
	metas, err := s.app.Store.ListMetas()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	cfg := s.cfg.Snapshot()
	// The built-in lists live in the binary, not the database, so they are
	// described here rather than stored: the UI shows them beside the
	// subscriptions with the same switch semantics.
	builtin := []map[string]any{
		{
			"id": "streaming-ads", "name": "Streaming devices: ads and viewing telemetry",
			"entries": adblock.StreamingAdDomainCount(), "enabled": cfg.AdBlock.StreamingAds,
			"category": "ads", "key": "adblock.streaming_ads",
			"description": "Samsung, LG, Roku, Fire TV, Vizio and the ACR vendors inside other brands; the CTV ad exchanges; music-app ad trackers. Only hosts no stream depends on.",
		},
		{
			"id": "doh-bypass", "name": "Public encrypted-DNS resolvers",
			"entries": adblock.DoHBypassDomainCount(), "enabled": cfg.AdBlock.BlockDNSBypass,
			"category": "bypass", "key": "adblock.block_dns_bypass",
			"description": "The well-known DoH and DoQ endpoints a device can use to route around this resolver.",
		},
	}
	writeOK(w, map[string]any{"lists": metas, "builtin": builtin})
}

func (s *Server) handleAddList(w http.ResponseWriter, r *http.Request) {
	var req config.BlockList
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.Name == "" || req.URL == "" {
		writeErr(w, http.StatusBadRequest, "name and url are required")
		return
	}
	if !strings.HasPrefix(req.URL, "http://") && !strings.HasPrefix(req.URL, "https://") {
		writeErr(w, http.StatusBadRequest, "url must be http or https")
		return
	}
	err := s.cfg.Update(func(c *config.Config) {
		for i := range c.AdBlock.Lists {
			if c.AdBlock.Lists[i].Name == req.Name {
				c.AdBlock.Lists[i] = req
				return
			}
		}
		c.AdBlock.Lists = append(c.AdBlock.Lists, req)
	})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		if err := s.app.Lists.UpdateAll(ctx, false); err != nil {
			s.app.Log("adblock: refresh after list add: %v", err)
		}
	}()
	writeOK(w, map[string]any{"ok": true})
}

func (s *Server) handleDeleteList(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	err := s.cfg.Update(func(c *config.Config) {
		out := c.AdBlock.Lists[:0]
		for _, l := range c.AdBlock.Lists {
			if l.Name != name {
				out = append(out, l)
			}
		}
		c.AdBlock.Lists = out
	})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := s.app.Store.DeleteList(name); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := s.app.Lists.Rebuild(); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeOK(w, map[string]any{"ok": true})
}

func (s *Server) handleRefreshLists(w http.ResponseWriter, r *http.Request) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()
		if err := s.app.RefreshBlocklists(ctx); err != nil {
			s.app.Log("adblock: manual refresh: %v", err)
		}
	}()
	writeOK(w, map[string]any{"started": true})
}

func (s *Server) handleTopBlocked(w http.ResponseWriter, r *http.Request) {
	top, err := s.app.Store.TopBlocked(querySince(r, 24), queryInt(r, "limit", 25, 200))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeOK(w, map[string]any{"domains": top})
}

func (s *Server) handleLocalRules(w http.ResponseWriter, r *http.Request) {
	rules, err := s.app.Store.LocalRules()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeOK(w, map[string]any{"rules": rules})
}

func (s *Server) handleAddLocalRule(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Domain   string `json:"domain"`
		Action   string `json:"action"`
		Wildcard bool   `json:"wildcard"`
		Note     string `json:"note"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	var err error
	if req.Action == "allow" {
		err = s.app.AllowDomain(req.Domain, req.Note)
	} else {
		err = s.app.BlockDomain(req.Domain, req.Wildcard, req.Note)
	}
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeOK(w, map[string]any{"ok": true})
}

func (s *Server) handleDeleteLocalRule(w http.ResponseWriter, r *http.Request) {
	domain := chi.URLParam(r, "domain")
	if err := s.app.Store.DeleteLocalRule(domain); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := s.app.Lists.Rebuild(); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.app.FlushDNSCache(domain)
	writeOK(w, map[string]any{"ok": true})
}

func (s *Server) handleCandidates(w http.ResponseWriter, r *http.Request) {
	status := r.URL.Query().Get("status")
	minScore := 0.0
	if v := r.URL.Query().Get("min_score"); v != "" {
		fmt.Sscanf(v, "%f", &minScore)
	}
	cands, err := s.app.Store.Candidates(status, minScore, queryInt(r, "limit", 100, 1000))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeOK(w, map[string]any{"count": len(cands), "candidates": cands})
}

func (s *Server) handleDecideCandidate(w http.ResponseWriter, r *http.Request) {
	domain := chi.URLParam(r, "domain")
	var req struct {
		Decision string `json:"decision"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.app.DecideCandidate(domain, req.Decision, "ui:"+r.RemoteAddr); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeOK(w, map[string]any{"ok": true})
}

// handleSmartScan forces an immediate scoring pass instead of waiting for the
// timer, which is what an operator wants right after enabling the feature.
func (s *Server) handleSmartScan(w http.ResponseWriter, r *http.Request) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		if err := s.app.Smart.Pass(ctx); err != nil {
			s.app.Log("smart-capture: manual pass: %v", err)
		}
	}()
	writeOK(w, map[string]any{"started": true})
}

// handleCheckDomain explains exactly why a domain is or is not blocked. This
// is the answer to "why can't I reach X", and having it one click away is the
// difference between a filter people trust and one they turn off.
func (s *Server) handleCheckDomain(w http.ResponseWriter, r *http.Request) {
	domain := chi.URLParam(r, "domain")
	match := s.app.Matcher.Lookup(domain)
	out := map[string]any{
		"domain":  domain,
		"blocked": match.Blocked,
		"allowed": match.Allowed,
	}
	if match.Source != "" {
		out["source"] = match.Source
	}
	if match.Rule != "" {
		out["matched_rule"] = match.Rule
	}
	if match.Category != "" {
		out["category"] = match.Category
	}
	if !match.Blocked && !match.Allowed {
		out["explanation"] = "No blocklist or local rule matches this name."
	} else if match.Blocked {
		out["explanation"] = fmt.Sprintf("Blocked by %s via the rule %q.", match.Source, match.Rule)
	} else {
		out["explanation"] = fmt.Sprintf("Explicitly allowed by %s, overriding any blocklist.", match.Source)
	}
	// Show the smart-capture evidence too, when there is any.
	if cands, err := s.app.Store.Candidates("", 0, 1000); err == nil {
		for _, c := range cands {
			if c.Domain == domain {
				out["candidate"] = c
				break
			}
		}
	}
	writeOK(w, out)
}

// ---- firewall ----

func (s *Server) handleRules(w http.ResponseWriter, r *http.Request) {
	rules, err := s.app.Store.Rules()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeOK(w, map[string]any{"rules": rules})
}

func (s *Server) handleCreateRule(w http.ResponseWriter, r *http.Request) {
	var rule store.Rule
	if err := decodeJSON(r, &rule); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if rule.Name == "" || rule.Chain == "" || rule.Action == "" {
		writeErr(w, http.StatusBadRequest, "name, chain and action are required")
		return
	}
	rule.ID = uuid.NewString()
	if rule.Origin == "" {
		rule.Origin = "user"
	}
	if err := s.app.AddRule(&rule); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, rule)
}

func (s *Server) handleUpdateRule(w http.ResponseWriter, r *http.Request) {
	var rule store.Rule
	if err := decodeJSON(r, &rule); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	rule.ID = chi.URLParam(r, "id")
	if err := s.app.Store.SaveRule(&rule); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.app.Store.Audit(r.RemoteAddr, "rule.update", rule.ID, "", rule.Name, "ok")
	writeOK(w, rule)
}

func (s *Server) handleDeleteRule(w http.ResponseWriter, r *http.Request) {
	if err := s.app.DeleteRule(chi.URLParam(r, "id")); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeOK(w, map[string]any{"ok": true})
}

func (s *Server) handleReorderRules(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Chain string   `json:"chain"`
		IDs   []string `json:"ids"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.app.Store.ReorderRules(req.Chain, req.IDs); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeOK(w, map[string]any{"ok": true})
}

func (s *Server) handlePreviewRuleset(w http.ResponseWriter, r *http.Request) {
	ruleset, err := s.app.Firewall.Render()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeOK(w, map[string]any{"ruleset": ruleset, "status": s.app.Firewall.Status()})
}

func (s *Server) handleApplyFirewall(w http.ResponseWriter, r *http.Request) {
	if err := s.app.ApplyFirewall(r.Context()); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeOK(w, s.app.Firewall.Status())
}

func (s *Server) handleFlushFirewall(w http.ResponseWriter, r *http.Request) {
	if err := s.app.Firewall.Flush(r.Context()); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.app.Store.Audit(r.RemoteAddr, "firewall.flush", "", "", "", "ok")
	writeOK(w, map[string]any{"ok": true})
}

func (s *Server) handleSysctl(w http.ResponseWriter, r *http.Request) {
	writeOK(w, map[string]any{"sysctl": firewall.CheckSysctls()})
}

func (s *Server) handleApplySysctl(w http.ResponseWriter, r *http.Request) {
	result := firewall.ApplySysctls()
	s.app.Store.Audit(r.RemoteAddr, "sysctl.apply", "", "", "", "ok")
	writeOK(w, map[string]any{"sysctl": result})
}

// ---- policies ----

func (s *Server) handlePolicies(w http.ResponseWriter, r *http.Request) {
	policies, err := s.app.Store.Policies()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeOK(w, map[string]any{"policies": policies})
}

func (s *Server) handleSavePolicy(w http.ResponseWriter, r *http.Request) {
	var p store.Policy
	if err := decodeJSON(r, &p); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if id := chi.URLParam(r, "id"); id != "" {
		p.ID = id
	}
	if p.ID == "" {
		p.ID = uuid.NewString()
	}
	if p.Name == "" {
		writeErr(w, http.StatusBadRequest, "name is required")
		return
	}
	if err := s.app.Store.SavePolicy(&p); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := s.app.ReloadPolicies(); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.app.FlushDNSCache("")
	writeOK(w, p)
}

func (s *Server) handleDeletePolicy(w http.ResponseWriter, r *http.Request) {
	if err := s.app.Store.DeletePolicy(chi.URLParam(r, "id")); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = s.app.ReloadPolicies()
	writeOK(w, map[string]any{"ok": true})
}

// ---- DHCP ----

func (s *Server) handleLeases(w http.ResponseWriter, r *http.Request) {
	leases := s.app.DHCP.Leases()
	if len(leases) == 0 {
		// Fall back to the persisted table when the server is not running,
		// so the page is not blank in observe mode.
		if stored, err := s.app.Store.Leases(); err == nil {
			leases = stored
		}
	}
	sort.Slice(leases, func(i, j int) bool { return leases[i].IP < leases[j].IP })
	writeOK(w, map[string]any{"count": len(leases), "leases": leases})
}

func (s *Server) handleDeleteLease(w http.ResponseWriter, r *http.Request) {
	if err := s.app.Store.DeleteLease(chi.URLParam(r, "mac")); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeOK(w, map[string]any{"ok": true})
}

func (s *Server) handleDHCPStats(w http.ResponseWriter, r *http.Request) {
	writeOK(w, s.app.DHCP.Stats())
}

// ---- VPN ----

func (s *Server) handleVPNStatus(w http.ResponseWriter, r *http.Request) {
	writeOK(w, map[string]any{
		"status":  s.app.VPN.Status(),
		"devices": s.app.VPN.Devices(),
	})
}

func (s *Server) handlePeers(w http.ResponseWriter, r *http.Request) {
	peers, err := s.app.Store.WGPeers()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeOK(w, map[string]any{"peers": peers})
}

func (s *Server) handleAddPeer(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name       string   `json:"name"`
		AllowedIPs []string `json:"allowed_ips"`
		Note       string   `json:"note"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.Name == "" {
		writeErr(w, http.StatusBadRequest, "name is required")
		return
	}
	peer, conf, err := s.app.VPN.AddPeer(req.Name, req.AllowedIPs, req.Note)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.app.Store.Audit(r.RemoteAddr, "vpn.peer.add", peer.ID, "", req.Name, "ok")
	// The config is returned exactly once, at creation: the private key is
	// stored so it can be re-shown, but surfacing it here means the operator
	// can hand it straight to the device.
	writeJSON(w, http.StatusCreated, map[string]any{"peer": peer, "config": conf})
}

func (s *Server) handleDeletePeer(w http.ResponseWriter, r *http.Request) {
	if err := s.app.VPN.DeletePeer(chi.URLParam(r, "id")); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeOK(w, map[string]any{"ok": true})
}

func (s *Server) handlePeerConfig(w http.ResponseWriter, r *http.Request) {
	peer := s.peerByID(chi.URLParam(r, "id"))
	if peer == nil {
		writeErr(w, http.StatusNotFound, "no such peer")
		return
	}
	conf := s.app.VPN.PeerConfig(peer)
	if r.URL.Query().Get("format") == "file" {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Disposition",
			fmt.Sprintf("attachment; filename=%q", sanitizeFilename(peer.Name)+".conf"))
		_, _ = w.Write([]byte(conf))
		return
	}
	writeOK(w, map[string]any{"config": conf})
}

func (s *Server) handlePeerQR(w http.ResponseWriter, r *http.Request) {
	peer := s.peerByID(chi.URLParam(r, "id"))
	if peer == nil {
		writeErr(w, http.StatusNotFound, "no such peer")
		return
	}
	conf := s.app.VPN.PeerConfig(peer)
	png, err := qrPNG(conf)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(png)
}

func (s *Server) peerByID(id string) *store.WGPeer {
	peers, err := s.app.Store.WGPeers()
	if err != nil {
		return nil
	}
	for i := range peers {
		if peers[i].ID == id {
			return &peers[i]
		}
	}
	return nil
}

func (s *Server) handleVPNServerAction(w http.ResponseWriter, r *http.Request) {
	switch chi.URLParam(r, "action") {
	case "start":
		if err := s.cfg.Update(func(c *config.Config) { c.VPN.Server.Enabled = true }); err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		if err := s.app.VPN.StartServer(r.Context()); err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		// The wg interface only exists once the server is up, so the tunnel
		// rules and the capture set have to be built after, not before.
		s.app.SyncTunnelRules()
	case "stop":
		if err := s.app.VPN.StopServer(r.Context()); err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		_ = s.cfg.Update(func(c *config.Config) { c.VPN.Server.Enabled = false })
		s.app.SyncTunnelRules()
	case "keys":
		pub, err := s.app.VPN.EnsureServerKeys()
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeOK(w, map[string]any{"public_key": pub})
		return
	default:
		writeErr(w, http.StatusBadRequest, "action must be start, stop or keys")
		return
	}
	writeOK(w, s.app.VPN.Status())
}

func (s *Server) handleVPNClientAction(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	switch chi.URLParam(r, "action") {
	case "start":
		if err := s.app.VPN.StartClient(r.Context(), name); err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		s.app.SyncTunnelRules()
	case "stop":
		if err := s.app.VPN.StopClient(r.Context(), name); err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
	case "keys":
		priv, pub, err := vpn.GenerateKeypair()
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeOK(w, map[string]any{"private_key": priv, "public_key": pub})
		return
	default:
		writeErr(w, http.StatusBadRequest, "action must be start, stop or keys")
		return
	}
	writeOK(w, s.app.VPN.Status())
}

// ---- filter proxy ----

func (s *Server) handleProxyStatus(w http.ResponseWriter, r *http.Request) {
	if s.app.MITM == nil {
		writeOK(w, map[string]any{"running": false, "error": "certificate authority unavailable"})
		return
	}
	writeOK(w, s.app.MITM.Stats())
}

func (s *Server) handleCAInfo(w http.ResponseWriter, r *http.Request) {
	if s.app.CA == nil {
		writeErr(w, http.StatusServiceUnavailable, "no certificate authority")
		return
	}
	writeOK(w, map[string]any{
		"ca":           s.app.CA.Info(),
		"download":     "/orbis-ca.crt",
		"mobileconfig": "/orbis-ca.mobileconfig",
		"setup_url":    "/setup",
		"instructions": mitm.TrustInstructions(),
	})
}

func (s *Server) handleCACert(w http.ResponseWriter, r *http.Request) {
	if s.app.CA == nil {
		http.Error(w, "no certificate authority", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/x-x509-ca-cert")
	w.Header().Set("Content-Disposition", `attachment; filename="orbis-ca.crt"`)
	_, _ = w.Write(s.app.CA.CertPEM())
}

func (s *Server) handleProxyAction(w http.ResponseWriter, r *http.Request) {
	if s.app.MITM == nil {
		writeErr(w, http.StatusServiceUnavailable, "no certificate authority")
		return
	}
	switch chi.URLParam(r, "action") {
	case "start":
		if err := s.cfg.Update(func(c *config.Config) { c.MITM.Enabled = true }); err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		if err := s.app.MITM.Start(); err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
	case "stop":
		s.app.MITM.Stop()
		_ = s.cfg.Update(func(c *config.Config) { c.MITM.Enabled = false })
	default:
		writeErr(w, http.StatusBadRequest, "action must be start or stop")
		return
	}
	s.app.Store.Audit(r.RemoteAddr, "proxy."+chi.URLParam(r, "action"), "", "", "", "ok")
	writeOK(w, s.app.MITM.Stats())
}

// ---- events / audit ----

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	events, err := s.app.Store.Events(querySince(r, 24), r.URL.Query().Get("severity"),
		queryBool(r, "unack_only"), queryInt(r, "limit", 200, 2000))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeOK(w, map[string]any{"count": len(events), "events": events})
}

func (s *Server) handleAckEvent(w http.ResponseWriter, r *http.Request) {
	if err := s.app.Store.AckEvent(chi.URLParam(r, "id")); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeOK(w, map[string]any{"ok": true})
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	entries, err := s.app.Store.AuditLog(queryInt(r, "limit", 200, 1000))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeOK(w, map[string]any{"entries": entries})
}

// ---- geoip ----

func (s *Server) handleGeoIP(w http.ResponseWriter, r *http.Request) {
	ip := chi.URLParam(r, "ip")
	loc := s.app.Geo.Lookup(ip)
	out := map[string]any{"ip": ip, "location": loc}
	if loc.Country != "" {
		out["country_name"] = geoip.CountryName(loc.Country)
	}
	writeOK(w, out)
}

// handleLocateSelf re-runs public-address discovery on demand, which is what
// an operator wants immediately after their address changes or after turning
// the feature on.
func (s *Server) handleLocateSelf(w http.ResponseWriter, r *http.Request) {
	if err := s.cfg.Update(func(c *config.Config) { c.Node.LocatePublicIP = true }); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.app.Self.SetEnabled(true)
	if err := s.app.Self.Refresh(r.Context()); err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	home := s.homePoint()
	writeOK(w, map[string]any{
		"self": s.app.Self.Status(),
		"home": map[string]any{"lat": home[0], "lng": home[1]},
	})
}

// handleGeoBackfill re-resolves stored history against the current database.
func (s *Server) handleGeoBackfill(w http.ResponseWriter, r *http.Request) {
	result, err := s.app.BackfillGeo(r.Context(), queryInt(r, "limit", 20000, 50000))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.app.Store.Audit(r.RemoteAddr, "geoip.backfill", "", "", "", "ok")
	writeOK(w, result)
}

// ---- config ----

func (s *Server) handleGetConfig(w http.ResponseWriter, r *http.Request) {
	writeOK(w, s.cfg.Redacted())
}

// handlePatchConfig applies a partial update. Only whitelisted paths are
// writable through the API; anything that could brick the node (the store
// path, the API listener) is deliberately config-file-only.
func (s *Server) handlePatchConfig(w http.ResponseWriter, r *http.Request) {
	var patch map[string]any
	if err := decodeJSON(r, &patch); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	applied, err := applyConfigPatch(s.cfg, patch)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.app.Store.Audit(r.RemoteAddr, "config.patch", strings.Join(applied, ","), "", "", "ok")

	// Some changes need a subsystem nudged rather than a restart.
	for _, key := range applied {
		switch {
		case strings.HasPrefix(key, "adblock."):
			if err := s.app.Lists.Rebuild(); err != nil {
				s.app.Log("adblock: rebuild after config change: %v", err)
			}
			s.app.FlushDNSCache("")
		case strings.HasPrefix(key, "dns.upstreams"), key == "dns.strategy":
			if err := s.app.DNS.ReloadUpstreams(); err != nil {
				s.app.Log("dns: reload upstreams: %v", err)
			}
		case strings.HasPrefix(key, "vpn."), strings.HasPrefix(key, "tailscale."),
			key == "firewall.wan_interface":
			// Anything that changes which interfaces carry tunnel traffic,
			// or where it egresses, invalidates the tunnel ruleset.
			s.app.SyncTunnelRules()
		case key == "ai.enabled", key == "ai.provider", key == "ai.api_key", key == "ai.base_url",
			key == "ai.auto_discover":
			// A new provider or key deserves a fresh ranking straight away
			// rather than at the next scheduled probe.
			s.app.AI.Router().RequestProbe()
		}
	}
	writeOK(w, map[string]any{"applied": applied, "config": s.cfg.Redacted()})
}

func (s *Server) handleInterfaces(w http.ResponseWriter, r *http.Request) {
	writeOK(w, map[string]any{"interfaces": listInterfaces()})
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

func sanitizeFilename(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteRune('-')
		}
	}
	out := b.String()
	if out == "" {
		return "peer"
	}
	return out
}

var _ = netip.Addr{}
var _ = adblock.Match{}
