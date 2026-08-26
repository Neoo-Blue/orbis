package api

import (
	"context"
	"net/http"
	"net/netip"
	"time"

	"github.com/Neoo-Blue/orbis/internal/geoip"
	"github.com/Neoo-Blue/orbis/internal/store"
	"github.com/Neoo-Blue/orbis/internal/topology"
	"github.com/go-chi/chi/v5"
)

func (s *Server) mountTopology(r chi.Router) {
	r.Route("/topology", func(r chi.Router) {
		r.Get("/", s.handleTopology)
		r.Post("/scan", s.handleTopologyScan)
	})
}

// handleTopology returns the map from whatever is already known. It never
// probes: a page load should not put traffic on the network, and a scan that
// happens as a side effect of opening a screen is a scan nobody consented to.
func (s *Server) handleTopology(w http.ResponseWriter, r *http.Request) {
	ports, scannedAt := s.app.Topology.Cached()
	writeOK(w, s.buildTopology(ports, scannedAt))
}

// handleTopologyScan probes the LAN, then rebuilds.
func (s *Server) handleTopologyScan(w http.ResponseWriter, r *http.Request) {
	// Bounded: a scan that outlives the request would keep touching the
	// network after the operator navigated away.
	ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
	defer cancel()

	var ips []string
	for _, c := range s.app.Clients() {
		if c.IP == "" {
			continue
		}
		addr, err := netip.ParseAddr(c.IP)
		if err != nil || !geoip.IsPrivate(addr) {
			continue // only probe this network, never a public address
		}
		ips = append(ips, c.IP)
	}
	ports := s.app.Topology.Scan(ctx, ips)
	s.app.Store.Audit(r.RemoteAddr, "topology.scan", itoaAPI(len(ips))+" host(s)", "", "", "ok")
	writeOK(w, s.buildTopology(ports, time.Now()))
}

func (s *Server) buildTopology(ports map[string][]int, scannedAt time.Time) topology.Graph {
	clients := s.app.Clients()
	devices := make([]topology.DeviceInput, 0, len(clients))
	for _, c := range clients {
		addr, err := netip.ParseAddr(c.IP)
		if err != nil || !geoip.IsPrivate(addr) {
			// Tailscale peers and public addresses are not part of this LAN's
			// physical topology and would clutter it.
			continue
		}
		devices = append(devices, topology.DeviceInput{
			ID: c.ID, IP: c.IP, MAC: c.MAC, Hostname: c.Hostname,
			Label: c.Label, Vendor: c.Vendor, OSGuess: c.OSGuess,
			Type: c.DeviceType, Online: c.Online, LastSeen: c.LastSeen,
		})
	}

	gateway := s.app.DefaultGateway()
	flows := s.internalFlows()

	g := topology.Build(devices, flows, ports, gateway, scannedAt)
	g.Subnet = topology.LocalSubnet(gateway)
	if len(ports) == 0 {
		g.Notes = append(g.Notes,
			"No scan has run, so roles come from MAC prefixes and behaviour alone. "+
				"Scanning probes a short list of ports and sharpens hypervisor, NAS and "+
				"printer detection considerably.")
	}
	return g
}

// internalFlows aggregates recent LAN-to-LAN conversations, which are the
// edges worth drawing. Anything leaving the network belongs on the globe.
func (s *Server) internalFlows() []topology.FlowInput {
	since := time.Now().Add(-24 * time.Hour)
	rows, err := s.app.Store.Flows(store.FlowQuery{Since: &since, Limit: 4000, OrderBy: "bytes"})
	if err != nil {
		return nil
	}
	type key struct{ src, dst string }
	agg := map[key]*topology.FlowInput{}
	for _, f := range rows {
		src, err1 := netip.ParseAddr(f.SrcIP)
		dst, err2 := netip.ParseAddr(f.DstIP)
		if err1 != nil || err2 != nil {
			continue
		}
		if !geoip.IsPrivate(src) {
			continue // inbound from the internet is a globe arc, not a LAN edge
		}
		external := !geoip.IsPrivate(dst)
		k := key{f.SrcIP, f.DstIP}
		if external {
			// Keep the count against the source so a device's external reach
			// is visible, but collapse the destination.
			k = key{f.SrcIP, "internet"}
		}
		e, ok := agg[k]
		if !ok {
			e = &topology.FlowInput{SrcIP: f.SrcIP, DstIP: k.dst, External: external}
			agg[k] = e
		}
		e.Bytes += f.BytesIn + f.BytesOut
		e.Conns++
	}
	out := make([]topology.FlowInput, 0, len(agg))
	for _, v := range agg {
		out = append(out, *v)
	}
	return out
}

func itoaAPI(n int) string {
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
