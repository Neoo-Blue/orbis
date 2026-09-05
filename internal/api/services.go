package api

import (
	"net/http"
	"time"

	"github.com/Neoo-Blue/orbis/internal/dpi"
	"github.com/go-chi/chi/v5"
)

// Services: who uses what. All numbers come from the hourly rollups; the
// hostnames behind a service come from the flow table.

func (s *Server) mountServices(r chi.Router) {
	r.Route("/services", func(r chi.Router) {
		r.Get("/", s.handleServices)
		r.Get("/detail", s.handleServiceDetail)
		r.Get("/devices", s.handleServiceDevices)
		r.Get("/catalogue", s.handleServiceCatalogue)
	})
}

func (s *Server) serviceWindow(r *http.Request) (time.Time, time.Time) {
	since := querySince(r, 24)
	return since, time.Now()
}

// deviceLabels maps client ids to display names and notes which devices this
// node sees bytes for (a flow in the window) versus lookups only.
func (s *Server) deviceLabels() map[string]map[string]any {
	out := map[string]map[string]any{}
	for _, c := range s.app.Registry.All() {
		name := c.Label
		if name == "" {
			name = c.Hostname
		}
		if name == "" {
			name = c.IP
		}
		out[c.ID] = map[string]any{
			"id": c.ID, "name": name, "ip": c.IP, "mac": c.MAC, "vendor": c.Vendor, "type": c.DeviceType, "online": c.Online,
		}
	}
	return out
}

func (s *Server) handleServices(w http.ResponseWriter, r *http.Request) {
	since, until := s.serviceWindow(r)
	clientID := r.URL.Query().Get("client_id")
	totals, err := s.app.Store.ServiceTotals(since, until, clientID, 24)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	devices, err := s.app.Store.ServiceDevices(since, until, "")
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	labels := s.deviceLabels()
	intercepted := map[string]bool{}
	for ip := range s.cfg.Snapshot().Network.Intercept.Clients {
		intercepted[ip] = true
	}
	vis := make([]map[string]any, 0, len(devices))
	for _, d := range devices {
		entry := map[string]any{
			"client_id": d.ClientID, "services": d.Devices, "conns": d.Conns,
			"bytes_in": d.BytesIn, "bytes_out": d.BytesOut, "lookups": d.Lookups, "blocked": d.Blocked,
			"bytes_visible": d.BytesIn+d.BytesOut > 0,
		}
		if l, ok := labels[d.ClientID]; ok {
			for k, v := range l {
				entry[k] = v
			}
			if ip, _ := l["ip"].(string); ip != "" {
				entry["intercepted"] = intercepted[ip]
			}
		} else {
			entry["name"] = d.ClientID
		}
		vis = append(vis, entry)
	}
	writeOK(w, map[string]any{
		"since": since, "until": until, "client_id": clientID,
		"services": totals, "devices": vis,
		"mode":      string(s.cfg.Snapshot().Mode),
		"catalogue": len(dpi.Catalogue()),
	})
}

// handleServiceDetail is one service: by device, hourly, and the hosts.
func (s *Server) handleServiceDetail(w http.ResponseWriter, r *http.Request) {
	since, until := s.serviceWindow(r)
	service := r.URL.Query().Get("service")
	clientID := r.URL.Query().Get("client_id")
	if service == "" {
		writeErr(w, http.StatusBadRequest, "service is required")
		return
	}
	devices, err := s.app.Store.ServiceDevices(since, until, service)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	labels := s.deviceLabels()
	rows := make([]map[string]any, 0, len(devices))
	for _, d := range devices {
		entry := map[string]any{
			"client_id": d.ClientID, "conns": d.Conns, "bytes_in": d.BytesIn, "bytes_out": d.BytesOut,
			"lookups": d.Lookups, "blocked": d.Blocked, "bytes_visible": d.BytesIn+d.BytesOut > 0,
		}
		if l, ok := labels[d.ClientID]; ok {
			entry["name"], entry["ip"] = l["name"], l["ip"]
		} else {
			entry["name"] = d.ClientID
		}
		rows = append(rows, entry)
	}
	series, err := s.app.Store.ServiceSeries(since, until, clientID, service)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	hosts, _ := s.app.Store.ServiceHosts(since, clientID, dpi.ClassifyApp, service, 25)
	if hosts == nil {
		hosts = []map[string]any{}
	}
	writeOK(w, map[string]any{
		"service": service, "since": since, "until": until,
		"devices": rows, "series": series, "hosts": hosts,
	})
}

// handleServiceDevices is the per-device view: each device with its top
// services and an hourly series.
func (s *Server) handleServiceDevices(w http.ResponseWriter, r *http.Request) {
	since, until := s.serviceWindow(r)
	clientID := r.URL.Query().Get("client_id")
	if clientID != "" {
		totals, err := s.app.Store.ServiceTotals(since, until, clientID, 24)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		series, _ := s.app.Store.ServiceSeries(since, until, clientID, "")
		entry := map[string]any{"client_id": clientID, "services": totals, "series": series}
		if l, ok := s.deviceLabels()[clientID]; ok {
			entry["device"] = l
		}
		writeOK(w, entry)
		return
	}
	matrix, err := s.app.Store.DeviceServiceMatrix(since, until, 6)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	labels := s.deviceLabels()
	out := make([]map[string]any, 0, len(matrix))
	for id, svcs := range matrix {
		var in, outb, lookups, blocked, conns int64
		for _, t := range svcs {
			in += t.BytesIn
			outb += t.BytesOut
			lookups += t.Lookups
			blocked += t.Blocked
			conns += t.Conns
		}
		entry := map[string]any{
			"client_id": id, "services": svcs, "bytes_in": in, "bytes_out": outb,
			"lookups": lookups, "blocked": blocked, "conns": conns, "bytes_visible": in+outb > 0,
		}
		if l, ok := labels[id]; ok {
			for k, v := range l {
				entry[k] = v
			}
		} else {
			entry["name"] = id
		}
		out = append(out, entry)
	}
	writeOK(w, map[string]any{"since": since, "until": until, "devices": out})
}

func (s *Server) handleServiceCatalogue(w http.ResponseWriter, r *http.Request) {
	writeOK(w, map[string]any{"services": dpi.Catalogue()})
}
