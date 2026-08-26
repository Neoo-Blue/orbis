package api

import (
	"net/http"
	"strings"

	"github.com/Neoo-Blue/orbis/internal/config"
	"github.com/Neoo-Blue/orbis/internal/dnsproxy"
	"github.com/go-chi/chi/v5"
)

// mountDNSRecords manages the local authoritative records that make Orbis a
// full DNS server for your own names, not only a filter for everyone else's.
func (s *Server) mountDNSRecords(r chi.Router) {
	r.Route("/dns/records", func(r chi.Router) {
		r.Get("/", s.handleRecordsList)
		r.Post("/", s.handleRecordSave)
		r.Post("/delete", s.handleRecordDelete)
	})
}

func (s *Server) handleRecordsList(w http.ResponseWriter, r *http.Request) {
	writeOK(w, map[string]any{
		"records":     orEmptyRecords(s.cfg.Snapshot().DNS.Records),
		"local_domain": s.cfg.Snapshot().DNS.LocalDomain,
	})
}

func (s *Server) handleRecordSave(w http.ResponseWriter, r *http.Request) {
	var rec config.DNSRecord
	if err := decodeJSON(r, &rec); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	rec.Name = strings.TrimSpace(rec.Name)
	rec.Type = strings.ToUpper(strings.TrimSpace(rec.Type))
	if msg := dnsproxy.ValidateRecord(dnsproxy.LocalRecord{
		Name: rec.Name, Type: rec.Type, Value: rec.Value,
		TTL: rec.TTL, Priority: rec.Priority, Weight: rec.Weight, Port: rec.Port,
	}); msg != "" {
		writeErr(w, http.StatusBadRequest, msg)
		return
	}
	err := s.cfg.Update(func(c *config.Config) {
		// A save replaces an existing record with the same name AND type,
		// which is how the UI edits one in place; otherwise it is added.
		for i := range c.DNS.Records {
			if strings.EqualFold(c.DNS.Records[i].Name, rec.Name) &&
				strings.EqualFold(c.DNS.Records[i].Type, rec.Type) &&
				c.DNS.Records[i].Value == rec.Value {
				c.DNS.Records[i] = rec
				return
			}
		}
		c.DNS.Records = append(c.DNS.Records, rec)
	})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.app.ReloadRecords()
	s.app.Store.Audit(r.RemoteAddr, "dns.record.save", rec.Name, "", rec.Type+" "+rec.Value, "ok")
	writeOK(w, map[string]any{"records": s.cfg.Snapshot().DNS.Records})
}

func (s *Server) handleRecordDelete(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name  string `json:"name"`
		Type  string `json:"type"`
		Value string `json:"value"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	err := s.cfg.Update(func(c *config.Config) {
		out := c.DNS.Records[:0]
		for _, rec := range c.DNS.Records {
			if strings.EqualFold(rec.Name, body.Name) &&
				strings.EqualFold(rec.Type, body.Type) && rec.Value == body.Value {
				continue
			}
			out = append(out, rec)
		}
		c.DNS.Records = out
	})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.app.ReloadRecords()
	s.app.Store.Audit(r.RemoteAddr, "dns.record.delete", body.Name, "", body.Type, "ok")
	writeOK(w, map[string]any{"records": s.cfg.Snapshot().DNS.Records})
}

func orEmptyRecords(in []config.DNSRecord) []config.DNSRecord {
	if in == nil {
		return []config.DNSRecord{}
	}
	return in
}
