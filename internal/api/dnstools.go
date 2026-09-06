package api

import (
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
)

// DNS tooling: the diagnose endpoint (see app.DiagnoseDomain for the trace
// itself, shared with the assistant) plus quick allow/block/import actions.

func (s *Server) mountDNSTools(r chi.Router) {
	r.Route("/dnstools", func(r chi.Router) {
		r.Post("/diagnose", s.handleDiagnose)
		r.Post("/import", s.handleImportList)
		r.Post("/allow", s.handleQuickAllow)
		r.Post("/block", s.handleQuickBlock)
		r.Post("/unblock", s.handleQuickUnblock)
	})
}

func (s *Server) handleDiagnose(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Domain   string `json:"domain"`
		ClientID string `json:"client_id"`
		Resolve  bool   `json:"resolve"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	out, err := s.app.DiagnoseDomain(r.Context(), req.Domain, req.ClientID, req.Resolve)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeOK(w, out)
}

// ---- quick actions ----

func (s *Server) handleQuickAllow(w http.ResponseWriter, r *http.Request) {
	s.quickRule(w, r, "allow")
}

func (s *Server) handleQuickBlock(w http.ResponseWriter, r *http.Request) {
	s.quickRule(w, r, "block")
}

func (s *Server) quickRule(w http.ResponseWriter, r *http.Request, action string) {
	var req struct {
		Domain   string `json:"domain"`
		Wildcard bool   `json:"wildcard"`
		Note     string `json:"note"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	domain := strings.ToLower(strings.TrimSpace(strings.TrimSuffix(req.Domain, ".")))
	if domain == "" {
		writeErr(w, http.StatusBadRequest, "domain is required")
		return
	}
	note := req.Note
	if note == "" {
		note = "added from the domain tester"
	}

	// Reuse the app-level operations rather than writing the rule here: they
	// already reindex the matcher, audit, and publish the change, and a second
	// implementation would drift from them.
	var err error
	if action == "allow" {
		err = s.app.AllowDomain(domain, note)
	} else {
		err = s.app.BlockDomain(domain, req.Wildcard, note)
	}
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	// A cached answer would keep serving the old verdict for its whole TTL,
	// which reads as the button not having worked.
	s.app.DNS.Cache().FlushDomain(domain)
	writeOK(w, map[string]any{"ok": true, "verdict": s.app.Matcher.Lookup(domain)})
}

// handleQuickUnblock removes any local rule for a name and flushes the cache,
// which is the "let this through again" button.
func (s *Server) handleQuickUnblock(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Domain string `json:"domain"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	domain := strings.ToLower(strings.TrimSpace(req.Domain))
	if domain == "" {
		writeErr(w, http.StatusBadRequest, "domain is required")
		return
	}
	if err := s.app.Store.DeleteLocalRule(domain); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := s.app.Lists.Rebuild(); err != nil {
		writeErr(w, http.StatusInternalServerError, "removed but reindex failed: "+err.Error())
		return
	}
	s.app.DNS.Cache().FlushDomain(domain)
	s.app.Store.Audit(r.RemoteAddr, "adblock.unblock", domain, "", "", "ok")
	writeOK(w, map[string]any{"ok": true, "verdict": s.app.Matcher.Lookup(domain)})
}

// ---- list import ----
