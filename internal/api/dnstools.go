package api

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/Neoo-Blue/orbis/internal/adblock"
	"github.com/Neoo-Blue/orbis/internal/store"
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

// handleImportList accepts a pasted or uploaded list in any of the formats
// ParseList understands, so a Pi-hole or AdGuard Home export can be moved over
// without converting it first.
func (s *Server) handleImportList(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Text     string `json:"text"`
		Action   string `json:"action"` // block | allow
		Note     string `json:"note"`
		DryRun   bool   `json:"dry_run"`
		Wildcard bool   `json:"wildcard_all"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if strings.TrimSpace(req.Text) == "" {
		writeErr(w, http.StatusBadRequest, "nothing to import")
		return
	}
	action := req.Action
	if action != "allow" {
		action = "block"
	}

	exact, wildcard, err := adblock.ParseList(strings.NewReader(req.Text))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "could not parse: "+err.Error())
		return
	}
	if len(exact) == 0 && len(wildcard) == 0 {
		writeErr(w, http.StatusBadRequest,
			"parsed successfully but found no usable domains. Cosmetic rules and rules with a URL path are skipped, because DNS cannot honour them.")
		return
	}

	// Report what would happen before touching anything: importing a list that
	// turns out to contain a whole-TLD wildcard takes a network offline, and
	// the time to notice is before it is applied.
	sample := make([]string, 0, 12)
	for _, d := range exact {
		if len(sample) >= 6 {
			break
		}
		sample = append(sample, d)
	}
	for _, d := range wildcard {
		if len(sample) >= 12 {
			break
		}
		sample = append(sample, "*."+d)
	}
	sort.Strings(sample)

	var risky []string
	for _, d := range wildcard {
		// A wildcard on a single label is a whole-TLD block. It is almost
		// always a parse artefact and honouring it is catastrophic.
		if !strings.Contains(d, ".") {
			risky = append(risky, "*."+d)
		}
	}

	result := map[string]any{
		"exact":    len(exact),
		"wildcard": len(wildcard),
		"total":    len(exact) + len(wildcard),
		"sample":   sample,
		"risky":    risky,
		"action":   action,
		"dry_run":  req.DryRun,
		"imported": 0,
	}
	if req.DryRun {
		writeOK(w, result)
		return
	}
	if len(risky) > 0 {
		writeErr(w, http.StatusBadRequest, fmt.Sprintf(
			"refusing to import: %v would block an entire top-level domain and take the network offline. Remove those lines and try again.", risky))
		return
	}

	note := req.Note
	if note == "" {
		note = "imported"
	}
	now := time.Now()
	n := 0
	for _, d := range exact {
		if err := s.app.Store.SaveLocalRule(store.LocalRule{
			Domain: d, Action: action, Wildcard: req.Wildcard,
			Origin: "import", Note: note, CreatedAt: now,
		}); err == nil {
			n++
		}
	}
	for _, d := range wildcard {
		if err := s.app.Store.SaveLocalRule(store.LocalRule{
			Domain: d, Action: action, Wildcard: true,
			Origin: "import", Note: note, CreatedAt: now,
		}); err == nil {
			n++
		}
	}
	if err := s.app.Lists.Rebuild(); err != nil {
		writeErr(w, http.StatusInternalServerError, "imported but reindex failed: "+err.Error())
		return
	}
	result["imported"] = n
	s.app.Store.Audit(r.RemoteAddr, "adblock.import", note, "",
		fmt.Sprintf("%d rule(s) as %s", n, action), "ok")
	writeOK(w, result)
}
