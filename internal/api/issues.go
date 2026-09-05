package api

import (
	"net/http"
	"strings"

	"github.com/Neoo-Blue/orbis/internal/issues"
	"github.com/go-chi/chi/v5"
)

// Problems: what went wrong on this node, scrubbed, and its GitHub state.

func (s *Server) mountIssues(r chi.Router) {
	r.Route("/issues", func(r chi.Router) {
		r.Get("/", s.handleIssues)
		r.Post("/", s.handleIssueCreate)
		r.Get("/{id}/preview", s.handleIssuePreview)
		r.Post("/{id}/report", s.handleIssueReport)
		r.Post("/{id}/status", s.handleIssueStatus)
		r.Delete("/{id}", s.handleIssueDelete)
	})
}

func (s *Server) handleIssues(w http.ResponseWriter, r *http.Request) {
	list, err := s.app.Store.Issues(r.URL.Query().Get("status"), queryInt(r, "limit", 100, 500))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	cfg := s.cfg.Snapshot().Issues
	writeOK(w, map[string]any{
		"issues": list,
		"recording": map[string]any{
			"enabled": cfg.Enabled, "auto_capture": cfg.AutoCapture,
		},
		"github": map[string]any{
			"enabled": cfg.GitHub.Enabled, "repo": cfg.GitHub.Repo,
			"ready":       cfg.GitHub.Enabled && (cfg.GitHub.Token != "" || cfg.GitHub.RelayURL != ""),
			"via":         map[bool]string{true: "token", false: "relay"}[cfg.GitHub.Token != ""],
			"auto_report": cfg.GitHub.AutoReport, "max_per_day": cfg.GitHub.MaxPerDay,
		},
	})
}

// handleIssueCreate is the report form. The report is recorded scrubbed and,
// when asked and possible, filed straight away.
func (s *Server) handleIssueCreate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Title  string `json:"title"`
		Detail string `json:"detail"`
		Report bool   `json:"report"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if strings.TrimSpace(req.Title) == "" {
		writeErr(w, http.StatusBadRequest, "a title is required")
		return
	}
	issue, err := s.app.Issues.Record(r.Context(), issues.Input{
		Severity: "notice", Category: "report", Title: req.Title, Detail: req.Detail, Source: "user",
	})
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if issue == nil {
		writeErr(w, http.StatusBadRequest, "problem recording is disabled")
		return
	}
	s.app.Store.Audit(r.RemoteAddr, "issue.create", issue.ID, "", issue.Title, "ok")
	if req.Report {
		if filed, err := s.app.Issues.Report(r.Context(), issue.ID, false); err != nil {
			writeJSON(w, http.StatusCreated, map[string]any{"issue": issue, "report_error": err.Error()})
			return
		} else if filed != nil {
			issue = filed
		}
	}
	writeJSON(w, http.StatusCreated, map[string]any{"issue": issue})
}

func (s *Server) handleIssuePreview(w http.ResponseWriter, r *http.Request) {
	title, body, labels, err := s.app.Issues.Preview(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}
	cfg := s.cfg.Snapshot().Issues.GitHub
	writeOK(w, map[string]any{"title": title, "body": body, "labels": labels, "repo": cfg.Repo})
}

func (s *Server) handleIssueReport(w http.ResponseWriter, r *http.Request) {
	issue, err := s.app.Issues.Report(r.Context(), chi.URLParam(r, "id"), false)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	s.app.Store.Audit(r.RemoteAddr, "issue.report", issue.ID, "", issue.GitHubURL, "ok")
	writeOK(w, map[string]any{"issue": issue})
}

func (s *Server) handleIssueStatus(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Status string `json:"status"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	switch req.Status {
	case "open", "dismissed", "resolved":
	default:
		writeErr(w, http.StatusBadRequest, "status must be open, dismissed or resolved")
		return
	}
	id := chi.URLParam(r, "id")
	if err := s.app.Store.SetIssueStatus(id, req.Status); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.app.Store.Audit(r.RemoteAddr, "issue.status", id, "", req.Status, "ok")
	issue, _ := s.app.Store.Issue(id)
	writeOK(w, map[string]any{"issue": issue})
}

func (s *Server) handleIssueDelete(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := s.app.Store.DeleteIssue(id); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.app.Store.Audit(r.RemoteAddr, "issue.delete", id, "", "", "ok")
	writeOK(w, map[string]any{"ok": true})
}
