package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
)

func (s *Server) mountReport(r chi.Router) {
	r.Get("/report", s.handleReport)
}

// handleReport returns the summary in the requested format. json for the UI
// preview, csv for a spreadsheet, html for a printable page.
func (s *Server) handleReport(w http.ResponseWriter, r *http.Request) {
	hours := queryInt(r, "hours", 24, 720)
	since := time.Now().Add(-time.Duration(hours) * time.Hour)
	window := humanWindow(hours)
	rep := s.app.BuildReport(window, since)

	switch r.URL.Query().Get("format") {
	case "csv":
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", `attachment; filename="orbis-report.csv"`)
		_ = rep.WriteCSV(w)
	case "html":
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Disposition", `inline; filename="orbis-report.html"`)
		_ = rep.WriteHTML(w)
	default:
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(rep)
	}
	s.app.Store.Audit(r.RemoteAddr, "report.generate", window, "", r.URL.Query().Get("format"), "ok")
}

func humanWindow(hours int) string {
	switch {
	case hours%168 == 0:
		return itoaAPI(hours/168) + "-week"
	case hours%24 == 0:
		return itoaAPI(hours/24) + "-day"
	default:
		return itoaAPI(hours) + "-hour"
	}
}
