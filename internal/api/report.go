package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/Neoo-Blue/orbis/internal/report"

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
	// A week of flows takes minutes to aggregate on a small node, so the
	// report is assembled in the background and kept for ten minutes; the
	// page asks again until it is there.
	v, ready := s.app.Store.MemoAsync("report|"+window, 10*time.Minute, func() (any, error) {
		return s.app.BuildReport(window, time.Now().Add(-time.Duration(hours)*time.Hour)), nil
	})
	if !ready {
		w.WriteHeader(http.StatusAccepted)
		if r.URL.Query().Get("format") == "" {
			_ = json.NewEncoder(w).Encode(map[string]any{"building": true, "window": window, "since": since})
		} else {
			fmt.Fprintf(w, "The %s report is still being assembled; try again in a minute.\n", window)
		}
		return
	}
	rep := v.(*report.Report)

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
