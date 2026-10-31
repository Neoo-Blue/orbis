package api

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/Neoo-Blue/orbis/internal/confighistory"
	"github.com/go-chi/chi/v5"
)

func (s *Server) mountConfigHistory(r chi.Router) {
	r.Get("/config/history", s.handleListConfigHistory)
	r.Get("/config/history/pending", s.handlePendingConfigHistory)
	r.Post("/config/history/confirm", s.handleConfirmConfigHistory)
	r.Post("/config/history/revert", s.handleRevertConfigHistory)
	r.Get("/config/history/{id}", s.handleGetConfigHistory)
	r.Get("/config/history/{id}/diff", s.handleDiffConfigHistory)
	r.Post("/config/history/{id}/restore", s.handleRestoreConfigHistory)
}

func (s *Server) historyManager() *confighistory.Manager {
	if s.app == nil {
		return nil
	}
	return s.app.History
}

func (s *Server) auditHistory(actor, action, target, before, after, result string) {
	if s.app != nil && s.app.Store != nil {
		s.app.Store.Audit(actor, action, target, before, after, result)
	}
}

func (s *Server) handleListConfigHistory(w http.ResponseWriter, r *http.Request) {
	mgr := s.historyManager()
	if mgr == nil {
		writeOK(w, map[string]any{
			"entries": []confighistory.Entry{},
			"pending": confighistory.PendingStatus{},
		})
		return
	}
	entries, err := mgr.List()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if entries == nil {
		entries = []confighistory.Entry{}
	}
	writeOK(w, map[string]any{
		"entries": entries,
		"pending": mgr.Pending(),
	})
}

func (s *Server) handlePendingConfigHistory(w http.ResponseWriter, r *http.Request) {
	mgr := s.historyManager()
	if mgr == nil {
		writeOK(w, confighistory.PendingStatus{})
		return
	}
	writeOK(w, mgr.Pending())
}

func (s *Server) handleGetConfigHistory(w http.ResponseWriter, r *http.Request) {
	mgr := s.historyManager()
	if mgr == nil {
		writeErr(w, http.StatusNotFound, confighistory.ErrNotFound.Error())
		return
	}
	id := chi.URLParam(r, "id")
	yml, err := mgr.Get(id)
	if err != nil {
		if errors.Is(err, confighistory.ErrNotFound) {
			writeErr(w, http.StatusNotFound, err.Error())
			return
		}
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeOK(w, map[string]any{"id": id, "yaml": yml})
}

func (s *Server) handleDiffConfigHistory(w http.ResponseWriter, r *http.Request) {
	mgr := s.historyManager()
	if mgr == nil {
		writeErr(w, http.StatusNotFound, confighistory.ErrNotFound.Error())
		return
	}
	id := chi.URLParam(r, "id")
	diff, err := mgr.Diff(id)
	if err != nil {
		if errors.Is(err, confighistory.ErrNotFound) {
			writeErr(w, http.StatusNotFound, err.Error())
			return
		}
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeOK(w, map[string]any{"id": id, "diff": diff})
}

func (s *Server) handleRestoreConfigHistory(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	mgr := s.historyManager()
	if mgr == nil {
		writeErr(w, http.StatusServiceUnavailable, "configuration history is unavailable")
		return
	}

	var req struct {
		ConfirmSeconds int `json:"confirm_seconds"`
	}
	if r.Body != nil {
		if err := decodeJSON(r, &req); err != nil && !errors.Is(err, io.EOF) {
			s.auditHistory(r.RemoteAddr, "config.history.restore", id, "", "", "error: "+err.Error())
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	if req.ConfirmSeconds < 0 || req.ConfirmSeconds > 3600 {
		msg := "confirm_seconds must be between 0 and 3600"
		s.auditHistory(r.RemoteAddr, "config.history.restore", id, "", "", "error: "+msg)
		writeErr(w, http.StatusBadRequest, msg)
		return
	}

	confirmFor := time.Duration(req.ConfirmSeconds) * mgr.ConfirmUnit()
	res, err := mgr.Restore(id, confirmFor)
	if err != nil {
		s.auditHistory(r.RemoteAddr, "config.history.restore", id, "", "", "error: "+err.Error())
		switch {
		case errors.Is(err, confighistory.ErrNotFound):
			writeErr(w, http.StatusNotFound, err.Error())
		case errors.Is(err, confighistory.ErrPendingRestore):
			writeErr(w, http.StatusConflict, err.Error())
		default:
			writeErr(w, http.StatusBadRequest, err.Error())
		}
		return
	}

	after := res.Summary
	if req.ConfirmSeconds > 0 {
		after = fmt.Sprintf("%s (confirm %ds)", res.Summary, req.ConfirmSeconds)
	}
	s.auditHistory(r.RemoteAddr, "config.history.restore", id, res.BackupID, after, "ok")
	writeOK(w, map[string]any{
		"restored_id": res.RestoredID,
		"backup_id":   res.BackupID,
		"keys":        res.Keys,
		"summary":     res.Summary,
		"pending":     res.Pending,
		"config":      s.cfg.Redacted(),

		"restart_required": res.RestartRequired,
	})
}

func (s *Server) handleConfirmConfigHistory(w http.ResponseWriter, r *http.Request) {
	mgr := s.historyManager()
	if mgr == nil {
		writeErr(w, http.StatusServiceUnavailable, "configuration history is unavailable")
		return
	}
	restoredID, err := mgr.Confirm()
	if err != nil {
		s.auditHistory(r.RemoteAddr, "config.history.confirm", "", "", "", "error: "+err.Error())
		if errors.Is(err, confighistory.ErrNoPendingRestore) {
			writeErr(w, http.StatusConflict, err.Error())
			return
		}
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.auditHistory(r.RemoteAddr, "config.history.confirm", restoredID, "", "", "ok")
	writeOK(w, map[string]any{
		"ok":           true,
		"confirmed_id": restoredID,
		"pending":      mgr.Pending(),
	})
}

func (s *Server) handleRevertConfigHistory(w http.ResponseWriter, r *http.Request) {
	mgr := s.historyManager()
	if mgr == nil {
		writeErr(w, http.StatusServiceUnavailable, "configuration history is unavailable")
		return
	}
	revertedToID, err := mgr.Revert()
	if err != nil {
		s.auditHistory(r.RemoteAddr, "config.history.revert", "", "", "", "error: "+err.Error())
		if errors.Is(err, confighistory.ErrNoPendingRestore) {
			writeErr(w, http.StatusConflict, err.Error())
			return
		}
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.auditHistory(r.RemoteAddr, "config.history.revert", revertedToID, "", "", "ok")
	writeOK(w, map[string]any{
		"ok":             true,
		"reverted_to_id": revertedToID,
		"pending":        mgr.Pending(),
		"config":         s.cfg.Redacted(),
	})
}
