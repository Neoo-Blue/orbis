package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/Neoo-Blue/orbis/internal/backup"
	"github.com/Neoo-Blue/orbis/internal/config"
	"github.com/go-chi/chi/v5"
)

// mountOps registers backup/restore and notification management.
func (s *Server) mountOps(r chi.Router) {
	r.Route("/backup", func(r chi.Router) {
		r.Get("/", s.handleBackupExport)
		r.Post("/restore", s.handleBackupRestore)
	})
	r.Route("/notify", func(r chi.Router) {
		r.Get("/", s.handleNotifyGet)
		r.Post("/test", s.handleNotifyTest)
		r.Post("/webhooks", s.handleNotifySaveWebhook)
		r.Delete("/webhooks/{name}", s.handleNotifyDeleteWebhook)
	})
}

func (s *Server) handleBackupExport(w http.ResponseWriter, r *http.Request) {
	// The export goes through Redacted so a bundle downloaded from the UI
	// never carries plaintext keys. Restore treats a masked field as
	// "leave alone", so a redacted bundle still restores cleanly onto the
	// node it came from.
	b, err := backup.Create(s.app.RedactedConfig(), s.app.Store, s.app.Build())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	body, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	name := fmt.Sprintf("orbis-backup-%s.json", time.Now().Format("2006-01-02-1504"))
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	s.app.Store.Audit(r.RemoteAddr, "backup.export", name, "", "", "ok")
	_, _ = w.Write(body)
}

func (s *Server) handleBackupRestore(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Bundle  json.RawMessage       `json:"bundle"`
		Options backup.RestoreOptions `json:"options"`
	}
	// Accept either a wrapped {bundle, options} body or a bare bundle, since
	// the obvious thing to do is upload the downloaded file unchanged.
	raw, err := io.ReadAll(io.LimitReader(r.Body, 32<<20))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "could not read body")
		return
	}
	if err := json.Unmarshal(raw, &req); err != nil || len(req.Bundle) == 0 {
		req.Bundle = raw
		req.Options = backup.RestoreOptions{
			Config: true, Policies: true, Rules: true,
			LocalRules: true, Clients: true, WGPeers: true,
		}
	}

	var b backup.Bundle
	if err := json.Unmarshal(req.Bundle, &b); err != nil {
		writeErr(w, http.StatusBadRequest, "not a valid backup bundle: "+err.Error())
		return
	}
	res, err := backup.Restore(s.cfg, s.app.Store, &b, req.Options)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	// Anything the restore changed has to be re-read by the subsystems that
	// cached it, or the box keeps running the old configuration.
	s.app.ReloadAfterRestore()
	s.app.Store.Audit(r.RemoteAddr, "backup.restore", b.NodeName, "", "", "ok")
	writeOK(w, res)
}

func (s *Server) handleNotifyGet(w http.ResponseWriter, r *http.Request) {
	writeOK(w, s.cfg.Redacted().Notify)
}

func (s *Server) handleNotifyTest(w http.ResponseWriter, r *http.Request) {
	if err := s.app.Notifier.Test(); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.app.Store.Audit(r.RemoteAddr, "notify.test", "", "", "", "ok")
	writeOK(w, map[string]any{"ok": true})
}

func (s *Server) handleNotifySaveWebhook(w http.ResponseWriter, r *http.Request) {
	var hook struct {
		Name    string            `json:"name"`
		Enabled bool              `json:"enabled"`
		URL     string            `json:"url"`
		Format  string            `json:"format"`
		Headers map[string]string `json:"headers"`
	}
	if err := decodeJSON(r, &hook); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if hook.Name == "" || hook.URL == "" {
		writeErr(w, http.StatusBadRequest, "name and url are required")
		return
	}
	err := s.cfg.Update(func(c *config.Config) {
		next := config.Webhook{
			Name: hook.Name, Enabled: hook.Enabled, URL: hook.URL,
			Format: hook.Format, Headers: hook.Headers,
		}
		for i := range c.Notify.Webhooks {
			if c.Notify.Webhooks[i].Name == hook.Name {
				c.Notify.Webhooks[i] = next
				return
			}
		}
		c.Notify.Webhooks = append(c.Notify.Webhooks, next)
	})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.app.Store.Audit(r.RemoteAddr, "notify.webhook.save", hook.Name, "", "", "ok")
	writeOK(w, s.cfg.Redacted().Notify)
}

func (s *Server) handleNotifyDeleteWebhook(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	err := s.cfg.Update(func(c *config.Config) {
		out := c.Notify.Webhooks[:0]
		for _, h := range c.Notify.Webhooks {
			if h.Name != name {
				out = append(out, h)
			}
		}
		c.Notify.Webhooks = out
	})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.app.Store.Audit(r.RemoteAddr, "notify.webhook.delete", name, "", "", "ok")
	writeOK(w, s.cfg.Redacted().Notify)
}
