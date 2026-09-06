package api

import (
	"context"
	"net/http"
	"time"

	"github.com/Neoo-Blue/orbis/internal/adblock"
	"github.com/Neoo-Blue/orbis/internal/config"
	"github.com/go-chi/chi/v5"
)

// Preset lists: the short catalogue people migrate from Pi-hole and AdGuard
// Home with, added with one click.

func (s *Server) handlePresets(w http.ResponseWriter, r *http.Request) {
	writeOK(w, map[string]any{"presets": adblock.Presets(s.cfg.Snapshot().AdBlock.Lists)})
}

func (s *Server) handleAddPreset(w http.ResponseWriter, r *http.Request) {
	p, ok := adblock.PresetByID(chi.URLParam(r, "id"))
	if !ok {
		writeErr(w, http.StatusNotFound, "no such preset")
		return
	}
	list := config.BlockList{Name: p.Name, URL: p.URL, Category: p.Category, Enabled: true, Action: p.Action, Format: p.Format}
	err := s.cfg.Update(func(c *config.Config) {
		for i := range c.AdBlock.Lists {
			if c.AdBlock.Lists[i].URL == p.URL || c.AdBlock.Lists[i].Name == p.Name {
				c.AdBlock.Lists[i] = list
				return
			}
		}
		c.AdBlock.Lists = append(c.AdBlock.Lists, list)
	})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.app.Store.Audit(r.RemoteAddr, "adblock.preset", p.ID, "", p.URL, "added")
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		if err := s.app.Lists.UpdateAll(ctx, false); err != nil {
			s.app.Log("adblock: refresh after preset add: %v", err)
		}
	}()
	writeOK(w, map[string]any{"ok": true, "list": list})
}
