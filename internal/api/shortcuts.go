package api

import (
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/Neoo-Blue/orbis/internal/config"
	"github.com/go-chi/chi/v5"
)

func (s *Server) mountShortcuts(r chi.Router) {
	r.Route("/dns/shortcuts", func(r chi.Router) {
		r.Get("/", s.handleShortcutsList)
		r.Post("/", s.handleShortcutSave)
		r.Post("/delete", s.handleShortcutDelete)
	})
}

func (s *Server) handleShortcutsList(w http.ResponseWriter, r *http.Request) {
	writeOK(w, map[string]any{"shortcuts": s.app.Shortcuts(), "node_port": listenPort(s.cfg.Snapshot().API.Listen)})
}

func (s *Server) handleShortcutSave(w http.ResponseWriter, r *http.Request) {
	var sc config.DNSShortcut
	if err := decodeJSON(r, &sc); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	saved, err := s.app.SaveShortcut(sc, r.RemoteAddr)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeOK(w, map[string]any{"shortcut": saved, "open": "http://" + saved.Name + portSuffix(s.cfg.Snapshot().API.Listen)})
}

func (s *Server) handleShortcutDelete(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.app.DeleteShortcut(req.Name, r.RemoteAddr); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeOK(w, map[string]any{"ok": true})
}

func listenPort(listen string) string {
	_, port, err := net.SplitHostPort(listen)
	if err != nil {
		return ""
	}
	return port
}

// portSuffix is ":8080" when the node does not listen on 80, else "".
func portSuffix(listen string) string {
	p := listenPort(listen)
	if p == "" || p == "80" {
		return ""
	}
	return ":" + p
}

// shortcuts wraps the router: a request whose Host is a shortcut name never
// reaches the UI; it is redirected to, or relayed from, the target.
func (s *Server) shortcuts(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sc := s.app.ShortcutFor(r.Host)
		if sc == nil {
			next.ServeHTTP(w, r)
			return
		}
		target, err := url.Parse(sc.Target)
		if err != nil {
			http.Error(w, "shortcut target is not a valid URL", http.StatusBadGateway)
			return
		}
		if sc.Mode != "proxy" {
			// Redirect: the browser lands on the real host and port, so
			// everything the app does afterwards (WebSockets, absolute URLs)
			// just works. 302, not 301, so a changed target is honoured.
			dest := *target
			dest.Path = strings.TrimSuffix(target.Path, "/") + r.URL.Path
			dest.RawQuery = r.URL.RawQuery
			http.Redirect(w, r, dest.String(), http.StatusFound)
			return
		}
		proxy := httputil.NewSingleHostReverseProxy(target)
		director := proxy.Director
		proxy.Director = func(req *http.Request) {
			director(req)
			req.Host = target.Host
		}
		proxy.Transport = &http.Transport{
			// LAN services almost always carry a self-signed certificate.
			TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
			ResponseHeaderTimeout: 60 * time.Second,
		}
		proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
			http.Error(w, "Orbis could not reach "+target.Host+": "+err.Error(), http.StatusBadGateway)
		}
		proxy.ServeHTTP(w, r)
	})
}

// startShortcutListener serves shortcuts on port 80 when the UI itself is
// on another port, so http://name works without typing one. Best effort: a
// busy port 80 is logged, not fatal.
func (s *Server) startShortcutListener(mainListen string) {
	if listenPort(mainListen) == "80" {
		return
	}
	ln, err := net.Listen("tcp", ":80")
	if err != nil {
		s.log("api: shortcuts on port 80 unavailable (%v); shortcuts work on the UI port only", err)
		return
	}
	srv := &http.Server{
		Handler: s.shortcuts(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "http://"+strings.Split(r.Host, ":")[0]+portSuffix(mainListen)+r.URL.RequestURI(), http.StatusFound)
		})),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	s.extra = append(s.extra, srv)
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.log("api: shortcut listener stopped: %v", err)
		}
	}()
	s.log("api: shortcuts also served on :80")
}
