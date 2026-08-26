// Package api serves the REST surface, the live WebSocket stream, and the
// built web UI.
package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Neoo-Blue/orbis/internal/app"
	"github.com/Neoo-Blue/orbis/internal/config"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
)

type Server struct {
	app  *app.App
	cfg  *config.Config
	http *http.Server
	log  func(string, ...any)
	// webFS is the embedded UI, used when no on-disk web root exists.
	webFS fs.FS
}

func New(a *app.App, cfg *config.Config, webFS fs.FS, log func(string, ...any)) *Server {
	if log == nil {
		log = func(string, ...any) {}
	}
	return &Server{app: a, cfg: cfg, webFS: webFS, log: log}
}

func (s *Server) Start() error {
	cfg := s.cfg.Snapshot()
	r := chi.NewRouter()

	r.Use(middleware.RealIP)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(120 * time.Second))
	r.Use(s.securityHeaders)

	if cfg.API.AllowCORS {
		r.Use(cors.Handler(cors.Options{
			AllowedOrigins:   []string{"*"},
			AllowedMethods:   []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
			AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-Orbis-Token"},
			AllowCredentials: true,
			MaxAge:           300,
		}))
	}

	r.Route("/api", func(r chi.Router) {
		r.Use(s.auth)
		s.mount(r)
	})

	// The CA certificate is served unauthenticated on purpose: a device being
	// onboarded has no way to present a session, and the certificate is
	// public by definition.
	r.Get("/orbis-ca.crt", s.handleCACert)

	// Prometheus scrapes cannot present a session cookie, so /metrics sits
	// outside the auth wrapper and is guarded by an optional bearer token.
	r.Get("/metrics", s.handleMetrics)

	r.NotFound(s.serveUI())

	s.http = &http.Server{
		Addr:              cfg.API.Listen,
		Handler:           r,
		ReadHeaderTimeout: 10 * time.Second,
		// No WriteTimeout: the WebSocket and the chat stream are long-lived.
		IdleTimeout: 120 * time.Second,
	}

	ln, err := net.Listen("tcp", cfg.API.Listen)
	if err != nil {
		return fmt.Errorf("listen %s: %w", cfg.API.Listen, err)
	}
	go func() {
		if err := s.http.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.log("api: server stopped: %v", err)
		}
	}()
	s.log("api: listening on %s", cfg.API.Listen)
	return nil
}

func (s *Server) Stop() error {
	if s.http == nil {
		return nil
	}
	return s.http.Close()
}

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		// The UI is entirely self-hosted; nothing should be loading from a
		// third party, and saying so blocks a whole class of injection.
		w.Header().Set("Content-Security-Policy",
			"default-src 'self'; script-src 'self' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; "+
				"img-src 'self' data: blob:; connect-src 'self' ws: wss:; worker-src 'self' blob:; font-src 'self' data:")
		next.ServeHTTP(w, r)
	})
}

// auth is deliberately simple: a shared token in a header or cookie. There is
// no multi-user model because this is a single-appliance admin surface, and
// pretending otherwise would imply isolation the product does not provide.
func (s *Server) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg := s.cfg.Snapshot()
		// Before a password is set the API is open so the setup wizard can
		// run. The UI shows a prominent warning in this state.
		if cfg.API.AdminHash == "" {
			next.ServeHTTP(w, r)
			return
		}
		token := r.Header.Get("X-Orbis-Token")
		if token == "" {
			if c, err := r.Cookie("orbis_session"); err == nil {
				token = c.Value
			}
		}
		if token == "" {
			if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
				token = strings.TrimPrefix(auth, "Bearer ")
			}
		}
		// The login endpoint has to be reachable without a session.
		if strings.HasSuffix(r.URL.Path, "/auth/login") || strings.HasSuffix(r.URL.Path, "/auth/status") {
			next.ServeHTTP(w, r)
			return
		}
		if !validSession(cfg.API.SessionKey, token) {
			writeErr(w, http.StatusUnauthorized, "not signed in")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// serveUI serves the built SPA, falling back to index.html so client-side
// routes survive a page refresh.
func (s *Server) serveUI() http.HandlerFunc {
	cfg := s.cfg.Snapshot()
	root := cfg.API.WebRoot

	var fileSystem http.FileSystem
	if root != "" {
		if st, err := os.Stat(filepath.Join(root, "index.html")); err == nil && !st.IsDir() {
			fileSystem = http.Dir(root)
		}
	}
	if fileSystem == nil && s.webFS != nil {
		if sub, err := fs.Sub(s.webFS, "dist"); err == nil {
			if _, err := fs.Stat(sub, "index.html"); err == nil {
				fileSystem = http.FS(sub)
			}
		}
	}
	if fileSystem == nil {
		return func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, placeholderHTML)
		}
	}

	fileServer := http.FileServer(fileSystem)
	return func(w http.ResponseWriter, r *http.Request) {
		upath := strings.TrimPrefix(r.URL.Path, "/")
		if upath == "" {
			upath = "index.html"
		}
		f, err := fileSystem.Open(upath)
		if err != nil {
			// Unknown path with no extension is a client-side route.
			if filepath.Ext(upath) == "" {
				r2 := *r
				r2.URL.Path = "/"
				serveIndex(w, &r2, fileSystem)
				return
			}
			http.NotFound(w, r)
			return
		}
		st, err := f.Stat()
		f.Close()
		if err == nil && st.IsDir() {
			serveIndex(w, r, fileSystem)
			return
		}
		// Hashed asset filenames are immutable; index.html must never be.
		if strings.HasPrefix(upath, "assets/") {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		} else {
			w.Header().Set("Cache-Control", "no-cache")
		}
		fileServer.ServeHTTP(w, r)
	}
}

func serveIndex(w http.ResponseWriter, r *http.Request, fsys http.FileSystem) {
	f, err := fsys.Open("index.html")
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Cache-Control", "no-cache")
	http.ServeContent(w, r, "index.html", st.ModTime(), f)
}

// ---- response helpers ----

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	if err := enc.Encode(v); err != nil {
		// The header is already written; nothing useful is left to do but
		// avoid a panic in the handler.
		_ = err
	}
}

func writeOK(w http.ResponseWriter, v any) { writeJSON(w, http.StatusOK, v) }

type errResponse struct {
	Error string `json:"error"`
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, errResponse{Error: msg})
}

func decodeJSON(r *http.Request, v any) error {
	defer r.Body.Close()
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 4<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("invalid request body: %w", err)
	}
	return nil
}

func queryInt(r *http.Request, key string, def, max int) int {
	raw := r.URL.Query().Get(key)
	if raw == "" {
		return def
	}
	v, err := strconv.Atoi(raw)
	if err != nil || v <= 0 {
		return def
	}
	if max > 0 && v > max {
		return max
	}
	return v
}

func queryBool(r *http.Request, key string) bool {
	v := strings.ToLower(r.URL.Query().Get(key))
	return v == "1" || v == "true" || v == "yes"
}

func querySince(r *http.Request, defHours int) time.Time {
	h := queryInt(r, "hours", defHours, 24*365)
	return time.Now().Add(-time.Duration(h) * time.Hour)
}

const placeholderHTML = `<!doctype html>
<html><head><meta charset="utf-8"><title>Orbis</title>
<style>
 body{background:#05070c;color:#c8d3e0;font:15px/1.6 ui-monospace,SFMono-Regular,Menlo,monospace;
      display:grid;place-items:center;min-height:100vh;margin:0}
 .card{max-width:52ch;padding:2.5rem;border:1px solid #16202e;border-radius:14px;background:#080c14}
 h1{font-size:1.1rem;letter-spacing:.18em;text-transform:uppercase;color:#4ee8c0;margin:0 0 1rem}
 code{color:#7fd3ff}
 a{color:#4ee8c0}
</style></head>
<body><div class="card">
<h1>Orbis</h1>
<p>The API is running, but no web UI build was found.</p>
<p>Build it with <code>cd web &amp;&amp; npm install &amp;&amp; npm run build</code>, or point
<code>api.web_root</code> at an existing build.</p>
<p>The REST surface is live at <code>/api</code> in the meantime.</p>
</div></body></html>`
