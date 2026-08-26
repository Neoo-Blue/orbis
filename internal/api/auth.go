package api

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Neoo-Blue/orbis/internal/config"
	"golang.org/x/crypto/bcrypt"
)

const sessionLifetime = 30 * 24 * time.Hour

// newSession mints an HMAC-signed bearer token. A signed token means sessions
// survive a restart without a session table, and revocation is a matter of
// rotating the key.
func newSession(key string) (string, error) {
	if key == "" {
		return "", fmt.Errorf("session key not initialised")
	}
	expires := time.Now().Add(sessionLifetime).Unix()
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	payload := fmt.Sprintf("%d.%s", expires, hex.EncodeToString(nonce))
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(payload))
	return payload + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

func validSession(key, token string) bool {
	if key == "" || token == "" {
		return false
	}
	idx := strings.LastIndexByte(token, '.')
	if idx < 0 {
		return false
	}
	payload, sig := token[:idx], token[idx+1:]
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(payload))
	want := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	// Constant-time compare: a timing oracle on the signature is a real
	// forgery path, not a theoretical one.
	if subtle.ConstantTimeCompare([]byte(sig), []byte(want)) != 1 {
		return false
	}
	expStr, _, ok := strings.Cut(payload, ".")
	if !ok {
		return false
	}
	exp, err := strconv.ParseInt(expStr, 10, 64)
	if err != nil {
		return false
	}
	return time.Now().Unix() < exp
}

// ensureSessionKey generates the signing key on first use.
func ensureSessionKey(cfg *config.Config) (string, error) {
	if k := cfg.Snapshot().API.SessionKey; k != "" {
		return k, nil
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	key := base64.StdEncoding.EncodeToString(raw)
	if err := cfg.Update(func(c *config.Config) { c.API.SessionKey = key }); err != nil {
		return "", err
	}
	return key, nil
}

func (s *Server) handleAuthStatus(w http.ResponseWriter, r *http.Request) {
	cfg := s.cfg.Snapshot()
	token := bearerFrom(r)
	writeOK(w, map[string]any{
		"setup_required": cfg.API.AdminHash == "",
		"authenticated":  cfg.API.AdminHash == "" || validSession(cfg.API.SessionKey, token),
	})
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Password string `json:"password"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	cfg := s.cfg.Snapshot()
	if cfg.API.AdminHash == "" {
		writeErr(w, http.StatusBadRequest, "no password is set; complete setup first")
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(cfg.API.AdminHash), []byte(req.Password)); err != nil {
		// A uniform delay makes online guessing meaningfully slower without
		// needing a lockout table.
		time.Sleep(750 * time.Millisecond)
		s.app.Store.Audit(r.RemoteAddr, "auth.login", "", "", "", "failed")
		writeErr(w, http.StatusUnauthorized, "incorrect password")
		return
	}
	key, err := ensureSessionKey(s.cfg)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	token, err := newSession(key)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: "orbis_session", Value: token, Path: "/",
		HttpOnly: true, SameSite: http.SameSiteLaxMode,
		MaxAge: int(sessionLifetime.Seconds()),
		// Secure is not forced: many deployments run this on plain HTTP on a
		// LAN address, and a cookie that never arrives is worse than one
		// that is not marked Secure on a link the operator controls.
		Secure: r.TLS != nil,
	})
	s.app.Store.Audit(r.RemoteAddr, "auth.login", "", "", "", "ok")
	writeOK(w, map[string]any{"token": token})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: "orbis_session", Value: "", Path: "/", MaxAge: -1})
	writeOK(w, map[string]any{"ok": true})
}

func (s *Server) handleSetPassword(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Current  string `json:"current"`
		Password string `json:"password"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if len(req.Password) < 10 {
		writeErr(w, http.StatusBadRequest, "password must be at least 10 characters")
		return
	}
	cfg := s.cfg.Snapshot()
	if cfg.API.AdminHash != "" {
		if err := bcrypt.CompareHashAndPassword([]byte(cfg.API.AdminHash), []byte(req.Current)); err != nil {
			writeErr(w, http.StatusUnauthorized, "current password is incorrect")
			return
		}
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), 12)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if _, err := ensureSessionKey(s.cfg); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := s.cfg.Update(func(c *config.Config) { c.API.AdminHash = string(hash) }); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	key := s.cfg.Snapshot().API.SessionKey
	token, err := newSession(key)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: "orbis_session", Value: token, Path: "/",
		HttpOnly: true, SameSite: http.SameSiteLaxMode,
		MaxAge: int(sessionLifetime.Seconds()), Secure: r.TLS != nil,
	})
	s.app.Store.Audit(r.RemoteAddr, "auth.set_password", "", "", "", "ok")
	writeOK(w, map[string]any{"token": token})
}

func bearerFrom(r *http.Request) string {
	if t := r.Header.Get("X-Orbis-Token"); t != "" {
		return t
	}
	if c, err := r.Cookie("orbis_session"); err == nil {
		return c.Value
	}
	if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimPrefix(auth, "Bearer ")
	}
	return ""
}
