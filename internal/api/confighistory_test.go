package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Neoo-Blue/orbis/internal/app"
	"github.com/Neoo-Blue/orbis/internal/config"
	"github.com/Neoo-Blue/orbis/internal/confighistory"
	"github.com/Neoo-Blue/orbis/internal/store"
	"github.com/go-chi/chi/v5"
)

func TestConfigAndHistoryRoutesCoexist(t *testing.T) {
	r := chi.NewRouter()
	(&Server{}).mount(r)

	for _, tc := range []struct {
		method string
		path   string
		want   string
	}{
		{http.MethodGet, "/config", "/config"},
		{http.MethodPatch, "/config", "/config"},
		{http.MethodGet, "/config/", "/config"},
		{http.MethodPatch, "/config/", "/config"},
		{http.MethodGet, "/config/interfaces", "/config/interfaces"},
		{http.MethodGet, "/config/history", "/config/history"},
		{http.MethodGet, "/config/history/pending", "/config/history/pending"},
		{http.MethodPost, "/config/history/confirm", "/config/history/confirm"},
		{http.MethodPost, "/config/history/revert", "/config/history/revert"},
		{http.MethodGet, "/config/history/1700000000000000000", "/config/history/{id}"},
		{http.MethodGet, "/config/history/1700000000000000000/diff", "/config/history/{id}/diff"},
		{http.MethodPost, "/config/history/1700000000000000000/restore", "/config/history/{id}/restore"},
	} {
		rctx := chi.NewRouteContext()
		req, _ := http.NewRequestWithContext(context.WithValue(context.Background(), chi.RouteCtxKey, rctx), tc.method, tc.path, nil)
		_ = req
		if !r.Match(rctx, tc.method, tc.path) {
			t.Fatalf("%s %s: no route matched", tc.method, tc.path)
		}
		if got := rctx.RoutePattern(); got != tc.want {
			t.Errorf("%s %s resolved to %q, want %q", tc.method, tc.path, got, tc.want)
		}
	}
}

func newTestConfigHistoryHandler(t *testing.T) (http.Handler, *config.Config, *store.Store, *confighistory.Manager) {
	t.Helper()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "orbis.yaml")
	dbPath := filepath.Join(dir, "orbis.db")
	histDir := filepath.Join(dir, "config-history")

	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.Update(func(c *config.Config) {
		c.Store.Path = dbPath
	}); err != nil {
		t.Fatal(err)
	}
	cfg.SetHistoryDir(histDir)

	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	a := &app.App{
		Cfg:   cfg,
		Store: st,
	}
	mgr := confighistory.New(histDir, cfg, confighistory.Hooks{
		OnApply: a.ApplyConfigChanges,
		OnAutoRevert: func(restoredID, revertToID string, err error) {
			res := "ok"
			if err != nil {
				res = "error: " + err.Error()
			}
			st.Audit("timer", "config.history.autorevert", restoredID, restoredID, revertToID, res)
		},
	})
	a.History = mgr
	t.Cleanup(mgr.Stop)

	srv := New(a, cfg, nil, nil)
	r := chi.NewRouter()
	r.Route("/api", func(r chi.Router) {
		r.Use(srv.auth)
		srv.mount(r)
	})
	return r, cfg, st, mgr
}

func TestConfigHistoryAuthRedactionRestoreConfirmAndAudit(t *testing.T) {
	h, cfg, st, mgr := newTestConfigHistoryHandler(t)
	mgr.SetConfirmUnit(25 * time.Millisecond)

	const (
		secretAI      = "sk-http-test-secret-ai-key"
		secretSession = "http-test-session-signing-key"
		secretHash    = "$2a$10$HTTPTESTADMINHASHVALUE000000000000000000000"
		secretWG      = "HTTP-TEST-WG-PRIVATE-KEY-SECRET"
	)

	// Enable auth by setting AdminHash + SessionKey, then make another change
	// so history has archived entries containing secrets.
	if err := cfg.Update(func(c *config.Config) {
		c.Node.Name = "v1-locked"
		c.AI.APIKey = secretAI
		c.API.SessionKey = secretSession
		c.API.AdminHash = secretHash
		c.VPN.Server.PrivateKey = secretWG
	}); err != nil {
		t.Fatal(err)
	}
	if err := cfg.Update(func(c *config.Config) {
		c.Node.Name = "v2-current"
		c.DNS.Upstreams = []string{"9.9.9.9:53"}
	}); err != nil {
		t.Fatal(err)
	}

	// Unauthenticated calls must be rejected just like GET /api/config.
	for _, path := range []string{"/api/config/history", "/api/config/history/pending"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("GET %s without session returned %d, want 401", path, rec.Code)
		}
	}

	tok, err := newSession(secretSession)
	if err != nil {
		t.Fatal(err)
	}
	doAuth := func(method, path, body string) *httptest.ResponseRecorder {
		t.Helper()
		var rdr *bytes.Reader
		if body != "" {
			rdr = bytes.NewReader([]byte(body))
		} else {
			rdr = bytes.NewReader(nil)
		}
		req := httptest.NewRequest(method, path, rdr)
		req.Header.Set("Authorization", "Bearer "+tok)
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	// List entries and verify secrets never appear.
	listRec := doAuth(http.MethodGet, "/api/config/history", "")
	if listRec.Code != http.StatusOK {
		t.Fatalf("GET /api/config/history: %d %s", listRec.Code, listRec.Body.String())
	}
	for _, sec := range []string{secretAI, secretSession, secretHash, secretWG} {
		if strings.Contains(listRec.Body.String(), sec) {
			t.Fatalf("secret %q leaked in GET /api/config/history", sec)
		}
	}

	var listPayload struct {
		Entries []confighistory.Entry       `json:"entries"`
		Pending confighistory.PendingStatus `json:"pending"`
	}
	if err := json.Unmarshal(listRec.Body.Bytes(), &listPayload); err != nil {
		t.Fatal(err)
	}
	if len(listPayload.Entries) < 2 {
		t.Fatalf("expected at least 2 history entries, got %d", len(listPayload.Entries))
	}
	v1ID := listPayload.Entries[0].ID // archived v1-locked

	// Get and Diff must redact every secret.
	getRec := doAuth(http.MethodGet, "/api/config/history/"+v1ID, "")
	if getRec.Code != http.StatusOK {
		t.Fatalf("GET /api/config/history/%s: %d", v1ID, getRec.Code)
	}
	diffRec := doAuth(http.MethodGet, "/api/config/history/"+v1ID+"/diff", "")
	if diffRec.Code != http.StatusOK {
		t.Fatalf("GET /api/config/history/%s/diff: %d", v1ID, diffRec.Code)
	}
	for _, sec := range []string{secretAI, secretSession, secretHash, secretWG} {
		if strings.Contains(getRec.Body.String(), sec) {
			t.Fatalf("secret %q leaked in GET /api/config/history/{id}", sec)
		}
		if strings.Contains(diffRec.Body.String(), sec) {
			t.Fatalf("secret %q leaked in GET /api/config/history/{id}/diff", sec)
		}
	}

	// Commit-confirm restore with confirm_seconds=4 (4 * 25ms = 100ms): let it
	// expire first and verify auto-revert.
	resRec := doAuth(http.MethodPost, "/api/config/history/"+v1ID+"/restore", `{"confirm_seconds":4}`)
	if resRec.Code != http.StatusOK {
		t.Fatalf("POST restore with confirm: %d %s", resRec.Code, resRec.Body.String())
	}
	pendRec := doAuth(http.MethodGet, "/api/config/history/pending", "")
	if pendRec.Code != http.StatusOK || !strings.Contains(pendRec.Body.String(), `"pending":true`) {
		t.Fatalf("expected pending=true, got %d %s", pendRec.Code, pendRec.Body.String())
	}

	// Second concurrent pending restore must be refused (409).
	conflictRec := doAuth(http.MethodPost, "/api/config/history/"+v1ID+"/restore", `{"confirm_seconds":4}`)
	if conflictRec.Code != http.StatusConflict {
		t.Fatalf("expected 409 for second pending restore, got %d", conflictRec.Code)
	}

	time.Sleep(180 * time.Millisecond)
	if got := cfg.Snapshot().Node.Name; got != "v2-current" {
		t.Fatalf("expected auto-revert to v2-current, got %q", got)
	}

	// Now restore with confirm_seconds=8 (200ms) and confirm via POST /confirm.
	resRec2 := doAuth(http.MethodPost, "/api/config/history/"+v1ID+"/restore", `{"confirm_seconds":8}`)
	if resRec2.Code != http.StatusOK {
		t.Fatalf("second POST restore: %d %s", resRec2.Code, resRec2.Body.String())
	}
	confRec := doAuth(http.MethodPost, "/api/config/history/confirm", "")
	if confRec.Code != http.StatusOK {
		t.Fatalf("POST /api/config/history/confirm: %d %s", confRec.Code, confRec.Body.String())
	}
	time.Sleep(260 * time.Millisecond)
	if got := cfg.Snapshot().Node.Name; got != "v1-locked" {
		t.Fatalf("expected confirmed restore to stay at v1-locked, got %q", got)
	}
	if got := cfg.Snapshot().AI.APIKey; got != secretAI {
		t.Fatalf("expected real secret preserved after restore, got %q", got)
	}

	// Verify audit trail recorded mutating routes.
	audits, err := st.AuditLog(20)
	if err != nil {
		t.Fatal(err)
	}
	seenActions := map[string]bool{}
	for _, a := range audits {
		seenActions[a.Action] = true
	}
	for _, want := range []string{"config.history.restore", "config.history.confirm", "config.history.autorevert"} {
		if !seenActions[want] {
			t.Errorf("expected audit action %q in %+v", want, audits)
		}
	}
}

func TestAConfigEditIsRefusedWhileARestoreWaits(t *testing.T) {
	h, cfg, _, mgr := newTestConfigHistoryHandler(t)
	for _, name := range []string{"before", "current"} {
		if err := cfg.Update(func(c *config.Config) { c.Node.Name = name }); err != nil {
			t.Fatal(err)
		}
	}
	entries, err := mgr.List()
	if err != nil {
		t.Fatal(err)
	}
	res, err := mgr.Restore(entries[0].ID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if res.RestartRequired == nil {
		t.Fatal("the reply must always carry the list")
	}
	patch := func() int {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPatch, "/api/config", strings.NewReader(`{"node.name":"edited"}`))
		r.Header.Set("Content-Type", "application/json")
		h.ServeHTTP(w, r)
		return w.Code
	}
	if code := patch(); code != http.StatusConflict {
		t.Fatalf("code %d, and the rollback would throw this edit away", code)
	}
	if _, err := mgr.Confirm(); err != nil {
		t.Fatal(err)
	}
	if code := patch(); code != http.StatusOK {
		t.Fatalf("code %d once the restore is settled", code)
	}
}
