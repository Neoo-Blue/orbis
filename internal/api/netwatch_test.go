package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Neoo-Blue/orbis/internal/app"
	"github.com/Neoo-Blue/orbis/internal/netwatch"
	"github.com/go-chi/chi/v5"
)

func TestNetwatchEndpoints(t *testing.T) {
	nw := netwatch.NewManager(nil, nil, nil)
	srv := &Server{app: &app.App{Netwatch: nw}}
	r := chi.NewRouter()
	srv.mount(r)

	for _, path := range []string{"/netwatch/status", "/netwatch/history?hours=6"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s status = %d, want 200", path, rec.Code)
		}
		if strings.Contains(rec.Body.String(), "null") {
			t.Fatalf("GET %s encoded a nil slice as null: %s", path, rec.Body.String())
		}
	}

	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/netwatch/status", nil))
	var st netwatch.Status
	if err := json.Unmarshal(rec.Body.Bytes(), &st); err != nil {
		t.Fatalf("decode status: %v", err)
	}
	if len(st.Targets) != 4 {
		t.Fatalf("status targets = %d, want 4", len(st.Targets))
	}

	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/netwatch/history?hours=6", nil))
	var hist netwatch.History
	if err := json.Unmarshal(rec.Body.Bytes(), &hist); err != nil {
		t.Fatalf("decode history: %v", err)
	}
	if hist.Hours != 6 || len(hist.Targets) != 4 {
		t.Fatalf("unexpected history response: hours=%d targets=%d", hist.Hours, len(hist.Targets))
	}
}
