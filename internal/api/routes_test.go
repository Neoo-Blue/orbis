package api

import (
	"context"
	"net/http"
	"testing"

	"github.com/go-chi/chi/v5"
)

// A router mounted at /clients/{id} once shadowed the /clients group: its
// catch-all answered /clients/{id} and every sub-path with the UI's HTML.
func TestDeviceRoutesResolve(t *testing.T) {
	r := chi.NewRouter()
	(&Server{}).mount(r)
	for _, tc := range []struct{ method, path, want string }{
		{http.MethodGet, "/clients/c_1", "/clients/{id}"},
		{http.MethodGet, "/clients/c_1/destinations", "/clients/{id}/destinations"},
		{http.MethodGet, "/clients/c_1/flows", "/clients/{id}/flows"},
		{http.MethodGet, "/clients/c_1/dns", "/clients/{id}/dns"},
		{http.MethodPost, "/clients/c_1/pause", "/clients/{id}/pause"},
		{http.MethodPost, "/clients/c_1/resume", "/clients/{id}/resume"},
	} {
		rctx := chi.NewRouteContext()
		req, _ := http.NewRequestWithContext(context.WithValue(context.Background(), chi.RouteCtxKey, rctx), tc.method, tc.path, nil)
		if !r.Match(rctx, tc.method, tc.path) {
			t.Fatalf("%s %s: no route", tc.method, tc.path)
		}
		_ = req
		got := rctx.RoutePattern()
		if got != tc.want {
			t.Errorf("%s %s resolved to %q, want %q", tc.method, tc.path, got, tc.want)
		}
	}
}
