package ai

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/Neoo-Blue/orbis/internal/adblock"
	"github.com/Neoo-Blue/orbis/internal/config"
)

// TypeSafe answers the domain judgments when it is on, with no chat model
// configured at all, and its probabilities map onto the verdict smart
// capture already consumes.
func TestTypeSafeJudge(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("Authorization") != "Bearer good" {
			w.WriteHeader(401)
			w.Write([]byte(`{"error":{"type":"authentication_error","message":"invalid key"}}`))
			return
		}
		var req struct {
			State map[string]any `json:"state"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		if req.State["heuristic_score"] != nil {
			t.Errorf("heuristic score leaked into the state")
		}
		ad, high := 0.95, 0.1
		switch req.State["domain"] {
		case "fonts.example":
			// DNS-only evidence must not arrive as zeros that read as first-party.
			if req.State["observed"] != "DNS lookups only" || req.State["http"] != nil {
				t.Errorf("DNS-only state = %v", req.State)
			}
			ad, high = 0.2, 0.45
		case "pixel.example":
			if req.State["http"] == nil {
				t.Errorf("HTTP evidence missing from state: %v", req.State)
			}
		}
		json.NewEncoder(w).Encode(map[string]any{
			"model": "jev-test",
			"answers": map[string]any{
				"ad":       map[string]any{"type": "noul", "noul": ad},
				"breakage": map[string]any{"type": "choice", "choice": "low", "probabilities": map[string]float64{"low": 1 - high, "high": high}},
			},
			"usage": map[string]int{"input_tokens": 100},
		})
	}))
	defer srv.Close()
	old := typeSafeURL
	typeSafeURL = srv.URL
	defer func() { typeSafeURL = old }()

	cfg := config.Default()
	cfg.AI.Enabled = false
	cfg.AI.TypeSafe = config.TypeSafeConfig{Enabled: true, APIKey: "good"}
	j := NewJudge(NewClient(cfg, nil, nil), nil)
	if !j.Available() {
		t.Fatal("TypeSafe alone should make the judge available")
	}

	batch := []adblock.DomainEvidence{
		{Domain: "pixel.example", ReferringSites: []string{"a.com", "b.com"}, ThirdPartyRatio: 1, AvgResponseBytes: 43},
		{Domain: "fonts.example"},
	}
	out, err := j.JudgeDomains(context.Background(), batch)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 2 {
		t.Fatalf("got %d verdicts", len(out))
	}
	if v := out[0]; !v.IsAdTech || v.Confidence != 0.95 || v.BreakageRisk != "low" {
		t.Errorf("pixel verdict = %+v", v)
	}
	// Not ad-tech at 80% confidence, and a 45% vote for high breakage is
	// enough to keep it away from an automatic block.
	if v := out[1]; v.IsAdTech || v.Confidence != 0.8 || v.BreakageRisk != "high" {
		t.Errorf("fonts verdict = %+v", v)
	}

	// A bad key fails the whole pass on the first request, not once per domain.
	cfg.Update(func(c *config.Config) { c.AI.TypeSafe.APIKey = "bad" })
	calls.Store(0)
	if _, err := j.JudgeDomains(context.Background(), batch); err == nil {
		t.Fatal("expected an auth error")
	}
	if n := calls.Load(); n != 1 {
		t.Errorf("bad key made %d requests, want 1", n)
	}

	cfg.Update(func(c *config.Config) { c.AI.TypeSafe.Enabled = false })
	if j.Available() {
		t.Error("judge available with TypeSafe off and no chat model")
	}
}
