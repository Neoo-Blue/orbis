package ai

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Neoo-Blue/orbis/internal/adblock"
	"github.com/Neoo-Blue/orbis/internal/config"
	"github.com/Neoo-Blue/orbis/internal/store"
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

// TypeSafe triage only ever lowers a detector's severity, and never sends a
// device's LAN or hardware address.
func TestTypeSafeTriage(t *testing.T) {
	unexplained := map[string]float64{"Beacon A": 0.05, "Beacon B": 0.3, "Beacon C": 0.8}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			State struct {
				Finding struct {
					Title    string         `json:"title"`
					Evidence map[string]any `json:"evidence"`
				} `json:"finding"`
			} `json:"state"`
		}
		body, _ := io.ReadAll(r.Body)
		json.Unmarshal(body, &req)
		if strings.Contains(string(body), "192.168.") || strings.Contains(string(body), "aa:bb") {
			t.Errorf("a LAN or hardware address left the node: %s", body)
		}
		if !strings.Contains(string(body), "8.8.8.8") {
			t.Errorf("the public destination was redacted too: %s", body)
		}
		u := unexplained[req.State.Finding.Title]
		json.NewEncoder(w).Encode(map[string]any{"model": "jev-test", "answers": map[string]any{
			"explanation": map[string]any{"type": "choice", "choice": "updates",
				"probabilities": map[string]float64{"updates": 1 - u, "unexplained": u}},
		}})
	}))
	defer srv.Close()
	old := typeSafeURL
	typeSafeURL = srv.URL
	defer func() { typeSafeURL = old }()

	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	cfg := config.Default()
	cfg.AI.TypeSafe = config.TypeSafeConfig{Enabled: true, APIKey: "k"}
	a := NewAnalyzer(cfg, NewClient(cfg, nil, nil), st, nil)
	var findings []Finding
	for _, title := range []string{"Beacon A", "Beacon B", "Beacon C"} {
		findings = append(findings, Finding{Kind: "beaconing", Severity: store.SevWarning, Title: title,
			Detail:   "Seen from 192.168.1.8 talking to 8.8.8.8.",
			Evidence: map[string]any{"ip": "192.168.1.5", "mac": "aa:bb", "source": "192.168.1.7", "destination": "8.8.8.8"}})
	}
	if err := a.triageTypeSafe(context.Background(), findings); err != nil {
		t.Fatal(err)
	}
	evs, _ := st.Events(time.Now().Add(-time.Hour), "", false, 10)
	got := map[string]string{}
	for _, e := range evs {
		got[e.Title] = e.Severity
	}
	want := map[string]string{"Beacon A": store.SevInfo, "Beacon B": store.SevNotice, "Beacon C": store.SevWarning}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: severity %q, want %q", k, got[k], v)
		}
	}
}

func TestLocalDestination(t *testing.T) {
	for ip, want := range map[string]bool{
		"192.168.50.75": true, "192.168.50.255": true, "127.0.0.1": true, "100.68.107.112": true,
		"224.0.0.251": true, "255.255.255.255": true, "fe80::1": true,
		"8.8.8.8": false, "91.200.42.46": false, "2606:4700::1111": false, "not-an-ip": false,
	} {
		if got := localDestination(ip); got != want {
			t.Errorf("localDestination(%s) = %v, want %v", ip, got, want)
		}
	}
}
