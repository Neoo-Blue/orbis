package ai

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Neoo-Blue/orbis/internal/config"
	"github.com/Neoo-Blue/orbis/internal/store"
)

func TestIdentifyProxmoxNoAPI(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		calls.Add(1)
		t.Error("TypeSafe should not be called for a deterministic vendor")
	}))
	defer srv.Close()
	defer swapTypeSafeURL(srv.URL)()

	cfg := config.Default()
	cfg.AI.TypeSafe = config.TypeSafeConfig{Enabled: true, APIKey: "good", Identify: true}

	var got [][3]string
	id := NewIdentifier(cfg, NewClient(cfg, nil, nil),
		func() []store.Client {
			return []store.Client{{
				ID: "vm1", MAC: "bc:24:11:00:00:01", IP: "192.168.1.20",
				Vendor: "Proxmox", DeviceType: "unknown",
			}}
		},
		func(time.Time, string) ([]store.DNSQuery, error) {
			t.Error("dns log should not be consulted when the vendor already classifies")
			return nil, nil
		},
		func(cid, class, os string) bool {
			got = append(got, [3]string{cid, class, os})
			return true
		}, nil)

	n, err := id.Pass(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 || len(got) != 1 || got[0] != [3]string{"vm1", "server", ""} {
		t.Fatalf("classified %d got %v, want vm1/server", n, got)
	}
	if calls.Load() != 0 {
		t.Errorf("TypeSafe was called %d times", calls.Load())
	}
}

func TestIdentifyTypeSafeTV(t *testing.T) {
	var calls atomic.Int32
	var lastState map[string]any
	var lastBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		var req struct {
			State     map[string]any `json:"state"`
			Questions map[string]any `json:"questions"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		lastState = req.State
		body, _ := json.Marshal(req.State)
		lastBody = body
		if req.Questions["class"] == nil || req.Questions["os"] == nil {
			t.Error("expected class and os questions")
		}
		json.NewEncoder(w).Encode(map[string]any{
			"model": "jev-test",
			"answers": map[string]any{
				"class": map[string]any{"type": "choice", "choice": "tv", "probabilities": map[string]float64{"tv": 0.91, "unknown": 0.09}},
				"os":    map[string]any{"type": "choice", "choice": "Tizen", "probabilities": map[string]float64{"Tizen": 0.8, "unknown": 0.2}},
			},
		})
	}))
	defer srv.Close()
	defer swapTypeSafeURL(srv.URL)()

	cfg := config.Default()
	cfg.AI.TypeSafe = config.TypeSafeConfig{Enabled: true, APIKey: "good", Identify: true}

	mac, ip, cid := "de:ad:be:ef:00:01", "192.168.50.99", "secret-client-id"
	client := store.Client{
		ID: cid, MAC: mac, IP: ip, DeviceType: "unknown",
		Meta: map[string]string{"dhcp_vendor_class": "udhcp 1.23"},
	}
	var applied [][3]string
	id := NewIdentifier(cfg, NewClient(cfg, nil, nil),
		func() []store.Client { return []store.Client{client} },
		func(time.Time, string) ([]store.DNSQuery, error) {
			return []store.DNSQuery{
				{Name: "osb-v2.samsungqbe.com", ClientID: cid},
				{Name: "info.cspserver.net", ClientID: cid},
				{Name: "1.0.0.127.in-addr.arpa", ClientID: cid},
				{Name: "_googlecast._tcp.local", ClientID: cid},
				{Name: "ads.example", Blocked: true, ClientID: cid},
			}, nil
		},
		func(id, class, os string) bool {
			applied = append(applied, [3]string{id, class, os})
			return true
		}, nil)

	n, err := id.Pass(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 || len(applied) != 1 || applied[0] != [3]string{cid, "tv", "Tizen"} {
		t.Fatalf("classified %d applied %v", n, applied)
	}
	if lastState["ip"] != nil || lastState["mac"] != nil || lastState["id"] != nil || lastState["client_id"] != nil {
		t.Errorf("address leaked into state: %v", lastState)
	}
	raw := string(lastBody)
	if strings.Contains(raw, mac) || strings.Contains(raw, ip) || strings.Contains(raw, cid) {
		t.Errorf("state JSON contained identity fields: %s", raw)
	}
	names, _ := lastState["most_queried_names"].([]any)
	if len(names) != 2 {
		t.Fatalf("names = %v, want the two Samsung hosts (noise dropped)", names)
	}

	// Unchanged evidence must not spend another request.
	n, err = id.Pass(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("second pass classified %d", n)
	}
	if calls.Load() != 1 {
		t.Errorf("TypeSafe called %d times, want 1", calls.Load())
	}
}

func TestIdentifyLowProbability(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"model": "jev-test",
			"answers": map[string]any{
				"class": map[string]any{"type": "choice", "choice": "tv", "probabilities": map[string]float64{"tv": 0.4, "unknown": 0.6}},
				"os":    map[string]any{"type": "choice", "choice": "Tizen", "probabilities": map[string]float64{"Tizen": 0.5, "unknown": 0.5}},
			},
		})
	}))
	defer srv.Close()
	defer swapTypeSafeURL(srv.URL)()

	cfg := config.Default()
	cfg.AI.TypeSafe = config.TypeSafeConfig{Enabled: true, APIKey: "good", Identify: true}

	called := false
	id := NewIdentifier(cfg, NewClient(cfg, nil, nil),
		func() []store.Client {
			return []store.Client{{ID: "d1", Hostname: "living-room", DeviceType: "unknown"}}
		},
		func(time.Time, string) ([]store.DNSQuery, error) {
			return []store.DNSQuery{{Name: "osb-v2.samsungqbe.com"}}, nil
		},
		func(string, string, string) bool {
			called = true
			return true
		}, nil)

	n, err := id.Pass(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 || called {
		t.Fatalf("low-probability answer was applied (n=%d called=%v)", n, called)
	}
}

func swapTypeSafeURL(u string) func() {
	old := typeSafeURL
	typeSafeURL = u
	return func() { typeSafeURL = old }
}
