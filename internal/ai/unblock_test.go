package ai

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/Neoo-Blue/orbis/internal/config"
	"github.com/Neoo-Blue/orbis/internal/store"
)

// fakeTypeSafe answers a choice question named q with the given
// distribution per domain, and records which domains were asked about.
func fakeTypeSafe(t *testing.T, q string, answers map[string]map[string]float64) (*sync.Map, func()) {
	asked := &sync.Map{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			State map[string]any `json:"state"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		d, _ := req.State["domain"].(string)
		asked.Store(d, true)
		probs, ok := answers[d]
		if !ok {
			t.Errorf("asked about %q", d)
			probs = map[string]float64{"other": 1}
		}
		choice, best := "", -1.0
		for k, p := range probs {
			if p > best {
				choice, best = k, p
			}
		}
		json.NewEncoder(w).Encode(map[string]any{"model": "jev-test", "answers": map[string]any{
			q: map[string]any{"type": "choice", "choice": choice, "probabilities": probs},
		}})
	}))
	old := typeSafeURL
	typeSafeURL = srv.URL
	return asked, func() { typeSafeURL = old; srv.Close() }
}

func unblockSetup(t *testing.T) (*store.Store, *config.Config) {
	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	lists := map[string][2]any{
		"Aggressive": {"ads", store.ListEntries{Exact: []string{"push.example", "cdn.example", "widely.example"}, Wildcard: []string{"tele.example"}}},
		"Bypass":     {"bypass", store.ListEntries{Exact: []string{"dns.example"}}},
		"Two":        {"ads", store.ListEntries{Exact: []string{"widely.example"}}},
		"Three":      {"tracking", store.ListEntries{Exact: []string{"widely.example"}}},
		"Four":       {"ads", store.ListEntries{Exact: []string{"widely.example"}}},
	}
	for name, l := range lists {
		if err := st.ReplaceListDomains(name, l[0].(string), l[1].(store.ListEntries)); err != nil {
			t.Fatal(err)
		}
	}
	cfg := config.Default()
	cfg.AI.TypeSafe = config.TypeSafeConfig{Enabled: true, APIKey: "k", Unblock: true, AutoUnblock: true}
	return st, cfg
}

func blockedLog(now time.Time) []store.DNSQuery {
	q := func(name, src, ip string) store.DNSQuery {
		return store.DNSQuery{TS: now, Name: name, Blocked: true, BlockSource: src, ClientIP: ip, ClientID: ip}
	}
	return []store.DNSQuery{
		q("push.example", "Aggressive", "a"), q("push.example", "Aggressive", "b"),
		q("cdn.example", "Aggressive", "a"),
		q("sub.tele.example", "Aggressive", "a"),
		q("widely.example", "Aggressive", "a"),
		q("dns.example", "Bypass", "a"),
		q("mine.example", "local", "a"),
	}
}

// The gates are code: bypass lists and the operator's own blocks are never
// asked about, a host many lists agree on is not suggested, content is only
// suggested, and only a push/sign-in/API/update host on one or two lists is
// allowed automatically.
func TestUnblockerGates(t *testing.T) {
	asked, done := fakeTypeSafe(t, "function", map[string]map[string]float64{
		"push.example":     {"push": 0.97, "telemetry": 0.03},
		"cdn.example":      {"content": 0.95, "ads": 0.05},
		"sub.tele.example": {"telemetry": 0.95, "app_api": 0.05},
		"widely.example":   {"app_api": 0.99, "ads": 0.01},
	})
	defer done()
	st, cfg := unblockSetup(t)
	var allowed []string
	u := NewUnblocker(cfg, NewClient(cfg, nil, nil), st,
		func(since time.Time, blockedOnly bool, search string, limit int) ([]store.DNSQuery, error) {
			return blockedLog(time.Now()), nil
		},
		func() []store.Client { return []store.Client{{ID: "a", DeviceType: "phone"}} },
		func(d, note string) error { allowed = append(allowed, d); return nil },
		func(string) error { return nil }, nil, nil)

	sug, alw, err := u.Pass(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if alw != 1 || len(allowed) != 1 || allowed[0] != "push.example" {
		t.Errorf("allowed %v (%d), want push.example only", allowed, alw)
	}
	if sug != 1 {
		t.Errorf("suggested %d, want cdn.example only", sug)
	}
	for _, d := range []string{"dns.example", "mine.example"} {
		if _, ok := asked.Load(d); ok {
			t.Errorf("%s is not an ad-list block and must not be asked about", d)
		}
	}
	recs, _ := st.Recommendations("", 50)
	got := map[string]string{}
	for _, r := range recs {
		got[r.Domain] = r.Status + "/" + r.DecidedBy
	}
	if got["push.example"] != "accepted/"+AutoUnblockActor || got["cdn.example"] != "open/" || len(got) != 2 {
		t.Errorf("recommendations = %v", got)
	}

	// Judged names are not asked again within the day.
	asked.Range(func(k, _ any) bool { asked.Delete(k); return true })
	if _, _, err := u.Pass(context.Background()); err != nil {
		t.Fatal(err)
	}
	n := 0
	asked.Range(func(any, any) bool { n++; return true })
	if n != 0 {
		t.Errorf("re-asked %d name(s) in the same day", n)
	}
}

// Three automatic allows in a day is the cap; the fourth waits for a person.
func TestUnblockerDailyCap(t *testing.T) {
	_, done := fakeTypeSafe(t, "function", map[string]map[string]float64{
		"push.example":     {"push": 0.97, "telemetry": 0.03},
		"cdn.example":      {"content": 0.95, "ads": 0.05},
		"sub.tele.example": {"telemetry": 0.95, "app_api": 0.05},
		"widely.example":   {"app_api": 0.99, "ads": 0.01},
	})
	defer done()
	st, cfg := unblockSetup(t)
	for _, d := range []string{"x1.example", "x2.example", "x3.example"} {
		r, _ := st.UpsertRecommendation(store.Recommendation{ID: d, TS: time.Now(), Kind: "allow", Domain: d})
		_ = st.DecideRecommendation(r.ID, "accepted", AutoUnblockActor)
	}
	u := NewUnblocker(cfg, NewClient(cfg, nil, nil), st,
		func(since time.Time, blockedOnly bool, search string, limit int) ([]store.DNSQuery, error) {
			if !blockedOnly {
				return nil, nil
			}
			return blockedLog(time.Now()), nil
		},
		func() []store.Client { return nil },
		func(d, note string) error { t.Errorf("allowed %s past the daily cap", d); return nil },
		func(string) error { return nil }, nil, nil)
	if _, alw, err := u.Pass(context.Background()); err != nil || alw != 0 {
		t.Fatalf("allowed %d, err %v", alw, err)
	}
}
