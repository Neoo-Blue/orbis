package app

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/Neoo-Blue/orbis/internal/adblock"
	"github.com/Neoo-Blue/orbis/internal/blockpage"
	"github.com/Neoo-Blue/orbis/internal/config"
	"github.com/Neoo-Blue/orbis/internal/store"
)

func TestOnlyWhatTheResolverPointedHereIsClaimed(t *testing.T) {
	a := &App{BlockGuard: blockpage.NewGuard()}
	if a.ClaimsBlockedHost("ads.example.com:443") {
		t.Fatal("nothing has been answered yet")
	}
}

func TestTheTraceAgreesWithTheResolverOnPolicies(t *testing.T) {
	cfg := config.Default()
	cfg.AdBlock.Enabled = true
	m := adblock.New()
	b := adblock.NewBuilder()
	b.AddBlock("listed.example.com", "test", "ads", false)
	m.Commit(b)
	st, err := store.Open(filepath.Join(t.TempDir(), "orbis.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.UpsertClient(&store.Client{ID: "client", PolicyID: "p"}); err != nil {
		t.Fatal(err)
	}
	a := &App{Cfg: cfg, Store: st, Matcher: m, policies: map[string]*store.Policy{
		"p": {ID: "p", Name: "Kids", Allowlist: []string{"listed.example.com", "www.tiktok.com"},
			Denylist: []string{"denied.example.com"}, BlockedServices: []string{"tiktok"}},
	}}
	for name, want := range map[string]string{
		"denied.example.com": "block",
		"www.tiktok.com":     "block",
		"listed.example.com": "allow",
		"plain.example.com":  "allow",
	} {
		out, err := a.DiagnoseDomain(context.Background(), name, "client", false)
		if err != nil {
			t.Fatal(err)
		}
		if out["verdict"] != want {
			t.Errorf("%s: %v, the resolver says %s", name, out["verdict"], want)
		}
	}
}
