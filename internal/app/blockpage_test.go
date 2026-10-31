package app

import (
	"context"
	"errors"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/Neoo-Blue/orbis/internal/adblock"
	"github.com/Neoo-Blue/orbis/internal/blockpage"
	"github.com/Neoo-Blue/orbis/internal/config"
	"github.com/Neoo-Blue/orbis/internal/flows"
	"github.com/Neoo-Blue/orbis/internal/store"
	"github.com/Neoo-Blue/orbis/internal/unblock"
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

func TestAThreatSiteCannotBeOpenedForEveryoneOrForGood(t *testing.T) {
	m, err := unblock.New(filepath.Join(t.TempDir(), "unblock.json"))
	if err != nil {
		t.Fatal(err)
	}
	r, _, err := m.Ask(unblock.Request{Host: "bad.example", ClientID: "guest", Risky: true}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	a := &App{Unblock: m}
	for _, tc := range []struct {
		minutes  int
		everyone bool
	}{{0, false}, {-1, false}, {60, true}, {0, true}} {
		if _, err := a.DecideUnblock(r.ID, true, tc.minutes, tc.everyone, "owner"); !errors.Is(err, ErrTooBroad) {
			t.Fatalf("%+v: %v", tc, err)
		}
	}
	if m.Granted("guest", "bad.example", time.Now()) {
		t.Fatal("a refused answer opened the site")
	}
}

func TestReadingTheNeighbourTable(t *testing.T) {
	for out, want := range map[string]string{
		"192.168.50.243 dev eth0 lladdr 7c:7b:bf:fc:33:5a REACHABLE\n": "7c:7b:bf:fc:33:5a",
		"192.168.50.243 dev eth0  FAILED\n":                            "",
		"":                                                             "",
	} {
		if got := lladdr(out); got != want {
			t.Errorf("%q: got %q", out, got)
		}
	}
}

func TestOnlyABlockedNameCanBeAskedFor(t *testing.T) {
	cfg := config.Default()
	cfg.AdBlock.Enabled = true
	m := adblock.New()
	b := adblock.NewBuilder()
	b.AddBlock("listed.example.com", "test", "ads", false)
	b.AddBlock("co.uk", "test", "ads", true)
	m.Commit(b)
	st, err := store.Open(filepath.Join(t.TempDir(), "orbis.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	grants, err := unblock.New(filepath.Join(t.TempDir(), "unblock.json"))
	if err != nil {
		t.Fatal(err)
	}
	a := &App{Cfg: cfg, Store: st, Matcher: m, Unblock: grants, BlockGuard: blockpage.NewGuard(), Registry: flows.NewClientRegistry(st, nil)}
	guest := netip.MustParseAddr("192.168.50.9")
	if _, err := a.unblockRequest("listed.example.com", blockpage.AskForm{Minutes: 60}, guest); err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{"open.example.com", "co.uk", "com"} {
		if _, err := a.unblockRequest(host, blockpage.AskForm{Minutes: 60}, guest); !errors.Is(err, ErrNotBlocked) {
			t.Errorf("%s: %v", host, err)
		}
	}
}
