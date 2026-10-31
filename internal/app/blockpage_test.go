package app

import (
	"net/netip"
	"testing"

	"github.com/Neoo-Blue/orbis/internal/adblock"
	"github.com/Neoo-Blue/orbis/internal/config"
)

func TestOnlyABlockedNameIsClaimed(t *testing.T) {
	cfg := config.Default()
	cfg.DNS.BlockPage = true
	cfg.AdBlock.Enabled = true
	m := adblock.New()
	b := adblock.NewBuilder()
	b.AddBlock("ads.example.com", "test", "ads", false)
	m.Commit(b)
	a := &App{Cfg: cfg, Matcher: m}
	client := netip.MustParseAddr("192.168.50.9")
	if !a.ClaimsBlockedHost("ads.example.com:443", client) {
		t.Fatal("a blocked name reaching this node belongs to the page")
	}
	for _, host := range []string{"192.168.50.75", "192.168.50.75:80", "orbis", "orbis:80"} {
		if a.ClaimsBlockedHost(host, client) {
			t.Fatalf("%s is someone opening Orbis", host)
		}
	}
}
