package threat

import (
	"net/netip"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/Neoo-Blue/orbis/internal/config"
	"github.com/Neoo-Blue/orbis/internal/store"
)

func newTestManager(t *testing.T) (*Manager, *config.Config) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	cfg := config.Default()
	cfg.Threat.Feeds = nil
	m := NewManager(cfg, st, nil, "test", t.Logf)
	return m, cfg
}

func TestBanLookupObserve(t *testing.T) {
	m, _ := newTestManager(t)

	var mu sync.Mutex
	var pushed [][]string
	var events []store.Event
	var blocked []string
	m.SetOnChange(func(v4, v6 []string) { mu.Lock(); pushed = append(pushed, v4); mu.Unlock() })
	m.SetEmit(func(ev store.Event) { mu.Lock(); events = append(events, ev); mu.Unlock() })
	m.SetBlocker(func(id, reason string) bool {
		mu.Lock()
		blocked = append(blocked, id+" "+reason)
		mu.Unlock()
		return true
	})
	m.SetEnforced(func(local netip.Addr, outbound bool) bool { return local == netip.MustParseAddr("192.168.1.20") })
	m.SetNamer(func(id string) string { return "Living room TV" })
	m.Load()

	if _, err := m.Ban("192.168.1.9", time.Hour, "nope", "manual", "test"); err == nil {
		t.Fatal("banning a private address must be refused")
	}
	dec, err := m.Ban("45.33.32.156", time.Hour, "smoke", "manual", "test")
	if err != nil {
		t.Fatal(err)
	}
	if e, ok := m.Lookup(netip.MustParseAddr("45.33.32.156")); !ok || e.Source != "manual" || e.Reason != "smoke" {
		t.Fatalf("banned address should be listed by the manual source: %v %+v", ok, e)
	}
	mu.Lock()
	if len(pushed) == 0 || len(pushed[len(pushed)-1]) != 1 || pushed[len(pushed)-1][0] != "45.33.32.156" {
		t.Fatalf("enforcement points should have received the banned host: %v", pushed)
	}
	mu.Unlock()

	// An enforced device: hit recorded, flow killed, event raised once.
	flow := &store.Flow{ID: "f1", ClientID: "c1", SrcIP: "192.168.1.20", DstIP: "45.33.32.156", DstPort: 443, Proto: "tcp", Direction: "out"}
	m.Observe(flow)
	m.Observe(&store.Flow{ID: "f2", ClientID: "c1", SrcIP: "192.168.1.20", DstIP: "45.33.32.156", DstPort: 80, Proto: "tcp", Direction: "out"})
	time.Sleep(50 * time.Millisecond) // the blocker runs on its own goroutine
	mu.Lock()
	if len(blocked) != 2 {
		t.Errorf("both flows should have been handed to the blocker: %v", blocked)
	}
	if len(events) != 1 {
		t.Errorf("the second hit within the hour must not raise a second event: %d", len(events))
	} else {
		ev := events[0]
		if ev.Category != "threat" || ev.Severity != store.SevWarning || ev.ClientID != "c1" {
			t.Errorf("event shape: %+v", ev)
		}
		if ev.Data["enforced"] != true {
			t.Errorf("event should say the connection was dropped: %v", ev.Data)
		}
		if !contains(ev.Title, "Living room TV") {
			t.Errorf("event should name the device: %q", ev.Title)
		}
	}
	mu.Unlock()

	// A device this node does not enforce for: recorded, not blocked.
	m.Observe(&store.Flow{ID: "f3", ClientID: "c2", SrcIP: "192.168.1.30", DstIP: "45.33.32.156", DstPort: 443, Proto: "tcp", Direction: "out"})
	time.Sleep(20 * time.Millisecond)
	mu.Lock()
	if len(blocked) != 2 {
		t.Errorf("an unenforced device's flow must not be blocked: %v", blocked)
	}
	mu.Unlock()
	hits, err := m.Hits(time.Now().Add(-time.Minute), 10)
	if err != nil {
		t.Fatal(err)
	}
	// f1 and f3 are distinct (device, remote) pairs; f2 fell inside f1's cooldown.
	if len(hits) != 2 {
		t.Fatalf("hits = %d, want 2: %+v", len(hits), hits)
	}
	var enforced, recorded int
	for _, h := range hits {
		if h.Enforced {
			enforced++
		} else {
			recorded++
		}
	}
	if enforced != 1 || recorded != 1 {
		t.Errorf("hits should be one dropped and one recorded: %+v", hits)
	}

	// Unban lifts it and the enforcement points hear about it.
	if n, err := m.Unban(dec.ID); err != nil || n != 1 {
		t.Fatalf("unban: %d %v", n, err)
	}
	if _, ok := m.Lookup(netip.MustParseAddr("45.33.32.156")); ok {
		t.Error("address still listed after unban")
	}
	mu.Lock()
	if last := pushed[len(pushed)-1]; len(last) != 0 {
		t.Errorf("enforcement points should now hold nothing: %v", last)
	}
	mu.Unlock()

	// Disabled feature: nothing is listed and the sets are emptied.
	m.Ban("45.33.32.156", 0, "again", "manual", "test")
	m.cfg.Update(func(c *config.Config) { c.Threat.Enabled = false })
	m.Reconfigure()
	if _, ok := m.Lookup(netip.MustParseAddr("45.33.32.156")); ok {
		t.Error("a disabled feature must list nothing")
	}
	mu.Lock()
	if last := pushed[len(pushed)-1]; len(last) != 0 {
		t.Errorf("a disabled feature must push empty sets: %v", last)
	}
	mu.Unlock()
}

func TestLoadRestoresEntriesAndDecisions(t *testing.T) {
	m, cfg := newTestManager(t)
	cfg.Threat.Feeds = []config.ThreatFeed{{Name: "test", URL: "http://x", Enabled: true, Category: "c2"}}
	if err := m.st.ReplaceThreatEntries("test", []string{"198.51.100.0/24", "5.6.7.8/32"}); err != nil {
		t.Fatal(err)
	}
	until := time.Now().Add(time.Hour)
	if err := m.st.PutThreatDecision(store.ThreatDecision{ID: "d1", Value: "9.9.9.0/24", Source: "crowdsec", Created: time.Now(), Until: &until}); err != nil {
		t.Fatal(err)
	}
	m.Load()
	// 198.51.100/24 is a documentation range; it was stored (a feed said so)
	// but the table builder trusts the parser, so it is listed.
	if e, ok := m.Lookup(netip.MustParseAddr("5.6.7.8")); !ok || e.Source != "test" || e.Reason != "c2" {
		t.Errorf("feed entry should be listed with its feed and category: %v %+v", ok, e)
	}
	if e, ok := m.Lookup(netip.MustParseAddr("9.9.9.9")); !ok || e.Source != "crowdsec" {
		t.Errorf("stored decision should be listed: %v %+v", ok, e)
	}
	entries, decisions := m.Counts()
	if entries != 3 || decisions != 1 {
		t.Errorf("counts = %d entries, %d decisions", entries, decisions)
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})()
}
