package ids

import (
	"net/netip"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/Neoo-Blue/orbis/internal/config"
	"github.com/Neoo-Blue/orbis/internal/store"
)

func TestScenarioFiresAndEscalates(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	cfg := config.Default()
	var mu sync.Mutex
	var bans []struct {
		ip string
		d  time.Duration
	}
	var events []store.Event
	m := NewManager(cfg, st, Hooks{
		Ban: func(ip string, d time.Duration, reason string) (*time.Time, error) {
			mu.Lock()
			bans = append(bans, struct {
				ip string
				d  time.Duration
			}{ip, d})
			mu.Unlock()
			u := time.Now().Add(d)
			return &u, nil
		},
		Emit: func(ev store.Event) { mu.Lock(); events = append(events, ev); mu.Unlock() },
	}, nil)
	line := "sshd[1]: Failed password for root from 45.33.32.156 port 1 ssh2"
	for i := 0; i < 4; i++ {
		m.ingest(Line{Source: "syslog", Host: "nas", Text: line})
	}
	mu.Lock()
	if len(bans) != 0 {
		t.Fatalf("four failures must not ban yet: %v", bans)
	}
	mu.Unlock()
	m.ingest(Line{Source: "syslog", Host: "nas", Text: line})
	mu.Lock()
	if len(bans) != 1 || bans[0].ip != "45.33.32.156" || bans[0].d != 4*time.Hour {
		t.Fatalf("fifth failure should ban for 4h: %v", bans)
	}
	if len(events) != 1 || events[0].Category != "ids" {
		t.Errorf("one event expected: %+v", events)
	}
	mu.Unlock()
	// The window was reset by the ban; five more earn a second, doubled ban.
	for i := 0; i < 5; i++ {
		m.ingest(Line{Source: "syslog", Host: "nas", Text: line})
	}
	mu.Lock()
	if len(bans) != 2 || bans[1].d != 8*time.Hour {
		t.Fatalf("a repeat offender's ban should double: %v", bans)
	}
	mu.Unlock()
	// "maximum authentication attempts exceeded" weighs three.
	heavy := "sshd[2]: error: maximum authentication attempts exceeded for root from 45.33.32.157 port 1 ssh2 [preauth]"
	m.ingest(Line{Text: heavy})
	m.ingest(Line{Text: heavy})
	mu.Lock()
	if len(bans) != 3 || bans[2].ip != "45.33.32.157" {
		t.Fatalf("two heavy lines (weight 3 each) should cross a threshold of 5: %v", bans)
	}
	mu.Unlock()

	// An inside address is reported, never banned.
	inside := "sshd[3]: Failed password for root from 192.168.1.50 port 1 ssh2"
	for i := 0; i < 6; i++ {
		m.ingest(Line{Text: inside})
	}
	mu.Lock()
	if len(bans) != 3 {
		t.Errorf("a LAN address must not be banned: %v", bans)
	}
	found := false
	for _, ev := range events {
		if ev.Severity == store.SevWarning && ev.Data["ip"] == "192.168.1.50" {
			found = true
		}
	}
	if !found {
		t.Errorf("inside brute force should raise a warning: %+v", events)
	}
	mu.Unlock()

	// Ignored addresses do nothing.
	cfg.IDS.Ignore = []string{"45.33.33.0/24"}
	for i := 0; i < 6; i++ {
		m.ingest(Line{Text: "sshd[4]: Failed password for root from 45.33.33.9 port 1 ssh2"})
	}
	mu.Lock()
	if len(bans) != 3 {
		t.Errorf("ignored range was banned: %v", bans)
	}
	mu.Unlock()

	alerts, _ := m.Alerts(time.Now().Add(-time.Hour), 50)
	if len(alerts) != 4 {
		t.Errorf("alerts recorded = %d, want 4 (3 bans + 1 report)", len(alerts))
	}
	top := m.TopOffenders(time.Now().Add(-time.Hour))
	if len(top) == 0 || top[0]["ip"] != "45.33.32.156" {
		t.Errorf("top offender should be the repeat address: %v", top)
	}
}

func TestFlowScenarios(t *testing.T) {
	st, _ := store.Open(filepath.Join(t.TempDir(), "t.db"))
	defer st.Close()
	var banned []string
	m := NewManager(config.Default(), st, Hooks{Ban: func(ip string, d time.Duration, reason string) (*time.Time, error) {
		banned = append(banned, ip+" "+reason)
		u := time.Now().Add(d)
		return &u, nil
	}}, nil)
	for p := 1; p <= 15; p++ {
		m.ObserveFlow(&store.Flow{SrcIP: "45.33.32.200", DstIP: "192.168.1.10", DstPort: 1000 + p, Direction: "in"})
	}
	if len(banned) != 1 || banned[0][:13] != "45.33.32.200 " {
		t.Fatalf("15 distinct ports in a minute should ban: %v", banned)
	}
	for i := 0; i < 20; i++ {
		m.ObserveFlow(&store.Flow{SrcIP: "192.168.1.99", DstIP: "192.168.1.10", DstPort: 2000 + i, Direction: "in"})
		m.ObserveFlow(&store.Flow{SrcIP: "45.33.32.201", DstIP: "192.168.1.10", DstPort: 443, Direction: "out"})
	}
	if len(banned) != 1 {
		t.Errorf("private sources and outbound flows must not fire: %v", banned)
	}
	for i := 0; i < 5; i++ {
		m.ObserveFlow(&store.Flow{SrcIP: "45.33.32.202", DstIP: "192.168.1.10", DstPort: 22, Direction: "in"})
	}
	if len(banned) != 2 {
		t.Errorf("five knocks on port 22 should fire sensitive-probe: %v", banned)
	}
	if got := Test("<38>Sep  6 01:50:02 nas sshd[57941]: Failed password for root from 45.33.32.1 port 2 ssh2"); got["matched"] != true || got["scenario"] != "ssh-auth-fail" || got["host"] != "nas" {
		t.Errorf("Test() = %v", got)
	}
	_ = netip.Addr{}
}
