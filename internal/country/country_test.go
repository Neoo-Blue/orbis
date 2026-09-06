package country

import (
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/Neoo-Blue/orbis/internal/config"
	"github.com/Neoo-Blue/orbis/internal/store"
)

func TestVerdictModes(t *testing.T) {
	m := NewManager(config.Default(), nil, nil, Hooks{}, nil)
	block := config.CountryConfig{Enabled: true, Mode: "block", Countries: []string{"CN", "ru"}}
	if !m.Verdict(block, "CN") || !m.Verdict(block, "RU") || m.Verdict(block, "US") || m.Verdict(block, "") {
		t.Error("block mode should block only the listed countries, never an unknown one")
	}
	allow := config.CountryConfig{Enabled: true, Mode: "allow", Countries: []string{"US", "CA"}}
	if m.Verdict(allow, "US") || !m.Verdict(allow, "DE") || m.Verdict(allow, "") {
		t.Error("allow mode should block everything not listed, never an unknown one")
	}
	if m.Verdict(config.CountryConfig{Mode: "block", Countries: []string{"CN"}}, "CN") {
		t.Error("a disabled rule blocks nothing")
	}
}

func TestObserveExemptionsAndEvents(t *testing.T) {
	cfg := config.Default()
	cfg.Country = config.CountryConfig{Enabled: true, Mode: "block", Countries: []string{"CN"}, BlockOutbound: true, BlockInbound: false,
		ExemptClients: []string{"tv"}, ExemptDomains: []string{"example.cn"}, ExemptIPs: []string{"203.0.113.0/24"}}
	var mu sync.Mutex
	var blocked []string
	var events []store.Event
	m := NewManager(cfg, nil, nil, Hooks{
		Blocker:   func(id, reason string) bool { mu.Lock(); blocked = append(blocked, id); mu.Unlock(); return true },
		Enforced:  func(local netip.Addr, outbound bool) bool { return true },
		Emit:      func(ev store.Event) { mu.Lock(); events = append(events, ev); mu.Unlock() },
		ClientFor: func(addr netip.Addr) (string, string) { return "laptop", "Laptop" },
	}, nil)
	flow := func(id, client, dst, host, dir string) *store.Flow {
		return &store.Flow{ID: id, ClientID: client, SrcIP: "192.168.1.5", DstIP: dst, Country: "CN", Hostname: host, Direction: dir}
	}
	m.Observe(flow("f1", "laptop", "1.2.3.4", "cdn.cn-site.com", "out")) // blocked
	m.Observe(flow("f2", "tv", "1.2.3.4", "", "out"))                    // exempt device
	m.Observe(flow("f3", "laptop", "1.2.3.5", "shop.example.cn", "out")) // exempt domain
	m.Observe(flow("f4", "laptop", "203.0.113.9", "", "out"))            // exempt address
	m.Observe(flow("f5", "laptop", "1.2.3.6", "", "in"))                 // inbound switched off
	m.Observe(flow("f6", "laptop", "1.2.3.7", "", "out"))                // blocked, same device+country within the hour
	time.Sleep(30 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if len(blocked) != 2 || blocked[0] != "f1" || blocked[1] != "f6" {
		t.Errorf("blocked = %v, want f1 and f6", blocked)
	}
	if len(events) != 1 || events[0].Category != "country" || events[0].Data["country"] != "CN" {
		t.Errorf("one event per device and country per hour: %+v", events)
	}
}
