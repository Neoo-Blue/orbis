package alerts

import (
	"testing"
	"time"
)

type fakeBackend struct {
	devices []DeviceSnapshot
	mbps    float64
	domains []string
	blocked float64
}

func (f *fakeBackend) AlertDevices() []DeviceSnapshot   { return f.devices }
func (f *fakeBackend) ThroughputMbps() float64          { return f.mbps }
func (f *fakeBackend) RecentDomains(time.Time) []string { return f.domains }
func (f *fakeBackend) BlockedPerMinute() float64        { return f.blocked }

func TestBandwidthRuleFiresOverThreshold(t *testing.T) {
	b := &fakeBackend{mbps: 120}
	e := NewEngine(func() []Rule {
		return []Rule{{ID: "1", Name: "spike", Enabled: true, Type: TypeBandwidth, Threshold: 100}}
	}, b)
	now := time.Now()
	if len(e.Evaluate(now)) != 1 {
		t.Fatal("120 Mbps over a 100 threshold should fire")
	}
	// Cooldown: a second immediate evaluation must not fire again.
	if len(e.Evaluate(now.Add(time.Second))) != 0 {
		t.Fatal("cooldown should suppress a repeat")
	}
}

func TestDisabledRuleNeverFires(t *testing.T) {
	b := &fakeBackend{mbps: 999}
	e := NewEngine(func() []Rule {
		return []Rule{{ID: "1", Name: "x", Enabled: false, Type: TypeBandwidth, Threshold: 1}}
	}, b)
	if len(e.Evaluate(time.Now())) != 0 {
		t.Fatal("a disabled rule must not fire")
	}
}

func TestDeviceOfflineRule(t *testing.T) {
	b := &fakeBackend{devices: []DeviceSnapshot{
		{ID: "d", IP: "192.168.1.5", Label: "server", LastSeen: time.Now().Add(-20 * time.Minute)},
	}}
	e := NewEngine(func() []Rule {
		return []Rule{{ID: "1", Name: "down", Enabled: true, Type: TypeDeviceOffline, Match: "server", Threshold: 10}}
	}, b)
	if len(e.Evaluate(time.Now())) != 1 {
		t.Fatal("a device offline 20m past a 10m threshold should fire")
	}
}

func TestDomainRuleMatchesSubstring(t *testing.T) {
	b := &fakeBackend{domains: []string{"ads.tracker.example.com"}}
	e := NewEngine(func() []Rule {
		return []Rule{{ID: "1", Name: "watch", Enabled: true, Type: TypeDomain, Match: "tracker"}}
	}, b)
	// Force the eval window to include the domains.
	e.lastEval = time.Now().Add(-time.Minute)
	if len(e.Evaluate(time.Now())) != 1 {
		t.Fatal("a queried domain containing the match should fire")
	}
}

func TestNewDeviceFiresOnceThenCoolsDown(t *testing.T) {
	now := time.Now()
	b := &fakeBackend{devices: []DeviceSnapshot{{ID: "new", IP: "10.0.0.9", FirstSeen: now.Add(-10 * time.Second)}}}
	e := NewEngine(func() []Rule {
		return []Rule{{ID: "1", Name: "joined", Enabled: true, Type: TypeNewDevice}}
	}, b)
	e.lastEval = now.Add(-time.Minute)
	if len(e.Evaluate(now)) != 1 {
		t.Fatal("a device first seen in the window should fire once")
	}
	if len(e.Evaluate(now.Add(2*time.Second))) != 0 {
		t.Fatal("the same device must not fire again")
	}
}
