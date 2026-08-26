package netconf

import "testing"

func TestStaticRouteValidate(t *testing.T) {
	ok := StaticRoute{Destination: "10.0.0.0/8", Gateway: "192.168.1.1"}
	if err := ok.Validate(); err != nil {
		t.Fatalf("valid route rejected: %v", err)
	}
	if err := (StaticRoute{Gateway: "192.168.1.1"}).Validate(); err == nil {
		t.Error("a route with no destination must be rejected")
	}
	if err := (StaticRoute{Destination: "notacidr", Gateway: "1.1.1.1"}).Validate(); err == nil {
		t.Error("a malformed destination must be rejected")
	}
	if err := (StaticRoute{Destination: "10.0.0.0/8"}).Validate(); err == nil {
		t.Error("a route with neither gateway nor interface must be rejected")
	}
	// Interface-only routes are legitimate for point-to-point links.
	if err := (StaticRoute{Destination: "10.0.0.0/8", Interface: "wg0"}).Validate(); err != nil {
		t.Errorf("interface-only route should be allowed: %v", err)
	}
	// Mixing families silently installs a route that can never match.
	if err := (StaticRoute{Destination: "10.0.0.0/8", Gateway: "fd00::1"}).Validate(); err == nil {
		t.Error("a v6 gateway for a v4 destination must be rejected")
	}
}

func TestBroadcastFor(t *testing.T) {
	cases := map[string]string{
		"192.168.1.10/24": "192.168.1.255",
		"10.0.0.5/8":      "10.255.255.255",
		"172.16.4.1/20":   "172.16.15.255",
		"192.168.1.1/32":  "192.168.1.1",
	}
	for in, want := range cases {
		if got := BroadcastFor(in); got != want {
			t.Errorf("BroadcastFor(%q) = %q, want %q", in, got, want)
		}
	}
	if got := BroadcastFor("garbage"); got != "" {
		t.Errorf("malformed CIDR should return empty, got %q", got)
	}
	if got := BroadcastFor("fd00::1/64"); got != "" {
		t.Errorf("IPv6 has no broadcast, should return empty, got %q", got)
	}
}

func TestValidTargetRejectsInjection(t *testing.T) {
	for _, bad := range []string{
		"example.com; rm -rf /", "$(whoami)", "a|b", "host`id`", "a\nb", "", "host&x",
	} {
		if err := validTarget(bad); err == nil {
			t.Errorf("target %q should be rejected", bad)
		}
	}
	for _, good := range []string{"example.com", "1.1.1.1", "sub-domain.example.co.uk", "fd00::1"} {
		if err := validTarget(good); err != nil {
			t.Errorf("target %q should be accepted: %v", good, err)
		}
	}
}

func TestMeanJitter(t *testing.T) {
	mean, jitter := meanJitter([]float64{10, 10, 10, 10})
	if mean != 10 || jitter != 0 {
		t.Fatalf("constant samples should have zero jitter, got mean=%v jitter=%v", mean, jitter)
	}
	mean, jitter = meanJitter([]float64{10, 20})
	if mean != 15 || jitter != 5 {
		t.Fatalf("expected mean 15 jitter 5, got %v/%v", mean, jitter)
	}
	if m, j := meanJitter(nil); m != 0 || j != 0 {
		t.Fatal("empty sample set must not divide by zero")
	}
}
