package intercept

import (
	"net"
	"net/netip"
	"testing"
)

var (
	gw      = netip.MustParseAddr("192.168.50.1")
	gwMAC   = mustMAC("7c:5e:98:af:67:cd")
	self    = netip.MustParseAddr("192.168.50.75")
	selfMAC = mustMAC("e4:5f:01:ae:d1:57")
	laptop  = "5c:b2:6d:06:6d:64"
	phone   = "7c:7b:bf:fc:33:5a"
	lan     = netip.MustParsePrefix("192.168.50.0/24")
)

func mustMAC(s string) net.HardwareAddr {
	m, err := net.ParseMAC(s)
	if err != nil {
		panic(err)
	}
	return m
}

func baseInput(clients map[string]string, seen map[string]string) PlanInput {
	return PlanInput{
		Clients: clients, Gateway: gw, GatewayMAC: gwMAC, SelfMAC: selfMAC,
		IsSelf: func(a netip.Addr) bool { return a == self }, LAN: lan,
		Seen: func(mac string) (netip.Addr, bool) {
			ip, ok := seen[mac]
			if !ok {
				return netip.Addr{}, false
			}
			return netip.MustParseAddr(ip), true
		},
	}
}

func targetIPs(p Plan) map[string]string {
	out := map[string]string{}
	for _, t := range p.Targets {
		out[t.IP.String()] = t.MAC.String()
	}
	return out
}

func TestPlanDropsGatewayAndSelf(t *testing.T) {
	p := MakePlan(baseInput(map[string]string{
		"192.168.50.1":  gwMAC.String(),      // the router itself
		"192.168.50.75": selfMAC.String(),    // this node
		"192.168.50.9":  "7c:5e:98:af:67:cd", // the router's MAC under another address
		"192.168.50.24": phone,               // a real device
		"192.168.50.30": "not-a-mac",         // malformed, skipped silently
		"fe80::1":       "aa:bb:cc:dd:ee:ff", // not IPv4, skipped silently
	}, map[string]string{phone: "192.168.50.24"}))

	for _, ip := range []string{"192.168.50.1", "192.168.50.75", "192.168.50.9"} {
		if p.Drops[ip] == "" {
			t.Errorf("%s should be dropped, drops=%v", ip, p.Drops)
		}
	}
	got := targetIPs(p)
	if len(got) != 1 || got["192.168.50.24"] != phone {
		t.Fatalf("targets = %v, want only the phone", got)
	}
}

// The Sep 2026 incident: a laptop enrolled at .31 took a new lease at .43.
// Without a probe it must be held back (never claimed while NAT still matches
// .31); with the laptop answering ARP at .43 the enrolment moves.
func TestPlanFollowsMovedDevice(t *testing.T) {
	clients := map[string]string{"192.168.50.31": laptop, "192.168.50.24": phone}
	seen := map[string]string{laptop: "192.168.50.43", phone: "192.168.50.24"}

	fast := MakePlan(baseInput(clients, seen))
	if _, held := fast.Held["192.168.50.31"]; !held {
		t.Fatalf("moved laptop should be held without a probe, held=%v", fast.Held)
	}
	if _, claimed := targetIPs(fast)["192.168.50.31"]; claimed {
		t.Fatal("moved laptop must not be claimed at its old address")
	}
	if _, claimed := targetIPs(fast)["192.168.50.43"]; claimed {
		t.Fatal("moved laptop must not be claimed at an unconfirmed address")
	}
	if targetIPs(fast)["192.168.50.24"] != phone {
		t.Fatal("the phone, which did not move, should still be a target")
	}

	in := baseInput(clients, seen)
	in.Confirm = func(a netip.Addr) (net.HardwareAddr, bool) {
		if a.String() == "192.168.50.43" {
			return mustMAC(laptop), true
		}
		return nil, false
	}
	probed := MakePlan(in)
	if probed.Moves["192.168.50.31"] != "192.168.50.43" {
		t.Fatalf("moves = %v, want .31 -> .43", probed.Moves)
	}
	if targetIPs(probed)["192.168.50.43"] != laptop {
		t.Fatalf("targets = %v, want the laptop at .43", targetIPs(probed))
	}
	if len(probed.Held) != 0 {
		t.Fatalf("nothing should be held once confirmed, held=%v", probed.Held)
	}
}

func TestPlanHoldsWhenProbeDisagrees(t *testing.T) {
	in := baseInput(map[string]string{"192.168.50.31": laptop}, map[string]string{laptop: "192.168.50.43"})
	in.Confirm = func(netip.Addr) (net.HardwareAddr, bool) { return mustMAC("00:11:22:33:44:55"), true }
	p := MakePlan(in)
	if len(p.Moves) != 0 || len(p.Targets) != 0 || p.Held["192.168.50.31"] == "" {
		t.Fatalf("a different MAC at the new address must hold, got %+v", p)
	}

	in.Confirm = func(netip.Addr) (net.HardwareAddr, bool) { return nil, false }
	p = MakePlan(in)
	if len(p.Moves) != 0 || len(p.Targets) != 0 || p.Held["192.168.50.31"] == "" {
		t.Fatalf("no answer at the new address must hold, got %+v", p)
	}
}

func TestPlanHoldsWhenNewAddressIsEnrolled(t *testing.T) {
	in := baseInput(map[string]string{
		"192.168.50.31": laptop,
		"192.168.50.43": phone,
	}, map[string]string{laptop: "192.168.50.43", phone: "192.168.50.43"})
	in.Confirm = func(netip.Addr) (net.HardwareAddr, bool) { return mustMAC(laptop), true }
	p := MakePlan(in)
	if p.Held["192.168.50.31"] == "" || len(p.Moves) != 0 {
		t.Fatalf("moving onto another enrolment must hold, got %+v", p)
	}
}

func TestPlanIgnoresSightingsOffTheLAN(t *testing.T) {
	// The phone joined the node's own Wi-Fi scope; that says nothing about
	// its LAN address, so keep claiming the enrolled one.
	p := MakePlan(baseInput(map[string]string{"192.168.50.24": phone}, map[string]string{phone: "192.168.60.77"}))
	if targetIPs(p)["192.168.50.24"] != phone || len(p.Held) != 0 {
		t.Fatalf("an off-LAN sighting should be ignored, got %+v", p)
	}
	// A sighting at the gateway's address is our own claim echoed back.
	p = MakePlan(baseInput(map[string]string{"192.168.50.24": phone}, map[string]string{phone: "192.168.50.1"}))
	if targetIPs(p)["192.168.50.24"] != phone || len(p.Held) != 0 {
		t.Fatalf("a sighting at the gateway address should be ignored, got %+v", p)
	}
}

func TestRefusal(t *testing.T) {
	isSelf := func(a netip.Addr) bool { return a == self }
	cases := []struct {
		ip, mac string
		refuse  bool
	}{
		{"192.168.50.1", "", true},
		{"192.168.50.75", "", true},
		{"", "7c:5e:98:af:67:cd", true},
		{"", "E4:5F:01:AE:D1:57", true},
		{"192.168.50.43", laptop, false},
		{"", "", false},
	}
	for _, c := range cases {
		var addr netip.Addr
		if c.ip != "" {
			addr = netip.MustParseAddr(c.ip)
		}
		var mac net.HardwareAddr
		if c.mac != "" {
			mac = mustMAC(c.mac)
		}
		if got := Refusal(addr, mac, gw, gwMAC, selfMAC, isSelf) != ""; got != c.refuse {
			t.Errorf("Refusal(%q, %q) refused=%v, want %v", c.ip, c.mac, got, c.refuse)
		}
	}
}
