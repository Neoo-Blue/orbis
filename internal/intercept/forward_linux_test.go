//go:build linux

package intercept

import (
	"net/netip"
	"strings"
	"testing"
)

func TestRenderForwardingMasqueradesAndScopesToClients(t *testing.T) {
	s := renderForwarding(ForwardConfig{
		LANInterface: "eth0",
		Clients:      []netip.Addr{netip.MustParseAddr("192.168.50.26")},
		RedirectDNS:  true, DNSPort: 53,
	})
	if !strings.Contains(s, "192.168.50.26") {
		t.Fatal("the client must be in the set")
	}
	if !strings.Contains(s, "masquerade") {
		t.Fatal("without masquerade the reply never returns and the client hangs")
	}
	if !strings.Contains(s, `oifname "eth0"`) {
		t.Fatal("masquerade must be scoped to the LAN interface")
	}
	if !strings.Contains(s, "udp dport 53 redirect to :53") {
		t.Fatal("DNS redirect requested but not rendered")
	}
	// A non-enrolled device must never appear, or its traffic gets filtered
	// and possibly broken without consent.
	if strings.Contains(s, "192.168.50.99") {
		t.Fatal("only enrolled clients may appear")
	}
}

func TestRenderForwardingHTTPOffByDefault(t *testing.T) {
	// The web redirect breaks any client without the CA, so it must not appear
	// unless explicitly requested.
	s := renderForwarding(ForwardConfig{
		LANInterface: "eth0",
		Clients:      []netip.Addr{netip.MustParseAddr("10.0.0.5")},
		RedirectHTTP: false,
	})
	if strings.Contains(s, "dport 443 redirect") {
		t.Fatal("HTTPS redirect must be opt-in")
	}
}

func TestRenderForwardingHTTPWhenEnabled(t *testing.T) {
	s := renderForwarding(ForwardConfig{
		LANInterface: "eth0",
		Clients:      []netip.Addr{netip.MustParseAddr("10.0.0.5")},
		RedirectHTTP: true, HTTPPort: 3128, HTTPSPort: 3129,
	})
	if !strings.Contains(s, "tcp dport 80 redirect to :3128") ||
		!strings.Contains(s, "tcp dport 443 redirect to :3129") {
		t.Fatal("opted-in web redirect not rendered")
	}
}

func TestBuildARPFrameShape(t *testing.T) {
	self, _ := parseMAC("aa:bb:cc:dd:ee:ff")
	tgt, _ := parseMAC("11:22:33:44:55:66")
	gw := netip.MustParseAddr("192.168.50.1")
	cl := netip.MustParseAddr("192.168.50.26")

	f := buildARP(arpOpReply, self, gw, tgt, cl)
	if len(f) != 42 {
		t.Fatalf("ethernet+arp frame must be 42 bytes, got %d", len(f))
	}
	// Ethernet dst is the target, src is us.
	if f[0] != 0x11 || f[6] != 0xaa {
		t.Fatal("ethernet header wrong")
	}
	// EtherType ARP.
	if f[12] != 0x08 || f[13] != 0x06 {
		t.Fatal("ethertype must be 0x0806")
	}
	// Opcode reply.
	if f[20] != 0x00 || f[21] != 0x02 {
		t.Fatal("opcode must be reply(2)")
	}
	// Sender IP is the gateway (bytes 28..32): this is the whole trick, the
	// frame claims the gateway address lives at our MAC.
	if f[28] != 192 || f[29] != 168 || f[30] != 50 || f[31] != 1 {
		t.Fatalf("sender IP must be the gateway, got %d.%d.%d.%d", f[28], f[29], f[30], f[31])
	}
	// Target IP is the client.
	if f[38] != 192 || f[39] != 168 || f[40] != 50 || f[41] != 26 {
		t.Fatal("target IP must be the client")
	}
}

func TestResolveTargetsDropsBadEntries(t *testing.T) {
	got := ResolveTargets(map[string]string{
		"192.168.50.26": "aa:bb:cc:dd:ee:ff",
		"not-an-ip":     "aa:bb:cc:dd:ee:ff",
		"192.168.50.27": "not-a-mac",
		"2001:db8::1":   "aa:bb:cc:dd:ee:ff", // v6 not supported by ARP
	})
	if len(got) != 1 {
		t.Fatalf("only the one valid v4 pair should survive, got %d", len(got))
	}
	if got[0].IP.String() != "192.168.50.26" {
		t.Fatalf("wrong survivor: %v", got[0].IP)
	}
}
