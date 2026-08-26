package firewall

import (
	"strings"
	"testing"

	"github.com/Neoo-Blue/orbis/internal/config"
)

// The tunnel ruleset is what makes an exit node and a VPN server actually
// move traffic. Observe mode installs no main ruleset at all, so if these
// rules were tied to inline mode a VPN would connect and reach nothing —
// which is exactly the failure this table exists to prevent.

func TestTunnelRulesetHasTheThreeThingsAnExitNodeNeeds(t *testing.T) {
	tc := TunnelConfig{
		Interfaces: []string{"tailscale0", "wg0"},
		Subnets:    []string{"100.64.0.0/10", "10.66.0.1/24"},
		WAN:        "eth0",
		RedirectDNS: true,
		DNSPort:    53,
	}
	out := renderTunnelRuleset(tc)

	// 1. Forwarding in both directions, or traffic goes out and never returns.
	if !strings.Contains(out, `iifname @tunnel_ifaces oifname "eth0" counter accept`) {
		t.Error("no rule forwarding tunnel traffic to the WAN")
	}
	if !strings.Contains(out, `iifname "eth0" oifname @tunnel_ifaces counter accept`) {
		t.Error("no rule forwarding replies back into the tunnel")
	}

	// 2. NAT. Without it the far end has no route back to a tunnel address,
	//    which looks exactly like "connected but nothing loads".
	if !strings.Contains(out, "masquerade") {
		t.Fatal("no masquerade rule — the single most common way an exit node silently fails")
	}
	if !strings.Contains(out, `iifname @tunnel_ifaces oifname "eth0" counter masquerade`) {
		t.Error("no catch-all NAT for traffic arriving on a tunnel interface")
	}

	// 3. The node's own resolver must be reachable from the tunnel.
	if !strings.Contains(out, "udp dport 53 accept") {
		t.Error("tunnel clients cannot reach the resolver")
	}

	// Balanced braces, or nft rejects the file wholesale.
	if strings.Count(out, "{") != strings.Count(out, "}") {
		t.Errorf("unbalanced braces: %d open, %d close", strings.Count(out, "{"), strings.Count(out, "}"))
	}
	// A separate table, so it can be applied and removed independently of
	// the operator's own rules.
	if !strings.Contains(out, "table inet orbis_tunnel") {
		t.Error("tunnel rules are not in their own table")
	}
	if strings.Contains(out, "table inet orbis {") {
		t.Error("tunnel rules leaked into the main table")
	}
}

func TestTunnelDNSRedirectForcesFiltering(t *testing.T) {
	tc := TunnelConfig{
		Interfaces: []string{"wg0"}, WAN: "eth0", RedirectDNS: true, DNSPort: 53,
	}
	out := renderTunnelRuleset(tc)
	// A remote device keeps its own DNS settings, so without a redirect it
	// tunnels its traffic through here and still resolves elsewhere.
	if !strings.Contains(out, "udp dport 53 redirect to :53") {
		t.Error("tunnel DNS is not redirected, so remote clients bypass filtering")
	}

	tc.RedirectDNS = false
	out = renderTunnelRuleset(tc)
	if strings.Contains(out, "redirect to :53") {
		t.Error("DNS redirect was rendered while disabled")
	}
}

func TestTunnelLANAccessIsExplicitBothWays(t *testing.T) {
	tc := TunnelConfig{
		Interfaces: []string{"tailscale0"}, WAN: "eth0",
		LANInterfaces: []string{"eth1"}, AllowLANAccess: false,
	}
	out := renderTunnelRuleset(tc)
	if !strings.Contains(out, "tunnel is internet-only") {
		t.Error("LAN access is off but nothing denies it — the behaviour would depend on another table's policy")
	}

	tc.AllowLANAccess = true
	out = renderTunnelRuleset(tc)
	if !strings.Contains(out, "tunnel to lan") || !strings.Contains(out, "lan to tunnel") {
		t.Error("LAN access is on but not permitted in both directions")
	}
	if strings.Contains(out, "tunnel is internet-only") {
		t.Error("the deny rule survived with LAN access enabled")
	}
}

func TestTunnelPrioritiesSitAheadOfTheMainTable(t *testing.T) {
	out := renderTunnelRuleset(TunnelConfig{
		Interfaces: []string{"wg0"}, WAN: "eth0", DNSPort: 53, RedirectDNS: true,
	})
	// A LAN rule must not be able to silently break the VPN, so the tunnel
	// chains run first.
	for _, want := range []string{
		"hook forward priority filter - 10",
		"hook input priority filter - 10",
		"hook postrouting priority srcnat - 10",
		"hook prerouting priority dstnat - 10",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q — tunnel rules would run after the main table", want)
		}
	}
}

func TestBuildTunnelConfigTriggers(t *testing.T) {
	base := func() config.Config {
		c := config.Default()
		c.Firewall.WANInterface = "eth0"
		return *c
	}

	// Nothing enabled: no tunnel rules at all.
	if tc := BuildTunnelConfig(base()); tc.Active() {
		t.Error("tunnel rules would be installed with no tunnel configured")
	}

	// Each of these independently makes this node a gateway for tunnel
	// traffic and so must trigger the ruleset.
	cases := map[string]func(*config.Config){
		"advertising as an exit node": func(c *config.Config) {
			c.Tailscale.Enabled = true
			c.Tailscale.AdvertiseExitNode = true
		},
		"acting as a subnet router": func(c *config.Config) {
			c.Tailscale.Enabled = true
			c.Tailscale.AdvertiseRoutes = []string{"192.168.1.0/24"}
		},
		"steering clients through an exit node": func(c *config.Config) {
			c.Tailscale.Enabled = true
			c.Tailscale.ExitNode = "peer"
			c.Tailscale.SteerClients = []string{"192.168.1.5"}
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			c := base()
			mutate(&c)
			tc := BuildTunnelConfig(c)
			// tailscale0 only lands in the set when the interface exists, so
			// assert on the subnet, which is unconditional.
			found := false
			for _, s := range tc.Subnets {
				if s == "100.64.0.0/10" {
					found = true
				}
			}
			if !found {
				t.Error("the tailnet range was not added, so tunnel traffic would not be NATed")
			}
		})
	}
}

func TestTunnelConfigSkipsInterfacesThatDoNotExist(t *testing.T) {
	c := config.Default()
	c.Firewall.WANInterface = "eth0"
	c.VPN.Server.Enabled = true
	c.VPN.Server.Interface = "wg-definitely-not-present-0"

	tc := BuildTunnelConfig(*c)
	for _, i := range tc.Interfaces {
		if i == "wg-definitely-not-present-0" {
			t.Fatal("a non-existent interface was included; nft would reject the whole ruleset")
		}
	}
}

func TestInactiveTunnelRendersNothing(t *testing.T) {
	// No WAN means tunnel traffic has nowhere to go; installing half a
	// ruleset would be worse than installing none.
	if (TunnelConfig{Interfaces: []string{"wg0"}}).Active() {
		t.Error("a tunnel with no WAN interface reported itself as active")
	}
	if (TunnelConfig{WAN: "eth0"}).Active() {
		t.Error("a WAN with no tunnel interfaces reported itself as active")
	}
}
