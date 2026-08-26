package firewall

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/Neoo-Blue/orbis/internal/config"
)

// The tunnel gateway ruleset.
//
// Observe mode deliberately installs nothing, because the node is not the
// LAN's gateway and must not behave like one. Tunnel traffic is different:
// when a device connects over WireGuard, or routes through this node as a
// Tailscale exit node, this node *is* its gateway by definition. Nothing on
// the LAN is affected either way, so there is no reason to make the operator
// choose between "watch my network" and "my VPN works".
//
// This lives in its own nftables table so it can be applied, reloaded and
// removed entirely independently of the main ruleset, and so an operator
// reading `nft list ruleset` can see at a glance which rules exist because of
// a tunnel and which because of their own policy.
const tunnelTable = "orbis_tunnel"

// TunnelConfig describes what the tunnel path needs to work.
type TunnelConfig struct {
	// Interfaces carrying tunnel traffic, e.g. wg0 and tailscale0.
	Interfaces []string
	// Subnets are the tunnel client address ranges, used for NAT matching.
	Subnets []string
	// WAN is the interface tunnel traffic egresses through.
	WAN string
	// RedirectDNS forces tunnel clients onto this node's resolver, so a
	// remote device gets the same filtering it would on the LAN even if its
	// own DNS settings say otherwise.
	RedirectDNS bool
	DNSPort     int
	// AllowLANAccess lets tunnel clients reach the local network. Off means
	// the tunnel is internet-egress only, which is what most people want from
	// an exit node.
	AllowLANAccess bool
	// LANInterfaces is what "the local network" means for the rule above.
	LANInterfaces []string
	// IPv6 adds the equivalent v6 rules.
	IPv6 bool
}

// Active reports whether there is anything to install.
func (t TunnelConfig) Active() bool {
	return len(t.Interfaces) > 0 && t.WAN != ""
}

// TunnelStatus is surfaced in the UI so an operator can see exactly why their
// exit node does or does not work.
type TunnelStatus struct {
	Applied     bool     `json:"applied"`
	Interfaces  []string `json:"interfaces"`
	WAN         string   `json:"wan"`
	Forwarding  bool     `json:"ip_forwarding"`
	Masquerade  bool     `json:"masquerade"`
	DNSRedirect bool     `json:"dns_redirect"`
	LastError   string   `json:"last_error,omitempty"`
	Blockers    []string `json:"blockers,omitempty"`
}

// BuildTunnelConfig works out what the tunnel path needs from the current
// configuration and the interfaces that actually exist.
func BuildTunnelConfig(cfg config.Config) TunnelConfig {
	tc := TunnelConfig{
		WAN:            cfg.Firewall.WANInterface,
		RedirectDNS:    cfg.DNS.Enabled,
		DNSPort:        53,
		IPv6:           cfg.Firewall.IPv6,
		AllowLANAccess: cfg.Tailscale.ExitNodeAllowLAN,
	}

	// Only include interfaces that are actually present; naming a
	// non-existent device makes nft reject the whole ruleset.
	add := func(name string) {
		if name == "" {
			return
		}
		if _, err := net.InterfaceByName(name); err != nil {
			return
		}
		for _, existing := range tc.Interfaces {
			if existing == name {
				return
			}
		}
		tc.Interfaces = append(tc.Interfaces, name)
	}

	if cfg.VPN.Server.Enabled {
		add(cfg.VPN.Server.Interface)
		if cfg.VPN.Server.Address != "" {
			tc.Subnets = append(tc.Subnets, cfg.VPN.Server.Address)
		}
	}
	// A Tailscale node that is advertising itself as an exit node, acting as
	// a subnet router, or steering clients all need the same forwarding and
	// NAT treatment.
	if cfg.Tailscale.Enabled &&
		(cfg.Tailscale.AdvertiseExitNode || len(cfg.Tailscale.AdvertiseRoutes) > 0 ||
			cfg.Tailscale.ExitNode != "" || len(cfg.Tailscale.SteerClients) > 0) {
		add("tailscale0")
		// The tailnet CGNAT range; Tailscale hands every node an address here.
		tc.Subnets = append(tc.Subnets, "100.64.0.0/10")
	}

	for _, z := range cfg.Firewall.Zones {
		if z.Trust == "lan" {
			tc.LANInterfaces = append(tc.LANInterfaces, z.Interfaces...)
		}
	}
	// With no zones configured, the WAN interface is usually also the LAN
	// side on a single-homed node, so "LAN access" is whatever is not the
	// tunnel. Leaving the list empty makes the rule a no-op rather than
	// guessing wrong.
	return tc
}

// ApplyTunnel installs (or removes) the tunnel gateway ruleset.
func (e *Engine) ApplyTunnel(ctx context.Context, tc TunnelConfig) error {
	if !e.available {
		return fmt.Errorf("nft is not available")
	}
	if !tc.Active() {
		return e.FlushTunnel(ctx)
	}

	ruleset := renderTunnelRuleset(tc)
	if err := e.run(ctx, ruleset, true); err != nil {
		e.mu.Lock()
		e.tunnelErr = "validation failed: " + err.Error()
		e.mu.Unlock()
		return fmt.Errorf("tunnel ruleset validation failed: %w", err)
	}
	if err := e.run(ctx, ruleset, false); err != nil {
		e.mu.Lock()
		e.tunnelErr = err.Error()
		e.mu.Unlock()
		return err
	}

	e.mu.Lock()
	e.tunnelApplied = true
	e.tunnelCfg = tc
	e.tunnelErr = ""
	e.mu.Unlock()
	e.log("firewall: tunnel gateway rules applied for %s via %s",
		strings.Join(tc.Interfaces, ", "), tc.WAN)
	return nil
}

func (e *Engine) FlushTunnel(ctx context.Context) error {
	if !e.available {
		return nil
	}
	script := fmt.Sprintf("table inet %s\ndelete table inet %s\n", tunnelTable, tunnelTable)
	if err := e.run(ctx, script, false); err != nil {
		return err
	}
	e.mu.Lock()
	e.tunnelApplied = false
	e.mu.Unlock()
	return nil
}

// TunnelStatus reports what is installed and what is stopping it working.
func (e *Engine) TunnelStatus() TunnelStatus {
	e.mu.Lock()
	st := TunnelStatus{
		Applied:     e.tunnelApplied,
		Interfaces:  e.tunnelCfg.Interfaces,
		WAN:         e.tunnelCfg.WAN,
		Masquerade:  e.tunnelApplied && e.tunnelCfg.WAN != "",
		DNSRedirect: e.tunnelApplied && e.tunnelCfg.RedirectDNS,
		LastError:   e.tunnelErr,
	}
	cfg := e.tunnelCfg
	e.mu.Unlock()

	// Forwarding is the single most common reason an exit node silently does
	// nothing, so it is checked explicitly rather than assumed.
	if v, err := readSysctl("net.ipv4.ip_forward"); err == nil {
		st.Forwarding = v == "1"
	}
	if !st.Forwarding {
		st.Blockers = append(st.Blockers,
			"net.ipv4.ip_forward is 0 — nothing can be routed through this node until it is 1")
	}
	if cfg.WAN == "" {
		st.Blockers = append(st.Blockers,
			"No WAN interface is set, so tunnel traffic has no route out and cannot be NATed")
	}
	if !e.available {
		st.Blockers = append(st.Blockers, "nft is not installed")
	}
	return st
}

// renderTunnelRuleset builds the minimal ruleset that makes a tunnel work.
//
// The priorities are chosen to sit ahead of the main table's chains, so that
// tunnel traffic is handled before any LAN policy can drop it — a rule
// written for the LAN should not be able to silently break the VPN.
func renderTunnelRuleset(tc TunnelConfig) string {
	var b strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&b, format+"\n", args...) }

	w("#!/usr/sbin/nft -f")
	w("# Generated by orbis at %s — tunnel gateway rules.", time.Now().Format(time.RFC3339))
	w("#")
	w("# These exist because this node is the gateway for traffic arriving over")
	w("# a tunnel, whether or not it is the gateway for the LAN. They touch only")
	w("# traffic on %s and are removed as soon as no tunnel needs them.", strings.Join(tc.Interfaces, "/"))
	w("")
	w("table inet %s", tunnelTable)
	w("delete table inet %s", tunnelTable)
	w("")
	w("table inet %s {", tunnelTable)

	w("  set tunnel_ifaces {")
	w("    type ifname")
	w("    elements = { %s }", quoteJoin(tc.Interfaces))
	w("  }")

	v4, v6 := splitFamilies(tc.Subnets)
	if len(v4) > 0 {
		w("  set tunnel_v4 { type ipv4_addr; flags interval; elements = { %s } }", strings.Join(v4, ", "))
	}
	if len(v6) > 0 && tc.IPv6 {
		w("  set tunnel_v6 { type ipv6_addr; flags interval; elements = { %s } }", strings.Join(v6, ", "))
	}
	w("")

	// Accept the node's own services from the tunnel: a remote client that
	// cannot reach the resolver or the UI has a working tunnel and no
	// working network.
	w("  chain input {")
	w("    type filter hook input priority filter - 10; policy accept;")
	w("    iifname @tunnel_ifaces ct state established,related accept")
	w("    iifname @tunnel_ifaces udp dport %d accept comment \"dns for tunnel clients\"", tc.DNSPort)
	w("    iifname @tunnel_ifaces tcp dport %d accept comment \"dns/tcp for tunnel clients\"", tc.DNSPort)
	w("    iifname @tunnel_ifaces icmp type echo-request accept")
	w("    iifname @tunnel_ifaces ip6 nexthdr icmpv6 accept")
	w("  }")
	w("")

	// Forwarding at a priority ahead of the main filter chain, so tunnel
	// traffic is accepted before LAN policy is consulted.
	w("  chain forward {")
	w("    type filter hook forward priority filter - 10; policy accept;")
	w("    ct state established,related accept")
	w("    ct state invalid drop")
	// Egress: tunnel -> internet. This is the exit-node path.
	w("    iifname @tunnel_ifaces oifname \"%s\" counter accept comment \"tunnel to internet\"", tc.WAN)
	w("    iifname \"%s\" oifname @tunnel_ifaces counter accept comment \"internet back to tunnel\"", tc.WAN)
	// Tunnel-to-tunnel, so two remote peers can reach each other.
	w("    iifname @tunnel_ifaces oifname @tunnel_ifaces counter accept comment \"between tunnel peers\"")

	if tc.AllowLANAccess && len(tc.LANInterfaces) > 0 {
		w("    iifname @tunnel_ifaces oifname { %s } counter accept comment \"tunnel to lan\"", quoteJoin(tc.LANInterfaces))
		w("    iifname { %s } oifname @tunnel_ifaces counter accept comment \"lan to tunnel\"", quoteJoin(tc.LANInterfaces))
	} else if len(tc.LANInterfaces) > 0 {
		// Explicitly deny rather than relying on the main table's policy,
		// so the behaviour is the same in observe and inline mode.
		w("    iifname @tunnel_ifaces oifname { %s } counter drop comment \"tunnel is internet-only\"", quoteJoin(tc.LANInterfaces))
	}
	w("    tcp flags syn tcp option maxseg size set rt mtu comment \"clamp mss for the tunnel path\"")
	w("  }")
	w("")

	// NAT. Without masquerade the far side has no route back to a tunnel
	// address and an exit node appears to connect but move no traffic — the
	// single most common way this is misconfigured.
	w("  chain postrouting {")
	w("    type nat hook postrouting priority srcnat - 10;")
	if len(v4) > 0 {
		w("    ip saddr @tunnel_v4 oifname \"%s\" counter masquerade comment \"nat tunnel clients to wan\"", tc.WAN)
	}
	if len(v6) > 0 && tc.IPv6 {
		w("    ip6 saddr @tunnel_v6 oifname \"%s\" counter masquerade comment \"nat tunnel clients to wan\"", tc.WAN)
	}
	// Catch-all for anything that came in on a tunnel interface, in case a
	// peer uses an address outside the configured subnets.
	w("    iifname @tunnel_ifaces oifname \"%s\" counter masquerade comment \"nat any tunnel source\"", tc.WAN)
	w("  }")
	w("")

	if tc.RedirectDNS {
		// Force tunnel clients onto this resolver. A remote device inherits
		// its own DNS settings, so without this it would tunnel its traffic
		// through here and still resolve — and be tracked — elsewhere.
		w("  chain prerouting {")
		w("    type nat hook prerouting priority dstnat - 10;")
		w("    iifname @tunnel_ifaces udp dport 53 redirect to :%d comment \"filter tunnel dns\"", tc.DNSPort)
		w("    iifname @tunnel_ifaces tcp dport 53 redirect to :%d comment \"filter tunnel dns\"", tc.DNSPort)
		w("  }")
	}

	w("}")
	return b.String()
}
