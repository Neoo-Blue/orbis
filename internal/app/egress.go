package app

import (
	"context"
	"fmt"
	"net/netip"
	"strings"

	"github.com/Neoo-Blue/orbis/internal/config"
	"github.com/Neoo-Blue/orbis/internal/flows"
	"github.com/Neoo-Blue/orbis/internal/geoip"
	"github.com/Neoo-Blue/orbis/internal/store"
	"github.com/Neoo-Blue/orbis/internal/vpn"
)

// Outbound VPN routing: which devices leave through which tunnel.
//
// The three pieces are deliberately separate. A tunnel is a connection to a
// provider. A target is anywhere traffic can egress, including the plain WAN
// and a Tailscale exit node. An assignment binds a source to a target. Keeping
// them apart is what lets the UI offer one device picker that does not care
// whether the destination is WireGuard or Tailscale.

// EgressTargets lists everywhere traffic can be routed, with live state.
func (a *App) EgressTargets(ctx context.Context) []vpn.EgressTarget {
	cfg := a.Cfg.Snapshot()

	targets := []vpn.EgressTarget{{
		ID: "wan", Name: "Direct (no VPN)", Kind: "wan",
		Interface: cfg.Firewall.WANInterface, Up: true,
		Detail: "Leaves through the WAN as normal",
	}}

	for _, t := range cfg.VPN.Tunnels {
		up, last := vpn.TunnelUp(t.Interface)
		detail := "not connected"
		switch {
		case !t.Enabled:
			detail = "disabled"
		case up:
			detail = "connected, last handshake " + last.Format("15:04:05")
		case !last.IsZero():
			// A tunnel that handshook once and then stopped is a different
			// problem from one that never connected, and the kill switch
			// makes the difference visible rather than silent.
			detail = "stalled since " + last.Format("15:04:05")
		}
		targets = append(targets, vpn.EgressTarget{
			ID: t.Name, Name: t.Name, Kind: "wireguard", Interface: t.Interface,
			RouteTable: t.RouteTable, Up: up && t.Enabled,
			KillSwitch: t.KillSwitch, Detail: detail,
		})
	}

	// A selected Tailscale exit node is an egress target like any other.
	if cfg.Tailscale.Enabled && cfg.Tailscale.ExitNode != "" {
		st := a.Tailscale.Status(ctx)
		targets = append(targets, vpn.EgressTarget{
			ID: "tailscale", Name: "Tailscale: " + cfg.Tailscale.ExitNode,
			Kind: "tailscale", Interface: "tailscale0", RouteTable: 52,
			Up:     st.Running && st.ExitNodeInUse != "",
			Detail: "Exit node " + cfg.Tailscale.ExitNode,
		})
	}
	return targets
}

// SyncEgress brings every enabled tunnel up, tears down the rest, and
// reinstalls the policy rules to match the configuration.
func (a *App) SyncEgress(ctx context.Context) error {
	cfg := a.Cfg.Snapshot()
	var problems []string

	for i := range cfg.VPN.Tunnels {
		t := toVPNTunnel(cfg.VPN.Tunnels[i])
		if !t.Enabled {
			_ = a.Egress.StopTunnel(ctx, t)
			continue
		}
		if err := a.Egress.StartTunnel(ctx, t); err != nil {
			problems = append(problems, fmt.Sprintf("%s: %v", t.Name, err))
			a.log("vpn: tunnel %q failed to start: %v", t.Name, err)
			continue
		}
		// A tunnel interface only exists once it is up, so the capture set
		// and the NAT rules have to be built afterwards.
		a.Capture.AddInterfaces([]string{t.Interface})
	}

	targets := map[string]vpn.EgressTarget{}
	for _, t := range a.EgressTargets(ctx) {
		targets[t.ID] = t
	}

	assignments := make([]vpn.Assignment, 0, len(cfg.VPN.Routes))
	for _, r := range cfg.VPN.Routes {
		assignments = append(assignments, vpn.Assignment{
			Source: r.Source, TargetID: r.TargetID, Label: r.Label,
		})
	}
	if err := a.Egress.ApplyAssignments(ctx, assignments, targets, a.lanPrefixes()); err != nil {
		problems = append(problems, err.Error())
	}

	// Tunnel interfaces need forwarding and NAT just like the inbound ones.
	a.SyncTunnelRules()

	if len(problems) > 0 {
		return fmt.Errorf("%s", strings.Join(problems, "; "))
	}
	return nil
}

// lanPrefixes is what "all devices" means. It is the node's own directly
// attached private networks, excluding tunnels — routing a tunnel's own
// subnet back into that tunnel would be a loop.
// LANPrefixes is exported for the API, which shows the operator exactly what
// "all devices" will match.
func (a *App) LANPrefixes() []string { return a.lanPrefixes() }

func (a *App) lanPrefixes() []string {
	// Tunnel interfaces are excluded by name. Routing a tunnel's own address
	// range into another tunnel is a loop, and the tailnet's CGNAT range
	// passes an IsPrivate check while being anything but a LAN — steering it
	// into a WireGuard provider would take Tailscale down.
	tunnelIfaces := map[string]bool{}
	cfg := a.Cfg.Snapshot()
	tunnelIfaces["tailscale0"] = true
	if cfg.VPN.Server.Interface != "" {
		tunnelIfaces[cfg.VPN.Server.Interface] = true
	}
	for _, t := range cfg.VPN.Tunnels {
		if t.Interface != "" {
			tunnelIfaces[t.Interface] = true
		}
	}

	var out []string
	for _, cidr := range flows.LocalPrefixesExcluding(tunnelIfaces) {
		pfx, err := netip.ParsePrefix(cidr)
		if err != nil || !geoip.IsPrivate(pfx.Addr()) {
			continue
		}
		if pfx.Addr().Is6() {
			// v6 policy routing through a v4 provider tunnel is a reliable
			// way to blackhole half the internet; leave it alone.
			continue
		}
		// A /32 is this node's own address, not a network of devices.
		if pfx.Bits() >= 31 {
			continue
		}
		out = append(out, pfx.Masked().String())
	}
	return out
}

// AssignDeviceEgress routes one device through a target, or back to the WAN.
func (a *App) AssignDeviceEgress(ctx context.Context, clientID, targetID string) error {
	c := a.Registry.ByID(clientID)
	if c == nil {
		return fmt.Errorf("no device with id %s", clientID)
	}
	if c.IP == "" {
		return fmt.Errorf("device %s has no address to route", clientID)
	}

	err := a.Cfg.Update(func(cfg *config.Config) {
		out := cfg.VPN.Routes[:0]
		for _, r := range cfg.VPN.Routes {
			if r.Source != c.IP {
				out = append(out, r)
			}
		}
		cfg.VPN.Routes = out
		// "wan" is the absence of a rule, so it is stored as nothing.
		if targetID != "" && targetID != "wan" {
			cfg.VPN.Routes = append(cfg.VPN.Routes, config.EgressRoute{
				Source: c.IP, TargetID: targetID, Label: displayName(*c),
			})
		}
	})
	if err != nil {
		return err
	}

	label := targetID
	if label == "" || label == "wan" {
		label = "wan"
	}
	if err := a.Store.SetClientFields(clientID, nil, nil, nil, &label, nil, nil); err != nil {
		return err
	}
	a.Store.Audit("api", "vpn.route", clientID, "", targetID, "ok")
	a.Bus.Publish(Event{Type: "client.changed", Data: map[string]any{
		"id": clientID, "vpn_route": targetID,
	}})
	return a.SyncEgress(ctx)
}

// SetAllDevicesEgress routes the entire LAN through a target, which is the
// "put my whole network behind the VPN" case.
func (a *App) SetAllDevicesEgress(ctx context.Context, targetID string) error {
	err := a.Cfg.Update(func(cfg *config.Config) {
		out := cfg.VPN.Routes[:0]
		for _, r := range cfg.VPN.Routes {
			if !strings.EqualFold(r.Source, "all") {
				out = append(out, r)
			}
		}
		cfg.VPN.Routes = out
		if targetID != "" && targetID != "wan" {
			cfg.VPN.Routes = append(cfg.VPN.Routes, config.EgressRoute{
				Source: "all", TargetID: targetID, Label: "Every device",
			})
		}
	})
	if err != nil {
		return err
	}
	a.Store.Audit("api", "vpn.route.all", "", "", targetID, "ok")
	return a.SyncEgress(ctx)
}

func toVPNTunnel(t config.TunnelConfig) *vpn.WGTunnel {
	return &vpn.WGTunnel{
		Name: t.Name, Enabled: t.Enabled, Interface: t.Interface,
		PrivateKey: t.PrivateKey, Addresses: t.Addresses, DNS: t.DNS, MTU: t.MTU,
		PeerPublicKey: t.PeerPublicKey, PresharedKey: t.PresharedKey,
		Endpoint: t.Endpoint, AllowedIPs: t.AllowedIPs, Keepalive: t.Keepalive,
		RouteTable: t.RouteTable, KillSwitch: t.KillSwitch, Note: t.Note,
	}
}

// displayName picks the most recognisable label for a device, so a stored
// route reads "Living room TV" rather than an address.
func displayName(c store.Client) string {
	switch {
	case c.Label != "":
		return c.Label
	case c.Hostname != "":
		return c.Hostname
	case c.Vendor != "":
		return c.Vendor + " (" + c.IP + ")"
	default:
		return c.IP
	}
}
