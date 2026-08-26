package app

import (
	"fmt"
	"net/netip"

	"github.com/Neoo-Blue/orbis/internal/config"
	"github.com/Neoo-Blue/orbis/internal/flows"
	"github.com/Neoo-Blue/orbis/internal/netconf"
)

// SyncVLANs reconciles the configured VLANs with the interfaces that exist,
// then makes everything downstream aware of them.
//
// A VLAN is only useful once the rest of the system knows about it: capture
// has to watch it or its devices are invisible, the flow tracker has to treat
// its subnet as local or every connection looks inbound from the internet,
// and it needs a zone or it gets no firewall policy at all. Doing all of that
// here keeps "add a VLAN" a single action rather than four.
func (a *App) SyncVLANs() error {
	cfg := a.Cfg.Snapshot()
	if len(cfg.Network.VLANs) == 0 {
		return a.Net.Apply(a.ctx, nil)
	}

	if ok, why := a.Net.Available(); !ok {
		return fmt.Errorf("VLANs cannot be configured on this node: %s", why)
	}

	applyErr := a.Net.Apply(a.ctx, cfg.Network.VLANs)

	// Fold each VLAN into its zone, so firewall policy applies without the
	// operator having to add the interface in a second place.
	if err := a.Cfg.Update(func(c *config.Config) {
		for _, v := range c.Network.VLANs {
			if !v.Enabled || v.Zone == "" {
				continue
			}
			name := v.DefaultName()
			found := false
			for i := range c.Firewall.Zones {
				if c.Firewall.Zones[i].Name != v.Zone {
					continue
				}
				found = true
				if !contains(c.Firewall.Zones[i].Interfaces, name) {
					c.Firewall.Zones[i].Interfaces = append(c.Firewall.Zones[i].Interfaces, name)
				}
				if v.Address != "" && !contains(c.Firewall.Zones[i].Subnets, subnetOf(v.Address)) {
					c.Firewall.Zones[i].Subnets = append(c.Firewall.Zones[i].Subnets, subnetOf(v.Address))
				}
			}
			if !found {
				// A zone named on a VLAN but never defined would silently
				// leave that VLAN with no policy; create it with a sensible
				// default instead.
				z := config.Zone{Name: v.Zone, Interfaces: []string{name}, Trust: "lan"}
				if v.Address != "" {
					z.Subnets = []string{subnetOf(v.Address)}
				}
				c.Firewall.Zones = append(c.Firewall.Zones, z)
			}
		}
	}); err != nil {
		return err
	}

	var names []string
	var subnets []string
	for _, v := range cfg.Network.VLANs {
		if !v.Enabled {
			continue
		}
		names = append(names, v.DefaultName())
		if v.Address != "" {
			subnets = append(subnets, subnetOf(v.Address))
		}
	}
	// Watch the tagged interfaces, and treat their subnets as local so
	// connections from them are attributed correctly rather than looking
	// like unsolicited inbound traffic.
	a.Capture.AddInterfaces(names)
	if len(subnets) > 0 {
		a.Tracker.SetLocalNets(localPrefixesPlus(subnets))
	}

	// Zones changed, so the ruleset has to be rebuilt.
	if a.Cfg.Snapshot().Mode == config.ModeInline {
		if err := a.Firewall.Apply(a.ctx); err != nil {
			a.log("firewall: reapply after VLAN change: %v", err)
		}
	}
	a.SyncTunnelRules()

	if applyErr != nil {
		return applyErr
	}
	a.log("network: %d VLAN(s) configured", len(names))
	return nil
}

// VLANStates is the live view for the UI.
func (a *App) VLANStates() []netconf.State {
	return a.Net.States(a.Cfg.Snapshot().Network.VLANs)
}

// subnetOf turns "192.168.20.1/24" into "192.168.20.0/24" — the network the
// address sits on, which is what a zone and the flow tracker care about.
func subnetOf(addr string) string {
	pfx, err := netip.ParsePrefix(addr)
	if err != nil {
		return addr
	}
	return pfx.Masked().String()
}

// localPrefixesPlus is the node's own networks plus the VLAN subnets, which
// only exist because Orbis created them.
func localPrefixesPlus(extra []string) []string {
	out := flows.LocalPrefixes()
	for _, e := range extra {
		if !contains(out, e) {
			out = append(out, e)
		}
	}
	return out
}

func contains(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}
