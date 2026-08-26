// Package backup exports and restores the configuration state of a node: the
// YAML file plus the operator-authored rows in the database. It deliberately
// does not carry telemetry (flows, DNS history, stats), because that is large,
// regenerates itself, and is not what anyone means when they ask for a backup.
package backup

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/Neoo-Blue/orbis/internal/config"
	"github.com/Neoo-Blue/orbis/internal/store"
)

// FormatVersion guards against restoring a bundle from a future layout.
const FormatVersion = 1

// Bundle is the on-disk backup document.
type Bundle struct {
	Version    int             `json:"version"`
	CreatedAt  time.Time       `json:"created_at"`
	NodeName   string          `json:"node_name"`
	OrbisBuild string          `json:"orbis_build,omitempty"`
	Config     json.RawMessage `json:"config"`
	Policies   []store.Policy  `json:"policies"`
	Rules      []store.Rule    `json:"firewall_rules"`
	LocalRules []store.LocalRule `json:"adblock_rules"`
	Clients    []ClientState   `json:"clients"`
	WGPeers    []store.WGPeer  `json:"wireguard_peers"`
}

// ClientState carries only the operator-set fields of a device. Counters and
// timestamps are observations, not configuration, and restoring them onto a
// different node would invent history that did not happen there.
type ClientState struct {
	ID       string `json:"id"`
	MAC      string `json:"mac,omitempty"`
	Label    string `json:"label,omitempty"`
	Zone     string `json:"zone,omitempty"`
	PolicyID string `json:"policy_id,omitempty"`
	VPNRoute string `json:"vpn_route,omitempty"`
	Notes    string `json:"notes,omitempty"`
	Blocked  bool   `json:"blocked"`
}

// Create builds a bundle from the live config and store.
func Create(cfg *config.Config, st *store.Store, build string) (*Bundle, error) {
	snap := cfg.Snapshot()
	// Round-tripping through JSON keeps the bundle self-describing and, more
	// importantly, reuses the same field names the API already exposes.
	raw, err := json.Marshal(snap)
	if err != nil {
		return nil, fmt.Errorf("encode config: %w", err)
	}

	b := &Bundle{
		Version:    FormatVersion,
		CreatedAt:  time.Now(),
		NodeName:   snap.Node.Name,
		OrbisBuild: build,
		Config:     raw,
	}
	if b.Policies, err = st.Policies(); err != nil {
		return nil, fmt.Errorf("policies: %w", err)
	}
	if b.Rules, err = st.Rules(); err != nil {
		return nil, fmt.Errorf("rules: %w", err)
	}
	if b.LocalRules, err = st.LocalRules(); err != nil {
		return nil, fmt.Errorf("local rules: %w", err)
	}
	if b.WGPeers, err = st.WGPeers(); err != nil {
		return nil, fmt.Errorf("wireguard peers: %w", err)
	}
	clients, err := st.Clients()
	if err != nil {
		return nil, fmt.Errorf("clients: %w", err)
	}
	for _, c := range clients {
		// A device with nothing configured on it is not worth carrying: it
		// will be rediscovered the moment it sends a packet.
		if c.Label == "" && c.Zone == "" && c.PolicyID == "" && c.VPNRoute == "" &&
			c.Notes == "" && !c.Blocked {
			continue
		}
		b.Clients = append(b.Clients, ClientState{
			ID: c.ID, MAC: c.MAC, Label: c.Label, Zone: c.Zone,
			PolicyID: c.PolicyID, VPNRoute: c.VPNRoute, Notes: c.Notes, Blocked: c.Blocked,
		})
	}
	return b, nil
}

// RestoreOptions selects what a restore touches. Restoring is destructive, so
// nothing happens unless the caller asks for it explicitly.
type RestoreOptions struct {
	Config     bool `json:"config"`
	Policies   bool `json:"policies"`
	Rules      bool `json:"firewall_rules"`
	LocalRules bool `json:"adblock_rules"`
	Clients    bool `json:"clients"`
	WGPeers    bool `json:"wireguard_peers"`
}

// Result reports what a restore actually changed.
type Result struct {
	Applied  []string `json:"applied"`
	Skipped  []string `json:"skipped"`
	Warnings []string `json:"warnings"`
}

// Restore applies a bundle. Config is rewritten wholesale via Update so that
// validation runs and a bad bundle rolls back rather than half-applying.
//
// Secrets are a deliberate exception: a bundle taken through the API has its
// keys masked, so restoring config would otherwise overwrite live credentials
// with the literal mask string. PreserveSecrets keeps the current values for
// any field that comes back masked or empty.
func Restore(cfg *config.Config, st *store.Store, b *Bundle, opts RestoreOptions) (*Result, error) {
	if b == nil {
		return nil, fmt.Errorf("empty bundle")
	}
	if b.Version > FormatVersion {
		return nil, fmt.Errorf("bundle format v%d is newer than this build understands (v%d)",
			b.Version, FormatVersion)
	}
	res := &Result{}

	if opts.Config && len(b.Config) > 0 {
		var incoming config.Config
		if err := json.Unmarshal(b.Config, &incoming); err != nil {
			return nil, fmt.Errorf("decode config: %w", err)
		}
		current := cfg.Snapshot()
		preserveSecrets(&incoming, &current)
		if err := cfg.Update(func(c *config.Config) {
			applyRestored(c, &incoming)
		}); err != nil {
			return nil, fmt.Errorf("apply config: %w", err)
		}
		res.Applied = append(res.Applied, "config")
	} else {
		res.Skipped = append(res.Skipped, "config")
	}

	if opts.Policies {
		for i := range b.Policies {
			if err := st.SavePolicy(&b.Policies[i]); err != nil {
				res.Warnings = append(res.Warnings,
					fmt.Sprintf("policy %s: %v", b.Policies[i].Name, err))
			}
		}
		res.Applied = append(res.Applied, fmt.Sprintf("policies (%d)", len(b.Policies)))
	}

	if opts.Rules {
		for i := range b.Rules {
			if err := st.SaveRule(&b.Rules[i]); err != nil {
				res.Warnings = append(res.Warnings, fmt.Sprintf("rule %s: %v", b.Rules[i].Name, err))
			}
		}
		res.Applied = append(res.Applied, fmt.Sprintf("firewall rules (%d)", len(b.Rules)))
	}

	if opts.LocalRules {
		for _, lr := range b.LocalRules {
			if err := st.SaveLocalRule(lr); err != nil {
				res.Warnings = append(res.Warnings, fmt.Sprintf("ad rule %s: %v", lr.Domain, err))
			}
		}
		res.Applied = append(res.Applied, fmt.Sprintf("ad rules (%d)", len(b.LocalRules)))
	}

	if opts.WGPeers {
		for i := range b.WGPeers {
			if err := st.SaveWGPeer(&b.WGPeers[i]); err != nil {
				res.Warnings = append(res.Warnings, fmt.Sprintf("peer %s: %v", b.WGPeers[i].Name, err))
			}
		}
		res.Applied = append(res.Applied, fmt.Sprintf("wireguard peers (%d)", len(b.WGPeers)))
	}

	if opts.Clients {
		n := 0
		for _, c := range b.Clients {
			label, zone, policy := c.Label, c.Zone, c.PolicyID
			route, notes, blocked := c.VPNRoute, c.Notes, c.Blocked
			if err := st.SetClientFields(c.ID, &label, &zone, &policy, &route, &notes, &blocked); err != nil {
				res.Warnings = append(res.Warnings, fmt.Sprintf("client %s: %v", c.ID, err))
				continue
			}
			n++
		}
		res.Applied = append(res.Applied, fmt.Sprintf("device settings (%d)", n))
	}

	return res, nil
}

// preserveSecrets copies live secret values over any that arrive masked or
// empty, so a bundle exported through the API cannot destroy credentials.
func preserveSecrets(in *config.Config, live *config.Config) {
	keep := func(dst *string, src string) {
		if *dst == "" || *dst == config.MaskedSecret {
			*dst = src
		}
	}
	keep(&in.API.SessionKey, live.API.SessionKey)
	keep(&in.API.AdminHash, live.API.AdminHash)
	keep(&in.AI.APIKey, live.AI.APIKey)
	keep(&in.Tailscale.AuthKey, live.Tailscale.AuthKey)
	keep(&in.VPN.Server.PrivateKey, live.VPN.Server.PrivateKey)
	keep(&in.Notify.Email.Password, live.Notify.Email.Password)
	for i := range in.VPN.Client {
		if i < len(live.VPN.Client) {
			keep(&in.VPN.Client[i].PrivateKey, live.VPN.Client[i].PrivateKey)
		}
	}
	for i := range in.VPN.Tunnels {
		if i < len(live.VPN.Tunnels) {
			keep(&in.VPN.Tunnels[i].PrivateKey, live.VPN.Tunnels[i].PrivateKey)
		}
	}
}

// applyRestored copies the restorable sections of a bundle onto the live
// config. Listen addresses and the store path are deliberately not restored:
// moving a bundle between hosts must not point the new node at the old one's
// paths or bind addresses and lock the operator out.
func applyRestored(dst *config.Config, src *config.Config) {
	dst.Mode = src.Mode
	dst.Node.Name = src.Node.Name
	dst.Node.Timezone = src.Node.Timezone
	dst.Node.Latitude = src.Node.Latitude
	dst.Node.Longitude = src.Node.Longitude
	dst.Node.LocatePublicIP = src.Node.LocatePublicIP
	dst.Network = src.Network
	dst.Capture = src.Capture
	dst.DNS = src.DNS
	dst.AdBlock = src.AdBlock
	dst.MITM = src.MITM
	dst.YouTube = src.YouTube
	dst.Firewall = src.Firewall
	dst.DHCP = src.DHCP
	dst.VPN = src.VPN
	dst.Tailscale = src.Tailscale
	dst.AI = src.AI
	dst.Notify = src.Notify
	dst.GeoIP = src.GeoIP
}
