package vpn

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Egress routing: sending some or all of the network out through a tunnel
// instead of the WAN.
//
// The mechanism is policy routing. Each tunnel owns a routing table holding a
// default route through its interface; an `ip rule` matching a source address
// selects that table. That is what makes "send the TV through the VPN and
// leave everything else alone" possible — a plain default route cannot express
// it, and NAT tricks break return traffic.
//
// The kill switch is a blackhole default in the same table at a worse metric.
// When the tunnel drops, its route disappears and the blackhole takes over, so
// steered traffic stops rather than silently falling back to the WAN — which is
// the failure a VPN exists to prevent, and the one users never notice.

// WGTunnel is an outbound WireGuard tunnel.
type WGTunnel struct {
	Name          string   `json:"name" yaml:"name"`
	Enabled       bool     `json:"enabled" yaml:"enabled"`
	Interface     string   `json:"interface" yaml:"interface"`
	PrivateKey    string   `json:"-" yaml:"private_key"`
	Addresses     []string `json:"addresses" yaml:"addresses"`
	DNS           []string `json:"dns" yaml:"dns"`
	MTU           int      `json:"mtu" yaml:"mtu"`
	PeerPublicKey string   `json:"peer_public_key" yaml:"peer_public_key"`
	PresharedKey  string   `json:"-" yaml:"preshared_key"`
	Endpoint      string   `json:"endpoint" yaml:"endpoint"`
	AllowedIPs    []string `json:"allowed_ips" yaml:"allowed_ips"`
	Keepalive     int      `json:"keepalive" yaml:"keepalive"`
	// RouteTable is the policy routing table id. Assigned automatically.
	RouteTable int `json:"route_table" yaml:"route_table"`
	// KillSwitch drops steered traffic when the tunnel is down instead of
	// leaking it to the WAN.
	KillSwitch bool `json:"kill_switch" yaml:"kill_switch"`
	// Ignored records wg-quick directives that were parsed but not applied,
	// so an operator importing a provider config knows what was dropped.
	Ignored []string `json:"ignored,omitempty" yaml:"-"`
	Note    string   `json:"note,omitempty" yaml:"note"`
}

// EgressTarget is somewhere traffic can be routed. Both WireGuard tunnels and
// a selected Tailscale exit node are expressed the same way so the assignment
// UI does not have to care which is which.
type EgressTarget struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Kind       string `json:"kind"` // "wireguard" | "tailscale" | "wan"
	Interface  string `json:"interface"`
	RouteTable int    `json:"route_table"`
	Up         bool   `json:"up"`
	KillSwitch bool   `json:"kill_switch"`
	Detail     string `json:"detail,omitempty"`
}

// Assignment routes one source through one target.
type Assignment struct {
	// Source is an address, a CIDR, or the literal "all" for the whole LAN.
	Source   string `json:"source" yaml:"source"`
	TargetID string `json:"target" yaml:"target"`
	// Label is the device name, purely so the UI can show it after a reload.
	Label string `json:"label,omitempty" yaml:"label"`
}

// rulePriority is the band Orbis owns. It sits above Tailscale's own rules
// (5210+) so a specific assignment wins, and well above the main table.
const (
	egressPriorityBase = 5100
	// tableBase is where WireGuard tunnel tables are allocated from. 52 is
	// Tailscale's; staying clear of it avoids a collision that would be
	// extremely confusing to debug.
	tableBase = 7100
)

type EgressManager struct {
	log func(string, ...any)

	mu       sync.RWMutex
	tunnels  map[string]*WGTunnel
	assigned []Assignment
	applied  []string
	lastErr  string
}

func NewEgressManager(log func(string, ...any)) *EgressManager {
	if log == nil {
		log = func(string, ...any) {}
	}
	return &EgressManager{log: log, tunnels: map[string]*WGTunnel{}}
}

// AllocateTable picks a routing table id that no other tunnel is using.
func (m *EgressManager) AllocateTable(existing []int) int {
	used := map[int]bool{52: true} // Tailscale's
	for _, t := range existing {
		used[t] = true
	}
	for id := tableBase; id < tableBase+200; id++ {
		if !used[id] {
			return id
		}
	}
	return 0
}

// StartTunnel brings a WireGuard tunnel up and installs its routing table.
func (m *EgressManager) StartTunnel(ctx context.Context, t *WGTunnel) error {
	if t.Interface == "" {
		t.Interface = "wgc-" + sanitizeIfname(t.Name)
	}
	if len(t.Interface) > 15 {
		// Linux caps interface names at IFNAMSIZ-1.
		t.Interface = t.Interface[:15]
	}
	if t.RouteTable == 0 {
		return fmt.Errorf("tunnel %q has no routing table assigned", t.Name)
	}

	if _, err := net.InterfaceByName(t.Interface); err != nil {
		if err := run(ctx, "ip", "link", "add", "dev", t.Interface, "type", "wireguard"); err != nil {
			return fmt.Errorf("create %s: %w", t.Interface, err)
		}
	}
	_ = run(ctx, "ip", "address", "flush", "dev", t.Interface)
	for _, addr := range t.Addresses {
		if err := run(ctx, "ip", "address", "add", addr, "dev", t.Interface); err != nil {
			return fmt.Errorf("address %s: %w", addr, err)
		}
	}
	if t.MTU > 0 {
		_ = run(ctx, "ip", "link", "set", "mtu", strconv.Itoa(t.MTU), "dev", t.Interface)
	}

	var conf strings.Builder
	fmt.Fprintf(&conf, "[Interface]\nPrivateKey = %s\n", t.PrivateKey)
	// fwmark is deliberately not set: Orbis selects the table by source
	// address, not by mark, so a mark here would only confuse the picture.
	fmt.Fprintf(&conf, "\n[Peer]\nPublicKey = %s\n", t.PeerPublicKey)
	if t.PresharedKey != "" {
		fmt.Fprintf(&conf, "PresharedKey = %s\n", t.PresharedKey)
	}
	allowed := t.AllowedIPs
	if len(allowed) == 0 {
		allowed = []string{"0.0.0.0/0", "::/0"}
	}
	fmt.Fprintf(&conf, "AllowedIPs = %s\nEndpoint = %s\n", strings.Join(allowed, ", "), t.Endpoint)
	if t.Keepalive > 0 {
		fmt.Fprintf(&conf, "PersistentKeepalive = %d\n", t.Keepalive)
	}

	cmd := exec.CommandContext(ctx, "wg", "setconf", t.Interface, "/dev/stdin")
	cmd.Stdin = strings.NewReader(conf.String())
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("wg setconf %s: %s", t.Interface, strings.TrimSpace(string(out)))
	}
	if err := run(ctx, "ip", "link", "set", "up", "dev", t.Interface); err != nil {
		return err
	}

	if err := m.installTable(ctx, t); err != nil {
		return err
	}

	m.mu.Lock()
	m.tunnels[t.Name] = t
	m.mu.Unlock()
	m.log("vpn: tunnel %q up on %s (table %d, kill switch %v)", t.Name, t.Interface, t.RouteTable, t.KillSwitch)
	return nil
}

// installTable builds the tunnel's routing table: a default through the
// tunnel, and — with the kill switch on — a blackhole behind it.
func (m *EgressManager) installTable(ctx context.Context, t *WGTunnel) error {
	table := strconv.Itoa(t.RouteTable)
	_ = run(ctx, "ip", "route", "flush", "table", table)

	if err := run(ctx, "ip", "route", "add", "default", "dev", t.Interface,
		"table", table, "metric", "1"); err != nil {
		return fmt.Errorf("default route in table %s: %w", table, err)
	}
	if t.KillSwitch {
		// A worse metric, so it only takes effect once the tunnel route is
		// withdrawn. Without it, a dropped tunnel silently sends the traffic
		// it was protecting straight out the WAN.
		_ = run(ctx, "ip", "route", "add", "blackhole", "default", "table", table, "metric", "9999")
	}
	// The tunnel's own subnet has to stay reachable inside the table, or the
	// handshake itself cannot complete.
	for _, addr := range t.Addresses {
		if pfx, err := netip.ParsePrefix(addr); err == nil {
			_ = run(ctx, "ip", "route", "add", pfx.Masked().String(), "dev", t.Interface, "table", table)
		}
	}
	return nil
}

func (m *EgressManager) StopTunnel(ctx context.Context, t *WGTunnel) error {
	if t.RouteTable > 0 {
		_ = run(ctx, "ip", "route", "flush", "table", strconv.Itoa(t.RouteTable))
	}
	if t.Interface != "" {
		_ = run(ctx, "ip", "link", "del", t.Interface)
	}
	m.mu.Lock()
	delete(m.tunnels, t.Name)
	m.mu.Unlock()
	m.log("vpn: tunnel %q down", t.Name)
	return nil
}

// ApplyAssignments rewrites every policy rule Orbis owns to match the
// requested set. Rules are cleared first so removing a device actually stops
// steering it, and a changed list never leaves a stale rule behind.
func (m *EgressManager) ApplyAssignments(ctx context.Context, assignments []Assignment, targets map[string]EgressTarget, lanPrefixes []string) error {
	m.clearRules(ctx)

	var applied []string
	var failures []string

	// Sort so a more specific source is installed at a better priority than
	// a broader one; otherwise "all devices" would shadow a per-device
	// override depending on insertion order.
	sorted := append([]Assignment(nil), assignments...)
	sort.SliceStable(sorted, func(i, j int) bool {
		return specificity(sorted[i].Source) > specificity(sorted[j].Source)
	})

	priority := egressPriorityBase
	for _, a := range sorted {
		target, ok := targets[a.TargetID]
		if !ok {
			failures = append(failures, fmt.Sprintf("%s: unknown target %q", a.Source, a.TargetID))
			continue
		}
		if target.Kind == "wan" || target.RouteTable == 0 {
			// Routing through the WAN is the absence of a rule, not a rule.
			continue
		}
		sources := []string{a.Source}
		if strings.EqualFold(a.Source, "all") {
			if len(lanPrefixes) == 0 {
				failures = append(failures, "all devices: no LAN prefixes are known")
				continue
			}
			sources = lanPrefixes
		}
		for _, src := range sources {
			err := run(ctx, "ip", "rule", "add", "from", src,
				"lookup", strconv.Itoa(target.RouteTable), "priority", strconv.Itoa(priority))
			if err != nil {
				failures = append(failures, fmt.Sprintf("%s: %v", src, err))
				continue
			}
			applied = append(applied, fmt.Sprintf("%s → %s", src, target.Name))
			priority++
		}
	}

	m.mu.Lock()
	m.assigned = assignments
	m.applied = applied
	m.lastErr = strings.Join(failures, "; ")
	m.mu.Unlock()

	if len(failures) > 0 {
		return fmt.Errorf("some assignments failed: %s", strings.Join(failures, "; "))
	}
	if len(applied) > 0 {
		m.log("vpn: routing %d source(s) through a tunnel", len(applied))
	}
	return nil
}

// specificity ranks a source so /32 beats /24 beats "all".
func specificity(src string) int {
	if strings.EqualFold(src, "all") {
		return -1
	}
	if pfx, err := netip.ParsePrefix(src); err == nil {
		return pfx.Bits()
	}
	if addr, err := netip.ParseAddr(src); err == nil {
		if addr.Is4() {
			return 32
		}
		return 128
	}
	return 0
}

// clearRules removes every rule in the band Orbis owns, identified by
// priority — which is why a dedicated band was chosen rather than letting the
// kernel assign one.
func (m *EgressManager) clearRules(ctx context.Context) {
	for p := egressPriorityBase; p < egressPriorityBase+200; p++ {
		// Each call removes one rule; loop until the kernel says there is
		// nothing left at that priority.
		for i := 0; i < 8; i++ {
			if err := run(ctx, "ip", "rule", "del", "priority", strconv.Itoa(p)); err != nil {
				break
			}
		}
	}
}

// ActiveRules reports the rules currently in the kernel, so the UI can show
// what is really in effect rather than what was requested.
func (m *EgressManager) ActiveRules(ctx context.Context) []string {
	out, err := runOutput(ctx, "ip", "rule", "show")
	if err != nil {
		return nil
	}
	active := []string{}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		colon := strings.IndexByte(line, ':')
		if colon <= 0 {
			continue
		}
		prio, err := strconv.Atoi(line[:colon])
		if err != nil || prio < egressPriorityBase || prio >= egressPriorityBase+200 {
			continue
		}
		active = append(active, strings.TrimSpace(line[colon+1:]))
	}
	return active
}

// TunnelUp reports whether a tunnel has completed a handshake recently. A
// WireGuard interface is "up" the moment it is created, so link state says
// nothing about whether the tunnel actually works.
func TunnelUp(iface string) (bool, time.Time) {
	out, err := exec.Command("wg", "show", iface, "latest-handshakes").Output()
	if err != nil {
		return false, time.Time{}
	}
	var newest time.Time
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		ts, err := strconv.ParseInt(fields[1], 10, 64)
		if err != nil || ts == 0 {
			continue
		}
		if t := time.Unix(ts, 0); t.After(newest) {
			newest = t
		}
	}
	if newest.IsZero() {
		return false, newest
	}
	// WireGuard rekeys every two minutes under load; three is a generous
	// window that still catches a genuinely dead tunnel.
	return time.Since(newest) < 3*time.Minute, newest
}

func (m *EgressManager) Status(ctx context.Context) map[string]any {
	m.mu.RLock()
	assigned := append([]Assignment(nil), m.assigned...)
	applied := append([]string(nil), m.applied...)
	lastErr := m.lastErr
	m.mu.RUnlock()

	if assigned == nil {
		assigned = []Assignment{}
	}
	if applied == nil {
		applied = []string{}
	}
	return map[string]any{
		"assignments":  assigned,
		"applied":      applied,
		"active_rules": m.ActiveRules(ctx),
		"last_error":   lastErr,
	}
}

func sanitizeIfname(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	out := b.String()
	if out == "" {
		return "tun"
	}
	return out
}

func runOutput(ctx context.Context, name string, args ...string) (string, error) {
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(cctx, name, args...).Output()
	return string(out), err
}
