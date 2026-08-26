// Package firewall renders the operator's zones, rules and NAT into a single
// nftables ruleset and applies it atomically.
//
// Generating a complete ruleset and loading it with `nft -f` in one
// transaction is deliberate: incremental rule edits are how a firewall ends
// up in a state nobody can reason about, and an atomic replace means the box
// is never briefly wide open or briefly cut off during a reload.
package firewall

import (
	"bytes"
	"context"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Neoo-Blue/orbis/internal/config"
	"github.com/Neoo-Blue/orbis/internal/store"
)

const tableName = "orbis"

type Engine struct {
	cfg *config.Config
	st  *store.Store
	log func(string, ...any)

	mu        sync.Mutex
	applied   bool
	lastRules string
	lastError string
	lastApply time.Time
	available bool
	version   string
}

func New(cfg *config.Config, st *store.Store, log func(string, ...any)) *Engine {
	if log == nil {
		log = func(string, ...any) {}
	}
	e := &Engine{cfg: cfg, st: st, log: log}
	e.probe()
	return e
}

// probe records whether nft exists and what version, so the UI can explain a
// failure instead of just reporting "apply failed".
func (e *Engine) probe() {
	out, err := exec.Command("nft", "--version").CombinedOutput()
	if err != nil {
		e.available = false
		e.lastError = "nft not available: " + err.Error()
		return
	}
	e.available = true
	e.version = strings.TrimSpace(string(out))
}

func (e *Engine) Available() bool { return e.available }

func (e *Engine) Status() map[string]any {
	e.mu.Lock()
	defer e.mu.Unlock()
	return map[string]any{
		"available":  e.available,
		"version":    e.version,
		"applied":    e.applied,
		"last_apply": e.lastApply,
		"last_error": e.lastError,
		"mode":       string(e.cfg.Snapshot().Mode),
		"enabled":    e.cfg.Snapshot().Firewall.Enabled,
	}
}

// Render produces the ruleset text without applying it, which is what the UI
// shows in the "preview changes" pane and what the assistant reads when asked
// to explain the current posture.
func (e *Engine) Render() (string, error) {
	cfg := e.cfg.Snapshot()
	rules, err := e.st.Rules()
	if err != nil {
		return "", err
	}
	return renderRuleset(cfg, rules)
}

// Apply writes and loads the ruleset. In observe mode it is a no-op with an
// explicit reason, so an operator can never be surprised by the node quietly
// taking over forwarding.
func (e *Engine) Apply(ctx context.Context) error {
	cfg := e.cfg.Snapshot()
	if cfg.Mode != config.ModeInline {
		e.mu.Lock()
		e.applied = false
		e.lastError = "not applied: node is in observe mode"
		e.mu.Unlock()
		return nil
	}
	if !cfg.Firewall.Enabled {
		e.mu.Lock()
		e.applied = false
		e.lastError = "not applied: firewall disabled in config"
		e.mu.Unlock()
		return nil
	}
	if !e.available {
		return fmt.Errorf("nft binary not available")
	}

	ruleset, err := e.Render()
	if err != nil {
		return err
	}

	// Check the ruleset before committing. `nft -c -f` parses and validates
	// without touching the live table.
	if err := e.run(ctx, ruleset, true); err != nil {
		e.mu.Lock()
		e.lastError = "validation failed: " + err.Error()
		e.mu.Unlock()
		return fmt.Errorf("ruleset validation failed: %w", err)
	}
	if err := e.run(ctx, ruleset, false); err != nil {
		e.mu.Lock()
		e.lastError = err.Error()
		e.mu.Unlock()
		return err
	}

	e.mu.Lock()
	e.applied = true
	e.lastRules = ruleset
	e.lastError = ""
	e.lastApply = time.Now()
	e.mu.Unlock()
	e.log("firewall: ruleset applied (%d bytes)", len(ruleset))
	return nil
}

func (e *Engine) run(ctx context.Context, ruleset string, checkOnly bool) error {
	args := []string{"-f", "-"}
	if checkOnly {
		args = append([]string{"-c"}, args...)
	}
	cmd := exec.CommandContext(ctx, "nft", args...)
	cmd.Stdin = strings.NewReader(ruleset)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return fmt.Errorf("nft: %s", msg)
	}
	return nil
}

// Flush removes the table entirely, returning the box to whatever other
// firewall (if any) manages it.
func (e *Engine) Flush(ctx context.Context) error {
	if !e.available {
		return nil
	}
	script := fmt.Sprintf("table inet %s\ndelete table inet %s\n", tableName, tableName)
	if err := e.run(ctx, script, false); err != nil {
		return err
	}
	e.mu.Lock()
	e.applied = false
	e.mu.Unlock()
	e.log("firewall: table flushed")
	return nil
}

// Counters reads back per-rule packet and byte counters using the JSON output
// so the UI can show which rules are actually doing work.
func (e *Engine) Counters(ctx context.Context) (map[string][2]int64, error) {
	if !e.available {
		return nil, nil
	}
	out, err := exec.CommandContext(ctx, "nft", "-j", "list", "table", "inet", tableName).Output()
	if err != nil {
		return nil, err
	}
	return parseCounters(out)
}

// Terminate implements flows.Enforcer: it blackholes an active connection by
// adding the destination to a drop set and killing the conntrack entry so the
// client sees an immediate failure rather than a stall.
func (e *Engine) Terminate(key string, srcIP, dstIP netip.Addr, srcPort, dstPort uint16, proto uint8) error {
	cfg := e.cfg.Snapshot()
	if cfg.Mode != config.ModeInline || !e.available {
		// In observe mode the verdict is recorded but not enforced; the UI
		// labels these as "would block" so the distinction is visible.
		return nil
	}
	family := "ipv4_addr"
	setName := "orbis_blocked_v4"
	if dstIP.Is6() {
		family, setName = "ipv6_addr", "orbis_blocked_v6"
	}
	_ = family
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	script := fmt.Sprintf("add element inet %s %s { %s }\n", tableName, setName, dstIP.String())
	if err := e.run(ctx, script, false); err != nil {
		return err
	}
	// conntrack -D removes the established entry so the existing socket does
	// not keep flowing through the fast path.
	if path, err := exec.LookPath("conntrack"); err == nil {
		args := []string{"-D", "-s", srcIP.String(), "-d", dstIP.String()}
		if proto == 6 {
			args = append(args, "-p", "tcp", "--dport", strconv.Itoa(int(dstPort)))
		} else if proto == 17 {
			args = append(args, "-p", "udp", "--dport", strconv.Itoa(int(dstPort)))
		}
		_ = exec.CommandContext(ctx, path, args...).Run()
	}
	return nil
}

// UnblockAddress removes an address from the dynamic drop set.
func (e *Engine) UnblockAddress(addr netip.Addr) error {
	if !e.available {
		return nil
	}
	setName := "orbis_blocked_v4"
	if addr.Is6() {
		setName = "orbis_blocked_v6"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return e.run(ctx, fmt.Sprintf("delete element inet %s %s { %s }\n", tableName, setName, addr.String()), false)
}

// ---- rendering ----

func renderRuleset(cfg config.Config, rules []store.Rule) (string, error) {
	var b strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&b, format+"\n", args...) }

	w("#!/usr/sbin/nft -f")
	w("# Generated by orbis at %s — do not edit by hand.", time.Now().Format(time.RFC3339))
	w("# Changes belong in the Orbis UI or /etc/orbis/orbis.yaml.")
	w("")
	// Deleting then recreating inside one file makes the whole load atomic.
	w("table inet %s", tableName)
	w("delete table inet %s", tableName)
	w("")
	w("table inet %s {", tableName)

	// Zone interface sets.
	zoneIfaces := map[string][]string{}
	for _, z := range cfg.Firewall.Zones {
		zoneIfaces[z.Name] = z.Interfaces
		if len(z.Interfaces) > 0 {
			w("  set zone_%s {", sanitize(z.Name))
			w("    type ifname")
			w("    elements = { %s }", quoteJoin(z.Interfaces))
			w("  }")
		}
		if len(z.Subnets) > 0 {
			v4, v6 := splitFamilies(z.Subnets)
			if len(v4) > 0 {
				w("  set net_%s_v4 {", sanitize(z.Name))
				w("    type ipv4_addr")
				w("    flags interval")
				w("    elements = { %s }", strings.Join(v4, ", "))
				w("  }")
			}
			if len(v6) > 0 {
				w("  set net_%s_v6 {", sanitize(z.Name))
				w("    type ipv6_addr")
				w("    flags interval")
				w("    elements = { %s }", strings.Join(v6, ", "))
				w("  }")
			}
		}
	}

	// Dynamic sets driven at runtime by the flow enforcer and client blocks.
	w("  set orbis_blocked_v4 { type ipv4_addr; flags interval, timeout; timeout 1h; }")
	w("  set orbis_blocked_v6 { type ipv6_addr; flags interval, timeout; timeout 1h; }")
	w("  set orbis_quarantine_v4 { type ipv4_addr; flags interval; }")
	w("  set orbis_quarantine_v6 { type ipv6_addr; flags interval; }")
	w("")

	if cfg.Firewall.FlowOffload {
		// A flowtable short-circuits established connections in the kernel.
		// It is a large throughput win and an explicit trade: offloaded
		// packets skip the inspection chains entirely.
		ifaces := allInterfaces(cfg)
		if len(ifaces) > 0 {
			w("  flowtable ft {")
			w("    hook ingress priority filter")
			w("    devices = { %s }", quoteJoin(ifaces))
			w("  }")
			w("")
		}
	}

	// ---- input chain ----
	w("  chain input {")
	w("    type filter hook input priority filter; policy drop;")
	w("    iif lo accept comment \"loopback\"")
	w("    ct state established,related accept")
	w("    ct state invalid drop comment \"malformed or out-of-window\"")
	if cfg.Firewall.AntiLockout {
		// Without this, one bad rule strands the operator outside their own
		// firewall with no way back in except a console.
		w("    tcp dport { 22, %d } ct state new accept comment \"orbis anti-lockout\"", apiPort(cfg))
	}
	w("    ip protocol icmp icmp type { echo-request, destination-unreachable, time-exceeded, parameter-problem } accept")
	w("    ip6 nexthdr icmpv6 icmpv6 type { echo-request, destination-unreachable, packet-too-big, time-exceeded, parameter-problem, nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit, nd-router-advert } accept")

	lanZones := zonesByTrust(cfg, "lan", "vpn")
	for _, z := range lanZones {
		if len(zoneIfaces[z]) == 0 {
			continue
		}
		if cfg.DNS.Enabled {
			w("    iifname @zone_%s udp dport 53 accept comment \"dns\"", sanitize(z))
			w("    iifname @zone_%s tcp dport 53 accept comment \"dns/tcp\"", sanitize(z))
		}
		if cfg.DHCP.Enabled {
			w("    iifname @zone_%s udp dport { 67, 68 } accept comment \"dhcp\"", sanitize(z))
		}
		w("    iifname @zone_%s tcp dport %d accept comment \"orbis ui\"", sanitize(z), apiPort(cfg))
	}
	if cfg.VPN.Server.Enabled {
		w("    udp dport %d accept comment \"wireguard\"", cfg.VPN.Server.ListenPort)
	}
	if cfg.Tailscale.Enabled {
		// Tailscale needs its own UDP port open and its interface trusted,
		// or the tunnel comes up and then carries nothing.
		w("    udp dport 41641 accept comment \"tailscale\"")
		w("    iifname \"tailscale0\" accept comment \"tailnet\"")
	}
	for _, r := range filterRules(rules, "input") {
		if line := renderRule(r, cfg); line != "" {
			w("    %s", line)
		}
	}
	if cfg.Firewall.LogDropped {
		w("    limit rate 10/second burst 20 packets log prefix \"orbis-input-drop \" group %d", cfg.Firewall.NFLogGroup)
	}
	w("  }")
	w("")

	// ---- forward chain ----
	w("  chain forward {")
	w("    type filter hook forward priority filter; policy %s;", cfg.Firewall.DefaultForward)
	if cfg.Firewall.FlowOffload && len(allInterfaces(cfg)) > 0 {
		w("    ct state established,related flow add @ft")
	}
	w("    ct state established,related accept")
	w("    ct state invalid drop")
	// Runtime blocks take effect before any user rule can allow them.
	w("    ip daddr @orbis_blocked_v4 counter reject with icmp type admin-prohibited comment \"orbis dynamic block\"")
	w("    ip6 daddr @orbis_blocked_v6 counter reject with icmpv6 type admin-prohibited comment \"orbis dynamic block\"")
	w("    ip saddr @orbis_quarantine_v4 counter drop comment \"quarantined client\"")
	w("    ip6 saddr @orbis_quarantine_v6 counter drop comment \"quarantined client\"")

	if cfg.Tailscale.Enabled {
		// Forwarding both ways across tailscale0 is what makes this node an
		// exit node and a subnet router; without it Tailscale advertises a
		// capability the firewall then silently drops.
		w("    iifname \"tailscale0\" counter accept comment \"from tailnet\"")
		w("    oifname \"tailscale0\" counter accept comment \"to tailnet\"")
	}

	for _, r := range filterRules(rules, "forward") {
		if line := renderRule(r, cfg); line != "" {
			w("    %s", line)
		}
	}

	// Default zone posture: LAN out to WAN is allowed, guest and IoT are
	// isolated from the rest of the network by default.
	wan := cfg.Firewall.WANInterface
	for _, z := range cfg.Firewall.Zones {
		if len(z.Interfaces) == 0 || z.Trust == "wan" {
			continue
		}
		switch z.Trust {
		case "guest", "iot":
			// Explicitly deny reaching any other local zone before allowing
			// internet egress, or "allow out" would also allow lateral moves.
			for _, other := range cfg.Firewall.Zones {
				if other.Name == z.Name || other.Trust == "wan" || len(other.Interfaces) == 0 {
					continue
				}
				w("    iifname @zone_%s oifname @zone_%s counter drop comment \"%s isolated from %s\"",
					sanitize(z.Name), sanitize(other.Name), z.Name, other.Name)
			}
			if wan != "" {
				w("    iifname @zone_%s oifname \"%s\" counter accept comment \"%s to internet\"",
					sanitize(z.Name), wan, z.Name)
			}
		case "lan", "vpn":
			if wan != "" {
				w("    iifname @zone_%s oifname \"%s\" counter accept comment \"%s to internet\"",
					sanitize(z.Name), wan, z.Name)
			}
		}
	}
	if cfg.Firewall.LogDropped {
		w("    limit rate 10/second burst 20 packets log prefix \"orbis-forward-drop \" group %d", cfg.Firewall.NFLogGroup)
	}
	w("  }")
	w("")

	w("  chain output {")
	w("    type filter hook output priority filter; policy accept;")
	for _, r := range filterRules(rules, "output") {
		if line := renderRule(r, cfg); line != "" {
			w("    %s", line)
		}
	}
	w("  }")
	w("")

	// ---- NAT ----
	w("  chain prerouting {")
	w("    type nat hook prerouting priority dstnat;")
	for _, r := range filterRules(rules, "dnat") {
		if line := renderNAT(r); line != "" {
			w("    %s", line)
		}
	}
	if cfg.MITM.Enabled {
		// Transparent redirect into the filtering proxy. Only the zones and
		// clients the operator selected are redirected; everything else
		// keeps its direct path.
		httpPort := portOf(cfg.MITM.ListenHTTP)
		tlsPort := portOf(cfg.MITM.ListenTLS)
		for _, z := range cfg.Firewall.Zones {
			if z.Trust == "wan" || len(z.Interfaces) == 0 {
				continue
			}
			w("    iifname @zone_%s tcp dport 80 redirect to :%d comment \"orbis filter proxy\"", sanitize(z.Name), httpPort)
			w("    iifname @zone_%s tcp dport 443 redirect to :%d comment \"orbis filter proxy\"", sanitize(z.Name), tlsPort)
		}
	}
	if cfg.DNS.Enabled && cfg.Mode == config.ModeInline {
		// Hijack outbound DNS so a device with hardcoded resolvers still
		// gets filtered. This is the difference between a filter that works
		// and one a smart TV walks straight around.
		for _, z := range cfg.Firewall.Zones {
			if z.Trust == "wan" || len(z.Interfaces) == 0 {
				continue
			}
			w("    iifname @zone_%s udp dport 53 redirect to :53 comment \"dns hijack\"", sanitize(z.Name))
			w("    iifname @zone_%s tcp dport 53 redirect to :53 comment \"dns hijack\"", sanitize(z.Name))
		}
	}
	w("  }")
	w("")

	w("  chain postrouting {")
	w("    type nat hook postrouting priority srcnat;")
	if wan != "" {
		w("    oifname \"%s\" counter masquerade comment \"nat to wan\"", wan)
	}
	for _, c := range cfg.VPN.Client {
		if c.Enabled && c.Interface != "" {
			w("    oifname \"%s\" counter masquerade comment \"nat to %s\"", c.Interface, c.Name)
		}
	}
	if cfg.Tailscale.Enabled {
		// LAN clients steered into a Tailscale exit node leave via
		// tailscale0 with their original LAN source address, which the exit
		// node has no route back to. NAT them to our tailnet address.
		w("    oifname \"tailscale0\" counter masquerade comment \"nat to tailnet\"")
	}
	for _, r := range filterRules(rules, "snat") {
		if line := renderNAT(r); line != "" {
			w("    %s", line)
		}
	}
	w("  }")
	w("")

	// MSS clamping: without it, PPPoE and WireGuard paths silently blackhole
	// large packets and users see "some sites do not load".
	w("  chain mangle_forward {")
	w("    type filter hook forward priority mangle;")
	w("    tcp flags syn tcp option maxseg size set rt mtu comment \"pmtu clamp\"")
	w("  }")

	w("}")
	return b.String(), nil
}

func renderRule(r store.Rule, cfg config.Config) string {
	if !r.Enabled {
		return ""
	}
	var parts []string
	if r.SrcZone != "" {
		parts = append(parts, "iifname @zone_"+sanitize(r.SrcZone))
	}
	if r.DstZone != "" {
		parts = append(parts, "oifname @zone_"+sanitize(r.DstZone))
	}
	if r.Src != "" {
		parts = append(parts, addrMatch("saddr", r.Src))
	}
	if r.Dst != "" {
		parts = append(parts, addrMatch("daddr", r.Dst))
	}
	proto := strings.ToLower(r.Proto)
	if proto != "" && proto != "any" {
		parts = append(parts, "meta l4proto "+proto)
	}
	if r.SrcPort != "" && (proto == "tcp" || proto == "udp") {
		parts = append(parts, proto+" sport "+portSpec(r.SrcPort))
	}
	if r.DstPort != "" && (proto == "tcp" || proto == "udp") {
		parts = append(parts, proto+" dport "+portSpec(r.DstPort))
	}
	if r.Schedule != "" {
		if m := scheduleMatch(r.Schedule); m != "" {
			parts = append(parts, m)
		}
	}
	// A named counter per rule is what makes the UI's hit columns possible.
	parts = append(parts, "counter")
	if r.Log {
		parts = append(parts, fmt.Sprintf("log prefix \"orbis-%s \" group %d", sanitize(r.Name), cfg.Firewall.NFLogGroup))
	}
	switch strings.ToLower(r.Action) {
	case "accept", "allow":
		parts = append(parts, "accept")
	case "drop":
		parts = append(parts, "drop")
	case "reject":
		parts = append(parts, "reject")
	default:
		return ""
	}
	parts = append(parts, fmt.Sprintf("comment \"%s|%s\"", r.ID, sanitizeComment(r.Name)))
	return strings.Join(parts, " ")
}

func renderNAT(r store.Rule) string {
	if !r.Enabled || r.Dst == "" {
		return ""
	}
	var parts []string
	proto := strings.ToLower(r.Proto)
	if proto == "" {
		proto = "tcp"
	}
	if r.SrcZone != "" {
		parts = append(parts, "iifname @zone_"+sanitize(r.SrcZone))
	}
	if r.DstPort != "" {
		parts = append(parts, proto+" dport "+portSpec(r.DstPort))
	}
	parts = append(parts, "counter")
	if r.Chain == "dnat" {
		parts = append(parts, "dnat to "+r.Dst)
	} else {
		parts = append(parts, "snat to "+r.Dst)
	}
	parts = append(parts, fmt.Sprintf("comment \"%s|%s\"", r.ID, sanitizeComment(r.Name)))
	return strings.Join(parts, " ")
}

// addrMatch handles a single address, a CIDR, or a comma-separated set, and
// picks the right family keyword.
func addrMatch(dir, spec string) string {
	items := strings.Split(spec, ",")
	var v4, v6 []string
	for _, it := range items {
		it = strings.TrimSpace(it)
		if it == "" {
			continue
		}
		if strings.Contains(it, ":") {
			v6 = append(v6, it)
		} else {
			v4 = append(v4, it)
		}
	}
	switch {
	case len(v6) > 0 && len(v4) == 0:
		return "ip6 " + dir + " " + set(v6)
	case len(v4) > 0 && len(v6) == 0:
		return "ip " + dir + " " + set(v4)
	default:
		// Mixed families cannot share one expression; the v4 half is used
		// and the config UI rejects mixed entries before they get here.
		return "ip " + dir + " " + set(v4)
	}
}

func set(items []string) string {
	if len(items) == 1 {
		return items[0]
	}
	return "{ " + strings.Join(items, ", ") + " }"
}

func portSpec(spec string) string {
	items := strings.Split(spec, ",")
	for i := range items {
		items[i] = strings.TrimSpace(strings.ReplaceAll(items[i], "-", "-"))
	}
	return set(items)
}

// scheduleMatch turns "mon-fri 09:00-17:00" into nftables time expressions,
// which is how "no social media during homework hours" becomes a real rule
// rather than a cron job that edits the firewall.
func scheduleMatch(spec string) string {
	parts := strings.Fields(strings.ToLower(spec))
	var out []string
	for _, p := range parts {
		if strings.Contains(p, ":") {
			if from, to, ok := strings.Cut(p, "-"); ok {
				out = append(out, fmt.Sprintf("meta hour \"%s\"-\"%s\"", from, to))
			}
			continue
		}
		if from, to, ok := strings.Cut(p, "-"); ok {
			days := expandDays(from, to)
			if len(days) > 0 {
				out = append(out, "meta day { "+strings.Join(days, ", ")+" }")
			}
		} else if d := dayName(p); d != "" {
			out = append(out, "meta day \""+d+"\"")
		}
	}
	return strings.Join(out, " ")
}

var dayOrder = []string{"sunday", "monday", "tuesday", "wednesday", "thursday", "friday", "saturday"}

func dayName(s string) string {
	s = strings.ToLower(s)
	for _, d := range dayOrder {
		if strings.HasPrefix(d, s) {
			return d
		}
	}
	return ""
}

func expandDays(from, to string) []string {
	f, t := dayName(from), dayName(to)
	if f == "" || t == "" {
		return nil
	}
	fi, ti := indexOf(dayOrder, f), indexOf(dayOrder, t)
	if fi < 0 || ti < 0 {
		return nil
	}
	var out []string
	for i := fi; ; i = (i + 1) % 7 {
		out = append(out, "\""+dayOrder[i]+"\"")
		if i == ti || len(out) > 7 {
			break
		}
	}
	return out
}

func indexOf(list []string, v string) int {
	for i, s := range list {
		if s == v {
			return i
		}
	}
	return -1
}

func filterRules(rules []store.Rule, chain string) []store.Rule {
	var out []store.Rule
	for _, r := range rules {
		if strings.EqualFold(r.Chain, chain) {
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Position < out[j].Position })
	return out
}

func zonesByTrust(cfg config.Config, trusts ...string) []string {
	want := map[string]bool{}
	for _, t := range trusts {
		want[t] = true
	}
	var out []string
	for _, z := range cfg.Firewall.Zones {
		if want[z.Trust] {
			out = append(out, z.Name)
		}
	}
	return out
}

func allInterfaces(cfg config.Config) []string {
	seen := map[string]bool{}
	var out []string
	for _, z := range cfg.Firewall.Zones {
		for _, i := range z.Interfaces {
			if !seen[i] {
				seen[i] = true
				out = append(out, i)
			}
		}
	}
	return out
}

func splitFamilies(cidrs []string) (v4, v6 []string) {
	for _, c := range cidrs {
		if strings.Contains(c, ":") {
			v6 = append(v6, c)
		} else {
			v4 = append(v4, c)
		}
	}
	return
}

// sanitize makes a user-supplied name safe as an nftables identifier.
func sanitize(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '_' || r == '-':
			b.WriteRune('_')
		default:
			b.WriteRune('_')
		}
	}
	out := b.String()
	if out == "" {
		return "zone"
	}
	if out[0] >= '0' && out[0] <= '9' {
		return "z" + out
	}
	return out
}

// sanitizeComment reduces an operator-supplied name to a form that cannot
// affect the ruleset. Stripping quotes and backslashes is what actually
// prevents breaking out of the comment string; semicolons, braces and the
// length cap are defence in depth, so that even a future change to how
// comments are emitted cannot turn a rule name into a statement.
func sanitizeComment(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch r {
		case '"', '\\', '\n', '\r', ';', '{', '}', '#':
			b.WriteByte(' ')
		default:
			if r < 0x20 || r > 0x7e {
				// nftables comments are ASCII; anything else is dropped
				// rather than emitted as bytes nft may reject.
				continue
			}
			b.WriteRune(r)
		}
	}
	out := strings.TrimSpace(b.String())
	// nftables caps comments at 128 bytes; 48 keeps `nft list ruleset`
	// readable and leaves room for the id prefix.
	if len(out) > 48 {
		out = out[:48]
	}
	return out
}

func quoteJoin(items []string) string {
	out := make([]string, len(items))
	for i, s := range items {
		out[i] = "\"" + sanitizeComment(s) + "\""
	}
	return strings.Join(out, ", ")
}

func apiPort(cfg config.Config) int {
	return portOf(cfg.API.Listen)
}

func portOf(listen string) int {
	_, portStr, err := splitHostPortLoose(listen)
	if err != nil {
		return 8080
	}
	p, err := strconv.Atoi(portStr)
	if err != nil {
		return 8080
	}
	return p
}

func splitHostPortLoose(s string) (string, string, error) {
	i := strings.LastIndex(s, ":")
	if i < 0 {
		return "", "", fmt.Errorf("no port in %q", s)
	}
	return s[:i], s[i+1:], nil
}

var _ = os.Getenv
