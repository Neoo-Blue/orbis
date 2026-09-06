// Package wifi runs an access point on a wireless adapter through hostapd.
// In routed mode the Wi-Fi network is its own subnet with this node as
// gateway, DHCP server and resolver, translated out through the wired side,
// so every Wi-Fi client is fully behind Orbis whether or not this node is
// the network's gateway. In bridge mode hostapd attaches the adapter to an
// existing bridge and the wired network serves it.
package wifi

import (
	"bufio"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Neoo-Blue/orbis/internal/config"
	"github.com/Neoo-Blue/orbis/internal/store"
	"github.com/google/uuid"
)

const (
	runDir    = "/run/orbis"
	tableName = "orbis_wifi"
)

// Hooks are what the application lends the manager.
type Hooks struct {
	// StartDHCP serves a scope on the Wi-Fi interface and returns a stop.
	StartDHCP func(scope config.DHCPScope) (func(), error)
	// ThreatElements are the listed addresses to drop for Wi-Fi clients.
	ThreatElements func() []string
	// GeoElements are the country sets: listed ranges, exempt devices, and
	// whether each direction is on.
	GeoElements func() (v4, exempt4 []string, out, in bool)
	NameByMAC   func(mac string) string
	LeaseByMAC  func(mac string) string
	Emit        func(store.Event)
}

// Manager owns the hostapd process and the plumbing around it.
type Manager struct {
	cfg   *config.Config
	hooks Hooks
	log   func(string, ...any)

	mu        sync.Mutex
	cmd       *exec.Cmd
	running   bool
	iface     string
	sig       string
	lastErr   string
	startedAt time.Time
	stopDHCP  func()
	nmManaged bool
	restarts  int
	lastLines []string
	ctx       context.Context
}

func NewManager(cfg *config.Config, hooks Hooks, log func(string, ...any)) *Manager {
	if log == nil {
		log = func(string, ...any) {}
	}
	return &Manager{cfg: cfg, hooks: hooks, log: log}
}

// Adapters lists wireless interfaces present on this node.
func Adapters() []string {
	entries, err := os.ReadDir("/sys/class/net")
	if err != nil {
		return []string{}
	}
	out := []string{}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "p2p-") {
			continue
		}
		if _, err := os.Stat(filepath.Join("/sys/class/net", e.Name(), "phy80211")); err == nil {
			out = append(out, e.Name())
		}
	}
	return out
}

func binary(name string) string {
	if p, err := exec.LookPath(name); err == nil {
		return p
	}
	for _, dir := range []string{"/usr/sbin", "/sbin", "/usr/local/sbin", "/usr/bin"} {
		p := filepath.Join(dir, name)
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p
		}
	}
	return ""
}

// GeneratePassphrase returns a passphrase a person can type from a phone.
func GeneratePassphrase() string {
	const alphabet = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	b := make([]byte, 14)
	if _, err := rand.Read(b); err != nil {
		return "orbis-" + strconv.FormatInt(time.Now().UnixNano()%1000000, 10)
	}
	for i := range b {
		b[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return string(b)
}

// Run keeps the access point matching the configuration until ctx ends.
func (m *Manager) Run(ctx context.Context) {
	m.mu.Lock()
	m.ctx = ctx
	m.mu.Unlock()
	if err := m.Reconcile(ctx); err != nil {
		m.log("wifi: %v", err)
	}
	tick := time.NewTicker(15 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			m.Stop()
			return
		case <-tick.C:
			// A hostapd that died is restarted; a config that changed is
			// applied. Both are the same reconcile.
			if err := m.Reconcile(ctx); err != nil {
				m.mu.Lock()
				changed := m.lastErr != err.Error()
				m.lastErr = err.Error()
				m.mu.Unlock()
				if changed {
					m.log("wifi: %v", err)
				}
			}
		}
	}
}

// Running reports whether hostapd is up.
func (m *Manager) Running() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.running
}

// Subnet returns the Wi-Fi network in routed mode, or an invalid prefix.
func (m *Manager) Subnet() netip.Prefix {
	cfg := m.cfg.Snapshot().WiFi
	if !cfg.Enabled || cfg.Mode == "bridge" {
		return netip.Prefix{}
	}
	p, err := netip.ParsePrefix(cfg.Subnet)
	if err != nil {
		return netip.Prefix{}
	}
	return p.Masked()
}

func (m *Manager) pickInterface(cfg config.WiFiConfig) string {
	if cfg.Interface != "" {
		return cfg.Interface
	}
	if a := Adapters(); len(a) > 0 {
		return a[0]
	}
	return ""
}

func signatureOf(cfg config.WiFiConfig, iface string) string {
	return strings.Join([]string{iface, cfg.SSID, cfg.Passphrase, cfg.Band, strconv.Itoa(cfg.Channel), cfg.Country,
		strconv.FormatBool(cfg.Hidden), strconv.FormatBool(cfg.IsolateClients), cfg.Mode, cfg.Bridge, cfg.Subnet,
		strconv.FormatBool(cfg.LANAccess), strconv.FormatBool(cfg.WPA3)}, "|")
}

// Reconcile makes the running state match the configuration.
func (m *Manager) Reconcile(ctx context.Context) error {
	cfg := m.cfg.Snapshot().WiFi
	m.mu.Lock()
	defer m.mu.Unlock()
	if !cfg.Enabled {
		if m.running {
			m.stopLocked()
		}
		m.lastErr = ""
		return nil
	}
	iface := m.pickInterface(cfg)
	if iface == "" {
		m.lastErr = "no wireless adapter found on this node"
		return fmt.Errorf("%s", m.lastErr)
	}
	sig := signatureOf(cfg, iface)
	if m.running && m.sig == sig {
		if m.cmd != nil && m.cmd.ProcessState == nil {
			return nil
		}
		m.log("wifi: hostapd exited; restarting")
		m.stopLocked()
		m.restarts++
	}
	if m.running {
		m.stopLocked()
	}
	if err := m.startLocked(ctx, cfg, iface); err != nil {
		m.lastErr = err.Error()
		return err
	}
	m.sig, m.lastErr = sig, ""
	return nil
}

func (m *Manager) startLocked(ctx context.Context, cfg config.WiFiConfig, iface string) error {
	hostapd := binary("hostapd")
	if hostapd == "" {
		return fmt.Errorf("hostapd is not installed; run: apt install hostapd iw")
	}
	if len(cfg.SSID) == 0 || len(cfg.SSID) > 32 {
		return fmt.Errorf("the network name must be 1 to 32 characters")
	}
	if len(cfg.Passphrase) < 8 || len(cfg.Passphrase) > 63 {
		return fmt.Errorf("the passphrase must be 8 to 63 characters")
	}
	if _, err := net.InterfaceByName(iface); err != nil {
		return fmt.Errorf("wireless interface %s: %w", iface, err)
	}
	mode := cfg.Mode
	if mode == "" {
		mode = "routed"
	}
	var subnet netip.Prefix
	if mode == "routed" {
		p, err := netip.ParsePrefix(cfg.Subnet)
		if err != nil || !p.Addr().Is4() || p.Bits() > 30 {
			return fmt.Errorf("wifi subnet must be an IPv4 address with a prefix, e.g. 192.168.60.1/24")
		}
		subnet = p
	} else if cfg.Bridge == "" {
		return fmt.Errorf("bridge mode needs the name of an existing bridge interface")
	}

	// Let go of the adapter: NetworkManager and wpa_supplicant would fight
	// hostapd for it. rfkill is a soft switch many boards boot with on.
	if nm := binary("nmcli"); nm != "" {
		if out, err := exec.CommandContext(ctx, nm, "-t", "-f", "GENERAL.STATE", "device", "show", iface).CombinedOutput(); err == nil && !strings.Contains(string(out), "unmanaged") {
			_ = exec.CommandContext(ctx, nm, "device", "set", iface, "managed", "no").Run()
			m.nmManaged = true
		}
	}
	if rf := binary("rfkill"); rf != "" {
		_ = exec.CommandContext(ctx, rf, "unblock", "wifi").Run()
	}
	_ = exec.CommandContext(ctx, "ip", "link", "set", iface, "down").Run()
	if mode == "routed" {
		_ = exec.CommandContext(ctx, "ip", "addr", "flush", "dev", iface).Run()
		if out, err := exec.CommandContext(ctx, "ip", "addr", "add", subnet.String(), "dev", iface).CombinedOutput(); err != nil && !strings.Contains(string(out), "File exists") {
			return fmt.Errorf("address %s on %s: %s", subnet, iface, strings.TrimSpace(string(out)))
		}
	}
	if out, err := exec.CommandContext(ctx, "ip", "link", "set", iface, "up").CombinedOutput(); err != nil {
		return fmt.Errorf("bring %s up: %s", iface, strings.TrimSpace(string(out)))
	}

	band, channel, notes := m.resolveBand(ctx, cfg, iface)
	conf := renderHostapd(cfg, iface, band, channel)
	if err := os.MkdirAll(runDir, 0o700); err != nil {
		return err
	}
	path := filepath.Join(runDir, "hostapd-"+iface+".conf")
	if err := os.WriteFile(path, []byte(conf), 0o600); err != nil {
		return err
	}

	cmd := exec.Command(hostapd, path)
	stdout, _ := cmd.StdoutPipe()
	cmd.Stderr = cmd.Stdout
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start hostapd: %w", err)
	}
	m.cmd, m.running, m.iface, m.startedAt = cmd, true, iface, time.Now()
	m.lastLines = nil
	go m.pump(stdout)
	go func() { _ = cmd.Wait() }()

	// hostapd reports a bad channel or a busy adapter within a second.
	time.Sleep(1500 * time.Millisecond)
	if cmd.ProcessState != nil {
		m.running = false
		return fmt.Errorf("hostapd exited at once: %s", m.tail())
	}

	if mode == "routed" {
		_ = os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0o644)
		if err := m.applyTable(ctx, cfg, iface, subnet); err != nil {
			m.log("wifi: nftables: %v (clients will associate but not route)", err)
		}
		if m.hooks.StartDHCP != nil {
			scope := scopeFor(cfg, iface, subnet)
			stop, err := m.hooks.StartDHCP(scope)
			if err != nil {
				m.log("wifi: dhcp on %s: %v", iface, err)
			} else {
				m.stopDHCP = stop
			}
		}
	}
	for _, n := range notes {
		m.log("wifi: %s", n)
	}
	m.log("wifi: %q is up on %s (%s, channel %d, %s)", cfg.SSID, iface, band, channel, mode)
	if m.hooks.Emit != nil {
		m.hooks.Emit(store.Event{ID: uuid.NewString(), TS: time.Now(), Severity: store.SevInfo, Category: "wifi",
			Title: "Wi-Fi network " + cfg.SSID + " is broadcasting", Detail: fmt.Sprintf("On %s, %s GHz channel %d, %s mode.", iface, band, channel, mode)})
	}
	return nil
}

func (m *Manager) pump(r io.Reader) {
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := sc.Text()
		m.mu.Lock()
		m.lastLines = append(m.lastLines, line)
		if len(m.lastLines) > 40 {
			m.lastLines = m.lastLines[len(m.lastLines)-40:]
		}
		m.mu.Unlock()
		if strings.Contains(line, "AP-ENABLED") || strings.Contains(line, "AP-DISABLED") || strings.Contains(line, "Failed") || strings.Contains(line, "error") {
			m.log("hostapd: %s", line)
		}
	}
}

func (m *Manager) tail() string {
	n := len(m.lastLines)
	if n > 6 {
		return strings.Join(m.lastLines[n-6:], " | ")
	}
	return strings.Join(m.lastLines, " | ")
}

func (m *Manager) stopLocked() {
	if m.stopDHCP != nil {
		m.stopDHCP()
		m.stopDHCP = nil
	}
	if m.cmd != nil && m.cmd.Process != nil && m.cmd.ProcessState == nil {
		_ = m.cmd.Process.Signal(os.Interrupt)
		done := make(chan struct{})
		go func() { _ = m.cmd.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			_ = m.cmd.Process.Kill()
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = exec.CommandContext(ctx, "nft", "delete", "table", "ip", tableName).Run()
	if m.iface != "" {
		_ = exec.CommandContext(ctx, "ip", "addr", "flush", "dev", m.iface).Run()
		_ = exec.CommandContext(ctx, "ip", "link", "set", m.iface, "down").Run()
		if m.nmManaged {
			if nm := binary("nmcli"); nm != "" {
				_ = exec.CommandContext(ctx, nm, "device", "set", m.iface, "managed", "yes").Run()
			}
			m.nmManaged = false
		}
	}
	m.cmd, m.running = nil, false
}

// Stop tears the access point down.
func (m *Manager) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.running {
		m.stopLocked()
	}
}

// resolveBand picks 2.4 or 5 GHz and a channel. 5 GHz needs a country code
// and an adapter that lists 5 GHz frequencies; otherwise 2.4 GHz, which
// everything supports.
func (m *Manager) resolveBand(ctx context.Context, cfg config.WiFiConfig, iface string) (band string, channel int, notes []string) {
	band = cfg.Band
	fiveOK := cfg.Country != "" && supports5GHz(ctx, iface)
	switch band {
	case "5":
		if !fiveOK {
			if cfg.Country == "" {
				notes = append(notes, "5 GHz needs a country code; using 2.4 GHz")
			} else {
				notes = append(notes, "the adapter does not list 5 GHz channels; using 2.4 GHz")
			}
			band = "2.4"
		}
	case "2.4":
	default:
		if fiveOK {
			band = "5"
		} else {
			band = "2.4"
		}
	}
	channel = cfg.Channel
	if band == "5" {
		if channel < 36 {
			channel = 36
		}
	} else if channel <= 0 || channel > 13 {
		channel = 6
	}
	return band, channel, notes
}

func supports5GHz(ctx context.Context, iface string) bool {
	iw := binary("iw")
	if iw == "" {
		return false
	}
	out, err := exec.CommandContext(ctx, iw, "list").Output()
	if err != nil {
		return false
	}
	return strings.Contains(string(out), "5180 MHz") || strings.Contains(string(out), "5180.0 MHz")
}

func renderHostapd(cfg config.WiFiConfig, iface, band string, channel int) string {
	var b strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&b, format+"\n", args...) }
	w("# Generated by orbis, do not edit by hand.")
	w("interface=%s", iface)
	if cfg.Mode == "bridge" && cfg.Bridge != "" {
		w("bridge=%s", cfg.Bridge)
	}
	w("driver=nl80211")
	w("ssid=%s", cfg.SSID)
	if cfg.Country != "" {
		w("country_code=%s", strings.ToUpper(cfg.Country))
		w("ieee80211d=1")
	}
	if band == "5" {
		w("hw_mode=a")
		w("channel=%d", channel)
		w("ieee80211n=1")
		w("ieee80211ac=1")
		w("ht_capab=[HT40+][SHORT-GI-20][SHORT-GI-40]")
	} else {
		w("hw_mode=g")
		w("channel=%d", channel)
		w("ieee80211n=1")
		w("ht_capab=[SHORT-GI-20]")
	}
	w("wmm_enabled=1")
	w("auth_algs=1")
	w("macaddr_acl=0")
	w("ignore_broadcast_ssid=%d", boolInt(cfg.Hidden))
	w("ap_isolate=%d", boolInt(cfg.IsolateClients))
	w("wpa=2")
	if cfg.WPA3 {
		w("wpa_key_mgmt=WPA-PSK SAE")
		w("ieee80211w=1")
	} else {
		w("wpa_key_mgmt=WPA-PSK")
	}
	w("rsn_pairwise=CCMP")
	w("wpa_passphrase=%s", cfg.Passphrase)
	return b.String()
}

func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

// scopeFor derives the DHCP scope from the subnet: the node's address is the
// gateway and resolver, the pool is the middle of the range.
func scopeFor(cfg config.WiFiConfig, iface string, subnet netip.Prefix) config.DHCPScope {
	gw := subnet.Addr()
	network := subnet.Masked()
	first := network.Addr()
	size := 1 << (32 - subnet.Bits())
	start := first
	for i := 0; i < min(50, size/4); i++ {
		start = start.Next()
	}
	end := first
	for i := 0; i < size-8; i++ {
		end = end.Next()
	}
	return config.DHCPScope{
		Name: "wifi", Interface: iface, Subnet: network.String(),
		RangeStart: start.String(), RangeEnd: end.String(), Gateway: gw.String(),
		DNS: []string{gw.String()}, LeaseHours: 12,
	}
}

// applyTable installs the Wi-Fi network's own nftables table: NAT out
// through the wired side, listed-address drops, and optional isolation from
// the wired network. It lives apart from the main ruleset so it works in
// observe mode and survives the main ruleset being re-rendered.
func (m *Manager) applyTable(ctx context.Context, cfg config.WiFiConfig, iface string, subnet netip.Prefix) error {
	var elems []string
	if m.hooks.ThreatElements != nil {
		elems = m.hooks.ThreatElements()
	}
	var b strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&b, format+"\n", args...) }
	w("add table ip %s", tableName)
	w("delete table ip %s", tableName)
	w("table ip %s {", tableName)
	w("  set threat_v4 {")
	w("    type ipv4_addr")
	w("    flags interval")
	w("    auto-merge")
	if len(elems) > 0 {
		w("    elements = {")
		for i := 0; i < len(elems); i += 16 {
			end := min(i+16, len(elems))
			line := strings.Join(elems[i:end], ", ")
			if end < len(elems) {
				line += ","
			}
			w("      %s", line)
		}
		w("    }")
	}
	w("  }")
	var geo4, geoEx []string
	geoOut, geoIn := false, false
	if m.hooks.GeoElements != nil {
		geo4, geoEx, geoOut, geoIn = m.hooks.GeoElements()
	}
	for _, set := range []struct {
		name  string
		elems []string
	}{{"geo_v4", geo4}, {"geo_exempt_v4", geoEx}} {
		w("  set %s {", set.name)
		w("    type ipv4_addr")
		w("    flags interval")
		w("    auto-merge")
		if len(set.elems) > 0 {
			w("    elements = {")
			for i := 0; i < len(set.elems); i += 16 {
				end := min(i+16, len(set.elems))
				line := strings.Join(set.elems[i:end], ", ")
				if end < len(set.elems) {
					line += ","
				}
				w("      %s", line)
			}
			w("    }")
		}
		w("  }")
	}
	w("  chain postrouting {")
	w("    type nat hook postrouting priority srcnat + 5; policy accept;")
	w("    ip saddr %s oifname != %q counter masquerade comment \"wifi: nat to the wired side\"", subnet.Masked(), iface)
	w("  }")
	w("  chain forward {")
	w("    type filter hook forward priority filter - 5; policy accept;")
	w("    iifname %q ip daddr @threat_v4 counter drop comment \"threat: outbound to listed address\"", iface)
	w("    oifname %q ip saddr @threat_v4 counter drop comment \"threat: inbound from listed address\"", iface)
	if geoOut {
		w("    iifname %q ip saddr != @geo_exempt_v4 ip daddr @geo_v4 counter drop comment \"country: outbound to a listed country\"", iface)
	}
	if geoIn {
		w("    oifname %q ip saddr @geo_v4 counter drop comment \"country: inbound from a listed country\"", iface)
	}
	if !cfg.LANAccess {
		w("    iifname %q ip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 } ip daddr != %s counter reject comment \"wifi: no access to the wired network\"", iface, subnet.Masked())
	}
	w("    iifname %q counter accept comment \"wifi: clients out\"", iface)
	w("    oifname %q ct state established,related counter accept comment \"wifi: replies in\"", iface)
	w("  }")
	w("}")
	cmd := exec.CommandContext(ctx, "nft", "-f", "-")
	cmd.Stdin = strings.NewReader(b.String())
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// SyncThreat replaces the listed-address set while the table is installed.
func (m *Manager) SyncThreat(v4 []string) error {
	m.mu.Lock()
	running := m.running
	m.mu.Unlock()
	if !running {
		return nil
	}
	var b strings.Builder
	fmt.Fprintf(&b, "flush set ip %s threat_v4\n", tableName)
	for i := 0; i < len(v4); i += 200 {
		end := min(i+200, len(v4))
		fmt.Fprintf(&b, "add element ip %s threat_v4 { %s }\n", tableName, strings.Join(v4[i:end], ", "))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "nft", "-f", "-")
	cmd.Stdin = strings.NewReader(b.String())
	if out, err := cmd.CombinedOutput(); err != nil {
		msg := strings.TrimSpace(string(out))
		if strings.Contains(msg, "No such file") || strings.Contains(msg, "does not exist") {
			return nil
		}
		return fmt.Errorf("%v: %s", err, msg)
	}
	return nil
}

// SyncGeo replaces the country sets while the table is installed.
func (m *Manager) SyncGeo(v4, exempt4 []string) error {
	m.mu.Lock()
	running := m.running
	m.mu.Unlock()
	if !running {
		return nil
	}
	var b strings.Builder
	for _, set := range []struct {
		name  string
		elems []string
	}{{"geo_v4", v4}, {"geo_exempt_v4", exempt4}} {
		fmt.Fprintf(&b, "flush set ip %s %s\n", tableName, set.name)
		for i := 0; i < len(set.elems); i += 200 {
			end := min(i+200, len(set.elems))
			fmt.Fprintf(&b, "add element ip %s %s { %s }\n", tableName, set.name, strings.Join(set.elems[i:end], ", "))
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "nft", "-f", "-")
	cmd.Stdin = strings.NewReader(b.String())
	if out, err := cmd.CombinedOutput(); err != nil {
		msg := strings.TrimSpace(string(out))
		if strings.Contains(msg, "No such file") || strings.Contains(msg, "does not exist") {
			return nil
		}
		return fmt.Errorf("%v: %s", err, msg)
	}
	return nil
}

// Client is one associated station.
type Client struct {
	MAC       string  `json:"mac"`
	Name      string  `json:"name,omitempty"`
	IP        string  `json:"ip,omitempty"`
	SignalDBm int     `json:"signal_dbm,omitempty"`
	RxBytes   int64   `json:"rx_bytes"`
	TxBytes   int64   `json:"tx_bytes"`
	Connected float64 `json:"connected_seconds"`
}

// Status is the page's view.
func (m *Manager) Status(ctx context.Context) map[string]any {
	cfg := m.cfg.Snapshot().WiFi
	m.mu.Lock()
	running, iface, lastErr, started, restarts := m.running, m.iface, m.lastErr, m.startedAt, m.restarts
	tail := m.tail()
	m.mu.Unlock()
	if iface == "" {
		iface = m.pickInterface(cfg)
	}
	out := map[string]any{
		"enabled": cfg.Enabled, "running": running, "interface": iface, "ssid": cfg.SSID, "mode": cfg.Mode,
		"subnet": cfg.Subnet, "error": lastErr, "restarts": restarts, "hostapd_available": binary("hostapd") != "",
		"iw_available": binary("iw") != "", "adapters": Adapters(), "hostapd_log": tail,
	}
	if running {
		out["since"] = started
		out["clients"] = m.stations(ctx, iface)
		if info := deviceInfo(ctx, iface); info != nil {
			for k, v := range info {
				out[k] = v
			}
		}
	}
	return out
}

func deviceInfo(ctx context.Context, iface string) map[string]any {
	iw := binary("iw")
	if iw == "" {
		return nil
	}
	out, err := exec.CommandContext(ctx, iw, "dev", iface, "info").Output()
	if err != nil {
		return nil
	}
	info := map[string]any{}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "channel "):
			info["channel_info"] = line
			if f := strings.Fields(line); len(f) > 1 {
				if ch, err := strconv.Atoi(f[1]); err == nil {
					info["channel"] = ch
				}
			}
		case strings.HasPrefix(line, "type "):
			info["type"] = strings.TrimPrefix(line, "type ")
		case strings.HasPrefix(line, "txpower "):
			info["txpower"] = strings.TrimPrefix(line, "txpower ")
		}
	}
	return info
}

func (m *Manager) stations(ctx context.Context, iface string) []Client {
	out := []Client{}
	iw := binary("iw")
	if iw == "" {
		return out
	}
	raw, err := exec.CommandContext(ctx, iw, "dev", iface, "station", "dump").Output()
	if err != nil {
		return out
	}
	var cur *Client
	flush := func() {
		if cur != nil {
			if m.hooks.NameByMAC != nil {
				cur.Name = m.hooks.NameByMAC(cur.MAC)
			}
			if m.hooks.LeaseByMAC != nil {
				cur.IP = m.hooks.LeaseByMAC(cur.MAC)
			}
			out = append(out, *cur)
		}
	}
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "Station "):
			flush()
			f := strings.Fields(line)
			cur = &Client{MAC: f[1]}
		case cur == nil:
		case strings.HasPrefix(line, "signal:"):
			if f := strings.Fields(line); len(f) > 1 {
				cur.SignalDBm, _ = strconv.Atoi(f[1])
			}
		case strings.HasPrefix(line, "rx bytes:"):
			cur.RxBytes, _ = strconv.ParseInt(strings.TrimSpace(strings.TrimPrefix(line, "rx bytes:")), 10, 64)
		case strings.HasPrefix(line, "tx bytes:"):
			cur.TxBytes, _ = strconv.ParseInt(strings.TrimSpace(strings.TrimPrefix(line, "tx bytes:")), 10, 64)
		case strings.HasPrefix(line, "connected time:"):
			if f := strings.Fields(strings.TrimPrefix(line, "connected time:")); len(f) > 0 {
				cur.Connected, _ = strconv.ParseFloat(f[0], 64)
			}
		}
	}
	flush()
	return out
}
