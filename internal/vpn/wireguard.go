// Package vpn manages WireGuard in both directions: a server for remote
// access into the network, and outbound client tunnels for policy-routing
// selected LAN devices through a provider.
//
// Interface and route management is done through `ip` and `wg` rather than a
// netlink library, because the failure modes are legible: an operator can copy
// the exact command out of the log and run it by hand.
package vpn

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Neoo-Blue/orbis/internal/config"
	"github.com/Neoo-Blue/orbis/internal/store"
	"github.com/google/uuid"
	"golang.org/x/crypto/curve25519"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type Manager struct {
	cfg *config.Config
	st  *store.Store
	log func(string, ...any)

	mu        sync.Mutex
	serverUp  bool
	clientsUp map[string]bool
	lastError string
	available bool
}

func New(cfg *config.Config, st *store.Store, log func(string, ...any)) *Manager {
	if log == nil {
		log = func(string, ...any) {}
	}
	m := &Manager{cfg: cfg, st: st, log: log, clientsUp: map[string]bool{}}
	_, err := exec.LookPath("wg")
	m.available = err == nil
	if !m.available {
		m.lastError = "wireguard-tools (wg) not installed"
	}
	return m
}

func (m *Manager) Available() bool { return m.available }

// GenerateKeypair produces a WireGuard private/public pair.
func GenerateKeypair() (priv, pub string, err error) {
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		return "", "", err
	}
	// Curve25519 clamping, per the WireGuard spec.
	key[0] &= 248
	key[31] &= 127
	key[31] |= 64
	pubKey, err := curve25519.X25519(key[:], curve25519.Basepoint)
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(key[:]),
		base64.StdEncoding.EncodeToString(pubKey), nil
}

// GeneratePSK produces a pre-shared key, which adds post-quantum resistance
// to a tunnel at zero cost.
func GeneratePSK() (string, error) {
	var k [32]byte
	if _, err := rand.Read(k[:]); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(k[:]), nil
}

// EnsureServerKeys generates the server keypair on first use and persists it.
func (m *Manager) EnsureServerKeys() (pub string, err error) {
	cfg := m.cfg.Snapshot()
	if cfg.VPN.Server.PrivateKey != "" {
		return publicFromPrivate(cfg.VPN.Server.PrivateKey)
	}
	priv, pub, err := GenerateKeypair()
	if err != nil {
		return "", err
	}
	if err := m.cfg.Update(func(c *config.Config) {
		c.VPN.Server.PrivateKey = priv
	}); err != nil {
		return "", err
	}
	return pub, nil
}

func publicFromPrivate(priv string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(priv)
	if err != nil || len(raw) != 32 {
		return "", fmt.Errorf("invalid private key")
	}
	pub, err := curve25519.X25519(raw, curve25519.Basepoint)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(pub), nil
}

// StartServer brings up the server interface and loads peers.
func (m *Manager) StartServer(ctx context.Context) error {
	cfg := m.cfg.Snapshot()
	s := cfg.VPN.Server
	if !s.Enabled {
		return nil
	}
	if !m.available {
		return fmt.Errorf("%s", m.lastError)
	}
	if _, err := m.EnsureServerKeys(); err != nil {
		return err
	}
	cfg = m.cfg.Snapshot()
	s = cfg.VPN.Server

	if err := m.ensureLink(ctx, s.Interface, s.Address, s.MTU); err != nil {
		return err
	}

	conf, err := m.serverConfig()
	if err != nil {
		return err
	}
	if err := m.applyWGConfig(ctx, s.Interface, conf); err != nil {
		return err
	}
	m.mu.Lock()
	m.serverUp = true
	m.mu.Unlock()
	m.log("vpn: server up on %s port %d", s.Interface, s.ListenPort)
	return nil
}

func (m *Manager) StopServer(ctx context.Context) error {
	cfg := m.cfg.Snapshot()
	if err := run(ctx, "ip", "link", "del", cfg.VPN.Server.Interface); err != nil {
		// Already gone is not an error worth surfacing.
		if !strings.Contains(err.Error(), "does not exist") {
			return err
		}
	}
	m.mu.Lock()
	m.serverUp = false
	m.mu.Unlock()
	return nil
}

// serverConfig renders the wg-quick style config for the server side.
func (m *Manager) serverConfig() (string, error) {
	cfg := m.cfg.Snapshot()
	s := cfg.VPN.Server
	peers, err := m.st.WGPeers()
	if err != nil {
		return "", err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "[Interface]\nPrivateKey = %s\nListenPort = %d\n", s.PrivateKey, s.ListenPort)
	for _, p := range peers {
		if !p.Enabled {
			continue
		}
		fmt.Fprintf(&b, "\n[Peer]\nPublicKey = %s\n", p.PublicKey)
		if p.PresharedKey != "" {
			fmt.Fprintf(&b, "PresharedKey = %s\n", p.PresharedKey)
		}
		allowed := p.Address
		if len(p.AllowedIPs) > 0 {
			allowed = strings.Join(p.AllowedIPs, ", ")
		}
		fmt.Fprintf(&b, "AllowedIPs = %s\n", allowed)
	}
	return b.String(), nil
}

// AddPeer creates a peer, allocating the next free tunnel address.
func (m *Manager) AddPeer(name string, allowedIPs []string, note string) (*store.WGPeer, string, error) {
	cfg := m.cfg.Snapshot()
	priv, pub, err := GenerateKeypair()
	if err != nil {
		return nil, "", err
	}
	psk, err := GeneratePSK()
	if err != nil {
		return nil, "", err
	}
	addr, err := m.nextPeerAddress()
	if err != nil {
		return nil, "", err
	}
	dns := cfg.VPN.Server.DNS
	if len(dns) == 0 {
		// Pointing peers at the node's own resolver is the whole point:
		// a remote device gets the same filtering as one on the LAN.
		if gw, err := serverGatewayIP(cfg.VPN.Server.Address); err == nil {
			dns = []string{gw}
		}
	}
	peer := &store.WGPeer{
		ID:           uuid.NewString(),
		Name:         name,
		PublicKey:    pub,
		PrivateKey:   priv,
		PresharedKey: psk,
		Address:      addr,
		AllowedIPs:   []string{addr},
		Enabled:      true,
		DNS:          dns,
		Keepalive:    25,
		CreatedAt:    time.Now(),
		Note:         note,
	}
	if len(allowedIPs) > 0 {
		peer.AllowedIPs = allowedIPs
	}
	if err := m.st.SaveWGPeer(peer); err != nil {
		return nil, "", err
	}

	clientConf := m.PeerConfig(peer)
	// Reload so the new peer works immediately rather than after a restart.
	if m.ServerUp() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if conf, err := m.serverConfig(); err == nil {
			_ = m.applyWGConfig(ctx, cfg.VPN.Server.Interface, conf)
		}
	}
	return peer, clientConf, nil
}

// PeerConfig renders the config file a client device imports.
func (m *Manager) PeerConfig(p *store.WGPeer) string {
	cfg := m.cfg.Snapshot()
	s := cfg.VPN.Server
	serverPub, _ := publicFromPrivate(s.PrivateKey)
	endpoint := s.Endpoint
	if endpoint == "" {
		endpoint = fmt.Sprintf("<set VPN endpoint in settings>:%d", s.ListenPort)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "[Interface]\nPrivateKey = %s\nAddress = %s\n", p.PrivateKey, p.Address)
	if len(p.DNS) > 0 {
		fmt.Fprintf(&b, "DNS = %s\n", strings.Join(p.DNS, ", "))
	}
	if s.MTU > 0 {
		fmt.Fprintf(&b, "MTU = %d\n", s.MTU)
	}
	fmt.Fprintf(&b, "\n[Peer]\nPublicKey = %s\n", serverPub)
	if p.PresharedKey != "" {
		fmt.Fprintf(&b, "PresharedKey = %s\n", p.PresharedKey)
	}
	// Full-tunnel by default: a split tunnel that leaks DNS is the most
	// common way a "private" VPN turns out not to be.
	fmt.Fprintf(&b, "AllowedIPs = 0.0.0.0/0, ::/0\n")
	fmt.Fprintf(&b, "Endpoint = %s\n", endpoint)
	if p.Keepalive > 0 {
		fmt.Fprintf(&b, "PersistentKeepalive = %d\n", p.Keepalive)
	}
	return b.String()
}

func (m *Manager) nextPeerAddress() (string, error) {
	cfg := m.cfg.Snapshot()
	pfx, err := netip.ParsePrefix(cfg.VPN.Server.Address)
	if err != nil {
		return "", fmt.Errorf("server address %q: %w", cfg.VPN.Server.Address, err)
	}
	peers, err := m.st.WGPeers()
	if err != nil {
		return "", err
	}
	used := map[netip.Addr]bool{pfx.Addr(): true}
	for _, p := range peers {
		if a, err := netip.ParsePrefix(p.Address); err == nil {
			used[a.Addr()] = true
		} else if a, err := netip.ParseAddr(p.Address); err == nil {
			used[a] = true
		}
	}
	cur := pfx.Addr().Next()
	for pfx.Contains(cur) {
		if !used[cur] {
			return netip.PrefixFrom(cur, pfx.Bits()).String(), nil
		}
		cur = cur.Next()
	}
	return "", fmt.Errorf("no free addresses in %s", pfx)
}

func serverGatewayIP(addr string) (string, error) {
	pfx, err := netip.ParsePrefix(addr)
	if err != nil {
		return "", err
	}
	return pfx.Addr().String(), nil
}

func (m *Manager) DeletePeer(id string) error {
	if err := m.st.DeleteWGPeer(id); err != nil {
		return err
	}
	if m.ServerUp() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		cfg := m.cfg.Snapshot()
		if conf, err := m.serverConfig(); err == nil {
			// syncconf removes peers that are no longer in the file, which
			// setconf alone does not.
			_ = m.syncWGConfig(ctx, cfg.VPN.Server.Interface, conf)
		}
	}
	return nil
}

// ---- outbound client tunnels ----

// StartClient brings up an outbound tunnel and its policy routing table.
func (m *Manager) StartClient(ctx context.Context, name string) error {
	cfg := m.cfg.Snapshot()
	var c *config.WGClientConfig
	for i := range cfg.VPN.Client {
		if cfg.VPN.Client[i].Name == name {
			c = &cfg.VPN.Client[i]
			break
		}
	}
	if c == nil {
		return fmt.Errorf("no client tunnel named %q", name)
	}
	if !c.Enabled {
		return fmt.Errorf("tunnel %q is disabled", name)
	}
	if err := m.ensureLink(ctx, c.Interface, c.Address, c.MTU); err != nil {
		return err
	}

	var b strings.Builder
	fmt.Fprintf(&b, "[Interface]\nPrivateKey = %s\n", c.PrivateKey)
	fmt.Fprintf(&b, "\n[Peer]\nPublicKey = %s\n", c.PeerPubkey)
	if c.PeerPSK != "" {
		fmt.Fprintf(&b, "PresharedKey = %s\n", c.PeerPSK)
	}
	allowed := c.AllowedIPs
	if len(allowed) == 0 {
		allowed = []string{"0.0.0.0/0", "::/0"}
	}
	fmt.Fprintf(&b, "AllowedIPs = %s\n", strings.Join(allowed, ", "))
	fmt.Fprintf(&b, "Endpoint = %s\n", c.Endpoint)
	if c.Keepalive > 0 {
		fmt.Fprintf(&b, "PersistentKeepalive = %d\n", c.Keepalive)
	}
	if err := m.applyWGConfig(ctx, c.Interface, b.String()); err != nil {
		return err
	}

	// Policy routing: a dedicated table with a default route through the
	// tunnel, which per-client fwmark rules then select. This is what makes
	// "send only the TV through the VPN" possible without a full-tunnel.
	if c.RouteTable > 0 {
		table := strconv.Itoa(c.RouteTable)
		_ = run(ctx, "ip", "route", "flush", "table", table)
		if err := run(ctx, "ip", "route", "add", "default", "dev", c.Interface, "table", table); err != nil {
			return fmt.Errorf("policy route: %w", err)
		}
		mark := strconv.Itoa(c.RouteTable)
		_ = run(ctx, "ip", "rule", "del", "fwmark", mark, "table", table)
		if err := run(ctx, "ip", "rule", "add", "fwmark", mark, "table", table, "priority", "1000"); err != nil {
			return fmt.Errorf("policy rule: %w", err)
		}
		if c.KillSwitch {
			// Without this, a tunnel that drops silently reverts steered
			// clients to the plain WAN — the exact failure a VPN is meant
			// to prevent.
			_ = run(ctx, "ip", "route", "add", "blackhole", "default", "metric", "9999", "table", table)
		}
	}

	m.mu.Lock()
	m.clientsUp[name] = true
	m.mu.Unlock()
	m.log("vpn: client tunnel %q up on %s", name, c.Interface)
	return nil
}

func (m *Manager) StopClient(ctx context.Context, name string) error {
	cfg := m.cfg.Snapshot()
	for _, c := range cfg.VPN.Client {
		if c.Name != name {
			continue
		}
		if c.RouteTable > 0 {
			mark := strconv.Itoa(c.RouteTable)
			_ = run(ctx, "ip", "rule", "del", "fwmark", mark, "table", mark)
			_ = run(ctx, "ip", "route", "flush", "table", mark)
		}
		_ = run(ctx, "ip", "link", "del", c.Interface)
	}
	m.mu.Lock()
	delete(m.clientsUp, name)
	m.mu.Unlock()
	return nil
}

// ---- link helpers ----

func (m *Manager) ensureLink(ctx context.Context, iface, addr string, mtu int) error {
	if iface == "" {
		return fmt.Errorf("interface name is empty")
	}
	if _, err := net.InterfaceByName(iface); err != nil {
		if err := run(ctx, "ip", "link", "add", "dev", iface, "type", "wireguard"); err != nil {
			return fmt.Errorf("create %s: %w", iface, err)
		}
	}
	if addr != "" {
		// Replace rather than add so a changed address does not stack.
		_ = run(ctx, "ip", "address", "flush", "dev", iface)
		if err := run(ctx, "ip", "address", "add", addr, "dev", iface); err != nil {
			return fmt.Errorf("address %s on %s: %w", addr, iface, err)
		}
	}
	if mtu > 0 {
		_ = run(ctx, "ip", "link", "set", "mtu", strconv.Itoa(mtu), "dev", iface)
	}
	return run(ctx, "ip", "link", "set", "up", "dev", iface)
}

// applyWGConfig writes a config through `wg setconf` via stdin, so the
// private key never lands on disk outside the config file.
func (m *Manager) applyWGConfig(ctx context.Context, iface, conf string) error {
	return m.wgConf(ctx, "setconf", iface, conf)
}

func (m *Manager) syncWGConfig(ctx context.Context, iface, conf string) error {
	return m.wgConf(ctx, "syncconf", iface, conf)
}

func (m *Manager) wgConf(ctx context.Context, verb, iface, conf string) error {
	cmd := exec.CommandContext(ctx, "wg", verb, iface, "/dev/stdin")
	cmd.Stdin = strings.NewReader(conf)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("wg %s %s: %s", verb, iface, strings.TrimSpace(stderr.String()))
	}
	return nil
}

func run(ctx context.Context, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return fmt.Errorf("%s %s: %s", name, strings.Join(args, " "), msg)
	}
	return nil
}

// ---- live state ----

// SyncStats reads handshake and byte counters from the kernel into the store.
func (m *Manager) SyncStats() error {
	client, err := wgctrl.New()
	if err != nil {
		return err
	}
	defer client.Close()
	devices, err := client.Devices()
	if err != nil {
		return err
	}
	for _, d := range devices {
		for _, p := range d.Peers {
			endpoint := ""
			if p.Endpoint != nil {
				endpoint = p.Endpoint.String()
			}
			_ = m.st.UpdateWGStats(p.PublicKey.String(), p.LastHandshakeTime,
				p.ReceiveBytes, p.TransmitBytes, endpoint)
		}
	}
	return nil
}

// Devices returns live interface state for the UI.
func (m *Manager) Devices() []map[string]any {
	client, err := wgctrl.New()
	if err != nil {
		return nil
	}
	defer client.Close()
	devices, err := client.Devices()
	if err != nil {
		return nil
	}
	out := make([]map[string]any, 0, len(devices))
	for _, d := range devices {
		peers := make([]map[string]any, 0, len(d.Peers))
		for _, p := range d.Peers {
			entry := map[string]any{
				"public_key": p.PublicKey.String(),
				"rx":         p.ReceiveBytes,
				"tx":         p.TransmitBytes,
				"allowed":    prefixStrings(p.AllowedIPs),
			}
			if !p.LastHandshakeTime.IsZero() {
				entry["last_handshake"] = p.LastHandshakeTime
				entry["online"] = time.Since(p.LastHandshakeTime) < 3*time.Minute
			} else {
				entry["online"] = false
			}
			if p.Endpoint != nil {
				entry["endpoint"] = p.Endpoint.String()
			}
			peers = append(peers, entry)
		}
		sort.Slice(peers, func(i, j int) bool {
			return fmt.Sprint(peers[i]["public_key"]) < fmt.Sprint(peers[j]["public_key"])
		})
		out = append(out, map[string]any{
			"name": d.Name, "listen_port": d.ListenPort,
			"public_key": d.PublicKey.String(), "peers": peers,
		})
	}
	return out
}

func prefixStrings(nets []net.IPNet) []string {
	out := make([]string, 0, len(nets))
	for _, n := range nets {
		out = append(out, n.String())
	}
	return out
}

func (m *Manager) ServerUp() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.serverUp
}

func (m *Manager) Status() map[string]any {
	m.mu.Lock()
	clients := make([]string, 0, len(m.clientsUp))
	for k := range m.clientsUp {
		clients = append(clients, k)
	}
	up, lastErr := m.serverUp, m.lastError
	m.mu.Unlock()
	sort.Strings(clients)
	cfg := m.cfg.Snapshot()
	pub, _ := publicFromPrivate(cfg.VPN.Server.PrivateKey)
	return map[string]any{
		"available":       m.available,
		"server_up":       up,
		"server_enabled":  cfg.VPN.Server.Enabled,
		"server_port":     cfg.VPN.Server.ListenPort,
		"server_pubkey":   pub,
		"server_endpoint": cfg.VPN.Server.Endpoint,
		"clients_up":      clients,
		"last_error":      lastErr,
	}
}

var _ = wgtypes.Key{}
