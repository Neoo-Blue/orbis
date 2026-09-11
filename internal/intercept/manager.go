package intercept

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"time"
)

// Manager owns the ARP engine and the forwarding rules together, and keeps them
// consistent with the configured client list. It is the single object the app
// and API talk to, so neither has to know that interception is two mechanisms
// (poisoning and NAT) that must move in step.
type Manager struct {
	log func(string, ...any)

	mu       sync.Mutex
	engine   *Engine
	running  bool
	ctx      context.Context
	cfg      Config
	priorFwd bool // ip_forward value before we touched it
	// markerPath, when set, records the active takeover on disk so a crash
	// can be cleaned up after by the release step.
	markerPath string
}

// SetMarkerPath chooses where the takeover marker is written.
func (m *Manager) SetMarkerPath(p string) {
	m.mu.Lock()
	m.markerPath = p
	m.mu.Unlock()
}

// Config is the whole feature, resolved from the app's configuration.
type Config struct {
	Enabled      bool
	LANInterface string
	Gateway      netip.Addr
	Clients      []Target
	RedirectDNS  bool
	DNSPort      int
	RedirectHTTP bool
	HTTPPort     int
	HTTPSPort    int
	HTTPScoped   bool
	HTTPClients  []netip.Addr
	// Listed addresses to drop for intercepted clients; see ForwardConfig.
	Threat4    []string
	ThreatOut  bool
	ThreatIn   bool
	Geo4       []string
	GeoExempt4 []string
	GeoOut     bool
	GeoIn      bool
}

func NewManager(log func(string, ...any)) *Manager {
	if log == nil {
		log = func(string, ...any) {}
	}
	return &Manager{log: log}
}

// Apply reconciles the running state with cfg. Turning the feature off, or
// changing the interface or gateway, tears everything down and rebuilds it,
// because a half-applied change here strands devices.
func (m *Manager) Apply(ctx context.Context, cfg Config) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ctx = ctx

	needRestart := m.running && (cfg.LANInterface != m.cfg.LANInterface ||
		cfg.Gateway != m.cfg.Gateway || !cfg.Enabled)
	if needRestart {
		m.stopLocked()
	}
	m.cfg = cfg

	if !cfg.Enabled || len(cfg.Clients) == 0 {
		m.stopLocked()
		// nftables state outlives this process, so a table left by a previous
		// run has to be removed explicitly even when this run never engaged.
		ctx := m.ctx
		if ctx == nil {
			ctx = context.Background()
		}
		_ = RemoveForwarding(ctx)
		return nil
	}

	if m.engine == nil {
		eng, err := New(cfg.LANInterface, cfg.Gateway, m.log)
		if err != nil {
			return err
		}
		m.engine = eng
	}
	if !m.running {
		// Forwarding must be on before we start attracting traffic, or the
		// first intercepted packets are dropped by the kernel.
		prior, err := EnableForwardingSysctl()
		if err != nil {
			m.log("intercept: could not enable ip forwarding: %v", err)
		}
		m.priorFwd = prior
		if err := m.engine.Start(ctx); err != nil {
			return err
		}
		m.running = true
	}

	m.engine.SetTargets(cfg.Clients)
	clients := make(map[string]string, len(cfg.Clients))
	for _, c := range cfg.Clients {
		clients[c.IP.String()] = c.MAC.String()
	}
	if err := WriteMarker(m.markerPath, Marker{Interface: cfg.LANInterface, Gateway: cfg.Gateway.String(), Clients: clients, Since: time.Now()}); err != nil {
		m.log("intercept: could not write the takeover marker: %v", err)
	}

	addrs := make([]netip.Addr, 0, len(cfg.Clients))
	for _, c := range cfg.Clients {
		addrs = append(addrs, c.IP)
	}
	return ApplyForwarding(ctx, ForwardConfig{
		LANInterface: cfg.LANInterface,
		Clients:      addrs,
		RedirectDNS:  cfg.RedirectDNS,
		DNSPort:      cfg.DNSPort,
		RedirectHTTP: cfg.RedirectHTTP,
		HTTPPort:     cfg.HTTPPort,
		HTTPSPort:    cfg.HTTPSPort,
		HTTPScoped:   cfg.HTTPScoped,
		HTTPClients:  cfg.HTTPClients,
		Threat4:      cfg.Threat4,
		ThreatOut:    cfg.ThreatOut,
		ThreatIn:     cfg.ThreatIn,
		Geo4:         cfg.Geo4,
		GeoExempt4:   cfg.GeoExempt4,
		GeoOut:       cfg.GeoOut,
		GeoIn:        cfg.GeoIn,
	})
}

// SyncGeo pushes new country sets into the running intercept table.
func (m *Manager) SyncGeo(v4, exempt4 []string) error {
	m.mu.Lock()
	running := m.running
	ctx := m.ctx
	m.cfg.Geo4, m.cfg.GeoExempt4 = v4, exempt4
	m.mu.Unlock()
	if !running {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	return SyncGeo(ctx, v4, exempt4)
}

// SyncThreat pushes a new listed-address set into the running intercept
// table. A manager that is not intercepting has no table to update.
func (m *Manager) SyncThreat(v4 []string) error {
	m.mu.Lock()
	running := m.running
	ctx := m.ctx
	m.cfg.Threat4 = v4
	m.mu.Unlock()
	if !running {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	return SyncThreat(ctx, v4)
}

// Running reports whether interception is active for at least one client.
func (m *Manager) Running() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.running
}

// IsTarget reports whether ip is being intercepted right now.
func (m *Manager) IsTarget(ip netip.Addr) bool {
	m.mu.Lock()
	eng := m.engine
	m.mu.Unlock()
	return eng != nil && eng.IsTarget(ip)
}

// Stop tears everything down: restore the ARP caches, remove the rules, and put
// ip_forward back the way we found it.
func (m *Manager) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stopLocked()
}

func (m *Manager) stopLocked() {
	if !m.running {
		return
	}
	if m.engine != nil {
		m.engine.Stop()
		m.engine = nil
	}
	ctx := m.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	_ = RemoveForwarding(ctx)
	if !m.priorFwd {
		_ = writeForwarding(false)
	}
	m.running = false
	RemoveMarker(m.markerPath)
}

// Stats returns the engine's view plus whether the manager considers itself on.
func (m *Manager) Stats() Stats {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.engine == nil {
		return Stats{Running: false}
	}
	return m.engine.StatsSnapshot()
}

// ResolveTargets turns (ip, mac) string pairs into Targets, dropping anything
// malformed so one bad entry cannot abort the whole set.
func ResolveTargets(pairs map[string]string) []Target {
	out := make([]Target, 0, len(pairs))
	for ipStr, macStr := range pairs {
		ip, err := netip.ParseAddr(ipStr)
		if err != nil || !ip.Is4() {
			continue
		}
		mac, err := net.ParseMAC(macStr)
		if err != nil || len(mac) != 6 {
			continue
		}
		out = append(out, Target{IP: ip, MAC: mac})
	}
	return out
}
