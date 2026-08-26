package intercept

import (
	"context"
	"net"
	"net/netip"
	"sync"
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
	})
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
