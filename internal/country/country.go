// Package country blocks or allows traffic by the country an address belongs
// to. It decides at three places: the resolver, before a name's answer
// reaches a device; the flow tracker, when a connection to or from a listed
// country starts; and the packet filter, where in block mode the countries'
// address ranges are loaded as sets so even a device that never asked the
// resolver is stopped where this node enforces.
package country

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Neoo-Blue/orbis/internal/config"
	"github.com/Neoo-Blue/orbis/internal/geoip"
	"github.com/Neoo-Blue/orbis/internal/store"
	"github.com/google/uuid"
)

// Hooks are what the application lends the manager.
type Hooks struct {
	// OnSets receives the packet-filter elements: the listed countries'
	// ranges (block mode only) and the exempt device addresses.
	OnSets func(v4, v6, exemptV4 []string)
	Emit   func(store.Event)
	// Blocker marks and kills a flow; Enforced says whether that is real.
	Blocker  func(flowID, reason string) bool
	Enforced func(local netip.Addr, outbound bool) bool
	// ClientFor maps a device address to its id and display name.
	ClientFor func(addr netip.Addr) (id, name string)
	// ClientAddr maps a device id to its current address.
	ClientAddr func(id string) string
}

// Manager evaluates the country rules and keeps the sets built.
type Manager struct {
	cfg   *config.Config
	st    *store.Store
	geo   *geoip.Resolver
	hooks Hooks
	log   func(string, ...any)

	mu        sync.Mutex
	building  bool
	lastBuild time.Time
	lastErr   string
	setSize   map[string]int
	counters  map[string]int64 // "dns:CN", "flow:CN"
	cooldown  map[string]time.Time
	kick      chan struct{}
}

func NewManager(cfg *config.Config, st *store.Store, geo *geoip.Resolver, hooks Hooks, log func(string, ...any)) *Manager {
	if log == nil {
		log = func(string, ...any) {}
	}
	return &Manager{cfg: cfg, st: st, geo: geo, hooks: hooks, log: log, setSize: map[string]int{}, counters: map[string]int64{}, cooldown: map[string]time.Time{}, kick: make(chan struct{}, 1)}
}

func (m *Manager) listed(cfg config.CountryConfig, code string) bool {
	code = strings.ToUpper(code)
	for _, c := range cfg.Countries {
		if strings.EqualFold(c, code) {
			return true
		}
	}
	return false
}

// Verdict says whether an address in this country is blocked under the
// current rules. Unknown countries (private space, unmapped ranges) are
// never blocked: a rule about places cannot apply to an address with none.
func (m *Manager) Verdict(cfg config.CountryConfig, code string) bool {
	if !cfg.Enabled || code == "" || len(cfg.Countries) == 0 {
		// An empty list is no rule at all. In allow mode it would otherwise
		// mean "allow nowhere", which once refused every name on a network
		// after the last country was removed.
		return false
	}
	if cfg.Mode == "allow" {
		return !m.listed(cfg, code)
	}
	return m.listed(cfg, code)
}

func (m *Manager) exemptClient(cfg config.CountryConfig, id string) bool {
	for _, c := range cfg.ExemptClients {
		if c == id {
			return true
		}
	}
	return false
}

func (m *Manager) exemptAddr(cfg config.CountryConfig, a netip.Addr) bool {
	for _, s := range cfg.ExemptIPs {
		if p, err := netip.ParsePrefix(s); err == nil && p.Contains(a) {
			return true
		}
		if x, err := netip.ParseAddr(s); err == nil && x == a {
			return true
		}
	}
	return false
}

func (m *Manager) exemptDomain(cfg config.CountryConfig, name string) bool {
	n := strings.ToLower(strings.TrimSuffix(name, "."))
	for _, d := range cfg.ExemptDomains {
		d = strings.ToLower(strings.TrimSuffix(strings.TrimPrefix(d, "*."), "."))
		if d != "" && (n == d || strings.HasSuffix(n, "."+d)) {
			return true
		}
	}
	return false
}

// CheckAnswer is the resolver hook: a name whose addresses land in a
// blocked country is refused for this client. It returns the country that
// decided it.
func (m *Manager) CheckAnswer(client netip.Addr, name string, addrs []netip.Addr) (bool, string) {
	cfg := m.cfg.Snapshot().Country
	if !cfg.Enabled || !cfg.DNS || !cfg.BlockOutbound || m.geo == nil {
		return false, ""
	}
	if m.exemptDomain(cfg, name) {
		return false, ""
	}
	if m.hooks.ClientFor != nil {
		if id, _ := m.hooks.ClientFor(client); id != "" && m.exemptClient(cfg, id) {
			return false, ""
		}
	}
	for _, a := range addrs {
		if geoip.IsPrivate(a) || m.exemptAddr(cfg, a) {
			continue
		}
		loc := m.geo.LookupAddr(a)
		if m.Verdict(cfg, loc.Country) {
			m.count("dns:" + loc.Country)
			return true, loc.Country
		}
	}
	return false, ""
}

// Observe is the flow hook: a new connection to or from a listed country
// is marked, killed where this node enforces, and announced once an hour
// per device and country.
func (m *Manager) Observe(f *store.Flow) {
	cfg := m.cfg.Snapshot().Country
	if !cfg.Enabled || f == nil || f.Country == "" {
		return
	}
	outbound := f.Direction != "in"
	if outbound && !cfg.BlockOutbound || !outbound && !cfg.BlockInbound {
		return
	}
	if !m.Verdict(cfg, f.Country) {
		return
	}
	remoteS, localS := f.DstIP, f.SrcIP
	if !outbound {
		remoteS, localS = f.SrcIP, f.DstIP
	}
	remote, err := netip.ParseAddr(remoteS)
	if err != nil || m.exemptAddr(cfg, remote) {
		return
	}
	local, _ := netip.ParseAddr(localS)
	if f.ClientID != "" && m.exemptClient(cfg, f.ClientID) {
		return
	}
	if f.Hostname != "" && m.exemptDomain(cfg, f.Hostname) {
		return
	}
	enforced := m.hooks.Enforced != nil && m.hooks.Enforced(local, outbound)
	reason := "country rule: " + f.Country
	if enforced && m.hooks.Blocker != nil && f.ID != "" {
		id := f.ID
		go m.hooks.Blocker(id, reason)
	}
	m.count("flow:" + f.Country)
	if m.hooks.Emit == nil || !m.cool(localS+"|"+f.Country, time.Hour) {
		return
	}
	name := localS
	if m.hooks.ClientFor != nil && local.IsValid() {
		if _, n := m.hooks.ClientFor(local); n != "" {
			name = n
		}
	}
	where := remoteS
	if f.Hostname != "" {
		where = f.Hostname + " (" + remoteS + ")"
	}
	var title, detail string
	if outbound {
		title = fmt.Sprintf("%s reached a server in %s", name, f.Country)
		detail = fmt.Sprintf("%s connected to %s, which is in %s, a country your rules block.", name, where, f.Country)
	} else {
		title = fmt.Sprintf("A connection from %s reached %s", f.Country, name)
		detail = fmt.Sprintf("%s in %s connected in to %s on port %d.", where, f.Country, name, f.DstPort)
	}
	if enforced {
		detail += " The connection was dropped."
	} else {
		detail += " It was recorded, not dropped: this node is not in the path for that device."
	}
	m.hooks.Emit(store.Event{
		ID: uuid.NewString(), TS: time.Now(), Severity: store.SevNotice, Category: "country", Title: title, Detail: detail,
		ClientID: f.ClientID, FlowID: f.ID,
		Data: map[string]any{"country": f.Country, "remote": remoteS, "local": localS, "enforced": enforced, "direction": f.Direction},
	})
}

func (m *Manager) count(key string) {
	m.mu.Lock()
	m.counters[key]++
	m.mu.Unlock()
}

func (m *Manager) cool(key string, d time.Duration) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	if t, ok := m.cooldown[key]; ok && now.Sub(t) < d {
		return false
	}
	m.cooldown[key] = now
	return true
}

// Run builds the sets at start and whenever the rules change, and refreshes
// them weekly in case the GeoIP database was updated.
func (m *Manager) Run(ctx context.Context) {
	m.Rebuild(ctx)
	tick := time.NewTicker(24 * time.Hour)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-m.kick:
			m.Rebuild(ctx)
		case <-tick.C:
			m.mu.Lock()
			stale := time.Since(m.lastBuild) > 7*24*time.Hour
			m.mu.Unlock()
			if stale {
				m.Rebuild(ctx)
			}
		}
	}
}

// Reconfigure schedules a rebuild after the rules changed.
func (m *Manager) Reconfigure() {
	select {
	case m.kick <- struct{}{}:
	default:
	}
}

// Rebuild computes the packet-filter sets. In allow mode the complement of
// the list is most of the internet, far too large for a set, so allow mode
// relies on the resolver and the flow tracker and the sets carry only the
// exemptions.
func (m *Manager) Rebuild(ctx context.Context) {
	cfg := m.cfg.Snapshot().Country
	m.mu.Lock()
	if m.building {
		m.mu.Unlock()
		return
	}
	m.building = true
	m.mu.Unlock()
	defer func() {
		m.mu.Lock()
		m.building = false
		m.lastBuild = time.Now()
		m.mu.Unlock()
	}()

	var exempt []string
	if m.hooks.ClientAddr != nil {
		for _, id := range cfg.ExemptClients {
			if ip := m.hooks.ClientAddr(id); ip != "" {
				exempt = append(exempt, ip)
			}
		}
	}
	for _, s := range cfg.ExemptIPs {
		if p, err := netip.ParsePrefix(s); err == nil && p.Addr().Is4() {
			exempt = append(exempt, p.String())
		} else if a, err := netip.ParseAddr(s); err == nil && a.Is4() {
			exempt = append(exempt, a.String())
		}
	}
	if !cfg.Enabled || cfg.Mode == "allow" || len(cfg.Countries) == 0 || m.geo == nil {
		m.mu.Lock()
		m.setSize = map[string]int{}
		m.lastErr = ""
		m.mu.Unlock()
		if m.hooks.OnSets != nil {
			m.hooks.OnSets(nil, nil, exempt)
		}
		return
	}

	var v4, v6 []string
	sizes := map[string]int{}
	var missing []string
	for _, c := range cfg.Countries {
		code := strings.ToUpper(strings.TrimSpace(c))
		if g, err := m.st.GeoSet(code); err == nil && time.Since(g.Built) < 30*24*time.Hour {
			v4 = append(v4, g.V4...)
			v6 = append(v6, g.V6...)
			sizes[code] = len(g.V4) + len(g.V6)
			continue
		}
		missing = append(missing, code)
	}
	if len(missing) > 0 {
		start := time.Now()
		nets, dbSize, err := m.geo.CountryNetworks(missing)
		if err != nil {
			m.mu.Lock()
			m.lastErr = err.Error()
			m.mu.Unlock()
			m.log("country: building sets: %v", err)
		} else {
			for _, code := range missing {
				g := store.GeoSet{Country: code, Built: time.Now(), DBSize: dbSize}
				raw := len(nets[code])
				aggregated := Aggregate(nets[code])
				if raw > 0 {
					m.log("country: %s: %d ranges aggregated to %d", code, raw, len(aggregated))
				}
				for _, p := range aggregated {
					if p.Addr().Is4() {
						g.V4 = append(g.V4, p.String())
					} else {
						g.V6 = append(g.V6, p.String())
					}
				}
				if err := m.st.PutGeoSet(g); err != nil {
					m.log("country: cache %s: %v", code, err)
				}
				v4 = append(v4, g.V4...)
				v6 = append(v6, g.V6...)
				sizes[code] = len(g.V4) + len(g.V6)
			}
			m.log("country: extracted ranges for %s in %s", strings.Join(missing, ", "), time.Since(start).Round(time.Second))
		}
	}
	sort.Strings(v4)
	sort.Strings(v6)
	m.mu.Lock()
	m.setSize = sizes
	if len(missing) == 0 {
		m.lastErr = ""
	}
	m.mu.Unlock()
	if m.hooks.OnSets != nil {
		m.hooks.OnSets(v4, v6, exempt)
	}
}

// Status is the page summary.
func (m *Manager) Status() map[string]any {
	cfg := m.cfg.Snapshot().Country
	m.mu.Lock()
	defer m.mu.Unlock()
	total := 0
	for _, n := range m.setSize {
		total += n
	}
	counters := map[string]int64{}
	for k, v := range m.counters {
		counters[k] = v
	}
	out := map[string]any{
		"enabled": cfg.Enabled, "mode": cfg.Mode, "countries": cfg.Countries,
		"block_outbound": cfg.BlockOutbound, "block_inbound": cfg.BlockInbound, "dns": cfg.DNS,
		"exempt_clients": cfg.ExemptClients, "exempt_domains": cfg.ExemptDomains, "exempt_ips": cfg.ExemptIPs,
		"set_sizes": m.setSize, "set_total": total, "building": m.building, "error": m.lastErr, "counters": counters,
		"packet_sets": cfg.Enabled && cfg.Mode != "allow" && len(cfg.Countries) > 0,
	}
	if !m.lastBuild.IsZero() {
		out["last_build"] = m.lastBuild
	}
	return out
}
