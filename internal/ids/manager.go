package ids

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Neoo-Blue/orbis/internal/config"
	"github.com/Neoo-Blue/orbis/internal/geoip"
	"github.com/Neoo-Blue/orbis/internal/store"
	"github.com/google/uuid"
)

// Hooks are what the application lends the detector.
type Hooks struct {
	// Ban records a timed ban at the gateway and returns its expiry.
	Ban func(ip string, d time.Duration, reason string) (*time.Time, error)
	// Locate names the network behind an address.
	Locate func(addr netip.Addr) (country, org string)
	// ClientFor names a local device.
	ClientFor func(addr netip.Addr) (id, name string)
	Emit      func(store.Event)
}

// Manager runs the sources and the rules.
type Manager struct {
	cfg   *config.Config
	st    *store.Store
	hooks Hooks
	log   func(string, ...any)

	win      *windows
	ports    *distinct
	hosts    *distinct
	mu       sync.Mutex
	lines    int64
	hits     int64
	bans     int64
	lastLine time.Time
	journal  bool
	authLog  string
	recv     *syslogReceiver
	recvErr  string
	recvAddr string
	cool     map[string]time.Time
	ctx      context.Context
}

func NewManager(cfg *config.Config, st *store.Store, hooks Hooks, log func(string, ...any)) *Manager {
	if log == nil {
		log = func(string, ...any) {}
	}
	return &Manager{cfg: cfg, st: st, hooks: hooks, log: log, win: newWindows(), ports: newDistinct(), hosts: newDistinct(), cool: map[string]time.Time{}}
}

// Run starts the sources and keeps the receiver matching the configuration.
func (m *Manager) Run(ctx context.Context) {
	m.mu.Lock()
	m.ctx = ctx
	m.mu.Unlock()
	cfg := m.cfg.Snapshot().IDS
	if cfg.Enabled && cfg.Journal {
		if p := authLogPath(); p != "" {
			m.mu.Lock()
			m.authLog = p
			m.mu.Unlock()
			go tailFile(ctx, p, m.ingest)
		} else {
			go func() {
				ok := runJournal(ctx, m.ingest, m.log)
				m.mu.Lock()
				m.journal = ok
				m.mu.Unlock()
			}()
			m.mu.Lock()
			m.journal = true
			m.mu.Unlock()
		}
	}
	m.reconcileReceiver(ctx)
	tick := time.NewTicker(30 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-tick.C:
			m.reconcileReceiver(ctx)
			m.win.sweep(now, time.Hour)
			m.ports.sweep(now, 10*time.Minute)
			m.hosts.sweep(now, 10*time.Minute)
			if now.Minute() == 0 {
				_ = m.st.PruneIDSAlerts(now.Add(-90 * 24 * time.Hour))
			}
		}
	}
}

func (m *Manager) reconcileReceiver(ctx context.Context) {
	cfg := m.cfg.Snapshot().IDS
	want := ""
	if cfg.Enabled && cfg.SyslogListen != "" {
		want = cfg.SyslogListen
	}
	m.mu.Lock()
	cur := m.recv
	curAddr := m.recvAddr
	m.mu.Unlock()
	if want == curAddr && (want == "" || cur != nil) {
		return
	}
	if cur != nil {
		cur.stop()
	}
	m.mu.Lock()
	m.recv, m.recvAddr, m.recvErr = nil, want, ""
	m.mu.Unlock()
	if want == "" {
		return
	}
	r := newSyslogReceiver(want, m.ingest, m.log)
	if err := r.start(ctx); err != nil {
		m.mu.Lock()
		m.recvErr = err.Error()
		m.mu.Unlock()
		m.log("ids: syslog receiver on %s: %v", want, err)
		return
	}
	m.mu.Lock()
	m.recv = r
	m.mu.Unlock()
	m.log("ids: receiving syslog on %s", want)
}

// ingest is every source's sink.
func (m *Manager) ingest(l Line) {
	m.mu.Lock()
	m.lines++
	m.lastLine = time.Now()
	m.mu.Unlock()
	h, ok := Parse(l.Text)
	if !ok {
		return
	}
	m.Hit(h, l.Source, l.Host)
}

// LoginFailure is Orbis's own login page reporting a wrong password.
func (m *Manager) LoginFailure(remote string) {
	host := remote
	if h, _, err := splitHostPort(remote); err == nil {
		host = h
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return
	}
	m.Hit(Hit{Kind: "orbis-auth-fail", IP: addr, Weight: 1, Sample: "wrong password on the Orbis login page"}, "orbis", "")
}

func splitHostPort(s string) (string, string, error) {
	i := strings.LastIndex(s, ":")
	if i < 0 {
		return s, "", fmt.Errorf("no port")
	}
	return strings.Trim(s[:i], "[]"), s[i+1:], nil
}

// Hit applies one observation to its scenario.
func (m *Manager) Hit(h Hit, source, host string) {
	cfg := m.cfg.Snapshot().IDS
	if !cfg.Enabled || !h.IP.IsValid() {
		return
	}
	if m.ignored(cfg, h.IP) {
		return
	}
	rule, ok := ruleFor(h.Kind)
	if !ok {
		return
	}
	m.mu.Lock()
	m.hits++
	m.mu.Unlock()
	if h.Weight <= 0 {
		h.Weight = 1
	}
	key := h.Kind + "|" + h.IP.String()
	n := m.win.add(key, h.Weight, time.Now(), rule.Window)
	if n < rule.Threshold {
		return
	}
	m.win.reset(key)
	m.fire(h.IP, rule, n, source, host, h.Sample)
}

// ObserveFlow feeds inbound connections from outside into the scan, sweep,
// flood and sensitive-port scenarios.
func (m *Manager) ObserveFlow(f *store.Flow) {
	cfg := m.cfg.Snapshot().IDS
	if !cfg.Enabled || !cfg.Flows || f == nil || f.Direction != "in" {
		return
	}
	src, err := netip.ParseAddr(f.SrcIP)
	if err != nil || geoip.IsPrivate(src) || m.ignored(cfg, src) {
		return
	}
	now := time.Now()
	key := src.String()
	if n := m.ports.add("ports|"+key, f.DstIP+":"+strconv.Itoa(f.DstPort), now, time.Minute); n >= 15 {
		if r, ok := ruleFor("port-scan"); ok {
			m.ports.reset("ports|" + key)
			m.fire(src, r, n, "flows", "", fmt.Sprintf("%d distinct ports touched in a minute, last %s:%d", n, f.DstIP, f.DstPort))
			return
		}
	}
	if n := m.hosts.add("hosts|"+key, f.DstIP, now, time.Minute); n >= 10 {
		if r, ok := ruleFor("host-sweep"); ok {
			m.hosts.reset("hosts|" + key)
			m.fire(src, r, n, "flows", "", fmt.Sprintf("%d distinct hosts touched in a minute", n))
			return
		}
	}
	if r, ok := ruleFor("conn-flood"); ok {
		if n := m.win.add("conn-flood|"+key, 1, now, r.Window); n >= r.Threshold {
			m.win.reset("conn-flood|" + key)
			m.fire(src, r, n, "flows", "", fmt.Sprintf("%d new connections in a minute", n))
			return
		}
	}
	switch f.DstPort {
	case 22, 23, 445, 3389, 5900, 21, 3306, 5432, 6379, 27017, 2375:
		if r, ok := ruleFor("sensitive-probe"); ok {
			if n := m.win.add("sensitive-probe|"+key, 1, now, r.Window); n >= r.Threshold {
				m.win.reset("sensitive-probe|" + key)
				m.fire(src, r, n, "flows", "", fmt.Sprintf("%d connections to sensitive ports, last %s:%d", n, f.DstIP, f.DstPort))
			}
		}
	}
}

func (m *Manager) ignored(cfg config.IDSConfig, a netip.Addr) bool {
	for _, s := range cfg.Ignore {
		if p, err := netip.ParsePrefix(s); err == nil && p.Contains(a) {
			return true
		}
		if x, err := netip.ParseAddr(s); err == nil && x == a {
			return true
		}
	}
	return false
}

// fire is a scenario crossing its threshold: an outside address is banned,
// longer each time it comes back; an inside device is reported, since
// banning a neighbour at the gateway helps nobody.
func (m *Manager) fire(ip netip.Addr, rule Rule, n int, source, host, sample string) {
	cfg := m.cfg.Snapshot().IDS
	now := time.Now()
	alert := store.IDSAlert{TS: now, IP: ip.String(), Scenario: rule.Kind, Count: n, Source: source, Host: host, Sample: sample}
	if m.hooks.Locate != nil {
		alert.Country, alert.ASOrg = m.hooks.Locate(ip)
	}
	if geoip.IsPrivate(ip) {
		alert.Action = "reported"
		_ = m.st.AddIDSAlert(alert)
		if m.hooks.Emit != nil && m.cooled("inside|"+ip.String()+"|"+rule.Kind, time.Hour) {
			name := ip.String()
			if m.hooks.ClientFor != nil {
				if _, n := m.hooks.ClientFor(ip); n != "" {
					name = n
				}
			}
			m.hooks.Emit(store.Event{
				ID: uuid.NewString(), TS: now, Severity: store.SevWarning, Category: "ids",
				Title:  fmt.Sprintf("%s from inside the network: %s", rule.Title, name),
				Detail: fmt.Sprintf("%s produced %d %s events in %s%s. A device on your own network doing this is either a misconfigured client retrying a password or something that should not be there. It was not banned: blocking a neighbour at the gateway would not stop it.", name, n, rule.Title, rule.Window, whereNote(host)),
				Data:   map[string]any{"ip": ip.String(), "scenario": rule.Kind, "count": n, "source": source, "host": host},
			})
		}
		return
	}
	prior, _ := m.st.IDSBanCount(ip.String(), now.Add(-7*24*time.Hour))
	d := rule.Ban
	if cfg.BanMultiplier > 0 {
		d = time.Duration(float64(d) * cfg.BanMultiplier)
	}
	for i := 0; i < prior && d < 7*24*time.Hour; i++ {
		d *= 2
	}
	if d > 7*24*time.Hour {
		d = 7 * 24 * time.Hour
	}
	alert.Action = "ban"
	reason := fmt.Sprintf("%s: %d in %s", rule.Title, n, rule.Window)
	if m.hooks.Ban != nil {
		until, err := m.hooks.Ban(ip.String(), d, reason)
		if err != nil {
			alert.Action = "ban-failed"
			m.log("ids: ban %s: %v", ip, err)
		} else {
			alert.BanUntil = until
		}
	}
	_ = m.st.AddIDSAlert(alert)
	m.mu.Lock()
	m.bans++
	m.mu.Unlock()
	m.log("ids: %s from %s (%d in %s, %s): banned for %s", rule.Title, ip, n, rule.Window, source, d)
	if m.hooks.Emit != nil && m.cooled("ban|"+ip.String(), 10*time.Minute) {
		where := ip.String()
		if alert.ASOrg != "" {
			where += " (" + alert.ASOrg
			if alert.Country != "" {
				where += ", " + alert.Country
			}
			where += ")"
		}
		esc := ""
		if prior > 0 {
			esc = fmt.Sprintf(" This is its %s ban this week, so the ban is longer.", ordinal(prior+1))
		}
		m.hooks.Emit(store.Event{
			ID: uuid.NewString(), TS: now, Severity: store.SevNotice, Category: "ids",
			Title:  fmt.Sprintf("%s from %s, banned %s", rule.Title, ip, humanDur(d)),
			Detail: fmt.Sprintf("%s produced %d %s events in %s%s.%s Connections to and from it are dropped where this node enforces.", where, n, strings.ToLower(rule.Title), rule.Window, whereNote(host), esc),
			Data:   map[string]any{"ip": ip.String(), "scenario": rule.Kind, "count": n, "source": source, "host": host, "ban_seconds": int(d.Seconds())},
		})
	}
}

func whereNote(host string) string {
	if host == "" {
		return ""
	}
	return " on " + host
}

func ordinal(n int) string {
	switch n {
	case 2:
		return "second"
	case 3:
		return "third"
	default:
		return strconv.Itoa(n) + "th"
	}
}

func humanDur(d time.Duration) string {
	switch {
	case d >= 24*time.Hour:
		return fmt.Sprintf("%d day(s)", int(d.Hours()/24))
	case d >= time.Hour:
		return fmt.Sprintf("%d hour(s)", int(d.Hours()))
	default:
		return fmt.Sprintf("%d minute(s)", int(d.Minutes()))
	}
}

func (m *Manager) cooled(key string, d time.Duration) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	if t, ok := m.cool[key]; ok && now.Sub(t) < d {
		return false
	}
	m.cool[key] = now
	return true
}

// Status is the page's view of sources and activity.
func (m *Manager) Status() map[string]any {
	cfg := m.cfg.Snapshot().IDS
	m.mu.Lock()
	out := map[string]any{
		"enabled": cfg.Enabled, "journal": m.journal, "auth_log": m.authLog, "flows": cfg.Flows,
		"lines": m.lines, "hits": m.hits, "bans_since_start": m.bans, "ignore": cfg.Ignore, "ban_multiplier": cfg.BanMultiplier,
		"syslog": map[string]any{"listen": m.recvAddr, "running": m.recv != nil, "error": m.recvErr},
	}
	if !m.lastLine.IsZero() {
		out["last_line"] = m.lastLine
	}
	recv := m.recv
	m.mu.Unlock()
	if recv != nil {
		out["syslog"] = recv.status()
	}
	rules := make([]map[string]any, 0, len(Rules))
	for _, r := range Rules {
		rules = append(rules, map[string]any{"kind": r.Kind, "title": r.Title, "threshold": r.Threshold, "window_seconds": int(r.Window.Seconds()), "ban_seconds": int(r.Ban.Seconds())})
	}
	out["rules"] = rules
	counts, bans, err := m.st.IDSAlertCounts(time.Now().Add(-24 * time.Hour))
	if err == nil {
		out["alerts_24h"] = counts
		out["bans_24h"] = bans
	}
	return out
}

// Alerts lists recent alerts.
func (m *Manager) Alerts(since time.Time, limit int) ([]store.IDSAlert, error) {
	return m.st.IDSAlerts(since, limit)
}

// TopOffenders aggregates alerts by address.
func (m *Manager) TopOffenders(since time.Time) []map[string]any {
	alerts, err := m.st.IDSAlerts(since, 2000)
	if err != nil {
		return nil
	}
	type agg struct {
		ip, country, org string
		alerts, bans     int
		last             time.Time
		scenarios        map[string]bool
	}
	by := map[string]*agg{}
	for _, a := range alerts {
		x := by[a.IP]
		if x == nil {
			x = &agg{ip: a.IP, country: a.Country, org: a.ASOrg, scenarios: map[string]bool{}}
			by[a.IP] = x
		}
		x.alerts++
		if a.Action == "ban" {
			x.bans++
		}
		if a.TS.After(x.last) {
			x.last = a.TS
		}
		x.scenarios[a.Scenario] = true
	}
	out := make([]map[string]any, 0, len(by))
	for _, x := range by {
		sc := make([]string, 0, len(x.scenarios))
		for k := range x.scenarios {
			sc = append(sc, k)
		}
		sort.Strings(sc)
		out = append(out, map[string]any{"ip": x.ip, "country": x.country, "as_org": x.org, "alerts": x.alerts, "bans": x.bans, "last": x.last, "scenarios": sc})
	}
	sort.Slice(out, func(i, j int) bool { return out[i]["alerts"].(int) > out[j]["alerts"].(int) })
	if len(out) > 50 {
		out = out[:50]
	}
	return out
}

// Test parses a line the operator pastes, so log forwarding can be checked
// before an attack proves it.
func Test(line string) map[string]any {
	m := ParseSyslog(line)
	h, ok := Parse(m.Message)
	out := map[string]any{"host": m.Host, "program": m.Program, "message": m.Message, "matched": ok}
	if ok {
		r, _ := ruleFor(h.Kind)
		out["scenario"] = h.Kind
		out["title"] = r.Title
		out["ip"] = h.IP.String()
		out["weight"] = h.Weight
		out["threshold"] = r.Threshold
		out["window_seconds"] = int(r.Window.Seconds())
	}
	return out
}
