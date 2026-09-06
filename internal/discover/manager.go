package discover

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Neoo-Blue/orbis/internal/config"
	"github.com/Neoo-Blue/orbis/internal/geoip"
	"github.com/Neoo-Blue/orbis/internal/store"
	"github.com/Neoo-Blue/orbis/internal/upnp"
	"github.com/google/uuid"
)

// Host is a device the application knows about, as the scanner needs it.
type Host struct {
	ID         string
	IP         string
	Name       string
	Vendor     string
	DeviceType string
	MAC        string
	Online     bool
	LastSeen   time.Time
}

// Hooks are what the application lends the manager.
type Hooks struct {
	Hosts         func() []Host
	ActiveFlows   func() []store.Flow
	Emit          func(store.Event)
	AddRule       func(r *store.Rule) error
	DeleteRule    func(id string) error
	ApplyFirewall func(ctx context.Context) error
	// Inline reports whether this node's own ruleset can carry a forward,
	// and the WAN zone name to attach it to.
	Inline   func() (bool, string)
	NodeAddr func() string
}

// Manager runs the periodic discovery and owns the port forwards.
type Manager struct {
	cfg   *config.Config
	st    *store.Store
	log   func(string, ...any)
	hooks Hooks

	mu       sync.Mutex
	scanning bool
	lastScan time.Time
	lastErr  string
	warned   map[string]bool
	kick     chan struct{}

	gwMu   sync.Mutex
	gw     *upnp.Gateway
	gwAt   time.Time
	gwErr  string
	extIP  string
	extAt  time.Time
	gwNext time.Time
}

func NewManager(cfg *config.Config, st *store.Store, hooks Hooks, log func(string, ...any)) *Manager {
	if log == nil {
		log = func(string, ...any) {}
	}
	return &Manager{cfg: cfg, st: st, hooks: hooks, log: log, warned: map[string]bool{}, kick: make(chan struct{}, 1)}
}

// Run scans on the configured interval, renews router leases, and prunes.
func (m *Manager) Run(ctx context.Context) {
	first := time.NewTimer(90 * time.Second)
	defer first.Stop()
	tick := time.NewTicker(time.Minute)
	defer tick.Stop()
	var lastRenew time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case <-first.C:
			m.maybeScan(ctx)
		case <-m.kick:
			if err := m.Scan(ctx); err != nil {
				m.log("discover: scan: %v", err)
			}
		case now := <-tick.C:
			m.maybeScan(ctx)
			if now.Sub(lastRenew) >= 30*time.Minute {
				lastRenew = now
				m.renewLeases(ctx)
				_ = m.st.PruneLANServices(now.Add(-30 * 24 * time.Hour))
			}
		}
	}
}

func (m *Manager) maybeScan(ctx context.Context) {
	cfg := m.cfg.Snapshot().Discover
	if !cfg.Enabled {
		return
	}
	m.mu.Lock()
	due := time.Since(m.lastScan) >= time.Duration(max(cfg.IntervalHours, 1))*time.Hour
	m.mu.Unlock()
	if due {
		if err := m.Scan(ctx); err != nil {
			m.log("discover: scheduled scan: %v", err)
		}
	}
}

// RequestScan schedules a scan as soon as the loop is free.
func (m *Manager) RequestScan() {
	select {
	case m.kick <- struct{}{}:
	default:
	}
}

// Scan probes every recently seen device on this network, fingerprints what
// answered, asks the configured Docker hosts what they run, and stores the
// result. New services become events.
func (m *Manager) Scan(ctx context.Context) error {
	m.mu.Lock()
	if m.scanning {
		m.mu.Unlock()
		return nil
	}
	m.scanning = true
	m.mu.Unlock()
	defer func() {
		m.mu.Lock()
		m.scanning = false
		m.lastScan = time.Now()
		m.mu.Unlock()
	}()
	cfg := m.cfg.Snapshot().Discover
	ctx, cancel := context.WithTimeout(ctx, 8*time.Minute)
	defer cancel()

	before, _ := m.st.LANServices()
	existed := map[string]bool{}
	for _, s := range before {
		existed[s.Host+":"+strconv.Itoa(s.Port)] = true
	}

	var hosts []Host
	if m.hooks.Hosts != nil {
		for _, h := range m.hooks.Hosts() {
			addr, err := netip.ParseAddr(h.IP)
			if err != nil || !geoip.IsPrivate(addr) {
				continue
			}
			if !h.Online && time.Since(h.LastSeen) > 24*time.Hour {
				continue
			}
			hosts = append(hosts, h)
		}
	}
	byIP := map[string]Host{}
	ips := make([]string, 0, len(hosts))
	for _, h := range hosts {
		byIP[h.IP] = h
		ips = append(ips, h.IP)
	}
	ports := Ports(cfg.ExtraPorts)
	start := time.Now()
	open := scanPorts(ctx, ips, ports, 24, 600*time.Millisecond)

	// Fingerprint what answered, a few at a time.
	type key struct {
		ip   string
		port int
	}
	fps := map[key]*Fingerprint{}
	var fpMu sync.Mutex
	sem := make(chan struct{}, 8)
	var wg sync.WaitGroup
	for ip, ps := range open {
		for _, p := range ps {
			k, isKnown := known(p)
			if isKnown && !k.HTTP {
				continue
			}
			wg.Add(1)
			sem <- struct{}{}
			go func(ip string, p int, tlsFirst bool) {
				defer wg.Done()
				defer func() { <-sem }()
				if fp := fingerprint(ctx, ip, p, tlsFirst); fp != nil {
					fpMu.Lock()
					fps[key{ip, p}] = fp
					fpMu.Unlock()
				}
			}(ip, p, k.TLS)
		}
	}
	wg.Wait()

	now := time.Now()
	var fresh []store.LANService
	for ip, ps := range open {
		h := byIP[ip]
		for _, p := range ps {
			fp := fps[key{ip, p}]
			name, kind, category, sensitive := Identify(p, fp, h.Vendor)
			svc := store.LANService{
				Host: ip, Port: p, Proto: "tcp", Name: name, Kind: kind, Category: category,
				Source: "scan", Sensitive: sensitive, FirstSeen: now, LastSeen: now, Online: true,
			}
			if fp != nil {
				svc.Title, svc.Server, svc.Scheme = fp.Title, fp.Server, fp.Scheme
			}
			if err := m.st.UpsertLANService(svc); err != nil {
				m.log("discover: store %s:%d: %v", ip, p, err)
			}
			if !existed[ip+":"+strconv.Itoa(p)] {
				fresh = append(fresh, svc)
			}
		}
		if err := m.st.MarkLANServicesOffline(ip, ps, "tcp"); err != nil {
			m.log("discover: mark offline %s: %v", ip, err)
		}
	}
	for _, ip := range ips {
		if _, ok := open[ip]; !ok {
			_ = m.st.MarkLANServicesOffline(ip, nil, "tcp")
		}
	}

	// Docker hosts: containers name the services behind the ports. Hosts
	// that answered on 2375 are asked too: an Engine API open on the LAN
	// without authentication is root on that machine for anyone here, which
	// is worth using and worth a warning.
	dockerHosts := append([]config.DockerHost(nil), cfg.Docker...)
	configured := map[string]bool{}
	for _, d := range cfg.Docker {
		if u := strings.TrimPrefix(strings.TrimPrefix(d.URL, "tcp://"), "http://"); u != "" {
			configured[strings.Split(u, ":")[0]] = true
		}
	}
	for ip, ps := range open {
		for _, p := range ps {
			if p != 2375 || configured[ip] {
				continue
			}
			probe, pcancel := context.WithTimeout(ctx, 6*time.Second)
			v, err := DockerVersion(probe, "tcp://"+ip+":2375")
			pcancel()
			if err != nil {
				continue
			}
			name := ip
			if h, ok := byIP[ip]; ok && h.Name != "" {
				name = h.Name
			}
			dockerHosts = append(dockerHosts, config.DockerHost{Name: name + " (found)", URL: "tcp://" + ip + ":2375", Enabled: true})
			if m.hooks.Emit != nil && !m.warnedOnce("docker-open:"+ip) {
				m.hooks.Emit(store.Event{
					ID: uuid.NewString(), TS: time.Now(), Severity: store.SevWarning, Category: "discover",
					Title:    fmt.Sprintf("Docker API on %s is open to the whole network", name),
					Detail:   fmt.Sprintf("%s answers the Docker Engine API on port 2375 with no authentication (Docker %v). Anyone on this network can start containers there, which is root on that machine. Orbis is using it read-only to name containers; bind it to localhost behind a socket proxy, or firewall it to this node.", name, v["version"]),
					ClientID: byIP[ip].ID,
					Data:     map[string]any{"host": ip, "port": 2375},
				})
			}
		}
	}
	var dockerErr error
	for _, d := range dockerHosts {
		if !d.Enabled || d.URL == "" {
			continue
		}
		containers, host, err := ListContainers(ctx, d.URL)
		if err != nil {
			m.log("discover: docker %q: %v", d.Name, err)
			if dockerErr == nil {
				dockerErr = fmt.Errorf("%s: %w", d.Name, err)
			}
			continue
		}
		if host == "" && m.hooks.NodeAddr != nil {
			host = m.hooks.NodeAddr()
		}
		if host == "" {
			continue
		}
		if ip := net.ParseIP(host); ip == nil {
			if addrs, err := net.DefaultResolver.LookupHost(ctx, host); err == nil && len(addrs) > 0 {
				host = addrs[0]
			}
		}
		for _, c := range containers {
			for _, p := range c.Ports {
				if p.PublicPort == 0 || p.IP == "127.0.0.1" || p.IP == "::1" {
					continue
				}
				proto := strings.ToLower(p.Type)
				if proto == "" {
					proto = "tcp"
				}
				name, kind, category, sensitive := Identify(p.PrivatePort, nil, "")
				if fp := fps[key{host, p.PublicPort}]; fp != nil {
					name, kind, category, sensitive = Identify(p.PrivatePort, fp, "")
				}
				if kind == "other" || kind == "web" {
					name = c.Name
				}
				svc := store.LANService{
					Host: host, Port: p.PublicPort, Proto: proto, Name: name, Kind: kind, Category: category,
					Source: "docker", Container: c.Name, Image: c.Image, Sensitive: sensitive,
					FirstSeen: now, LastSeen: now, Online: c.State == "running",
				}
				if err := m.st.UpsertLANService(svc); err != nil {
					m.log("discover: store container %s: %v", c.Name, err)
				}
				if !existed[host+":"+strconv.Itoa(p.PublicPort)] {
					fresh = append(fresh, svc)
				}
			}
		}
	}

	m.mu.Lock()
	m.lastErr = ""
	if dockerErr != nil {
		m.lastErr = dockerErr.Error()
	}
	m.mu.Unlock()
	m.log("discover: scanned %d host(s), %d port(s) each in %s; %d service(s) up, %d new",
		len(ips), len(ports), time.Since(start).Round(time.Second), countOpen(open), len(fresh))

	// Announce what is new, once, quietly. The first scan on a fresh install
	// would announce everything, which is noise; it goes into the log only.
	if len(before) > 0 && m.hooks.Emit != nil {
		for _, s := range fresh {
			who := s.Host
			if h, ok := byIP[s.Host]; ok && h.Name != "" {
				who = h.Name
			}
			detail := fmt.Sprintf("%s is answering on port %d.", s.Name, s.Port)
			if s.Container != "" {
				detail = fmt.Sprintf("Container %s (%s) publishes port %d.", s.Container, s.Image, s.Port)
			}
			m.hooks.Emit(store.Event{
				ID: uuid.NewString(), TS: now, Severity: store.SevInfo, Category: "discover",
				Title: fmt.Sprintf("New service on %s: %s", who, s.Name), Detail: detail, ClientID: byIP[s.Host].ID,
				Data: map[string]any{"host": s.Host, "port": s.Port, "name": s.Name, "kind": s.Kind},
			})
		}
	}
	m.warnExposed()
	return nil
}

// warnedOnce reports whether a key was already warned about, marking it.
func (m *Manager) warnedOnce(key string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	done := m.warned[key]
	m.warned[key] = true
	return done
}

func countOpen(open map[string][]int) int {
	n := 0
	for _, ps := range open {
		n += len(ps)
	}
	return n
}

// warnExposed raises a warning when one of this node's forwards points at a
// service that should not face the internet.
func (m *Manager) warnExposed() {
	if m.hooks.Emit == nil {
		return
	}
	forwards, err := m.st.PortForwards()
	if err != nil {
		return
	}
	services, err := m.st.LANServices()
	if err != nil {
		return
	}
	byKey := map[string]store.LANService{}
	for _, s := range services {
		byKey[s.Host+":"+strconv.Itoa(s.Port)] = s
	}
	for _, f := range forwards {
		s, ok := byKey[f.Host+":"+strconv.Itoa(f.Port)]
		if !ok || !s.Sensitive {
			continue
		}
		k := "exposed:" + f.ID
		m.mu.Lock()
		done := m.warned[k]
		m.warned[k] = true
		m.mu.Unlock()
		if done {
			continue
		}
		m.hooks.Emit(store.Event{
			ID: uuid.NewString(), TS: time.Now(), Severity: store.SevWarning, Category: "discover",
			Title:  fmt.Sprintf("%s is reachable from the internet", s.Name),
			Detail: fmt.Sprintf("Port forward %q sends internet port %d to %s:%d, which is %s. Storage, admin panels and databases on the open internet are the usual way a home network gets compromised. Prefer a VPN or a tunnel.", f.Name, f.ExtPort, f.Host, f.Port, s.Name),
			Data:   map[string]any{"forward": f.ID, "host": f.Host, "port": f.Port},
		})
	}
}

// Status is the page header.
func (m *Manager) Status() map[string]any {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := map[string]any{"scanning": m.scanning, "last_error": m.lastErr}
	if !m.lastScan.IsZero() {
		out["last_scan"] = m.lastScan
	}
	return out
}

// HostView is one device with what it hosts.
type HostView struct {
	Host
	Services []store.LANService `json:"services"`
	Docker   bool               `json:"docker"`
	Storage  bool               `json:"storage"`
}

// Hosts groups services by device, most services first.
func (m *Manager) Hosts() ([]HostView, error) {
	services, err := m.st.LANServices()
	if err != nil {
		return nil, err
	}
	known := map[string]Host{}
	if m.hooks.Hosts != nil {
		for _, h := range m.hooks.Hosts() {
			known[h.IP] = h
		}
	}
	views := map[string]*HostView{}
	for _, s := range services {
		v := views[s.Host]
		if v == nil {
			h := known[s.Host]
			if h.IP == "" {
				h = Host{IP: s.Host, Name: s.Host}
			}
			v = &HostView{Host: h}
			views[s.Host] = v
		}
		v.Services = append(v.Services, s)
		if s.Source == "docker" {
			v.Docker = true
		}
	}
	out := make([]HostView, 0, len(views))
	for _, v := range views {
		ports := make([]int, 0, len(v.Services))
		for _, s := range v.Services {
			if s.Online {
				ports = append(ports, s.Port)
			}
		}
		v.Storage = IsStorage(v.Vendor, v.DeviceType, ports)
		out = append(out, *v)
	}
	sort.Slice(out, func(i, j int) bool {
		if len(out[i].Services) != len(out[j].Services) {
			return len(out[i].Services) > len(out[j].Services)
		}
		return out[i].IP < out[j].IP
	})
	return out, nil
}

// StorageView is a NAS or SAN with its protocols and who is using it now.
type StorageView struct {
	Host
	Protocols []map[string]any `json:"protocols"`
	WebUI     string           `json:"web_ui,omitempty"`
	Users     []map[string]any `json:"users"`
	BytesIn   int64            `json:"bytes_in"`
	BytesOut  int64            `json:"bytes_out"`
	Exposed   []string         `json:"exposed"`
}

// Storage lists the storage devices with their protocols, the devices
// talking to them right now, and any forward that exposes them.
func (m *Manager) Storage() ([]StorageView, error) {
	hosts, err := m.Hosts()
	if err != nil {
		return nil, err
	}
	forwards, _ := m.st.PortForwards()
	var flows []store.Flow
	if m.hooks.ActiveFlows != nil {
		flows = m.hooks.ActiveFlows()
	}
	var out []StorageView
	for _, h := range hosts {
		if !h.Storage {
			continue
		}
		v := StorageView{Host: h.Host, Users: []map[string]any{}, Exposed: []string{}}
		seenProto := map[string]bool{}
		for _, s := range h.Services {
			if !s.Online {
				continue
			}
			if sp := StorageProtocol(s.Port); sp != "" && !seenProto[sp] {
				seenProto[sp] = true
				v.Protocols = append(v.Protocols, map[string]any{"name": sp, "port": s.Port})
			}
			if v.WebUI == "" && s.Kind == "admin" && s.Scheme != "" {
				v.WebUI = fmt.Sprintf("%s://%s:%d/", s.Scheme, s.Host, s.Port)
			}
		}
		users := map[string]*struct {
			ip    string
			in    int64
			out   int64
			conns int
		}{}
		for _, f := range flows {
			if f.DstIP != h.IP {
				continue
			}
			u := users[f.SrcIP]
			if u == nil {
				u = &struct {
					ip    string
					in    int64
					out   int64
					conns int
				}{ip: f.SrcIP}
				users[f.SrcIP] = u
			}
			u.in += f.BytesIn
			u.out += f.BytesOut
			u.conns++
			v.BytesIn += f.BytesIn
			v.BytesOut += f.BytesOut
		}
		for _, u := range users {
			v.Users = append(v.Users, map[string]any{"ip": u.ip, "connections": u.conns, "bytes_in": u.in, "bytes_out": u.out})
		}
		sort.Slice(v.Users, func(i, j int) bool { return v.Users[i]["connections"].(int) > v.Users[j]["connections"].(int) })
		for _, f := range forwards {
			if f.Host == h.IP {
				v.Exposed = append(v.Exposed, fmt.Sprintf("%d/%s -> %d", f.ExtPort, f.Proto, f.Port))
			}
		}
		out = append(out, v)
	}
	return out, nil
}

// ---- port forwards ----

// ForwardRequest is what the operator (or the assistant) asks for.
type ForwardRequest struct {
	Host    string `json:"host"`
	Port    int    `json:"port"`
	Proto   string `json:"proto"`
	ExtPort int    `json:"ext_port"`
	Name    string `json:"name"`
	// Confirm acknowledges the warning for a sensitive service.
	Confirm bool `json:"confirm"`
}

// SensitiveError is returned when a forward would expose a service that
// should not face the internet and the caller has not confirmed.
type SensitiveError struct{ Service string }

func (e *SensitiveError) Error() string {
	return fmt.Sprintf("%s should not be exposed to the internet directly (this is how home networks get compromised). Use a VPN or a tunnel, or confirm to forward it anyway.", e.Service)
}

// Forward creates a port forward: a DNAT rule when this node is the gateway,
// otherwise a UPnP mapping on the upstream router.
func (m *Manager) Forward(ctx context.Context, req ForwardRequest, actor string) (*store.PortForward, error) {
	addr, err := netip.ParseAddr(strings.TrimSpace(req.Host))
	if err != nil || !geoip.IsPrivate(addr) {
		return nil, fmt.Errorf("host must be an address on this network")
	}
	if req.Port <= 0 || req.Port > 65535 {
		return nil, fmt.Errorf("port must be 1 to 65535")
	}
	if req.ExtPort == 0 {
		req.ExtPort = req.Port
	}
	if req.ExtPort <= 0 || req.ExtPort > 65535 {
		return nil, fmt.Errorf("external port must be 1 to 65535")
	}
	proto := strings.ToLower(strings.TrimSpace(req.Proto))
	if proto == "" {
		proto = "tcp"
	}
	if proto != "tcp" && proto != "udp" {
		return nil, fmt.Errorf("protocol must be tcp or udp")
	}
	name := strings.TrimSpace(req.Name)
	services, _ := m.st.LANServices()
	for _, s := range services {
		if s.Host == addr.String() && s.Port == req.Port && s.Proto == proto {
			if name == "" {
				name = s.Name
			}
			if s.Sensitive && !req.Confirm {
				return nil, &SensitiveError{Service: s.Name}
			}
		}
	}
	if name == "" {
		name = fmt.Sprintf("%s:%d", addr, req.Port)
	}
	existing, _ := m.st.PortForwards()
	for _, f := range existing {
		if f.ExtPort == req.ExtPort && f.Proto == proto {
			return nil, fmt.Errorf("external port %d/%s is already forwarded to %s:%d (%s)", f.ExtPort, f.Proto, f.Host, f.Port, f.Name)
		}
	}

	fw := store.PortForward{
		ID: uuid.NewString(), Name: name, Proto: proto, ExtPort: req.ExtPort, Host: addr.String(), Port: req.Port,
		Created: time.Now(), Actor: actor,
	}
	inline, wanZone := false, ""
	if m.hooks.Inline != nil {
		inline, wanZone = m.hooks.Inline()
	}
	switch {
	case inline && m.hooks.AddRule != nil:
		dnat := &store.Rule{
			ID: uuid.NewString(), Enabled: true, Name: "Forward " + name,
			Description: fmt.Sprintf("Internet port %d/%s to %s:%d. Created from Hosted apps.", req.ExtPort, proto, addr, req.Port),
			Chain:       "dnat", Action: "dnat", SrcZone: wanZone, Proto: proto, DstPort: strconv.Itoa(req.ExtPort),
			Dst: net.JoinHostPort(addr.String(), strconv.Itoa(req.Port)), Origin: "discover",
		}
		accept := &store.Rule{
			ID: uuid.NewString(), Enabled: true, Name: "Allow forwarded " + name,
			Description: "Lets the forwarded connections through the forward chain.",
			Chain:       "forward", Action: "accept", SrcZone: wanZone, Proto: proto, Dst: addr.String(), DstPort: strconv.Itoa(req.Port),
			Origin: "discover",
		}
		if err := m.hooks.AddRule(dnat); err != nil {
			return nil, err
		}
		if err := m.hooks.AddRule(accept); err != nil {
			_ = m.hooks.DeleteRule(dnat.ID)
			return nil, err
		}
		fw.Method, fw.RuleID = "nft", dnat.ID+","+accept.ID
		if m.hooks.ApplyFirewall != nil {
			if err := m.hooks.ApplyFirewall(ctx); err != nil {
				_ = m.hooks.DeleteRule(dnat.ID)
				_ = m.hooks.DeleteRule(accept.ID)
				return nil, fmt.Errorf("rules saved but the ruleset failed to apply: %w", err)
			}
		}
	case m.cfg.Snapshot().Discover.UPnP:
		gw, err := m.gateway(ctx)
		if err != nil {
			return nil, fmt.Errorf("this node is not the gateway, and the router could not be reached over UPnP: %w", err)
		}
		mapping := upnp.Mapping{ExtPort: req.ExtPort, Proto: proto, Host: addr.String(), Port: req.Port, Description: "orbis: " + name}
		if err := gw.AddMapping(ctx, mapping); err != nil {
			var ue *upnp.Error
			if asUPnP(err, &ue) && ue.Code == "725" {
				mapping.Lease = 7 * 24 * 3600
				if err := gw.AddMapping(ctx, mapping); err != nil {
					return nil, err
				}
				t := time.Now().Add(7 * 24 * time.Hour)
				fw.LeaseUntil = &t
			} else {
				return nil, err
			}
		}
		fw.Method = "upnp"
	default:
		return nil, fmt.Errorf("this node is not the gateway and UPnP is switched off, so there is nowhere to create the forward")
	}
	if err := m.st.PutPortForward(fw); err != nil {
		return nil, err
	}
	m.warnExposed()
	return &fw, nil
}

func asUPnP(err error, target **upnp.Error) bool {
	e, ok := err.(*upnp.Error)
	if ok {
		*target = e
	}
	return ok
}

// Remove undoes a forward by id.
func (m *Manager) Remove(ctx context.Context, id string) error {
	forwards, err := m.st.PortForwards()
	if err != nil {
		return err
	}
	for _, f := range forwards {
		if f.ID != id {
			continue
		}
		switch f.Method {
		case "nft":
			for _, rid := range strings.Split(f.RuleID, ",") {
				if rid != "" && m.hooks.DeleteRule != nil {
					_ = m.hooks.DeleteRule(rid)
				}
			}
			if m.hooks.ApplyFirewall != nil {
				if inline, _ := m.hooks.Inline(); inline {
					_ = m.hooks.ApplyFirewall(ctx)
				}
			}
		case "upnp":
			gw, err := m.gateway(ctx)
			if err != nil {
				return fmt.Errorf("the router could not be reached to remove the mapping: %w", err)
			}
			if err := gw.DeleteMapping(ctx, f.ExtPort, f.Proto); err != nil {
				return err
			}
		}
		return m.st.DeletePortForward(id)
	}
	return fmt.Errorf("no forward with id %q", id)
}

// Forwards lists this node's forwards.
func (m *Manager) Forwards() ([]store.PortForward, error) { return m.st.PortForwards() }

// gateway finds the UPnP router, cached for ten minutes; failures are
// retried no more than once a minute so a router without UPnP does not cost
// a multicast round every page load.
func (m *Manager) gateway(ctx context.Context) (*upnp.Gateway, error) {
	m.gwMu.Lock()
	defer m.gwMu.Unlock()
	if m.gw != nil && time.Since(m.gwAt) < 10*time.Minute {
		return m.gw, nil
	}
	if m.gw == nil && time.Now().Before(m.gwNext) {
		return nil, fmt.Errorf("%s", m.gwErr)
	}
	gw, err := upnp.Discover(ctx)
	if err != nil {
		m.gwErr = err.Error()
		m.gwNext = time.Now().Add(time.Minute)
		if m.gw != nil {
			return m.gw, nil // keep the stale one rather than fail
		}
		return nil, err
	}
	m.gw, m.gwAt, m.gwErr = gw, time.Now(), ""
	return gw, nil
}

// Router describes the UPnP gateway and its mapping table for the UI.
func (m *Manager) Router(ctx context.Context) map[string]any {
	out := map[string]any{"upnp_enabled": m.cfg.Snapshot().Discover.UPnP}
	if !m.cfg.Snapshot().Discover.UPnP {
		return out
	}
	gw, err := m.gateway(ctx)
	if err != nil {
		out["found"] = false
		out["error"] = err.Error()
		return out
	}
	out["found"] = true
	out["model"] = strings.TrimSpace(gw.Manufacturer + " " + gw.Model)
	out["name"] = gw.FriendlyName
	m.gwMu.Lock()
	ext, extAt := m.extIP, m.extAt
	m.gwMu.Unlock()
	if ext == "" || time.Since(extAt) > 10*time.Minute {
		if ip, err := gw.ExternalIP(ctx); err == nil {
			ext = ip
			m.gwMu.Lock()
			m.extIP, m.extAt = ip, time.Now()
			m.gwMu.Unlock()
		}
	}
	out["external_ip"] = ext
	if maps, err := gw.Mappings(ctx); err == nil {
		ours, _ := m.st.PortForwards()
		mine := map[string]bool{}
		for _, f := range ours {
			if f.Method == "upnp" {
				mine[strconv.Itoa(f.ExtPort)+"/"+f.Proto] = true
			}
		}
		rows := make([]map[string]any, 0, len(maps))
		for _, mp := range maps {
			rows = append(rows, map[string]any{
				"ext_port": mp.ExtPort, "proto": mp.Proto, "host": mp.Host, "port": mp.Port,
				"description": mp.Description, "enabled": mp.Enabled, "lease_seconds": mp.Lease,
				"ours": mine[strconv.Itoa(mp.ExtPort)+"/"+mp.Proto],
			})
		}
		out["mappings"] = rows
	} else {
		out["mappings_error"] = err.Error()
	}
	return out
}

// RemoveRouterMapping deletes a mapping on the router that this node did not
// create, for cleaning up what a console or an old app left behind.
func (m *Manager) RemoveRouterMapping(ctx context.Context, extPort int, proto string) error {
	gw, err := m.gateway(ctx)
	if err != nil {
		return err
	}
	return gw.DeleteMapping(ctx, extPort, proto)
}

// renewLeases re-adds UPnP mappings whose lease is running out.
func (m *Manager) renewLeases(ctx context.Context) {
	forwards, err := m.st.PortForwards()
	if err != nil {
		return
	}
	for _, f := range forwards {
		if f.Method != "upnp" || f.LeaseUntil == nil || time.Until(*f.LeaseUntil) > 24*time.Hour {
			continue
		}
		gw, err := m.gateway(ctx)
		if err != nil {
			return
		}
		if err := gw.AddMapping(ctx, upnp.Mapping{ExtPort: f.ExtPort, Proto: f.Proto, Host: f.Host, Port: f.Port, Description: "orbis: " + f.Name, Lease: 7 * 24 * 3600}); err != nil {
			m.log("discover: renew %d/%s: %v", f.ExtPort, f.Proto, err)
			continue
		}
		t := time.Now().Add(7 * 24 * time.Hour)
		f.LeaseUntil = &t
		_ = m.st.PutPortForward(f)
	}
}
