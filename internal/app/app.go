// Package app wires every subsystem together and owns their lifecycle. It is
// also the single place that implements the assistant's Backend interface, so
// the tools the model can call and the endpoints the UI calls go through the
// same code paths and cannot drift apart.
package app

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/Neoo-Blue/orbis/internal/adblock"
	"github.com/Neoo-Blue/orbis/internal/ai"
	"github.com/Neoo-Blue/orbis/internal/alerts"
	"github.com/Neoo-Blue/orbis/internal/config"
	"github.com/Neoo-Blue/orbis/internal/consent"
	"github.com/Neoo-Blue/orbis/internal/dhcp"
	"github.com/Neoo-Blue/orbis/internal/dnsproxy"
	"github.com/Neoo-Blue/orbis/internal/dpi"
	"github.com/Neoo-Blue/orbis/internal/firewall"
	"github.com/Neoo-Blue/orbis/internal/flows"
	"github.com/Neoo-Blue/orbis/internal/geoip"
	"github.com/Neoo-Blue/orbis/internal/intercept"
	"github.com/Neoo-Blue/orbis/internal/issues"
	"github.com/Neoo-Blue/orbis/internal/lounge"
	"github.com/Neoo-Blue/orbis/internal/mitm"
	"github.com/Neoo-Blue/orbis/internal/netconf"
	"github.com/Neoo-Blue/orbis/internal/notify"
	"github.com/Neoo-Blue/orbis/internal/portmap"
	"github.com/Neoo-Blue/orbis/internal/store"
	"github.com/Neoo-Blue/orbis/internal/topology"
	"github.com/Neoo-Blue/orbis/internal/usage"
	"github.com/Neoo-Blue/orbis/internal/vpn"
	"github.com/google/uuid"
	"github.com/miekg/dns"
)

type App struct {
	Cfg   *config.Config
	Store *store.Store
	Geo   *geoip.Resolver
	Self  *geoip.SelfLocator

	Tracker   *flows.Tracker
	Registry  *flows.ClientRegistry
	Capture   *flows.Capturer
	Conntrack *flows.ConntrackPoller

	Matcher *adblock.Matcher
	Lists   *adblock.Manager
	Smart   *adblock.SmartCapture

	DNS       *dnsproxy.Server
	DNSCrypt  *dnsproxy.EncryptedServer
	DHCP      *dhcp.Server
	Firewall  *firewall.Engine
	VPN       *vpn.Manager
	Tailscale *vpn.Tailscale
	Egress    *vpn.EgressManager
	Net       *netconf.Manager
	WAN       *netconf.WANMonitor
	PortMap   *portmap.Server
	Topology  *topology.Scanner
	Intercept *intercept.Manager
	MITM      *mitm.Proxy
	CA        *mitm.CA
	Lounge    *lounge.Manager

	AI        *ai.Client
	Assistant *ai.Assistant
	Analyzer  *ai.Analyzer
	Briefer   *ai.Briefer
	Reviewer  *ai.Reviewer

	// Issues is the problem recorder (and GitHub reporter).
	Issues *issues.Recorder
	// Usage rolls the live flow table and the query log into per-device,
	// per-service counters.
	Usage *usage.Meter
	// logRing keeps the last few hundred log lines for diagnostics bundles.
	logRing *logRing

	// Notifier delivers events off the box (webhook, email).
	Notifier *notify.Notifier
	Alerts   *alerts.Engine

	// Consent is ask-on-first-connection for enrolled devices.
	Consent *consent.Store

	// Bus is the live fan-out used by the WebSocket layer.
	Bus *Bus

	// build is the version string, for backups and the status surface.
	build string

	log  func(string, ...any)
	ctx  context.Context
	stop context.CancelFunc
	wg   sync.WaitGroup

	policyMu sync.RWMutex
	policies map[string]*store.Policy

	recordsMu sync.RWMutex
	records   *dnsproxy.RecordSet

	reportMu   sync.Mutex
	lastReport string

	startedAt time.Time
}

func New(cfg *config.Config, logf func(string, ...any)) (*App, error) {
	if logf == nil {
		logf = func(format string, args ...any) {
			fmt.Fprintf(os.Stderr, format+"\n", args...)
		}
	}
	st, err := store.Open(cfg.Store.Path)
	if err != nil {
		return nil, fmt.Errorf("open store: %w", err)
	}

	geo := geoip.New()
	if err := geo.LoadCity(cfg.GeoIP.CityDB); err != nil && cfg.GeoIP.CityDB != "" {
		logf("geoip: city database unavailable (%v); falling back to region-level placement", err)
	}
	if err := geo.LoadASN(cfg.GeoIP.ASNDB); err != nil && cfg.GeoIP.ASNDB != "" {
		logf("geoip: ASN database unavailable (%v); network operator will be blank", err)
	}

	self := geoip.NewSelfLocator(geo, logf)
	self.SetEnabled(cfg.Node.LocatePublicIP)

	ctx, cancel := context.WithCancel(context.Background())
	ring := newLogRing(400)
	baseLog := logf
	logf = func(format string, args ...any) {
		ring.add(fmt.Sprintf(format, args...))
		baseLog(format, args...)
	}
	a := &App{
		Cfg: cfg, Store: st, Geo: geo, Self: self, log: logf,
		ctx: ctx, stop: cancel,
		Bus:       NewBus(1024),
		policies:  map[string]*store.Policy{},
		startedAt: time.Now(),
		logRing:   ring,
	}

	// Flow tracking.
	flows.SetAppClassifier(dpi.ClassifyApp)
	a.Tracker = flows.NewTracker(st, geo,
		time.Duration(cfg.Capture.FlowIdleTimeout)*time.Second, cfg.Capture.MaxActiveFlows)
	a.Tracker.SetLocalNets(flows.LocalPrefixes())
	a.Registry = flows.NewClientRegistry(st, a.Tracker)
	flows.SetARPSink(a.Registry)
	if err := a.Registry.Load(); err != nil {
		logf("clients: load failed: %v", err)
	}
	// Ask-on-first-connection. Seeded from the database so decisions survive
	// a restart; enrolment is per device and off by default.
	a.Consent = consent.NewStore(500)
	if rules, err := st.ConsentRules(); err == nil {
		conv := make([]consent.Rule, 0, len(rules))
		for _, r := range rules {
			conv = append(conv, consent.Rule{
				ClientID: r.ClientID, Host: r.Host,
				Decision: consent.Decision(r.Decision), Scope: r.Scope, DecidedAt: r.DecidedAt,
			})
		}
		a.Consent.LoadRules(conv)
	} else {
		logf("consent: could not load rules: %v", err)
	}
	a.Consent.SetOnNew(func(req consent.Request) {
		a.Bus.Publish(Event{Type: "consent.pending", Data: req})
	})

	a.Tracker.Subscribe(func(u flows.Update) {
		a.Bus.Publish(Event{Type: string(u.Kind), Data: u.Flow})
		if u.Kind == flows.UpdateNew {
			a.observeConsent(u.Flow)
		}
	})
	a.Registry.SetOnNew(func(c *store.Client) {
		a.Bus.Publish(Event{Type: "client.new", Data: c})
	})

	// Ad blocking.
	a.Matcher = adblock.New()
	a.Lists = adblock.NewManager(st, a.Matcher, cfg, logf)
	a.Smart = adblock.NewSmartCapture(st, cfg, a.Matcher, a.Lists, logf)
	a.Smart.SetOnBlock(func(domain string, score float64, reason string) {
		a.Bus.Publish(Event{Type: "adblock.auto", Data: map[string]any{
			"domain": domain, "score": score, "reason": reason,
		}})
		_ = st.AddEvent(store.Event{
			ID: uuid.NewString(), TS: time.Now(), Severity: store.SevInfo,
			Category: "adblock", Title: "Auto-blocked " + domain,
			Detail: reason, Data: map[string]any{"score": score},
		})
	})

	// Firewall + VPN.
	a.Firewall = firewall.New(cfg, st, logf)
	a.Tracker.SetEnforcer(a.Firewall)
	a.VPN = vpn.New(cfg, st, logf)
	a.Tailscale = vpn.NewTailscale(cfg, logf)
	a.Egress = vpn.NewEgressManager(logf)
	a.Net = netconf.NewManager(logf)
	a.WAN = netconf.NewWANMonitor(logf)
	a.Topology = topology.NewScanner()
	a.Intercept = intercept.NewManager(logf)
	a.PortMap = portmap.New(func() portmap.Config {
		return cfg.Snapshot().Network.PortMap
	}, logf)

	// Filter proxy.
	ca, err := mitm.LoadOrCreateCA(cfg.MITM.CADir)
	if err != nil {
		logf("mitm: certificate authority unavailable: %v", err)
	} else {
		a.CA = ca
		a.MITM = mitm.New(cfg, ca, logf)
		a.MITM.SetPinStore(pinStore{st})
		a.MITM.OnRequest = func(clientIP netip.Addr, host, path, referer string, respBytes int64) {
			a.Smart.ObserveRequest(host, adblock.ClientKeyFor(clientIP),
				dpi.RefererHost(referer), path, respBytes, "")
		}
	}

	// DNS.
	a.DNS = dnsproxy.New(cfg, st, a.Matcher, dnsproxy.Hooks{
		OnAnswer:     a.Tracker.NoteHostname,
		OnQuery:      a.onDNSQuery,
		ClientFor:    a.clientForAddr,
		PolicyFor:    a.policyByID,
		LocalRecords: a.localRecords,
		Publish: func(q store.DNSQuery) {
			a.Bus.Publish(Event{Type: "dns.query", Data: q})
		},
	}, logf)

	// Encrypted DNS for clients (DoT/DoH), sharing the resolver's policy path.
	a.DNSCrypt = dnsproxy.NewEncrypted(a.DNS, logf)
	a.ReloadRecords()

	// DHCP.
	a.DHCP = dhcp.New(cfg, st, dhcp.Hooks{OnLease: a.onLease}, logf)

	// Native YouTube ad control (Lounge engine): no CA, drives the player on
	// cast-capable devices.
	a.Lounge = lounge.New(cfg, logf)
	if a.MITM != nil {
		// The in-page engine gets its SponsorBlock segments from Orbis, so a
		// browser never talks to the segment database directly.
		a.MITM.SponsorSegments = a.Lounge.Segments
	}

	// Event delivery.
	a.Notifier = notify.New(cfg, logf)
	a.Alerts = alerts.NewEngine(func() []alerts.Rule {
		return a.Cfg.Snapshot().Notify.Rules
	}, a)

	// Capture.
	a.Capture = flows.NewCapturer(a.Tracker, cfg.Capture.SnapLen, cfg.Capture.Interfaces, logf)
	a.Capture.SetHTTPHook(func(clientIP netip.Addr, req *dpi.HTTPRequest) {
		a.Registry.NoteUserAgent(clientIP, req.UserAgent)
		a.Smart.ObserveRequest(req.Host, adblock.ClientKeyFor(clientIP),
			dpi.RefererHost(req.Referer), req.Path, 0, "")
	})
	a.Conntrack = flows.NewConntrackPoller(a.Tracker,
		time.Duration(cfg.Capture.ConntrackInterval)*time.Second,
		func(msg string) { logf("capture: %s", msg) })

	// AI.
	a.AI = ai.NewClient(cfg, st, logf)
	a.Assistant = ai.NewAssistant(cfg, a.AI, a, st, logf)
	a.Analyzer = ai.NewAnalyzer(cfg, a.AI, st, logf)
	a.Briefer = ai.NewBriefer(cfg, a.AI, a, st, a.recordBrief, logf)
	a.Reviewer = ai.NewReviewer(cfg, a.AI, a, st, a.recordBrief, logf)
	a.Smart.SetJudge(ai.NewJudge(a.AI, logf))

	// Problem recorder. Device names are scrubbed from every report, and
	// the diagnostics bundle is the same snapshot the status page shows.
	a.Issues = issues.New(cfg, st, "", a.identifyingNames, a.diagnostics, logf)

	// Per-service usage accounting.
	a.Usage = usage.NewMeter()

	if err := a.reloadPolicies(); err != nil {
		logf("policies: load failed: %v", err)
	}
	return a, nil
}

// Start brings up every enabled subsystem. A subsystem that fails to start is
// reported and skipped rather than aborting the daemon, so a node with (say)
// no permission to bind port 53 still gives the operator a working UI that
// explains the problem.
func (a *App) Start() {
	cfg := a.Cfg.Snapshot()

	// VLANs come first: zones, DHCP scopes and capture all refer to
	// interfaces that have to exist before anything else looks for them.
	if len(cfg.Network.VLANs) > 0 {
		if err := a.SyncVLANs(); err != nil {
			a.log("network: %v", err)
			a.raise(store.SevWarning, "network", "Some VLANs could not be configured", err.Error())
		}
	}

	// Static routes go in before anything that depends on reachability.
	if len(cfg.Network.Routes) > 0 {
		if err := a.Net.ApplyRoutes(a.ctx, cfg.Network.Routes); err != nil {
			a.log("network: static routes: %v", err)
			a.raise(store.SevWarning, "network", "Some static routes could not be installed", err.Error())
		}
	}

	// Multi-WAN probing owns the default route once it is enabled.
	if cfg.Network.MultiWAN.Enabled {
		a.WAN.Start(a.ctx, cfg.Network.MultiWAN)
	}

	// Traffic shaping only makes sense inline: in observe mode this node is
	// not on the forwarding path and shaping its own interface does nothing
	// for the network.
	if cfg.Network.Shaping.Enabled && cfg.Mode == config.ModeInline {
		if st, err := a.Net.ApplyShaping(a.ctx, cfg.Network.Shaping); err != nil {
			a.log("network: shaping: %v", err)
			a.raise(store.SevWarning, "network", "Traffic shaping failed to apply", err.Error())
		} else if st.Detail != "" {
			a.log("network: shaping applied with notes: %s", st.Detail)
		}
	}

	// NAT-PMP hands out inbound port forwards, which only means anything when
	// this node is the gateway doing the NAT.
	if cfg.Network.PortMap.Enabled && cfg.Mode == config.ModeInline {
		if err := a.PortMap.Start(a.ctx); err != nil {
			a.log("portmap: %v", err)
			a.raise(store.SevWarning, "network", "NAT-PMP failed to start", err.Error())
		}
	}

	a.Tracker.Start()
	a.Registry.Start()

	if cfg.Capture.Enabled {
		if err := a.Capture.Start(); err != nil {
			a.log("capture: %v", err)
			a.raise(store.SevWarning, "capture", "Packet capture unavailable", err.Error())
		}
		if cfg.Capture.Conntrack {
			a.wg.Add(1)
			go func() { defer a.wg.Done(); a.Conntrack.Run() }()
		}
	}

	// The blocklist index builds in the background while the resolver
	// starts. On a large list set (1.5M+ entries on a Raspberry Pi) the
	// build takes 15-30 seconds; holding the listener for that long would be
	// a DNS outage for every device on each restart, which is worse than
	// the alternative of answering a few lookups unfiltered. The window is
	// logged so it is visible, and the index is rebuilt from the store, not
	// the network, so it is as short as the disk allows.
	a.wg.Add(1)
	go func() { defer a.wg.Done(); a.Lists.Run(a.ctx) }()

	if cfg.AdBlock.SmartCapture.Enabled {
		a.wg.Add(1)
		go func() { defer a.wg.Done(); a.Smart.Run(a.ctx) }()
	}

	if cfg.DNS.Enabled {
		if err := a.DNS.Start(); err != nil {
			a.log("dns: %v", err)
			a.raise(store.SevWarning, "dns", "DNS resolver failed to start", err.Error())
		}
	}

	if cfg.DNS.Enabled && cfg.DNS.Encrypted.Enabled {
		if err := a.DNSCrypt.Start(); err != nil {
			a.log("dns: encrypted transports: %v", err)
			a.raise(store.SevWarning, "dns", "Encrypted DNS failed to start", err.Error())
		}
	}

	if cfg.DHCP.Enabled {
		if err := a.DHCP.Start(); err != nil {
			a.log("dhcp: %v", err)
			a.raise(store.SevWarning, "dhcp", "DHCP server failed to start", err.Error())
		}
	}

	if cfg.Firewall.Enabled && cfg.Mode == config.ModeInline {
		if err := a.Firewall.Apply(a.ctx); err != nil {
			a.log("firewall: %v", err)
			a.raise(store.SevCritical, "firewall", "Firewall ruleset failed to apply", err.Error())
		}
	}

	if cfg.VPN.Server.Enabled {
		if err := a.VPN.StartServer(a.ctx); err != nil {
			a.log("vpn: %v", err)
			a.raise(store.SevWarning, "vpn", "WireGuard server failed to start", err.Error())
		}
	}
	for _, c := range cfg.VPN.Client {
		if !c.Enabled {
			continue
		}
		if err := a.VPN.StartClient(a.ctx, c.Name); err != nil {
			a.log("vpn: client %s: %v", c.Name, err)
		}
	}

	if cfg.Tailscale.Enabled {
		if err := a.Tailscale.Up(a.ctx); err != nil {
			a.log("tailscale: %v", err)
			a.raise(store.SevWarning, "tailscale", "Tailscale did not come up", err.Error())
		}
		if err := a.Tailscale.ApplySteering(a.ctx); err != nil {
			a.log("tailscale: %v", err)
		}
	}

	if a.MITM != nil && cfg.MITM.Enabled {
		if err := a.MITM.Start(); err != nil {
			a.log("mitm: %v", err)
			a.raise(store.SevWarning, "mitm", "Filter proxy failed to start", err.Error())
		}
	}

	// The Lounge manager always runs so the UI can discover and pair devices;
	// it starts controllers only when the feature is enabled.
	a.Lounge.Start(a.ctx)

	if cfg.AI.Enabled && cfg.AI.Anomaly.Enabled {
		a.wg.Add(1)
		go func() { defer a.wg.Done(); a.Analyzer.Run(a.ctx) }()
	}
	// The model router and the brief writer always run: both read the
	// configuration on every tick, so turning the assistant on from the UI
	// takes effect without a restart.
	a.wg.Add(3)
	go func() { defer a.wg.Done(); a.AI.Router().Run(a.ctx) }()
	go func() { defer a.wg.Done(); a.Briefer.Run(a.ctx) }()
	go func() { defer a.wg.Done(); a.Reviewer.Run(a.ctx) }()

	// Installing a GeoIP database should fix the history too, not just new
	// traffic, so reconcile stored rows once at startup.
	if cfg.GeoIP.CityDB != "" || cfg.GeoIP.ASNDB != "" {
		a.wg.Add(1)
		go func() {
			defer a.wg.Done()
			select {
			case <-a.ctx.Done():
				return
			case <-time.After(15 * time.Second):
			}
			if _, err := a.BackfillGeo(a.ctx, 20000); err != nil && a.ctx.Err() == nil {
				a.log("geoip: backfill failed: %v", err)
			}
		}()
	}

	if cfg.Node.LocatePublicIP {
		a.wg.Add(1)
		go func() { defer a.wg.Done(); a.Self.Run(a.ctx) }()
	}

	// Tunnel traffic makes this node a gateway for that traffic whatever the
	// mode says about the LAN, so the tunnel rules go in either way.
	a.SyncTunnelRules()

	// Outbound tunnels and the device routing that depends on them.
	if len(cfg.VPN.Tunnels) > 0 || len(cfg.VPN.Routes) > 0 {
		if err := a.SyncEgress(a.ctx); err != nil {
			a.log("vpn: outbound routing: %v", err)
			a.raise(store.SevWarning, "vpn", "Outbound VPN routing is incomplete", err.Error())
		}
	}

	// ARP interception, if any devices are enrolled. It is independent of
	// inline/observe mode: it is how a node that is NOT the gateway still gets
	// selected devices' traffic.
	if cfg.Network.Intercept.Enabled && len(cfg.Network.Intercept.Clients) > 0 {
		if err := a.SyncIntercept(); err != nil {
			a.log("intercept: %v", err)
			a.raise(store.SevWarning, "intercept", "ARP interception failed to start", err.Error())
		}
	}

	a.wg.Add(1)
	go func() { defer a.wg.Done(); a.maintenanceLoop() }()

	a.log("orbis: started in %s mode", cfg.Mode)
}

func (a *App) Stop() {
	a.log("orbis: shutting down")
	a.stop()
	if a.MITM != nil {
		a.MITM.Stop()
	}
	if a.Lounge != nil {
		a.Lounge.Stop()
	}
	a.DNS.Stop()
	if a.WAN != nil {
		a.WAN.Stop()
	}
	if a.PortMap != nil {
		a.PortMap.Stop()
	}
	if a.Intercept != nil {
		a.Intercept.Stop()
	}
	if a.DNSCrypt != nil {
		a.DNSCrypt.Stop()
	}
	a.DHCP.Stop()
	a.Capture.Stop()
	a.Conntrack.Stop()
	a.Tracker.Stop()
	a.Registry.Stop()
	a.wg.Wait()
	a.Bus.Close()
	a.Geo.Close()
	_ = a.Store.Close()
}

func (a *App) Uptime() time.Duration { return time.Since(a.startedAt) }

// maintenanceLoop handles the periodic housekeeping: retention pruning,
// counter sync, per-minute stats, and VPN handshake refresh.
func (a *App) maintenanceLoop() {
	stats := time.NewTicker(time.Minute)
	counters := time.NewTicker(30 * time.Second)
	prune := time.NewTicker(6 * time.Hour)
	defer stats.Stop()
	defer counters.Stop()
	defer prune.Stop()

	// History that predates the rollups gets folded in once, in the
	// background, so the Services page has a week of numbers on day one.
	if a.Store.ServiceStatsEmpty() {
		a.wg.Add(1)
		go func() { defer a.wg.Done(); a.backfillUsage() }()
	}

	for {
		select {
		case <-a.ctx.Done():
			return

		case <-stats.C:
			a.recordStats()
			a.flushUsage()
			for _, f := range a.Alerts.Evaluate(time.Now()) {
				a.raise(f.Severity, "alert", f.Title, f.Detail)
			}
			a.maybeSendReport(time.Now())

		case <-counters.C:
			if c, err := a.Firewall.Counters(a.ctx); err == nil && len(c) > 0 {
				_ = a.Store.UpdateRuleCounters(c)
			}
			if a.VPN.ServerUp() {
				_ = a.VPN.SyncStats()
			}

		case <-prune.C:
			cfg := a.Cfg.Snapshot()
			if err := a.Store.Prune(a.ctx, cfg.Store.FlowRetentionDays, cfg.Store.EventRetentionDays); err != nil {
				a.log("store: prune failed: %v", err)
			}
			_ = a.Store.PruneAIUsage(45)
			_ = a.Store.PruneServiceStats(90)
		}
	}
}

// flushUsage samples the live flow table and lands the minute's deltas.
func (a *App) flushUsage() {
	if a.Usage == nil || a.Tracker == nil {
		return
	}
	a.Usage.Sample(a.Tracker.Active(0))
	rows := a.Usage.Drain()
	if len(rows) == 0 {
		return
	}
	stats := make([]store.ServiceStat, 0, len(rows))
	for _, r := range rows {
		stats = append(stats, store.ServiceStat{
			Bucket: r.Bucket, ClientID: r.ClientID, Service: r.Service, Category: r.Category,
			Conns: r.Conns, BytesIn: r.BytesIn, BytesOut: r.BytesOut, Lookups: r.Lookups, Blocked: r.Blocked,
		})
	}
	if err := a.Store.AddServiceStats(stats); err != nil {
		a.log("usage: flush failed: %v", err)
	}
}

// backfillUsage folds the last week of flows and lookups into rollups. A
// flow's whole volume lands in the hour it started, which is an approximation
// the live accounting does not make; it is only ever run on a node that has
// no rollups at all.
func (a *App) backfillUsage() {
	select {
	case <-a.ctx.Done():
		return
	case <-time.After(90 * time.Second):
	}
	since := time.Now().Add(-7 * 24 * time.Hour)
	flows, err := a.Store.FlowsForBackfill(since, 400000)
	if err != nil {
		a.log("usage: backfill flows: %v", err)
		return
	}
	queries, err := a.Store.DNSLog(since, "", false, "", 300000)
	if err != nil {
		a.log("usage: backfill lookups: %v", err)
		return
	}
	clientOf := func(ip string) string {
		if addr, err := netip.ParseAddr(ip); err == nil {
			if c := a.Registry.ByIP(addr); c != nil {
				return c.ID
			}
		}
		return "ip:" + ip
	}
	rows := usage.Backfill(flows, queries, clientOf)
	stats := make([]store.ServiceStat, 0, len(rows))
	for _, r := range rows {
		stats = append(stats, store.ServiceStat{
			Bucket: r.Bucket, ClientID: r.ClientID, Service: r.Service, Category: r.Category,
			Conns: r.Conns, BytesIn: r.BytesIn, BytesOut: r.BytesOut, Lookups: r.Lookups, Blocked: r.Blocked,
		})
	}
	// In slices, so one huge transaction does not hold the writer for long.
	for i := 0; i < len(stats); i += 2000 {
		end := i + 2000
		if end > len(stats) {
			end = len(stats)
		}
		if err := a.Store.AddServiceStats(stats[i:end]); err != nil {
			a.log("usage: backfill write: %v", err)
			return
		}
	}
	a.log("usage: backfilled %d rollup rows from %d flows and %d lookups (7 days)", len(stats), len(flows), len(queries))
}

// SyncTunnelRules installs, updates or removes the tunnel gateway ruleset to
// match the current configuration. Called at startup and whenever a VPN or
// Tailscale setting changes.
func (a *App) SyncTunnelRules() {
	cfg := a.Cfg.Snapshot()
	tc := firewall.BuildTunnelConfig(cfg)

	if tc.Active() {
		// Routing anything requires forwarding; enabling it here rather than
		// leaving it to the operator is the difference between the VPN
		// working and appearing to connect but moving nothing.
		if err := enableForwarding(tc.IPv6); err != nil {
			a.log("firewall: could not enable IP forwarding (%v) — tunnel clients will connect but reach nothing", err)
			a.raise(store.SevWarning, "vpn", "IP forwarding is off",
				"Tunnel clients can connect but cannot reach anything through this node. "+
					"On a container, set net.ipv4.ip_forward=1 on the host.")
		}
	}

	if err := a.Firewall.ApplyTunnel(a.ctx, tc); err != nil {
		a.log("firewall: tunnel rules: %v", err)
		return
	}
	if tc.Active() {
		// Tunnel interfaces carry real client traffic, so they belong in the
		// capture set; otherwise a VPN client's connections never appear.
		a.Capture.AddInterfaces(tc.Interfaces)
		a.Tracker.SetLocalNets(append(flows.LocalPrefixes(), tc.Subnets...))
	}
}

// enableForwarding turns on routing. It is idempotent and reports the failure
// rather than hiding it, because in an unprivileged container this is owned
// by the host and the operator needs to know.
func enableForwarding(ipv6 bool) error {
	if err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0o644); err != nil {
		return err
	}
	if ipv6 {
		// A v6 failure is not fatal: plenty of networks are v4-only.
		_ = os.WriteFile("/proc/sys/net/ipv6/conf/all/forwarding", []byte("1"), 0o644)
	}
	return nil
}

func (a *App) recordStats() {
	now := time.Now()
	trackerStats := a.Tracker.Stats()
	_ = a.Store.RecordStat("flows_active", float64(trackerStats.Active), now)

	dnsStats := a.DNS.Stats()
	if q, ok := dnsStats["queries"].(int64); ok {
		_ = a.Store.RecordStat("dns_queries_total", float64(q), now)
	}
	if bl, ok := dnsStats["blocked"].(int64); ok {
		_ = a.Store.RecordStat("dns_blocked_total", float64(bl), now)
	}

	var rateIn, rateOut float64
	for _, r := range a.Tracker.ClientRates() {
		rateIn += r[0]
		rateOut += r[1]
	}
	_ = a.Store.RecordStat("throughput_in", rateIn, now)
	_ = a.Store.RecordStat("throughput_out", rateOut, now)

	a.Bus.Publish(Event{Type: "stats.tick", Data: map[string]any{
		"t": now.Unix(), "flows_active": trackerStats.Active,
		"rate_in": rateIn, "rate_out": rateOut,
	}})
}

func (a *App) raise(severity, category, title, detail string) {
	ev := store.Event{
		ID: uuid.NewString(), TS: time.Now(), Severity: severity,
		Category: category, Title: title, Detail: detail,
	}
	_ = a.Store.AddEvent(ev)
	if a.Notifier != nil {
		a.Notifier.Send(ev)
	}
	a.Bus.Publish(Event{Type: "event.new", Data: map[string]any{
		"severity": severity, "category": category, "title": title, "detail": detail,
	}})
	// Warnings and worse are also problems worth recording, scrubbed, so
	// they can be reported and fixed rather than scrolling past in Events.
	// Detector findings, alert rules and operator to-dos (a Tailscale login
	// waiting, a missing binary) are not defects and stay out.
	if a.Issues != nil && a.Cfg.Snapshot().Issues.AutoCapture &&
		store.SeverityRank(severity) >= store.SeverityRank(store.SevWarning) &&
		!strings.HasPrefix(category, "anomaly:") && category != "alert" && !operatorActionable(title, detail) {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			_, _ = a.Issues.Record(ctx, issues.Input{
				Severity: severity, Category: category, Title: title, Detail: detail, Source: "auto",
			})
		}()
	}
}

// operatorActionable recognises warnings that ask the operator to do
// something rather than describe software misbehaving. Recording them as
// problems, or worse filing them upstream, would only add noise.
func operatorActionable(title, detail string) bool {
	hay := strings.ToLower(title + " " + detail)
	for _, marker := range []string{
		"needs to be authenticated", "did not come up", "not installed", "log in at",
		"no api key", "is disabled", "set an api key", "not configured", "permission denied",
		"address already in use", "on the host, for a container",
	} {
		if strings.Contains(hay, marker) {
			return true
		}
	}
	return false
}

// identifyingNames lists the strings that would identify this network in a
// report: device labels and hostnames, and the node's own name.
func (a *App) identifyingNames() []string {
	var out []string
	if a.Registry != nil {
		for _, c := range a.Registry.All() {
			if c.Label != "" {
				out = append(out, c.Label)
			}
			if c.Hostname != "" {
				out = append(out, c.Hostname)
			}
		}
	}
	if n := a.Cfg.Snapshot().Node.Name; n != "" {
		out = append(out, n)
	}
	return out
}

// diagnostics is the snapshot attached to problem reports. It describes the
// node, not the network: versions, mode, which subsystems are up, counts, and
// the recent log lines. The recorder scrubs it again before it is stored.
func (a *App) diagnostics() map[string]any {
	cfg := a.Cfg.Snapshot()
	out := map[string]any{
		"version":  orDefaultStr(a.build, "dev"),
		"platform": runtime.GOOS + "/" + runtime.GOARCH,
		"go":       runtime.Version(),
		"mode":     string(cfg.Mode),
		"uptime_s": int(a.Uptime().Seconds()),
		"subsystems": map[string]any{
			"dns": cfg.DNS.Enabled, "dns_encrypted": cfg.DNS.Encrypted.Enabled, "adblock": cfg.AdBlock.Enabled,
			"smart_capture": cfg.AdBlock.SmartCapture.Enabled, "filter_proxy": cfg.MITM.Enabled,
			"firewall": cfg.Firewall.Enabled, "dhcp": cfg.DHCP.Enabled, "vpn_server": cfg.VPN.Server.Enabled,
			"tailscale": cfg.Tailscale.Enabled, "intercept": cfg.Network.Intercept.Enabled,
			"lounge": cfg.YouTube.Lounge.Enabled, "ai": cfg.AI.Enabled, "ai_provider": cfg.AI.Provider,
		},
		"blocklists": len(cfg.AdBlock.Lists),
	}
	if raw, err := os.ReadFile("/proc/version"); err == nil {
		out["kernel"] = strings.TrimSpace(string(raw))
	}
	if a.Matcher != nil {
		out["index_entries"] = a.Matcher.Count()
	}
	if a.Registry != nil {
		out["devices"] = len(a.Registry.All())
	}
	if a.Tracker != nil {
		ts := a.Tracker.Stats()
		out["flows_active"] = ts.Active
		out["flows_total"] = ts.Total
	}
	if a.Capture != nil {
		cs := a.Capture.Stats()
		out["capture"] = map[string]any{"interfaces": cs.Interfaces, "kernel_drops": cs.KernelDrops, "parse_errors": cs.ParseErrors}
	}
	if a.DNS != nil {
		out["dns_running"] = a.DNS.Running()
	}
	if a.logRing != nil {
		out["recent_log"] = a.logRing.tail(40)
	}
	return out
}

// logRing keeps recent log lines in memory for diagnostics bundles.
type logRing struct {
	mu    sync.Mutex
	lines []string
	max   int
}

func newLogRing(max int) *logRing { return &logRing{max: max} }

func (r *logRing) add(line string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lines = append(r.lines, time.Now().Format("15:04:05")+" "+line)
	if len(r.lines) > r.max {
		r.lines = r.lines[len(r.lines)-r.max:]
	}
}

func (r *logRing) tail(n int) []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if n > len(r.lines) {
		n = len(r.lines)
	}
	out := make([]string, n)
	copy(out, r.lines[len(r.lines)-n:])
	return out
}

func orDefaultStr(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

// ---- hooks ----

func (a *App) onDNSQuery(clientIP netip.Addr, name string, blocked bool) {
	if a.Usage != nil {
		clientID, _ := a.clientForAddr(clientIP)
		if clientID == "" {
			clientID = "ip:" + clientIP.String()
		}
		a.Usage.NoteDNS(clientID, name, blocked)
	}
	if blocked {
		return
	}
	// Feeding every allowed lookup into smart capture is what lets it notice
	// a new ad host the first day it appears, before any list ships it.
	a.Smart.ObserveRequest(name, adblock.ClientKeyFor(clientIP), "", "", 0, "")
}

func (a *App) clientForAddr(addr netip.Addr) (clientID, policyID string) {
	c := a.Registry.ByIP(addr)
	if c == nil {
		// An address we have never seen still deserves a stable identity, so
		// its queries are attributable in the log.
		c = a.Registry.Observe(addr, "", "")
	}
	if c == nil {
		return "", ""
	}
	return c.ID, c.PolicyID
}

func (a *App) policyByID(id string) *store.Policy {
	a.policyMu.RLock()
	defer a.policyMu.RUnlock()
	return a.policies[id]
}

func (a *App) reloadPolicies() error {
	list, err := a.Store.Policies()
	if err != nil {
		return err
	}
	m := make(map[string]*store.Policy, len(list))
	for i := range list {
		m[list[i].ID] = &list[i]
	}
	a.policyMu.Lock()
	a.policies = m
	a.policyMu.Unlock()
	return nil
}

func (a *App) onLease(lease store.Lease, fingerprint, vendorClass string) {
	addr, err := netip.ParseAddr(lease.IP)
	if err != nil {
		return
	}
	a.Registry.NoteDHCP(addr, lease.MAC, lease.Hostname, vendorClass, fingerprint)
	a.Bus.Publish(Event{Type: "dhcp.lease", Data: lease})
}

// localRecords answers A/AAAA/PTR for names from the DHCP lease table, so
// devices resolve each other by hostname without any extra configuration.
func (a *App) localRecords(qname string, qtype uint16) []dns.RR {
	cfg := a.Cfg.Snapshot()

	// Operator-defined records win over everything: they are an explicit
	// instruction, and are checked before the DHCP-derived names below.
	a.recordsMu.RLock()
	rs := a.records
	a.recordsMu.RUnlock()
	if rs != nil {
		if rrs := rs.Lookup(qname, qtype); len(rrs) > 0 {
			return rrs
		}
	}

	domain := strings.ToLower(cfg.DNS.LocalDomain)
	name := strings.ToLower(strings.TrimSuffix(qname, "."))

	if qtype == dns.TypePTR {
		return a.reversePTR(name, domain)
	}
	if qtype != dns.TypeA && qtype != dns.TypeAAAA {
		return nil
	}

	host := name
	if domain != "" {
		if !strings.HasSuffix(name, "."+domain) {
			// A bare single-label name is still worth answering locally.
			if strings.Contains(name, ".") {
				return nil
			}
		} else {
			host = strings.TrimSuffix(name, "."+domain)
		}
	}
	if host == "" {
		return nil
	}

	for _, l := range a.DHCP.Leases() {
		if !strings.EqualFold(l.Hostname, host) {
			continue
		}
		addr, err := netip.ParseAddr(l.IP)
		if err != nil {
			continue
		}
		if qtype == dns.TypeA && addr.Is4() {
			return []dns.RR{&dns.A{
				Hdr: dns.RR_Header{Name: qname, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   addr.AsSlice(),
			}}
		}
		if qtype == dns.TypeAAAA && addr.Is6() {
			return []dns.RR{&dns.AAAA{
				Hdr:  dns.RR_Header{Name: qname, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60},
				AAAA: addr.AsSlice(),
			}}
		}
	}
	return nil
}

func (a *App) reversePTR(name, domain string) []dns.RR {
	if !strings.HasSuffix(name, ".in-addr.arpa") {
		return nil
	}
	labels := strings.Split(strings.TrimSuffix(name, ".in-addr.arpa"), ".")
	if len(labels) != 4 {
		return nil
	}
	// in-addr.arpa reverses the octets.
	ip := fmt.Sprintf("%s.%s.%s.%s", labels[3], labels[2], labels[1], labels[0])
	for _, l := range a.DHCP.Leases() {
		if l.IP != ip || l.Hostname == "" {
			continue
		}
		target := l.Hostname
		if domain != "" {
			target = l.Hostname + "." + domain
		}
		return []dns.RR{&dns.PTR{
			Hdr: dns.RR_Header{Name: name + ".", Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: 60},
			Ptr: dns.Fqdn(target),
		}}
	}
	return nil
}

// pinStore adapts the store to the proxy's persistence interface.
type pinStore struct{ st *store.Store }

func (p pinStore) SavePinBypass(client, name string, until time.Time) error {
	return p.st.SavePinBypass(client, name, until)
}

func (p pinStore) PinBypasses() ([]mitm.Bypass, error) {
	rows, err := p.st.PinBypasses()
	if err != nil {
		return nil, err
	}
	out := make([]mitm.Bypass, 0, len(rows))
	for _, r := range rows {
		out = append(out, mitm.Bypass{Client: r.Client, Name: r.Name, Until: r.Until, Fails: r.Fails})
	}
	return out, nil
}
