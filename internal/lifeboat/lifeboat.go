// Package lifeboat is what runs when Orbis cannot: a resolver that forwards
// without filtering, a DHCP server that keeps every device on the address it
// already has, forwarding and NAT for a gateway, and the ARP truth for
// intercepted devices. It reads the configuration if it can and falls back
// to safe defaults if it cannot; it opens no database, loads no list and
// talks to no model, because any of those may be the reason Orbis is down.
package lifeboat

import (
	"context"
	"encoding/json"
	"fmt"
	"html"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/Neoo-Blue/orbis/internal/config"
	"github.com/Neoo-Blue/orbis/internal/dhcp"
	"github.com/Neoo-Blue/orbis/internal/dnsproxy"
	"github.com/Neoo-Blue/orbis/internal/intercept"
	"github.com/Neoo-Blue/orbis/internal/safety"
	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv4/server4"
	"github.com/miekg/dns"
)

// Options steer a run.
type Options struct {
	Config     *config.Config // nil when it could not be loaded
	ConfigErr  error
	DataDir    string
	Version    string
	Log        func(string, ...any)
	NoRetry    bool // tests
	RetryStart time.Duration
}

// Lifeboat is one run.
type Lifeboat struct {
	opt       Options
	cfg       config.Config
	log       func(string, ...any)
	upstreams []*dnsproxy.Upstream
	fallbacks []*dnsproxy.Upstream

	mu       sync.Mutex
	episode  safety.Episode
	answered int64
	failed   int64
	leases   map[string]lease // mac -> lease
	byIP     map[netip.Addr]string
	dnsSrv   []*dns.Server
	dhcpSrv  []*server4.Server
	httpSrv  *http.Server
	natTable bool
	retryAt  time.Time
}

type lease struct {
	ip      netip.Addr
	expires time.Time
}

const leaseTime = time.Hour

// Run serves until ctx ends.
func Run(ctx context.Context, opt Options) error {
	if opt.Log == nil {
		opt.Log = func(string, ...any) {}
	}
	l := &Lifeboat{opt: opt, log: opt.Log, leases: map[string]lease{}, byIP: map[netip.Addr]string{}}
	if opt.Config != nil {
		l.cfg = opt.Config.Snapshot()
	} else {
		l.cfg = config.Default().Snapshot()
	}
	l.upstreams, l.fallbacks = l.resolvers()
	l.episode = safety.Episode{Started: time.Now(), LastSeen: time.Now(), Reason: l.reason()}
	if prev := safety.ReadEpisode(opt.DataDir); prev != nil && time.Since(prev.LastSeen) < 10*time.Minute {
		// A lifeboat restarting keeps counting the same episode.
		l.episode = *prev
		l.episode.LastSeen = time.Now()
	}
	l.writeEpisode()
	l.log("lifeboat: starting (%s); Orbis itself is down", l.episode.Reason)

	// Devices first: an intercepted device pointed at a dead node has no
	// internet at all until it hears the real gateway's address.
	if n, err := intercept.RestoreFromMarker(ctx, safety.MarkerPath(opt.DataDir), l.log); err != nil {
		l.log("lifeboat: could not restore intercepted devices: %v", err)
	} else if n > 0 {
		l.log("lifeboat: %d intercepted device(s) put back on the real gateway", n)
	}

	if err := l.startDNS(); err != nil {
		l.log("lifeboat: DNS: %v", err)
	}
	l.startDHCP()
	l.ensureForwarding(ctx)
	l.startStatusPage()

	retry := opt.RetryStart
	if retry <= 0 {
		retry = 3 * time.Minute
	}
	tick := time.NewTicker(15 * time.Second)
	defer tick.Stop()
	l.mu.Lock()
	l.retryAt = time.Now().Add(retry)
	l.mu.Unlock()
	for {
		select {
		case <-ctx.Done():
			l.shutdown()
			return nil
		case <-tick.C:
			l.mu.Lock()
			l.episode.LastSeen = time.Now()
			due := !opt.NoRetry && time.Now().After(l.retryAt)
			l.mu.Unlock()
			l.writeEpisode()
			if due {
				l.mu.Lock()
				l.episode.Retries++
				// Back off: 3, 6, 12, 24, 30, 30 minutes. A service that keeps
				// dying on start should not take the network down with it
				// every few minutes.
				retry = retry * 2
				if retry > 30*time.Minute {
					retry = 30 * time.Minute
				}
				l.retryAt = time.Now().Add(retry)
				l.mu.Unlock()
				l.writeEpisode()
				l.log("lifeboat: asking systemd to start Orbis again (attempt %d)", l.episode.Retries)
				if err := safety.Retry(ctx); err != nil {
					l.log("lifeboat: retry: %v", err)
				}
			}
		}
	}
}

func (l *Lifeboat) reason() string {
	if l.opt.ConfigErr != nil {
		return "configuration could not be read: " + l.opt.ConfigErr.Error()
	}
	st := safety.ServiceStatus(context.Background(), "orbis.service", 3)
	for _, line := range strings.Split(st, "\n") {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "Active:") {
			return t
		}
	}
	return "orbis.service failed"
}

func (l *Lifeboat) writeEpisode() {
	if l.opt.DataDir == "" {
		return
	}
	l.mu.Lock()
	b, _ := json.Marshal(l.episode)
	l.mu.Unlock()
	_ = os.WriteFile(safety.EpisodePath(l.opt.DataDir), b, 0o644)
}

// resolvers picks upstreams: the configured ones, then public fallbacks that
// need no certificate or DNS of their own to reach.
func (l *Lifeboat) resolvers() (ups, fallbacks []*dnsproxy.Upstream) {
	for _, spec := range l.cfg.DNS.Upstreams {
		u, err := dnsproxy.ParseUpstream(spec)
		if err != nil {
			continue
		}
		ups = append(ups, u)
	}
	for _, spec := range []string{"1.1.1.1:53", "8.8.8.8:53", "9.9.9.9:53"} {
		if u, err := dnsproxy.ParseUpstream(spec); err == nil {
			fallbacks = append(fallbacks, u)
		}
	}
	return ups, fallbacks
}

func (l *Lifeboat) startDNS() error {
	listen := l.cfg.DNS.Listen
	if len(listen) == 0 || !l.cfg.DNS.Enabled {
		listen = []string{":53"}
	}
	handler := dns.HandlerFunc(l.serveDNS)
	var errs []string
	for _, addr := range listen {
		for _, netw := range []string{"udp", "tcp"} {
			srv := &dns.Server{Addr: addr, Net: netw, Handler: handler, ReusePort: true}
			go func(s *dns.Server) {
				if err := s.ListenAndServe(); err != nil {
					l.log("lifeboat: DNS %s %s: %v", s.Net, s.Addr, err)
				}
			}(srv)
			l.dnsSrv = append(l.dnsSrv, srv)
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	l.log("lifeboat: forwarding DNS on %s to %d upstream(s) without filtering", strings.Join(listen, ", "), len(l.upstreams))
	return nil
}

// serveDNS forwards to the configured upstreams and then to the public
// fallbacks. No cache, no filtering, no local records: the point is to answer.
func (l *Lifeboat) serveDNS(w dns.ResponseWriter, req *dns.Msg) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, group := range [][]*dnsproxy.Upstream{l.upstreams, l.fallbacks} {
		for _, u := range group {
			resp, err := u.Exchange(ctx, req)
			if err != nil || resp == nil {
				continue
			}
			resp.Id = req.Id
			l.mu.Lock()
			l.answered++
			l.mu.Unlock()
			_ = w.WriteMsg(resp)
			return
		}
	}
	l.mu.Lock()
	l.failed++
	l.mu.Unlock()
	m := new(dns.Msg)
	m.SetRcode(req, dns.RcodeServerFailure)
	_ = w.WriteMsg(m)
}

// startDHCP serves the configured scopes permissively: a device asking for
// the address it already has keeps it, a new device gets one from the top
// of the range that nothing answers on. Leases are an hour so the real
// server takes over cleanly when it is back.
func (l *Lifeboat) startDHCP() {
	if l.cfg.Mode != config.ModeInline || !l.cfg.DHCP.Enabled {
		return
	}
	for _, scope := range l.cfg.DHCP.Scopes {
		if scope.Interface == "" {
			continue
		}
		iface, err := net.InterfaceByName(scope.Interface)
		if err != nil {
			l.log("lifeboat: DHCP scope %q: %v", scope.Name, err)
			continue
		}
		sc := scope
		srv, err := server4.NewServer(iface.Name, &net.UDPAddr{IP: net.IPv4zero, Port: dhcpv4.ServerPort}, l.dhcpHandler(sc))
		if err != nil {
			l.log("lifeboat: DHCP on %s: %v", scope.Interface, err)
			continue
		}
		go func() {
			if err := srv.Serve(); err != nil {
				l.log("lifeboat: DHCP %s stopped: %v", sc.Name, err)
			}
		}()
		l.dhcpSrv = append(l.dhcpSrv, srv)
		l.log("lifeboat: DHCP serving scope %q on %s (%s-%s), one-hour leases", scope.Name, scope.Interface, scope.RangeStart, scope.RangeEnd)
	}
}

func (l *Lifeboat) dhcpHandler(scope config.DHCPScope) server4.Handler {
	statics := map[string]netip.Addr{}
	for _, st := range l.cfg.DHCP.Static {
		if ip, err := netip.ParseAddr(st.IP); err == nil {
			statics[strings.ToLower(st.MAC)] = ip
		}
	}
	return func(conn net.PacketConn, peer net.Addr, req *dhcpv4.DHCPv4) {
		if req == nil || req.OpCode != dhcpv4.OpcodeBootRequest {
			return
		}
		defer func() { _ = recover() }()
		mac := strings.ToLower(req.ClientHWAddr.String())
		var reply *dhcpv4.DHCPv4
		switch req.MessageType() {
		case dhcpv4.MessageTypeDiscover:
			ip, ok := l.pick(scope, mac, statics, requestedIP(req))
			if !ok {
				return
			}
			reply = l.reply(req, dhcpv4.MessageTypeOffer, ip, scope)
		case dhcpv4.MessageTypeRequest:
			want := requestedIP(req)
			if !want.IsValid() {
				if a, ok := netip.AddrFromSlice(req.ClientIPAddr.To4()); ok && !a.IsUnspecified() {
					want = a
				}
			}
			if st, ok := statics[mac]; ok {
				want = st
			}
			if !want.IsValid() || !inSubnet(scope, want) || l.reserved(scope, want) || l.takenByOther(want, mac) {
				nak := l.reply(req, dhcpv4.MessageTypeNak, netip.Addr{}, scope)
				_, _ = conn.WriteTo(nak.ToBytes(), peer)
				return
			}
			l.grant(mac, want)
			reply = l.reply(req, dhcpv4.MessageTypeAck, want, scope)
		case dhcpv4.MessageTypeRelease, dhcpv4.MessageTypeDecline:
			l.mu.Lock()
			if ls, ok := l.leases[mac]; ok {
				delete(l.byIP, ls.ip)
				delete(l.leases, mac)
			}
			l.mu.Unlock()
			return
		default:
			return
		}
		dst := peer
		if req.GatewayIPAddr == nil || req.GatewayIPAddr.IsUnspecified() {
			dst = &net.UDPAddr{IP: net.IPv4bcast, Port: dhcpv4.ClientPort}
		}
		_, _ = conn.WriteTo(reply.ToBytes(), dst)
	}
}

func requestedIP(req *dhcpv4.DHCPv4) netip.Addr {
	if ip := req.RequestedIPAddress(); ip != nil {
		if a, ok := netip.AddrFromSlice(ip.To4()); ok {
			return a
		}
	}
	return netip.Addr{}
}

func inSubnet(scope config.DHCPScope, ip netip.Addr) bool {
	p, err := netip.ParsePrefix(scope.Subnet)
	if err != nil {
		return false
	}
	return p.Contains(ip)
}

// reserved is what a device must never be handed: the gateway, this node's
// own address on the interface, and the network and broadcast addresses.
func (l *Lifeboat) reserved(scope config.DHCPScope, ip netip.Addr) bool {
	if gw, err := netip.ParseAddr(scope.Gateway); err == nil && gw == ip {
		return true
	}
	p, err := netip.ParsePrefix(scope.Subnet)
	if err == nil {
		if ip == p.Masked().Addr() {
			return true
		}
		if bc, ok := broadcast(p); ok && ip == bc {
			return true
		}
	}
	if iface, err := net.InterfaceByName(scope.Interface); err == nil {
		addrs, _ := iface.Addrs()
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok {
				if x, ok := netip.AddrFromSlice(n.IP.To4()); ok && x == ip {
					return true
				}
			}
		}
	}
	return false
}

func broadcast(p netip.Prefix) (netip.Addr, bool) {
	if !p.Addr().Is4() {
		return netip.Addr{}, false
	}
	a := p.Masked().Addr().As4()
	bits := p.Bits()
	for i := bits; i < 32; i++ {
		a[i/8] |= 1 << (7 - uint(i%8))
	}
	return netip.AddrFrom4(a), true
}

func (l *Lifeboat) takenByOther(ip netip.Addr, mac string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	owner, ok := l.byIP[ip]
	if !ok {
		return false
	}
	if owner == mac {
		return false
	}
	if ls, ok := l.leases[owner]; ok && time.Now().After(ls.expires) {
		delete(l.leases, owner)
		delete(l.byIP, ip)
		return false
	}
	return true
}

func (l *Lifeboat) grant(mac string, ip netip.Addr) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if old, ok := l.leases[mac]; ok && old.ip != ip {
		delete(l.byIP, old.ip)
	}
	l.leases[mac] = lease{ip: ip, expires: time.Now().Add(leaseTime)}
	l.byIP[ip] = mac
}

// pick chooses an address for a discovering device: its static mapping, the
// one it asks for if free, its previous lease, or a free one from the top
// of the range downward, skipping anything that answers ARP. The main
// server allocates from the bottom, so the two rarely collide even before
// the probe.
func (l *Lifeboat) pick(scope config.DHCPScope, mac string, statics map[string]netip.Addr, wanted netip.Addr) (netip.Addr, bool) {
	if st, ok := statics[mac]; ok {
		return st, true
	}
	l.mu.Lock()
	if ls, ok := l.leases[mac]; ok {
		l.mu.Unlock()
		return ls.ip, true
	}
	l.mu.Unlock()
	if wanted.IsValid() && inSubnet(scope, wanted) && !l.reserved(scope, wanted) && !l.takenByOther(wanted, mac) && !answers(wanted) {
		return wanted, true
	}
	start, err1 := netip.ParseAddr(scope.RangeStart)
	end, err2 := netip.ParseAddr(scope.RangeEnd)
	if err1 != nil || err2 != nil || start.Compare(end) > 0 {
		return netip.Addr{}, false
	}
	for ip := end; ip.Compare(start) >= 0; ip = ip.Prev() {
		if l.reserved(scope, ip) || l.takenByOther(ip, mac) || answers(ip) {
			continue
		}
		return ip, true
	}
	return netip.Addr{}, false
}

// answers reports whether something already uses the address: a datagram
// nudges the kernel into ARP, and the neighbour table says what it found.
func answers(ip netip.Addr) bool {
	if conn, err := net.Dial("udp", net.JoinHostPort(ip.String(), "9")); err == nil {
		_, _ = conn.Write([]byte{0})
		conn.Close()
	}
	time.Sleep(120 * time.Millisecond)
	out, err := exec.Command("ip", "-4", "neigh", "show", ip.String()).Output()
	if err != nil {
		return false
	}
	s := string(out)
	return strings.Contains(s, "lladdr") && !strings.Contains(s, "FAILED") && !strings.Contains(s, "INCOMPLETE")
}

func (l *Lifeboat) reply(req *dhcpv4.DHCPv4, mt dhcpv4.MessageType, ip netip.Addr, scope config.DHCPScope) *dhcpv4.DHCPv4 {
	reply, err := dhcpv4.NewReplyFromRequest(req)
	if err != nil {
		return nil
	}
	reply.UpdateOption(dhcpv4.OptMessageType(mt))
	gw := net.ParseIP(scope.Gateway)
	if gw != nil {
		reply.ServerIPAddr = gw
		reply.UpdateOption(dhcpv4.OptServerIdentifier(gw))
	}
	if mt == dhcpv4.MessageTypeNak {
		return reply
	}
	reply.YourIPAddr = ip.AsSlice()
	if _, ipnet, err := net.ParseCIDR(scope.Subnet); err == nil {
		reply.UpdateOption(dhcpv4.OptSubnetMask(ipnet.Mask))
	}
	if gw != nil {
		reply.UpdateOption(dhcpv4.OptRouter(gw))
	}
	var dnsIPs []net.IP
	for _, d := range scope.DNS {
		if x := net.ParseIP(d); x != nil {
			dnsIPs = append(dnsIPs, x)
		}
	}
	if fb := dhcp.FallbackDNS(l.cfg); fb != nil {
		dnsIPs = append(dnsIPs, fb)
	}
	if len(dnsIPs) > 0 {
		reply.UpdateOption(dhcpv4.OptDNS(dnsIPs...))
	}
	if scope.Domain != "" {
		reply.UpdateOption(dhcpv4.OptDomainName(scope.Domain))
	}
	reply.UpdateOption(dhcpv4.OptIPAddressLeaseTime(leaseTime))
	return reply
}

// ensureForwarding keeps a gateway forwarding: if the main ruleset is gone,
// a minimal one with NAT and accept-everything takes its place.
func (l *Lifeboat) ensureForwarding(ctx context.Context) {
	if l.cfg.Mode != config.ModeInline {
		return
	}
	_ = os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1\n"), 0o644)
	if err := exec.CommandContext(ctx, "nft", "list", "table", "inet", "orbis").Run(); err == nil {
		l.log("lifeboat: the firewall ruleset is still loaded; leaving it alone")
		return
	}
	wan := l.cfg.Firewall.WANInterface
	if wan == "" {
		l.log("lifeboat: no WAN interface configured; forwarding without NAT")
	}
	script := "table inet orbis_lifeboat\ndelete table inet orbis_lifeboat\ntable inet orbis_lifeboat {\n" +
		"  chain forward { type filter hook forward priority filter; policy accept; }\n" +
		"  chain input { type filter hook input priority filter; policy accept; }\n"
	if wan != "" {
		script += fmt.Sprintf("  chain postrouting { type nat hook postrouting priority srcnat; oifname %q masquerade }\n", wan)
	}
	script += "}\n"
	cmd := exec.CommandContext(ctx, "nft", "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	if out, err := cmd.CombinedOutput(); err != nil {
		l.log("lifeboat: could not load the fail-open ruleset: %s", strings.TrimSpace(string(out)))
		return
	}
	l.natTable = true
	l.log("lifeboat: fail-open ruleset loaded (forward accept, NAT on %s)", wan)
}

func (l *Lifeboat) shutdown() {
	for _, s := range l.dnsSrv {
		_ = s.Shutdown()
	}
	for _, s := range l.dhcpSrv {
		_ = s.Close()
	}
	if l.httpSrv != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_ = l.httpSrv.Shutdown(ctx)
		cancel()
	}
	if l.natTable {
		_ = exec.Command("nft", "delete", "table", "inet", "orbis_lifeboat").Run()
	}
	l.log("lifeboat: handing back")
}

// startStatusPage serves one page on the interface's address: what is
// happening, why, and a button to try the main service now.
func (l *Lifeboat) startStatusPage() {
	addr := l.cfg.API.Listen
	if addr == "" {
		addr = ":80"
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", l.statusPage)
	mux.HandleFunc("/lifeboat/start", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		l.mu.Lock()
		l.episode.Retries++
		l.mu.Unlock()
		l.writeEpisode()
		_ = safety.Retry(r.Context())
		http.Redirect(w, r, "/?starting=1", http.StatusSeeOther)
	})
	mux.HandleFunc("/api/lifeboat", func(w http.ResponseWriter, r *http.Request) {
		l.mu.Lock()
		defer l.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"lifeboat": true, "episode": l.episode, "answered": l.answered, "failed": l.failed, "leases": len(l.leases), "version": l.opt.Version})
	})
	l.httpSrv = &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		if err := l.httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			l.log("lifeboat: status page on %s: %v", addr, err)
		}
	}()
}

func (l *Lifeboat) statusPage(w http.ResponseWriter, r *http.Request) {
	l.mu.Lock()
	ep, answered, failed, leases, retryAt := l.episode, l.answered, l.failed, len(l.leases), l.retryAt
	l.mu.Unlock()
	status := safety.ServiceStatus(r.Context(), "orbis.service", 12)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Refresh", "20")
	fmt.Fprintf(w, `<!doctype html><meta name="viewport" content="width=device-width,initial-scale=1"><title>Orbis lifeboat</title>
<style>body{font:15px/1.6 -apple-system,Segoe UI,sans-serif;background:#0b0f14;color:#dfe6ee;margin:0;padding:28px;max-width:760px}
h1{font-size:22px;margin:0 0 4px}.tag{display:inline-block;padding:2px 9px;border-radius:999px;background:#3a2a0c;color:#f0b84a;font-size:12px;letter-spacing:.06em;text-transform:uppercase}
.card{background:#111821;border:1px solid #1e2a36;border-radius:12px;padding:16px 18px;margin:14px 0}dt{color:#8a97a6;font-size:12px;text-transform:uppercase;letter-spacing:.08em;margin-top:8px}dd{margin:0}
pre{background:#0b1016;border:1px solid #1e2a36;border-radius:8px;padding:10px;font-size:12px;overflow:auto;white-space:pre-wrap}button{background:#2ed3a3;color:#04110c;border:0;border-radius:8px;padding:10px 16px;font-weight:600;font-size:14px;cursor:pointer}</style>
<span class="tag">lifeboat mode</span><h1>Orbis is down. The network is not.</h1>
<p>The main service failed, so this standby is keeping the essentials running: names resolve (without any filtering), devices keep their addresses, and traffic keeps flowing. It asks systemd to start Orbis again on a backoff, and stops the moment Orbis is back.</p>
<div class="card"><dl>
<dt>Since</dt><dd>%s (%s ago)</dd>
<dt>Why</dt><dd>%s</dd>
<dt>Serving</dt><dd>%d lookups answered, %d failed, %d DHCP leases</dd>
<dt>Next automatic retry</dt><dd>in %s (attempt %d so far)</dd>
</dl>
<form method="post" action="/lifeboat/start" style="margin-top:12px"><button>Start Orbis now</button></form></div>
<div class="card"><dt>What systemd says</dt><pre>%s</pre></div>
<div class="card"><dt>If it keeps failing</dt><dd>Read the log with <code>journalctl -u orbis -n 100</code>. A broken configuration is the usual cause: <code>orbisd -check -config /etc/orbis/orbis.yaml</code> says which line. The previous binary is at <code>/usr/local/bin/orbisd.prev</code> if an update did this.</dd></div>
<p style="color:#8a97a6;font-size:12px">Orbis %s, lifeboat. This page refreshes every 20 seconds.</p>`,
		ep.Started.Format("2006-01-02 15:04"), time.Since(ep.Started).Round(time.Minute), html.EscapeString(ep.Reason),
		answered, failed, leases, time.Until(retryAt).Round(time.Second), ep.Retries, html.EscapeString(status), html.EscapeString(l.opt.Version))
}
