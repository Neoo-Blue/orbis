package app

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Neoo-Blue/orbis/internal/config"
	"github.com/Neoo-Blue/orbis/internal/intercept"
	"github.com/Neoo-Blue/orbis/internal/store"
)

// interceptEnv is the network facts interception decisions depend on.
type interceptEnv struct {
	lan     string
	gateway netip.Addr
	gwMAC   net.HardwareAddr
	selfMAC net.HardwareAddr
	prefix  netip.Prefix
	local   map[netip.Addr]bool
}

func (e interceptEnv) isSelf(a netip.Addr) bool { return e.local[a.Unmap()] }

func (a *App) interceptEnv(cfg config.InterceptConfig) (interceptEnv, error) {
	gw := cfg.Gateway
	if gw == "" {
		gw = a.DefaultGateway()
	}
	gwAddr, err := netip.ParseAddr(gw)
	if err != nil {
		return interceptEnv{}, fmt.Errorf("no usable gateway (%q): %w", gw, err)
	}
	lan := cfg.LANInterface
	if lan == "" {
		lan = a.Cfg.Snapshot().Firewall.WANInterface // the node's primary LAN nic
	}
	if lan == "" {
		lan = "eth0"
	}
	env := interceptEnv{lan: lan, gateway: gwAddr, local: map[netip.Addr]bool{}}
	if ifc, err := net.InterfaceByName(lan); err == nil {
		env.selfMAC = ifc.HardwareAddr
		if addrs, err := ifc.Addrs(); err == nil {
			for _, ad := range addrs {
				if ipn, ok := ad.(*net.IPNet); ok && ipn.IP.To4() != nil {
					if p, err := netip.ParsePrefix(ipn.String()); err == nil {
						env.prefix = p.Masked()
						break
					}
				}
			}
		}
	}
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, ad := range addrs {
			if ipn, ok := ad.(*net.IPNet); ok {
				if x, ok := netip.AddrFromSlice(ipn.IP); ok {
					env.local[x.Unmap()] = true
				}
			}
		}
	}
	if a.Intercept != nil {
		if st := a.Intercept.Stats(); st.GatewayMAC != "" {
			env.gwMAC, _ = net.ParseMAC(st.GatewayMAC)
		}
	}
	if env.gwMAC == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		env.gwMAC, _ = intercept.ProbeMAC(ctx, lan, gwAddr)
		cancel()
	}
	return env, nil
}

// interceptPlan resolves the enrolled set against where devices are now. A nil
// confirm means no probing, which is what every sync uses; only the
// background reconcile probes.
func (a *App) interceptPlan(cfg config.InterceptConfig, env interceptEnv, confirm func(netip.Addr) (net.HardwareAddr, bool)) intercept.Plan {
	// Fill in any missing MACs from what the registry has observed, so the
	// operator can enrol a device by address alone.
	pairs := map[string]string{}
	for ip, mac := range cfg.Clients {
		if mac == "" && a.Registry != nil {
			if addr, err := netip.ParseAddr(ip); err == nil {
				if c := a.Registry.ByIP(addr); c != nil {
					mac = c.MAC
				}
			}
		}
		if mac != "" {
			pairs[ip] = mac
		}
	}
	in := intercept.PlanInput{
		Clients: pairs, Gateway: env.gateway, GatewayMAC: env.gwMAC, SelfMAC: env.selfMAC,
		IsSelf: env.isSelf, LAN: env.prefix, Confirm: confirm,
	}
	if a.Registry != nil {
		in.Seen = func(mac string) (netip.Addr, bool) {
			c := a.Registry.ByMAC(mac)
			if c == nil {
				return netip.Addr{}, false
			}
			ip, err := netip.ParseAddr(c.IP)
			return ip, err == nil
		}
	}
	return intercept.MakePlan(in)
}

// planKey identifies what a plan asks of the engine (who is claimed at which
// address, who is held back), so the reconcile can tell when what is applied
// has drifted from what the configuration and the registry now say. Reasons
// are left out so a reworded hold does not cause a resync.
func planKey(p intercept.Plan) string {
	parts := make([]string, 0, len(p.Targets)+len(p.Held))
	for _, t := range p.Targets {
		parts = append(parts, t.IP.String()+"="+t.MAC.String())
	}
	for ip := range p.Held {
		parts = append(parts, "held:"+ip)
	}
	sort.Strings(parts)
	return strings.Join(parts, ",")
}

// InterceptRefusal says why an address or MAC can never be enrolled, or ""
// when it can. The API asks before saving an enrolment.
func (a *App) InterceptRefusal(ip, mac string) string {
	env, err := a.interceptEnv(a.Cfg.Snapshot().Network.Intercept)
	if err != nil {
		return ""
	}
	addr, _ := netip.ParseAddr(ip)
	hw, _ := net.ParseMAC(mac)
	return intercept.Refusal(addr, hw, env.gateway, env.gwMAC, env.selfMAC, env.isSelf)
}

// noteClientMoved runs on the capture path when a known MAC shows up at a new
// address. If it is an enrolled device, wake the intercept loop so the
// enrolment follows it now rather than at the next tick.
func (a *App) noteClientMoved(mac string, from, to netip.Addr) {
	for _, m := range a.Cfg.Snapshot().Network.Intercept.Clients {
		if strings.EqualFold(m, mac) {
			select {
			case a.interceptKick <- struct{}{}:
			default:
			}
			return
		}
	}
}

// interceptLoop keeps interception honest in the background: it follows
// devices that change address and backs off when the node cannot keep up.
func (a *App) interceptLoop() {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-a.ctx.Done():
			return
		case <-a.interceptKick:
			a.reconcileIntercept()
		case now := <-t.C:
			a.reconcileIntercept()
			a.guardInterceptLoad(now)
		}
	}
}

// reconcileIntercept follows enrolled devices to their new addresses (after
// the device itself answers ARP for the new one), drops entries that can never
// be intercepted, and applies the result. It probes the network, so it runs
// off the request path.
func (a *App) reconcileIntercept() {
	a.interceptMu.Lock()
	defer a.interceptMu.Unlock()

	cfg := a.Cfg.Snapshot().Network.Intercept
	if !cfg.Enabled || len(cfg.Clients) == 0 {
		return
	}
	env, err := a.interceptEnv(cfg)
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(a.ctx, 20*time.Second)
	defer cancel()
	plan := a.interceptPlan(cfg, env, func(ip netip.Addr) (net.HardwareAddr, bool) {
		return intercept.ProbeMAC(ctx, env.lan, ip)
	})
	// A device enrolled by address alone is anchored to the MAC the registry
	// has for that address now, so it can be followed when the address
	// changes; an unanchored entry would simply be lost at its next lease.
	fills := map[string]string{}
	if a.Registry != nil {
		for ip, mac := range cfg.Clients {
			if mac != "" {
				continue
			}
			if addr, err := netip.ParseAddr(ip); err == nil {
				if c := a.Registry.ByIP(addr); c != nil && c.MAC != "" {
					fills[ip] = c.MAC
				}
			}
		}
	}
	if len(plan.Moves) > 0 || len(plan.Drops) > 0 || len(fills) > 0 {
		err := a.Cfg.Update(func(c *config.Config) {
			cl := c.Network.Intercept.Clients
			for ip, mac := range fills {
				if m, ok := cl[ip]; ok && m == "" {
					cl[ip] = mac
				}
			}
			for old, now := range plan.Moves {
				mac, ok := cl[old]
				if _, taken := cl[now]; !ok || taken || mac == "" {
					continue
				}
				delete(cl, old)
				cl[now] = mac
			}
			for ip := range plan.Drops {
				delete(cl, ip)
			}
		})
		if err != nil {
			// The live set may have changed even though saving it failed;
			// the comparison below applies whatever it now says, so the
			// engine never keeps claiming an address NAT no longer matches.
			a.log("intercept: could not save the enrolled set: %v", err)
		}
		for old, now := range plan.Moves {
			if err != nil {
				break
			}
			name := a.deviceName(now)
			a.log("intercept: %s moved from %s to %s; interception follows it", name, old, now)
			a.raise(store.SevInfo, "intercept", "Interception followed "+name+" to "+now,
				fmt.Sprintf("%s took a new address (%s, was %s), usually a new DHCP lease. Interception moved "+
					"with it, so its traffic is still filtered and its replies still come back through this node.",
					name, now, old))
		}
		for ip, why := range plan.Drops {
			if err != nil {
				break
			}
			a.log("intercept: removed %s from the enrolled set: %s", ip, why)
			a.raise(store.SevInfo, "intercept", "Removed "+ip+" from interception",
				fmt.Sprintf("%s was enrolled for interception, but %s. Intercepting it can only confuse the "+
					"network, so it was taken off the list.", ip, why))
		}
	}

	// Apply when what a sync would do differs from what is applied: the moves
	// and drops above, but also a device the registry no longer places at its
	// enrolled address, or an entry whose MAC can no longer be resolved.
	want := a.interceptPlan(a.Cfg.Snapshot().Network.Intercept, env, nil)
	if planKey(want) == a.interceptApplied {
		return
	}
	if err := a.syncInterceptLocked(); err != nil {
		a.log("intercept: %v", err)
	}
}

// strayHealer rate-limits the stray-device check per MAC, so a device sending
// thousands of packets costs one decision every few seconds.
type strayHealer struct {
	mu     sync.Mutex
	seen   map[string]time.Time // mac -> last decision
	logged map[string]time.Time // mac -> last log line
}

const (
	strayEvery    = 5 * time.Second
	strayLogEvery = 10 * time.Minute
	// A one-way conntrack entry outlives the device's move back to the
	// router by up to a few minutes, so that path decides less often.
	strayConntrackEvery = 30 * time.Second
)

// noteStrayIP is the conntrack side of noteStray: a one-way connection from a
// LAN address to the internet. Conntrack has no MAC, so it is looked up.
func (a *App) noteStrayIP(src netip.Addr) {
	now := time.Now()
	key := "ct:" + src.String()
	s := &a.stray
	s.mu.Lock()
	if s.seen == nil {
		s.seen = map[string]time.Time{}
	}
	if now.Sub(s.seen[key]) < strayConntrackEvery {
		s.mu.Unlock()
		return
	}
	s.seen[key] = now
	s.mu.Unlock()
	go func() {
		if a.Cfg.Snapshot().Mode != config.ModeObserve || (a.Intercept != nil && a.Intercept.IsTarget(src)) {
			return
		}
		// This node's own unanswered connections look the same.
		if addrs, err := net.InterfaceAddrs(); err == nil {
			for _, ad := range addrs {
				if ipn, ok := ad.(*net.IPNet); ok {
					if x, ok := netip.AddrFromSlice(ipn.IP); ok && x.Unmap() == src {
						return
					}
				}
			}
		}
		lan := a.Cfg.Snapshot().Network.Intercept.LANInterface
		if lan == "" {
			lan = "eth0"
		}
		ctx, cancel := context.WithTimeout(a.ctx, 2*time.Second)
		mac, ok := intercept.ProbeMAC(ctx, lan, src)
		cancel()
		if !ok && a.Registry != nil {
			if c := a.Registry.ByIP(src); c != nil && c.MAC != "" {
				mac, _ = net.ParseMAC(c.MAC)
				ok = mac != nil
			}
		}
		if ok {
			a.healStray(src, mac.String())
		}
	}()
}

// noteStray runs on the capture path for packets a local device sends through
// this node. It only rate-limits and hands the decision off.
func (a *App) noteStray(src netip.Addr, mac string) {
	now := time.Now()
	s := &a.stray
	s.mu.Lock()
	if s.seen == nil {
		s.seen = map[string]time.Time{}
	}
	if now.Sub(s.seen[mac]) < strayEvery {
		s.mu.Unlock()
		return
	}
	s.seen[mac] = now
	if len(s.seen) > 4096 {
		for k, t := range s.seen {
			if now.Sub(t) > time.Minute {
				delete(s.seen, k)
			}
		}
	}
	s.mu.Unlock()
	go a.healStray(src, mac)
}

// healStray decides whether a device sending its traffic here should be, and if
// not, tells it where the real gateway is. A device left pointing at this node
// is otherwise half-routed until its own cache happens to expire, which a
// Windows laptop with busy connections never does. Only in observe mode: there
// nothing on the LAN subnet is meant to route through this node unless it is
// being intercepted (the node's Wi-Fi and tunnels use other subnets). In inline
// mode devices route here on purpose.
func (a *App) healStray(src netip.Addr, mac string) {
	cfg := a.Cfg.Snapshot()
	if cfg.Mode != config.ModeObserve {
		return
	}
	if a.Intercept != nil && a.Intercept.IsTarget(src) {
		return
	}
	env, err := a.interceptEnv(cfg.Network.Intercept)
	if err != nil || env.gwMAC == nil || !env.prefix.IsValid() || !env.prefix.Contains(src) ||
		src == env.gateway || env.isSelf(src) {
		return
	}
	hw, err := net.ParseMAC(mac)
	if err != nil || bytes.Equal(hw, env.gwMAC) {
		return
	}
	if err := intercept.Heal(env.lan, env.gateway, env.gwMAC, intercept.Target{IP: src, MAC: hw}); err != nil {
		a.log("intercept: could not point %s back at the router: %v", src, err)
		return
	}
	s := &a.stray
	s.mu.Lock()
	if s.logged == nil {
		s.logged = map[string]time.Time{}
	}
	quiet := time.Since(s.logged[mac]) < strayLogEvery
	if !quiet {
		s.logged[mac] = time.Now()
	}
	s.mu.Unlock()
	if !quiet {
		a.log("intercept: %s (%s) was sending its traffic through this node without being intercepted; "+
			"told it the router is at %s", src, mac, env.gwMAC)
	}
	// The frame itself says where this MAC is: a LAN source that is not the
	// router is the device's own address. The registry otherwise learns
	// addresses only from ARP, and until it does the reconcile cannot see an
	// enrolled device's move, so the healer and the takeover would take
	// turns with it. Observe reports a move, which wakes the reconcile.
	if a.Registry != nil {
		a.Registry.Observe(src, mac, "")
	}
	a.noteClientMoved(mac, netip.Addr{}, src)
}

// deviceName is how a device is named in events: its label, its hostname, or
// its address.
func (a *App) deviceName(ip string) string {
	if a.Registry != nil {
		if addr, err := netip.ParseAddr(ip); err == nil {
			if c := a.Registry.ByIP(addr); c != nil {
				if c.Label != "" {
					return c.Label
				}
				if c.Hostname != "" {
					return c.Hostname
				}
			}
		}
	}
	return ip
}
