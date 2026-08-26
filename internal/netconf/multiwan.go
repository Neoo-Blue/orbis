package netconf

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"
)

// Multi-WAN. A gateway with one uplink is a gateway with a single point of
// failure, and OPNsense, UniFi and Meraki all treat failover as table stakes.
//
// The design here is deliberately the simple one that actually works on Linux:
// probe each uplink independently, and when the set of healthy uplinks changes,
// rewrite the default route. Load balancing across uplinks with equal-cost
// multipath is offered but off by default, because ECMP breaks any service
// that pins a session to a source address, and a household notices that as
// "the bank keeps logging me out" long before it notices the extra bandwidth.

// WANLink is one uplink.
type WANLink struct {
	Name      string `yaml:"name" json:"name"`
	Enabled   bool   `yaml:"enabled" json:"enabled"`
	Interface string `yaml:"interface" json:"interface"`
	// Gateway may be empty for DHCP uplinks, in which case the current
	// default route via this interface is discovered at probe time.
	Gateway string `yaml:"gateway" json:"gateway"`
	// Priority orders failover: lowest wins. Ties are broken by name so the
	// selection is stable across restarts.
	Priority int `yaml:"priority" json:"priority"`
	// Weight biases load balancing when enabled.
	Weight int `yaml:"weight" json:"weight"`
	// Probes are addresses pinged to decide health. Defaults are used when
	// empty. Probing the gateway alone is not enough: a modem that is up but
	// has no internet answers pings happily.
	Probes []string `yaml:"probes" json:"probes"`
}

// MultiWANConfig is the whole feature.
type MultiWANConfig struct {
	Enabled bool      `yaml:"enabled" json:"enabled"`
	Links   []WANLink `yaml:"links" json:"links"`
	// IntervalSeconds between probe rounds.
	IntervalSeconds int `yaml:"interval_seconds" json:"interval_seconds"`
	// FailuresToDown / SuccessesToUp add hysteresis. Flapping a default route
	// is worse than being down: every existing connection breaks on each move.
	FailuresToDown  int `yaml:"failures_to_down" json:"failures_to_down"`
	SuccessesToUp   int `yaml:"successes_to_up" json:"successes_to_up"`
	// LoadBalance spreads new connections across healthy links via ECMP.
	LoadBalance bool `yaml:"load_balance" json:"load_balance"`
}

// LinkState is the observable health of one uplink.
type LinkState struct {
	Name        string    `json:"name"`
	Interface   string    `json:"interface"`
	Gateway     string    `json:"gateway"`
	Up          bool      `json:"up"`
	Active      bool      `json:"active"`
	LatencyMS   float64   `json:"latency_ms"`
	LossPercent float64   `json:"loss_percent"`
	Failures    int       `json:"consecutive_failures"`
	Successes   int       `json:"consecutive_successes"`
	LastChange  time.Time `json:"last_change"`
	LastError   string    `json:"last_error,omitempty"`
}

// WANMonitor probes uplinks and maintains the default route.
type WANMonitor struct {
	log func(string, ...any)

	mu      sync.RWMutex
	cfg     MultiWANConfig
	state   map[string]*LinkState
	active  string
	running bool
	cancel  context.CancelFunc
}

func NewWANMonitor(log func(string, ...any)) *WANMonitor {
	if log == nil {
		log = func(string, ...any) {}
	}
	return &WANMonitor{log: log, state: map[string]*LinkState{}}
}

var defaultProbes = []string{"1.1.1.1", "8.8.8.8", "9.9.9.9"}

// Start begins probing. Calling it again replaces the configuration.
func (w *WANMonitor) Start(ctx context.Context, cfg MultiWANConfig) {
	w.Stop()
	if !cfg.Enabled || len(cfg.Links) == 0 {
		return
	}
	if cfg.IntervalSeconds <= 0 {
		cfg.IntervalSeconds = 10
	}
	if cfg.FailuresToDown <= 0 {
		cfg.FailuresToDown = 3
	}
	if cfg.SuccessesToUp <= 0 {
		cfg.SuccessesToUp = 2
	}

	cctx, cancel := context.WithCancel(ctx)
	w.mu.Lock()
	w.cfg = cfg
	w.cancel = cancel
	w.running = true
	for _, l := range cfg.Links {
		if _, ok := w.state[l.Name]; !ok {
			w.state[l.Name] = &LinkState{Name: l.Name, Interface: l.Interface, Gateway: l.Gateway}
		}
	}
	w.mu.Unlock()

	go w.loop(cctx)
}

func (w *WANMonitor) Stop() {
	w.mu.Lock()
	if w.cancel != nil {
		w.cancel()
		w.cancel = nil
	}
	w.running = false
	w.mu.Unlock()
}

func (w *WANMonitor) Running() bool {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.running
}

func (w *WANMonitor) loop(ctx context.Context) {
	t := time.NewTicker(time.Duration(w.currentCfg().IntervalSeconds) * time.Second)
	defer t.Stop()
	w.round(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			w.round(ctx)
		}
	}
}

func (w *WANMonitor) currentCfg() MultiWANConfig {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.cfg
}

// round probes every enabled link concurrently and then reconciles routing.
func (w *WANMonitor) round(ctx context.Context) {
	cfg := w.currentCfg()

	var wg sync.WaitGroup
	for _, link := range cfg.Links {
		if !link.Enabled {
			continue
		}
		wg.Add(1)
		go func(l WANLink) {
			defer wg.Done()
			w.probe(ctx, l, cfg)
		}(link)
	}
	wg.Wait()

	w.reconcile(ctx, cfg)
}

// probe pings the link's targets through its interface and applies hysteresis.
func (w *WANMonitor) probe(ctx context.Context, l WANLink, cfg MultiWANConfig) {
	probes := l.Probes
	if len(probes) == 0 {
		probes = defaultProbes
	}

	ok := 0
	var totalMS float64
	var lastErr string
	for _, target := range probes {
		lat, err := pingThrough(ctx, l.Interface, target)
		if err != nil {
			lastErr = err.Error()
			continue
		}
		ok++
		totalMS += lat
	}

	w.mu.Lock()
	defer w.mu.Unlock()
	st, exists := w.state[l.Name]
	if !exists {
		st = &LinkState{Name: l.Name}
		w.state[l.Name] = st
	}
	st.Interface = l.Interface
	if l.Gateway != "" {
		st.Gateway = l.Gateway
	} else if gw := discoverGateway(ctx, l.Interface); gw != "" {
		st.Gateway = gw
	}
	st.LossPercent = 100 * float64(len(probes)-ok) / float64(len(probes))
	if ok > 0 {
		st.LatencyMS = totalMS / float64(ok)
		st.LastError = ""
	} else {
		st.LatencyMS = 0
		st.LastError = lastErr
	}

	// A link is healthy when any probe answered. Requiring all of them makes
	// one blocked target look like an outage.
	healthy := ok > 0
	if healthy {
		st.Successes++
		st.Failures = 0
		if !st.Up && st.Successes >= cfg.SuccessesToUp {
			st.Up = true
			st.LastChange = time.Now()
			w.log("wan: %s is up (%.0fms, %.0f%% loss)", l.Name, st.LatencyMS, st.LossPercent)
		}
	} else {
		st.Failures++
		st.Successes = 0
		if st.Up && st.Failures >= cfg.FailuresToDown {
			st.Up = false
			st.LastChange = time.Now()
			w.log("wan: %s is down after %d failed probes (%s)", l.Name, st.Failures, st.LastError)
		}
	}
	// A link that has never been up should come up on its first success
	// without waiting for hysteresis, or boot takes SuccessesToUp rounds.
	if healthy && st.LastChange.IsZero() {
		st.Up = true
		st.LastChange = time.Now()
	}
}

// reconcile installs the default route for the best healthy link.
func (w *WANMonitor) reconcile(ctx context.Context, cfg MultiWANConfig) {
	var healthy []wanCandidate

	w.mu.RLock()
	for _, l := range cfg.Links {
		if !l.Enabled {
			continue
		}
		if st, ok := w.state[l.Name]; ok && st.Up && st.Gateway != "" {
			healthy = append(healthy, wanCandidate{l, st})
		}
	}
	prevActive := w.active
	w.mu.RUnlock()

	if len(healthy) == 0 {
		// Deliberately leave the existing default route alone. Tearing it
		// down when every probe fails converts "the internet is flaky" into
		// "the network is definitely gone", and recovery needs a route to
		// probe over anyway.
		if prevActive != "" {
			w.log("wan: no healthy uplink; leaving the current default route in place")
		}
		return
	}

	sort.Slice(healthy, func(i, j int) bool {
		if healthy[i].link.Priority != healthy[j].link.Priority {
			return healthy[i].link.Priority < healthy[j].link.Priority
		}
		return healthy[i].link.Name < healthy[j].link.Name
	})

	if cfg.LoadBalance && len(healthy) > 1 {
		if err := installECMP(ctx, healthy2routes(healthy)); err != nil {
			w.log("wan: load-balanced route failed: %v", err)
			return
		}
		w.setActive("balanced", healthy)
		return
	}

	best := healthy[0]
	if prevActive == best.link.Name {
		w.markActive(best.link.Name)
		return
	}
	if err := installDefault(ctx, best.st.Gateway, best.link.Interface); err != nil {
		w.log("wan: failed to install default route via %s: %v", best.link.Name, err)
		return
	}
	w.log("wan: default route now via %s (%s dev %s)", best.link.Name, best.st.Gateway, best.link.Interface)
	w.setActive(best.link.Name, healthy)
}

// wanCandidate pairs a configured link with its live health.
type wanCandidate struct {
	link WANLink
	st   *LinkState
}

func healthy2routes(in []wanCandidate) []ecmpHop {
	out := make([]ecmpHop, 0, len(in))
	for _, c := range in {
		wgt := c.link.Weight
		if wgt <= 0 {
			wgt = 1
		}
		out = append(out, ecmpHop{Gateway: c.st.Gateway, Interface: c.link.Interface, Weight: wgt})
	}
	return out
}

func (w *WANMonitor) setActive(name string, healthy []wanCandidate) {
	w.mu.Lock()
	w.active = name
	for _, st := range w.state {
		st.Active = false
	}
	for _, c := range healthy {
		if name == "balanced" || c.link.Name == name {
			if st, ok := w.state[c.link.Name]; ok {
				st.Active = true
			}
		}
	}
	w.mu.Unlock()
}

func (w *WANMonitor) markActive(name string) {
	w.mu.Lock()
	w.active = name
	w.mu.Unlock()
}

// States returns a snapshot for the API.
func (w *WANMonitor) States() []LinkState {
	w.mu.RLock()
	defer w.mu.RUnlock()
	out := make([]LinkState, 0, len(w.state))
	for _, st := range w.state {
		out = append(out, *st)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Active reports the uplink currently carrying the default route.
func (w *WANMonitor) Active() string {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.active
}

// ---- shell helpers ----

type ecmpHop struct {
	Gateway   string
	Interface string
	Weight    int
}

// pingThrough sends probes bound to a specific interface, which is the whole
// trick: without -I the probe follows the current default route and every link
// looks identical.
func pingThrough(ctx context.Context, iface, target string) (float64, error) {
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	args := []string{"-c", "1", "-W", "2", "-n", "-q"}
	if iface != "" {
		args = append(args, "-I", iface)
	}
	args = append(args, target)

	out, err := exec.CommandContext(cctx, "ping", args...).CombinedOutput()
	if err != nil {
		return 0, fmt.Errorf("probe %s via %s failed", target, iface)
	}
	// "rtt min/avg/max/mdev = 8.435/8.435/8.435/0.000 ms"
	for _, line := range strings.Split(string(out), "\n") {
		if !strings.Contains(line, "min/avg/max") {
			continue
		}
		_, vals, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		parts := strings.Split(strings.TrimSpace(vals), "/")
		if len(parts) < 2 {
			continue
		}
		var avg float64
		if _, err := fmt.Sscanf(parts[1], "%f", &avg); err == nil {
			return avg, nil
		}
	}
	return 0, nil
}

// discoverGateway finds the next hop currently associated with an interface,
// which is how a DHCP uplink with no configured gateway is handled.
func discoverGateway(ctx context.Context, iface string) string {
	if iface == "" {
		return ""
	}
	out, err := exec.CommandContext(ctx, "ip", "-4", "route", "show", "dev", iface).CombinedOutput()
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		for i, f := range fields {
			if f == "via" && i+1 < len(fields) {
				if net.ParseIP(fields[i+1]) != nil {
					return fields[i+1]
				}
			}
		}
	}
	// A point-to-point or directly-attached uplink has a default with no via.
	out, err = exec.CommandContext(ctx, "ip", "-4", "route", "show", "default").CombinedOutput()
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(out), "\n") {
		if !strings.Contains(line, "dev "+iface) {
			continue
		}
		fields := strings.Fields(line)
		for i, f := range fields {
			if f == "via" && i+1 < len(fields) {
				return fields[i+1]
			}
		}
	}
	return ""
}

func installDefault(ctx context.Context, gateway, iface string) error {
	args := []string{"-4", "route", "replace", "default", "via", gateway}
	if iface != "" {
		args = append(args, "dev", iface)
	}
	out, err := exec.CommandContext(ctx, "ip", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func installECMP(ctx context.Context, hops []ecmpHop) error {
	args := []string{"-4", "route", "replace", "default"}
	for _, h := range hops {
		args = append(args, "nexthop", "via", h.Gateway)
		if h.Interface != "" {
			args = append(args, "dev", h.Interface)
		}
		args = append(args, "weight", fmt.Sprint(h.Weight))
	}
	out, err := exec.CommandContext(ctx, "ip", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}
