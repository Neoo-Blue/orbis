// Package links tells the physical interfaces apart: which cable is the
// internet, which is the network, which adapter is wireless, and which port
// has nothing in it. It watches for cables being plugged in and either
// proposes the assignment with its evidence or, when allowed and the
// evidence is unambiguous, applies it.
package links

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Neoo-Blue/orbis/internal/config"
	"github.com/Neoo-Blue/orbis/internal/store"
	"github.com/google/uuid"
)

// Link is one physical interface with what is known about it.
type Link struct {
	Name         string   `json:"name"`
	MAC          string   `json:"mac"`
	Wireless     bool     `json:"wireless"`
	Carrier      bool     `json:"carrier"`
	Up           bool     `json:"up"`
	SpeedMbps    int      `json:"speed_mbps,omitempty"`
	Addresses    []string `json:"addresses"`
	DefaultRoute bool     `json:"default_route"`
	Neighbours   int      `json:"neighbours"`
	Clients      int      `json:"clients"`
	Role         string   `json:"role"`       // wan | lan | wifi | unplugged | single
	Configured   string   `json:"configured"` // wan | lan | none: what the config says today
	Confidence   string   `json:"confidence"` // high | low
	Evidence     []string `json:"evidence"`
}

// Suggestion is the assignment the evidence supports.
type Suggestion struct {
	WAN        string   `json:"wan"`
	LAN        []string `json:"lan"`
	WiFi       []string `json:"wifi"`
	Confidence string   `json:"confidence"`
	Changes    []string `json:"changes"`
	Reason     string   `json:"reason"`
}

// Hooks are what the application lends the watcher.
type Hooks struct {
	// ClientsIn counts known devices whose address falls in these prefixes.
	ClientsIn func(prefixes []netip.Prefix) int
	// WiFiEnabled reports whether the access point is on, which makes a
	// single cable the uplink rather than the network.
	WiFiEnabled func() bool
	Emit        func(store.Event)
	// Applied is called after an assignment was written, so rulesets that
	// name interfaces can be re-rendered.
	Applied func()
}

var virtualPrefixes = []string{"docker", "br-", "veth", "virbr", "cni", "flannel", "kube", "wg", "tailscale", "zt", "tun", "tap", "p2p-", "lo"}

// Scan reads the physical interfaces from sysfs and the routing tables.
func Scan(hooks Hooks) []Link {
	entries, err := os.ReadDir("/sys/class/net")
	if err != nil {
		return []Link{}
	}
	defRoute := defaultRouteDev()
	out := []Link{}
	for _, e := range entries {
		name := e.Name()
		if isVirtualName(name) {
			continue
		}
		base := filepath.Join("/sys/class/net", name)
		if _, err := os.Stat(filepath.Join(base, "device")); err != nil {
			continue // no backing device: bridges, tunnels, dummies
		}
		if t := readFile(filepath.Join(base, "type")); t != "1" {
			continue // not Ethernet-framed
		}
		l := Link{Name: name, Addresses: []string{}, Evidence: []string{}}
		l.MAC = readFile(filepath.Join(base, "address"))
		_, wifiErr := os.Stat(filepath.Join(base, "phy80211"))
		l.Wireless = wifiErr == nil
		l.Carrier = readFile(filepath.Join(base, "carrier")) == "1"
		l.Up = readFile(filepath.Join(base, "operstate")) == "up"
		if sp, err := strconv.Atoi(readFile(filepath.Join(base, "speed"))); err == nil && sp > 0 {
			l.SpeedMbps = sp
		}
		var prefixes []netip.Prefix
		if iface, err := net.InterfaceByName(name); err == nil {
			if addrs, err := iface.Addrs(); err == nil {
				for _, a := range addrs {
					if p, err := netip.ParsePrefix(a.String()); err == nil && p.Addr().Is4() {
						l.Addresses = append(l.Addresses, p.String())
						prefixes = append(prefixes, p.Masked())
					}
				}
			}
		}
		l.DefaultRoute = name == defRoute
		l.Neighbours = neighbourCount(name)
		if hooks.ClientsIn != nil && len(prefixes) > 0 {
			l.Clients = hooks.ClientsIn(prefixes)
		}
		out = append(out, l)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func isVirtualName(name string) bool {
	for _, p := range virtualPrefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

func readFile(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func defaultRouteDev() string {
	out, err := exec.Command("ip", "-4", "route", "show", "default").Output()
	if err != nil {
		return ""
	}
	fields := strings.Fields(string(out))
	for i, f := range fields {
		if f == "dev" && i+1 < len(fields) {
			return fields[i+1]
		}
	}
	return ""
}

func neighbourCount(dev string) int {
	out, err := exec.Command("ip", "-4", "neigh", "show", "dev", dev).Output()
	if err != nil {
		return 0
	}
	n := 0
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, "REACHABLE") || strings.Contains(line, "STALE") || strings.Contains(line, "DELAY") || strings.Contains(line, "PROBE") {
			n++
		}
	}
	return n
}

// Classify assigns a role to every link and derives the suggestion. The
// wired cable carrying the default route is the internet; other wired cables
// with a carrier are the network; wireless adapters are the Wi-Fi network;
// a port with nothing in it is unplugged. With one wired cable the node sits
// on a network it does not route (observe), unless it runs an access point,
// in which case that one cable is the uplink the Wi-Fi is translated onto.
func Classify(links []Link, cfg config.Config, wifiEnabled bool) ([]Link, Suggestion) {
	var wired, wireless []int
	for i := range links {
		if links[i].Wireless {
			wireless = append(wireless, i)
		} else {
			wired = append(wired, i)
		}
	}
	current := currentRoles(cfg)
	for i := range links {
		links[i].Configured = current[links[i].Name]
		if links[i].Configured == "" {
			links[i].Configured = "none"
		}
	}
	sug := Suggestion{Confidence: "high", LAN: []string{}, WiFi: []string{}, Changes: []string{}}
	if links == nil {
		links = []Link{}
	}
	var live []int
	for _, i := range wired {
		if links[i].Carrier {
			live = append(live, i)
		} else {
			links[i].Role, links[i].Confidence = "unplugged", "high"
			links[i].Evidence = []string{"no carrier: nothing is plugged in, or the other end is off"}
		}
	}
	for _, i := range wireless {
		links[i].Role, links[i].Confidence = "wifi", "high"
		links[i].Evidence = []string{"wireless adapter: it can be the Wi-Fi network, never the internet uplink"}
		sug.WiFi = append(sug.WiFi, links[i].Name)
	}
	switch len(live) {
	case 0:
		sug.Reason = "No cable is plugged in."
	case 1:
		i := live[0]
		l := &links[i]
		l.Role, l.Confidence = "single", "high"
		l.Evidence = []string{"the only cable: this node is on the network, not between it and the internet"}
		if l.DefaultRoute {
			l.Evidence = append(l.Evidence, "carries the default route")
		}
		if l.Clients > 0 {
			l.Evidence = append(l.Evidence, fmt.Sprintf("%d known device(s) live on its subnet", l.Clients))
		}
		sug.WAN = l.Name
		if wifiEnabled {
			sug.Reason = "One cable and an access point: the cable is the uplink the Wi-Fi network is translated onto."
		} else {
			sug.Reason = "One cable: the node observes and filters from inside the network. Plug a second cable in to make it a gateway."
		}
	default:
		// Two or more live cables: the default route names the internet.
		wanIdx := -1
		for _, i := range live {
			if links[i].DefaultRoute {
				wanIdx = i
			}
		}
		if wanIdx < 0 {
			// No default route yet: the cable with the fewest devices behind
			// it is the most likely uplink, but that is a guess.
			sort.SliceStable(live, func(a, b int) bool {
				return links[live[a]].Clients+links[live[a]].Neighbours < links[live[b]].Clients+links[live[b]].Neighbours
			})
			wanIdx = live[0]
			sug.Confidence = "low"
		}
		wan := &links[wanIdx]
		wan.Role = "wan"
		wan.Evidence = nil
		if wan.DefaultRoute {
			wan.Evidence = append(wan.Evidence, "carries the default route to the internet")
		} else {
			wan.Evidence = append(wan.Evidence, "no default route yet; fewest devices behind it")
		}
		if wan.Clients > 0 {
			wan.Evidence = append(wan.Evidence, fmt.Sprintf("%d known device(s) on its subnet, which is unusual for an uplink", wan.Clients))
		}
		sug.WAN = wan.Name
		othersHaveDevices := false
		for _, i := range live {
			if i == wanIdx {
				continue
			}
			l := &links[i]
			l.Role = "lan"
			l.Evidence = []string{"a second cable that is not the default route"}
			if l.Neighbours > 0 {
				l.Evidence = append(l.Evidence, fmt.Sprintf("%d neighbour(s) answer on it", l.Neighbours))
			}
			if l.Clients > 0 {
				l.Evidence = append(l.Evidence, fmt.Sprintf("%d known device(s) live on its subnet", l.Clients))
				othersHaveDevices = true
			}
			sug.LAN = append(sug.LAN, l.Name)
		}
		// The uplink hosting most of the known devices while the other cable
		// hosts none is what a freshly plugged, still-quiet LAN looks like,
		// and also what a mistake looks like. Ask before acting on it.
		if wan.Clients > 2 && !othersHaveDevices {
			sug.Confidence = "low"
		}
		for _, i := range live {
			links[i].Confidence = sug.Confidence
		}
		sug.Reason = fmt.Sprintf("%s carries the default route, so it is the internet; %s the network.", wan.Name, strings.Join(sug.LAN, " and ")+" is")
		if len(sug.LAN) > 1 {
			sug.Reason = fmt.Sprintf("%s carries the default route, so it is the internet; %s are the network.", wan.Name, strings.Join(sug.LAN, " and "))
		}
		if sug.Confidence == "low" {
			sug.Reason += " The evidence is thin, so this is a proposal."
		}
	}
	sug.Changes = changes(cfg, sug)
	return links, sug
}

// currentRoles reads the configuration's view: the WAN interface and zone
// membership.
func currentRoles(cfg config.Config) map[string]string {
	out := map[string]string{}
	for _, z := range cfg.Firewall.Zones {
		for _, i := range z.Interfaces {
			switch z.Trust {
			case "wan":
				out[i] = "wan"
			case "lan", "guest", "iot", "dmz":
				if out[i] == "" {
					out[i] = "lan"
				}
			}
		}
	}
	if cfg.Firewall.WANInterface != "" && out[cfg.Firewall.WANInterface] == "" {
		out[cfg.Firewall.WANInterface] = "wan"
	}
	return out
}

func changes(cfg config.Config, s Suggestion) []string {
	out := []string{}
	if s.WAN != "" && cfg.Firewall.WANInterface != s.WAN {
		out = append(out, fmt.Sprintf("WAN interface %s -> %s", orNone(cfg.Firewall.WANInterface), s.WAN))
	}
	want := map[string]string{}
	if s.WAN != "" && (len(s.LAN) > 0 || len(s.WiFi) > 0) {
		want[s.WAN] = "wan"
	}
	for _, l := range s.LAN {
		want[l] = "lan"
	}
	for _, w := range s.WiFi {
		want[w] = "lan"
	}
	have := currentRoles(cfg)
	names := make([]string, 0, len(want))
	for n := range want {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if have[n] != want[n] {
			out = append(out, fmt.Sprintf("%s joins the %s zone", n, want[n]))
		}
	}
	return out
}

func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}

// Apply writes an assignment: the WAN interface, and zone membership for the
// WAN and LAN sides. Zones are created when missing and otherwise kept, so a
// zone renamed by the operator survives.
func Apply(cfg *config.Config, s Suggestion) error {
	return cfg.Update(func(c *config.Config) {
		if s.WAN != "" {
			c.Firewall.WANInterface = s.WAN
		}
		wanMembers := []string{}
		if s.WAN != "" && (len(s.LAN) > 0 || len(s.WiFi) > 0) {
			wanMembers = []string{s.WAN}
		}
		lanMembers := append(append([]string{}, s.LAN...), s.WiFi...)
		remove := map[string]bool{s.WAN: true}
		for _, l := range lanMembers {
			remove[l] = true
		}
		wanDone, lanDone := false, false
		for i := range c.Firewall.Zones {
			z := &c.Firewall.Zones[i]
			kept := z.Interfaces[:0]
			for _, iface := range z.Interfaces {
				if !remove[iface] {
					kept = append(kept, iface)
				}
			}
			z.Interfaces = kept
			if z.Trust == "wan" && !wanDone {
				z.Interfaces = append(z.Interfaces, wanMembers...)
				wanDone = true
			}
			if z.Trust == "lan" && !lanDone {
				z.Interfaces = append(z.Interfaces, lanMembers...)
				lanDone = true
			}
		}
		if !wanDone && len(wanMembers) > 0 {
			c.Firewall.Zones = append(c.Firewall.Zones, config.Zone{Name: "wan", Trust: "wan", Interfaces: wanMembers})
		}
		if !lanDone && len(lanMembers) > 0 {
			c.Firewall.Zones = append(c.Firewall.Zones, config.Zone{Name: "lan", Trust: "lan", Interfaces: lanMembers})
		}
	})
}

// Watcher polls the links and reacts to cables.
type Watcher struct {
	cfg   *config.Config
	hooks Hooks
	log   func(string, ...any)

	mu       sync.Mutex
	links    []Link
	sug      Suggestion
	lastSig  string
	proposed string
	scanned  time.Time
}

func NewWatcher(cfg *config.Config, hooks Hooks, log func(string, ...any)) *Watcher {
	if log == nil {
		log = func(string, ...any) {}
	}
	return &Watcher{cfg: cfg, hooks: hooks, log: log}
}

// Refresh scans and classifies now.
func (w *Watcher) Refresh() ([]Link, Suggestion) {
	wifi := w.hooks.WiFiEnabled != nil && w.hooks.WiFiEnabled()
	links, sug := Classify(Scan(w.hooks), w.cfg.Snapshot(), wifi)
	w.mu.Lock()
	w.links, w.sug, w.scanned = links, sug, time.Now()
	w.mu.Unlock()
	return links, sug
}

// Current returns the last scan without probing.
func (w *Watcher) Current() ([]Link, Suggestion, time.Time) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]Link(nil), w.links...), w.sug, w.scanned
}

// Run watches for carrier changes every few seconds. A change raises an
// event; an unambiguous classification is applied when auto-assign is on,
// otherwise it is proposed once.
func (w *Watcher) Run(ctx context.Context) {
	w.Refresh()
	w.mu.Lock()
	w.lastSig = signature(w.links)
	w.mu.Unlock()
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			links, sug := w.Refresh()
			sig := signature(links)
			w.mu.Lock()
			changed := sig != w.lastSig
			prev := w.lastSig
			w.lastSig = sig
			w.mu.Unlock()
			if !changed {
				continue
			}
			w.announce(prev, sig, links)
			if len(sug.Changes) == 0 {
				continue
			}
			if sug.Confidence == "high" && w.cfg.Snapshot().Network.Links.AutoAssign {
				if err := Apply(w.cfg, sug); err != nil {
					w.log("links: apply: %v", err)
					continue
				}
				w.log("links: assigned wan=%s lan=%v wifi=%v", sug.WAN, sug.LAN, sug.WiFi)
				if w.hooks.Emit != nil {
					w.hooks.Emit(store.Event{
						ID: uuid.NewString(), TS: time.Now(), Severity: store.SevInfo, Category: "links",
						Title:  fmt.Sprintf("%s is now the internet, %s the network", sug.WAN, strings.Join(append(sug.LAN, sug.WiFi...), ", ")),
						Detail: sug.Reason + " Applied automatically: " + strings.Join(sug.Changes, "; ") + ".",
					})
				}
				if w.hooks.Applied != nil {
					w.hooks.Applied()
				}
				w.Refresh()
				continue
			}
			w.propose(sug)
		}
	}
}

func (w *Watcher) announce(prev, now string, links []Link) {
	if w.hooks.Emit == nil {
		return
	}
	before := map[string]bool{}
	for _, part := range strings.Split(prev, ",") {
		if strings.HasSuffix(part, "=1") {
			before[strings.TrimSuffix(part, "=1")] = true
		}
	}
	for _, l := range links {
		if l.Wireless {
			continue
		}
		if l.Carrier && !before[l.Name] {
			w.hooks.Emit(store.Event{ID: uuid.NewString(), TS: time.Now(), Severity: store.SevInfo, Category: "links",
				Title: "Cable plugged into " + l.Name, Detail: fmt.Sprintf("%s has a carrier%s.", l.Name, speedNote(l))})
		}
		if !l.Carrier && before[l.Name] {
			w.hooks.Emit(store.Event{ID: uuid.NewString(), TS: time.Now(), Severity: store.SevNotice, Category: "links",
				Title: "Cable unplugged from " + l.Name, Detail: fmt.Sprintf("%s lost its carrier. If that was the %s side, traffic through it has stopped.", l.Name, l.Configured)})
		}
	}
}

func speedNote(l Link) string {
	if l.SpeedMbps > 0 {
		return fmt.Sprintf(" at %d Mbps", l.SpeedMbps)
	}
	return ""
}

func (w *Watcher) propose(sug Suggestion) {
	key := sug.WAN + "|" + strings.Join(sug.LAN, ",") + "|" + strings.Join(sug.Changes, ";")
	w.mu.Lock()
	if w.proposed == key {
		w.mu.Unlock()
		return
	}
	w.proposed = key
	w.mu.Unlock()
	if w.hooks.Emit != nil {
		w.hooks.Emit(store.Event{
			ID: uuid.NewString(), TS: time.Now(), Severity: store.SevNotice, Category: "links",
			Title:  "Cables changed: " + sug.WAN + " looks like the internet",
			Detail: sug.Reason + " Proposed: " + strings.Join(sug.Changes, "; ") + ". Apply it on the Cables & Wi-Fi page, or turn on auto-assign.",
		})
	}
}

// signature is the carrier state of every port. The default route is left
// out on purpose: tunnels and multi-WAN move it around at runtime, and a
// route moving is not a cable moving.
func signature(links []Link) string {
	parts := make([]string, 0, len(links))
	for _, l := range links {
		c := "0"
		if l.Carrier {
			c = "1"
		}
		parts = append(parts, l.Name+"="+c)
	}
	return strings.Join(parts, ",")
}
