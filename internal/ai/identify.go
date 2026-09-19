package ai

import (
	"context"
	"encoding/json"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Neoo-Blue/orbis/internal/config"
	"github.com/Neoo-Blue/orbis/internal/ident"
	"github.com/Neoo-Blue/orbis/internal/store"
)

const identifyMinProb = 0.6

// Identifier labels unknown devices from vendor/hostname rules first, then
// TypeSafe when a key is configured. It is off until the operator opts in
// because a pass sends hostnames and DNS names off-box.
type Identifier struct {
	cfg      *config.Config
	client   *Client
	clients  func() []store.Client
	dnsLog   func(since time.Time, clientID string) ([]store.DNSQuery, error)
	setClass func(id, class, os string) bool
	log      func(string, ...any)

	mu    sync.Mutex
	asked map[string]string // client id -> last evidence key sent to TypeSafe
}

func NewIdentifier(cfg *config.Config, client *Client, clients func() []store.Client,
	dnsLog func(since time.Time, clientID string) ([]store.DNSQuery, error),
	setClass func(id, class, os string) bool, log func(string, ...any)) *Identifier {
	if log == nil {
		log = func(string, ...any) {}
	}
	if clients == nil {
		clients = func() []store.Client { return nil }
	}
	if setClass == nil {
		setClass = func(string, string, string) bool { return false }
	}
	return &Identifier{
		cfg: cfg, client: client, clients: clients, dnsLog: dnsLog,
		setClass: setClass, log: log, asked: map[string]string{},
	}
}

// Run waits two minutes for DHCP and DNS to accumulate, then classifies
// on a six-hour cadence so a device is not re-asked all day.
func (id *Identifier) Run(ctx context.Context) {
	select {
	case <-ctx.Done():
		return
	case <-time.After(2 * time.Minute):
	}
	if _, err := id.Pass(ctx); err != nil && ctx.Err() == nil {
		id.log("identify: %v", err)
	}
	t := time.NewTicker(6 * time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if _, err := id.Pass(ctx); err != nil && ctx.Err() == nil {
			id.log("identify: %v", err)
		}
	}
}

// Pass classifies unknown devices. Deterministic rules run even without a
// TypeSafe key; the API is only used for what those rules cannot name.
func (id *Identifier) Pass(ctx context.Context) (int, error) {
	if !id.cfg.Snapshot().AI.TypeSafe.Identify {
		return 0, nil
	}
	classified, asked := 0, 0
	key := typeSafeKey(id.cfg)
	for _, c := range id.clients() {
		if err := ctx.Err(); err != nil {
			return classified, err
		}
		if c.DeviceType != "" && c.DeviceType != "unknown" {
			continue
		}
		fp := ""
		if c.Meta != nil {
			fp = c.Meta["dhcp_fingerprint"]
		}
		class, os := ident.DeviceClass(c.Vendor, c.Hostname, "", fp)
		if class != "unknown" {
			if id.setClass(c.ID, class, os) {
				classified++
			}
			continue
		}
		if key == "" || id.client == nil {
			continue
		}

		names := id.queriedNames(c.ID)
		if c.Hostname == "" && c.Vendor == "" && len(names) == 0 {
			continue
		}
		state := identifyState(c, names)
		ek := evidenceKey(state)
		id.mu.Lock()
		same := id.asked[c.ID] == ek
		id.mu.Unlock()
		if same {
			continue
		}

		resp, err := id.client.askTypeSafe(ctx, key, state, identifyQuestions)
		if err != nil {
			if _, retriable := classify(err); !retriable || ctx.Err() != nil {
				return classified, err
			}
			id.log("identify: %v", err)
			continue
		}
		asked++
		id.mu.Lock()
		id.asked[c.ID] = ek
		id.mu.Unlock()

		gotClass := applyChoice(resp.Answers["class"])
		gotOS := applyChoice(resp.Answers["os"])
		if gotClass == "" && gotOS == "" {
			continue
		}
		if id.setClass(c.ID, gotClass, gotOS) {
			classified++
		}
	}
	id.log("identify: %d device(s) classified (%d asked TypeSafe)", classified, asked)
	return classified, nil
}

func (id *Identifier) queriedNames(clientID string) []string {
	if id.dnsLog == nil {
		return nil
	}
	qs, err := id.dnsLog(time.Now().Add(-24*time.Hour), clientID)
	if err != nil {
		id.log("identify: %v", err)
		return nil
	}
	return topQueriedNames(qs, 25)
}

func applyChoice(a typeSafeAnswer) string {
	if a.Choice == "" || a.Choice == "unknown" {
		return ""
	}
	if a.Probabilities[a.Choice] >= identifyMinProb {
		return a.Choice
	}
	return ""
}

func identifyState(c store.Client, names []string) map[string]any {
	st := map[string]any{}
	if c.Hostname != "" {
		st["hostname"] = c.Hostname
	}
	if c.Vendor != "" {
		st["vendor"] = c.Vendor
	}
	st["randomized_mac"] = ident.IsRandomizedMAC(c.MAC) || c.Meta["randomized_mac"] == "true"
	if vc := c.Meta["dhcp_vendor_class"]; vc != "" {
		st["dhcp_vendor_class"] = vc
	}
	if len(names) > 0 {
		st["most_queried_names"] = names
	}
	return st
}

func evidenceKey(state map[string]any) string {
	b, err := json.Marshal(state)
	if err != nil {
		return ""
	}
	return string(b)
}

func topQueriedNames(qs []store.DNSQuery, n int) []string {
	counts := map[string]int{}
	for _, q := range qs {
		if q.Blocked {
			continue
		}
		name := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(q.Name), "."))
		if name == "" || strings.HasSuffix(name, ".arpa") || strings.HasPrefix(name, "_") {
			continue
		}
		counts[name]++
	}
	type kv struct {
		name  string
		count int
	}
	list := make([]kv, 0, len(counts))
	for name, c := range counts {
		list = append(list, kv{name, c})
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].count != list[j].count {
			return list[i].count > list[j].count
		}
		return list[i].name < list[j].name
	})
	if len(list) > n {
		list = list[:n]
	}
	out := make([]string, len(list))
	for i, x := range list {
		out[i] = x.name
	}
	return out
}

// identifyQuestions are asked about one device's evidence at a time.
var identifyQuestions = map[string]any{
	"class": map[string]any{
		"type": "choice",
		// One worked example in the instructions anchors the model on it (a
		// Samsung phone came back a TV); platform hints sit in every option.
		"instructions": "What kind of device is this on a home network? The names it looks up " +
			"(`most_queried_names`) are the strongest evidence of what it is, taken together: the " +
			"operating system's own services (push, connectivity checks, updates) say what platform " +
			"it runs, and app or vendor services say what it is for. Use hostname, vendor, DHCP " +
			"vendor class and whether the MAC is randomized as supporting evidence. Pick unknown " +
			"when the evidence is too thin or mixed.",
		"criteria": map[string]string{
			"phone":   "Mobile phone: Android phones look up mtalk.google.com (push) and connectivitycheck.gstatic.com; iPhones look up Apple push and iCloud services",
			"tablet":  "Tablet: the same platform services as a phone",
			"laptop":  "Laptop or notebook computer",
			"desktop": "Desktop PC or workstation",
			"tv":      "Smart TV or streaming box: Samsung Tizen TVs look up cspserver.net and samsungcloudsolution; LG webOS, Roku, Fire TV, Chromecast, Apple TV",
			"console": "Game console: PlayStation, Xbox, Nintendo Switch",
			"speaker": "Smart speaker or audio device: Sonos, HomePod, Echo",
			"camera":  "Security camera, doorbell or NVR",
			"printer": "Printer or scanner",
			"iot":     "Appliance or smart-home device: robot vacuum, plug, thermostat, bulb, hub",
			"server":  "Server, virtual machine or container running services",
			"nas":     "Network-attached storage",
			"unknown": "Not enough evidence to tell",
		},
	},
	"os": map[string]any{
		"type": "choice",
		"instructions": "Which operating system does this device run? Infer from vendor, hostname, " +
			"DHCP vendor class and the names it looks up. Pick unknown when the evidence is too thin.",
		"criteria": map[string]string{
			"Android":    "Android phone, tablet or TV: looks up mtalk.google.com and connectivitycheck.gstatic.com",
			"iOS/iPadOS": "iPhone or iPad",
			"macOS":      "Mac",
			"Windows":    "Windows PC",
			"Linux":      "Linux computer, NAS or server",
			"Tizen":      "Samsung TV (Tizen): looks up cspserver.net",
			"webOS":      "LG TV (webOS)",
			"Roku OS":    "Roku player or Roku TV",
			"Fire OS":    "Amazon Fire TV or Fire tablet",
			"embedded":   "Embedded or RTOS firmware on an appliance, camera, printer or IoT device",
			"unknown":    "Not enough evidence to tell",
		},
	},
}
