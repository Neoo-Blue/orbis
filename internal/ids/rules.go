package ids

import (
	"sync"
	"time"
)

// Rule is one scenario: how many weighted hits inside a window earn a ban,
// and for how long.
type Rule struct {
	Kind      string
	Title     string
	Threshold int
	Window    time.Duration
	Ban       time.Duration
}

// Rules are the built-in scenarios.
var Rules = []Rule{
	{"ssh-auth-fail", "SSH brute force", 5, 5 * time.Minute, 4 * time.Hour},
	{"ssh-probe", "SSH probing", 6, 10 * time.Minute, 2 * time.Hour},
	{"auth-fail", "Login brute force", 8, 10 * time.Minute, 4 * time.Hour},
	{"nas-auth-fail", "NAS login brute force", 5, 10 * time.Minute, 12 * time.Hour},
	{"http-auth-fail", "Web login brute force", 10, 5 * time.Minute, 4 * time.Hour},
	{"http-probe", "Web path scanning", 40, 2 * time.Minute, 2 * time.Hour},
	{"app-auth-fail", "App login brute force", 6, 10 * time.Minute, 6 * time.Hour},
	{"rdp-auth-fail", "Remote desktop brute force", 5, 10 * time.Minute, 12 * time.Hour},
	{"vpn-auth-fail", "VPN handshake abuse", 10, 5 * time.Minute, 2 * time.Hour},
	{"orbis-auth-fail", "Orbis login brute force", 5, 10 * time.Minute, 1 * time.Hour},
	{"port-scan", "Port scan", 15, time.Minute, 2 * time.Hour},
	{"host-sweep", "Host sweep", 10, time.Minute, 2 * time.Hour},
	{"conn-flood", "Connection flood", 300, time.Minute, time.Hour},
	{"sensitive-probe", "Knocking on sensitive ports", 5, 5 * time.Minute, time.Hour},
}

func ruleFor(kind string) (Rule, bool) {
	for _, r := range Rules {
		if r.Kind == kind {
			return r, true
		}
	}
	return Rule{}, false
}

// windows keeps per-(kind, address) timestamps and answers "how many in the
// last window". Entries are pruned as they are read and swept periodically.
type windows struct {
	mu   sync.Mutex
	hits map[string][]time.Time
}

func newWindows() *windows { return &windows{hits: map[string][]time.Time{}} }

// add records weight hits now and returns how many fall inside window.
func (w *windows) add(key string, weight int, now time.Time, window time.Duration) int {
	w.mu.Lock()
	defer w.mu.Unlock()
	list := w.hits[key]
	cut := now.Add(-window)
	i := 0
	for i < len(list) && list[i].Before(cut) {
		i++
	}
	list = list[i:]
	for n := 0; n < weight; n++ {
		list = append(list, now)
	}
	if len(list) > 2000 {
		list = list[len(list)-2000:]
	}
	w.hits[key] = list
	return len(list)
}

// reset forgets a key after it fired, so a ban is not re-earned by the same
// hits.
func (w *windows) reset(key string) {
	w.mu.Lock()
	delete(w.hits, key)
	w.mu.Unlock()
}

// sweep drops keys with nothing recent.
func (w *windows) sweep(now time.Time, keep time.Duration) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for k, list := range w.hits {
		if len(list) == 0 || now.Sub(list[len(list)-1]) > keep {
			delete(w.hits, k)
		}
	}
}

// distinct tracks distinct values (ports, hosts) per key inside a window.
type distinct struct {
	mu   sync.Mutex
	seen map[string]map[string]time.Time
}

func newDistinct() *distinct { return &distinct{seen: map[string]map[string]time.Time{}} }

func (d *distinct) add(key, value string, now time.Time, window time.Duration) int {
	d.mu.Lock()
	defer d.mu.Unlock()
	m := d.seen[key]
	if m == nil {
		m = map[string]time.Time{}
		d.seen[key] = m
	}
	m[value] = now
	cut := now.Add(-window)
	for v, t := range m {
		if t.Before(cut) {
			delete(m, v)
		}
	}
	return len(m)
}

func (d *distinct) reset(key string) {
	d.mu.Lock()
	delete(d.seen, key)
	d.mu.Unlock()
}

func (d *distinct) sweep(now time.Time, keep time.Duration) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for k, m := range d.seen {
		stale := true
		for _, t := range m {
			if now.Sub(t) <= keep {
				stale = false
				break
			}
		}
		if stale {
			delete(d.seen, k)
		}
	}
}
