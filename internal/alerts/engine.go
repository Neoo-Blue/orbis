// Package alerts is a user-defined trigger engine. The statistical anomaly
// detectors answer "is anything unusual"; this answers "tell me when THIS
// happens" — a named device goes offline, a domain is queried, throughput
// crosses a line. Both feed the same event stream and the same notification
// sinks, so an alert reaches a webhook or an inbox the same way an anomaly does.
package alerts

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

// Rule is one operator-defined trigger.
type Rule struct {
	ID              string  `json:"id" yaml:"id"`
	Name            string  `json:"name" yaml:"name"`
	Enabled         bool    `json:"enabled" yaml:"enabled"`
	Type            string  `json:"type" yaml:"type"`
	Match           string  `json:"match" yaml:"match"`
	Threshold       float64 `json:"threshold" yaml:"threshold"`
	Severity        string  `json:"severity" yaml:"severity"`
	CooldownMinutes int     `json:"cooldown_minutes" yaml:"cooldown_minutes"`
}

const (
	TypeNewDevice     = "new_device"
	TypeDeviceOffline = "device_offline"
	TypeBandwidth     = "bandwidth"
	TypeDomain        = "domain"
	TypeBlockedRate   = "blocked_rate"
)

// Backend is the slice of app state the engine reads.
type Backend interface {
	AlertDevices() []DeviceSnapshot
	ThroughputMbps() float64
	RecentDomains(since time.Time) []string
	BlockedPerMinute() float64
}

// DeviceSnapshot is the device view the engine needs.
type DeviceSnapshot struct {
	ID, IP, Label       string
	LastSeen, FirstSeen time.Time
	Online              bool
}

// Fired is one alert the engine produced.
type Fired struct {
	Severity string
	Title    string
	Detail   string
}

// Engine evaluates rules and remembers when each last fired.
type Engine struct {
	cfg  func() []Rule
	back Backend

	mu       sync.Mutex
	lastFire map[string]time.Time
	lastEval time.Time
	seen     map[string]bool
}

func NewEngine(cfg func() []Rule, back Backend) *Engine {
	return &Engine{cfg: cfg, back: back, lastFire: map[string]time.Time{}, seen: map[string]bool{}}
}

// Evaluate runs every rule once and returns whatever fired. The caller raises
// each result into the event stream, which is where notification happens.
func (e *Engine) Evaluate(now time.Time) []Fired {
	rules := e.cfg()
	var out []Fired
	e.mu.Lock()
	since := e.lastEval
	if since.IsZero() {
		since = now.Add(-time.Minute)
	}
	e.lastEval = now
	e.mu.Unlock()

	for _, r := range rules {
		if !r.Enabled {
			continue
		}
		f, ok := e.evalRule(r, now, since)
		if !ok {
			continue
		}
		if e.onCooldown(r, now) {
			continue
		}
		e.markFired(r, now)
		out = append(out, f)
	}
	return out
}

func (e *Engine) evalRule(r Rule, now, since time.Time) (Fired, bool) {
	sev := r.Severity
	if sev == "" {
		sev = "warning"
	}
	switch r.Type {
	case TypeNewDevice:
		for _, d := range e.back.AlertDevices() {
			if d.FirstSeen.After(since) {
				e.mu.Lock()
				already := e.seen[d.ID]
				e.seen[d.ID] = true
				e.mu.Unlock()
				if already {
					continue
				}
				return Fired{sev, r.Name, fmt.Sprintf("New device joined: %s (%s)", label(d), d.IP)}, true
			}
		}
	case TypeDeviceOffline:
		want := strings.ToLower(strings.TrimSpace(r.Match))
		for _, d := range e.back.AlertDevices() {
			if !matchDevice(d, want) {
				continue
			}
			mins := now.Sub(d.LastSeen).Minutes()
			if mins >= r.Threshold {
				return Fired{sev, r.Name,
					fmt.Sprintf("%s has been offline for %.0f minutes", label(d), mins)}, true
			}
		}
	case TypeBandwidth:
		mbps := e.back.ThroughputMbps()
		if mbps > r.Threshold {
			return Fired{sev, r.Name,
				fmt.Sprintf("Throughput is %.1f Mbps, over the %.0f Mbps threshold", mbps, r.Threshold)}, true
		}
	case TypeDomain:
		want := strings.ToLower(strings.TrimSpace(r.Match))
		if want == "" {
			return Fired{}, false
		}
		for _, name := range e.back.RecentDomains(since) {
			if strings.Contains(strings.ToLower(name), want) {
				return Fired{sev, r.Name, fmt.Sprintf("A device queried %q (matched %q)", name, want)}, true
			}
		}
	case TypeBlockedRate:
		rate := e.back.BlockedPerMinute()
		if rate > r.Threshold {
			return Fired{sev, r.Name,
				fmt.Sprintf("Blocking %.0f domains/min, over the %.0f/min threshold", rate, r.Threshold)}, true
		}
	}
	return Fired{}, false
}

func (e *Engine) onCooldown(r Rule, now time.Time) bool {
	cd := time.Duration(r.CooldownMinutes) * time.Minute
	if cd <= 0 {
		cd = 30 * time.Minute
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	last, ok := e.lastFire[r.ID]
	return ok && now.Sub(last) < cd
}

func (e *Engine) markFired(r Rule, now time.Time) {
	e.mu.Lock()
	e.lastFire[r.ID] = now
	e.mu.Unlock()
}

func matchDevice(d DeviceSnapshot, want string) bool {
	if want == "" {
		return false
	}
	return strings.ToLower(d.IP) == want ||
		strings.Contains(strings.ToLower(d.Label), want) ||
		d.ID == want
}

func label(d DeviceSnapshot) string {
	if d.Label != "" {
		return d.Label
	}
	return d.IP
}
