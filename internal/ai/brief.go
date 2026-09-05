package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/Neoo-Blue/orbis/internal/config"
	"github.com/Neoo-Blue/orbis/internal/store"
	"github.com/google/uuid"
)

// Briefer writes the periodic network check: a short note on what happened
// in the last window, anything worth a second look, and whether the node
// itself is healthy. It is the answer to "did anything happen while I was
// away" without having to open the chat and ask.
type Briefer struct {
	cfg     *config.Config
	client  *Client
	backend Backend
	st      *store.Store
	log     func(string, ...any)
	// record persists the brief as an event and, when notify is set, pushes
	// it through the notification sinks. The app owns both of those paths.
	record func(e store.Event, notify bool)

	mu      sync.Mutex
	running bool
	last    time.Time
}

func NewBriefer(cfg *config.Config, client *Client, backend Backend, st *store.Store,
	record func(e store.Event, notify bool), log func(string, ...any)) *Briefer {
	if log == nil {
		log = func(string, ...any) {}
	}
	if record == nil {
		record = func(store.Event, bool) {}
	}
	b := &Briefer{cfg: cfg, client: client, backend: backend, st: st, log: log, record: record}
	if st != nil {
		if prev, err := st.AIBriefs(1); err == nil && len(prev) > 0 {
			b.last = prev[0].TS
		}
	}
	return b
}

// Run checks once a minute whether a brief is due. The interval is read on
// every tick so a settings change takes effect without a restart.
func (b *Briefer) Run(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		cfg := b.cfg.Snapshot().AI
		if !cfg.Enabled || !cfg.Brief.Enabled || !b.client.Configured() {
			continue
		}
		interval := time.Duration(cfg.Brief.IntervalHours) * time.Hour
		if interval < time.Hour {
			interval = 6 * time.Hour
		}
		b.mu.Lock()
		due := time.Since(b.last) >= interval
		b.mu.Unlock()
		if !due {
			continue
		}
		hours := int(interval / time.Hour)
		if _, err := b.Generate(ctx, hours); err != nil && ctx.Err() == nil {
			b.log("brief: %v", err)
			// A failed brief still moves the clock a little so a stuck
			// provider is retried every ten minutes, not every minute.
			b.mu.Lock()
			b.last = time.Now().Add(-interval + 10*time.Minute)
			b.mu.Unlock()
		}
	}
}

const briefPrompt = `You write the periodic network brief inside Orbis, a home/small-office
firewall and DNS filter. The reader administers this network and will read the brief on their
phone in thirty seconds.

You are given JSON gathered by the node itself for the window: totals, top destinations, top
blocked domains, events, devices (including any new ones), subsystem health and, if present,
YouTube ad-skipping stats. Write from the data only. Do not invent numbers or devices.

Answer with a single JSON object and nothing else:
{"headline": "...", "severity": "info|notice|warning", "body": "..."}

- headline: one plain sentence, under 90 characters, that says the most important thing.
  "Quiet six hours: 3.1 GB, 14% of lookups blocked, nothing to look at" is a good headline.
- severity: "info" when nothing needs attention; "notice" when something is worth a look but
  is probably benign (a new device, an unusual destination); "warning" only when a subsystem
  is failing or a device is doing something that looks like exfiltration, scanning or
  command-and-control. Most briefs are "info".
- body: Markdown, at most 180 words, 3 to 6 short bullets. Cover: what the network did
  (real numbers, biggest talkers and destinations), anything worth a look with the specific
  device or domain and what would confirm or rule it out, and one line on node health
  (subsystems down, capture drops, blocklist errors). Most unexpected traffic is a CDN or
  telemetry; say so instead of raising alarm. No preamble, no sign-off.`

// Generate writes one brief covering the last hours. It uses the chat model
// family without tools: the evidence is handed over up front, so the call is
// one round-trip and works on models that cannot call tools reliably.
func (b *Briefer) Generate(ctx context.Context, hours int) (*store.AIBrief, error) {
	if !b.client.Configured() {
		return nil, fmt.Errorf("the assistant is not configured")
	}
	b.mu.Lock()
	if b.running {
		b.mu.Unlock()
		return nil, fmt.Errorf("a brief is already being written")
	}
	b.running = true
	b.mu.Unlock()
	defer func() {
		b.mu.Lock()
		b.running = false
		b.mu.Unlock()
	}()

	if hours <= 0 {
		hours = 6
	}
	if hours > 168 {
		hours = 168
	}
	since := time.Now().Add(-time.Duration(hours) * time.Hour)
	evidence := b.gather(since, hours)
	payload, err := jsonOf(evidence, nil)
	if err != nil {
		return nil, err
	}

	cctx, cancel := context.WithTimeout(ctx, 4*time.Minute)
	defer cancel()
	type briefOut struct {
		Headline string `json:"headline"`
		Severity string `json:"severity"`
		Body     string `json:"body"`
	}
	validate := func(text string) error {
		var probe briefOut
		if err := parseJSONObject(text, &probe); err != nil {
			return err
		}
		if strings.TrimSpace(probe.Headline) == "" || strings.TrimSpace(probe.Body) == "" {
			return fmt.Errorf("headline or body missing")
		}
		return nil
	}
	resp, err := b.client.CompleteJSON(cctx, briefPrompt,
		[]Message{{Role: RoleUser, Content: payload}}, false, validate)
	if err != nil {
		return nil, err
	}
	var out briefOut
	if err := parseJSONObject(resp.Text, &out); err != nil {
		return nil, fmt.Errorf("brief output unreadable: %w", err)
	}
	out.Headline = strings.TrimSpace(out.Headline)
	out.Body = strings.TrimSpace(out.Body)
	if out.Headline == "" {
		out.Headline = fmt.Sprintf("Network brief for the last %d hours", hours)
	}
	if len(out.Headline) > 140 {
		out.Headline = out.Headline[:140] + "…"
	}
	switch out.Severity {
	case store.SevNotice, store.SevWarning:
	default:
		out.Severity = store.SevInfo
	}

	brief := &store.AIBrief{
		ID: uuid.NewString(), TS: time.Now(), Hours: hours, Model: resp.Model,
		Severity: out.Severity, Headline: out.Headline, Body: out.Body,
	}
	if b.st != nil {
		if err := b.st.SaveAIBrief(*brief); err != nil {
			return nil, err
		}
		_ = b.st.PruneAIBriefs(120)
	}
	b.record(store.Event{
		ID: uuid.NewString(), TS: brief.TS, Severity: brief.Severity,
		Category: "ai:brief", Title: brief.Headline, Detail: brief.Body,
		Data: map[string]any{"hours": hours, "model": resp.Model, "brief_id": brief.ID},
	}, b.cfg.Snapshot().AI.Brief.Notify)

	b.mu.Lock()
	b.last = brief.TS
	b.mu.Unlock()
	b.log("brief: %s (%s, %d in / %d out tokens)", brief.Headline, resp.Model, resp.TokensIn, resp.TokensOut)
	return brief, nil
}

// gather assembles the evidence. Everything here is what the dashboard
// already shows; the brief is a reading of it, not a new data source.
func (b *Briefer) gather(since time.Time, hours int) map[string]any {
	out := map[string]any{
		"window_hours": hours,
		"since":        since.Format(time.RFC3339),
		"now":          time.Now().Format(time.RFC3339),
	}
	if sum, err := b.backend.Summary(since); err == nil {
		out["summary"] = sum
	}
	if rows, err := b.backend.TopDestinations(since, "", 8); err == nil {
		out["top_destinations"] = rows
	}
	if rows, err := b.backend.TopBlocked(since, 8); err == nil {
		out["top_blocked"] = rows
	}
	if rows, err := b.backend.CountryTotals(since); err == nil {
		if len(rows) > 8 {
			rows = rows[:8]
		}
		out["top_countries"] = rows
	}
	if events, err := b.backend.Events(since, store.SevNotice, false, 40); err == nil {
		compact := make([]map[string]any, 0, len(events))
		for _, e := range events {
			if e.Category == "ai:brief" {
				continue
			}
			compact = append(compact, map[string]any{
				"time": e.TS.Format(time.RFC3339), "severity": e.Severity,
				"category": e.Category, "title": e.Title, "acknowledged": e.Ack,
			})
		}
		out["events"] = compact
	}

	clients := b.backend.Clients()
	online, blocked := 0, 0
	var fresh []map[string]any
	for _, c := range clients {
		if c.Online {
			online++
		}
		if c.Blocked {
			blocked++
		}
		if c.FirstSeen.After(since) {
			fresh = append(fresh, map[string]any{
				"name": displayName(c), "ip": c.IP, "vendor": c.Vendor, "type": c.DeviceType,
				"first_seen": c.FirstSeen.Format(time.RFC3339),
			})
		}
	}
	out["devices"] = map[string]any{
		"total": len(clients), "online": online, "blocked": blocked, "new_in_window": fresh,
	}

	status := b.backend.SystemStatus()
	health := map[string]any{}
	for _, k := range []string{"mode", "uptime_sec", "capture", "dns", "adblock", "firewall", "dhcp"} {
		if v, ok := status[k]; ok {
			health[k] = v
		}
	}
	if fp, ok := status["filter_proxy"].(map[string]any); ok {
		health["filter_proxy"] = map[string]any{"running": fp["running"], "error": fp["error"]}
	}
	out["node_health"] = health

	if b.st != nil {
		if notes, err := b.st.Notes(25); err == nil && len(notes) > 0 {
			var lines []string
			for _, n := range notes {
				lines = append(lines, n.Note)
			}
			out["operator_notes"] = lines
		}
	}
	if yt := b.backend.YouTubeStatus(); yt != nil {
		// Only the per-screen counters matter here; discovery and coverage
		// tables are UI furniture.
		if raw, err := json.Marshal(yt); err == nil {
			var m map[string]any
			if json.Unmarshal(raw, &m) == nil {
				out["youtube"] = map[string]any{"enabled": m["enabled"], "devices": m["devices"]}
			}
		}
	}
	return out
}

// parseJSONObject tolerates fences and preamble around a JSON object.
func parseJSONObject(text string, out any) error {
	s := strings.TrimSpace(text)
	if i := strings.Index(s, "```"); i >= 0 {
		s = s[i+3:]
		if j := strings.IndexByte(s, '\n'); j >= 0 && !strings.Contains(s[:j], "{") {
			s = s[j+1:]
		}
		if k := strings.Index(s, "```"); k >= 0 {
			s = s[:k]
		}
	}
	start := strings.IndexByte(s, '{')
	end := strings.LastIndexByte(s, '}')
	if start < 0 || end <= start {
		return fmt.Errorf("no JSON object found in output")
	}
	return json.Unmarshal([]byte(s[start:end+1]), out)
}
