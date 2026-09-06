package threat

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Neoo-Blue/orbis/internal/store"
)

// A CrowdSec decision as the Local API's bouncer endpoint serializes it.
type csDecision struct {
	ID       int64  `json:"id"`
	Origin   string `json:"origin"`
	Type     string `json:"type"`
	Scope    string `json:"scope"`
	Value    string `json:"value"`
	Duration string `json:"duration"`
	Scenario string `json:"scenario"`
}

type csStream struct {
	New     []csDecision `json:"new"`
	Deleted []csDecision `json:"deleted"`
}

const crowdsecSource = "crowdsec"

// pollCrowdSec pulls the decision stream. The first pull after start, or
// after the URL or key changed, asks for the whole state; later pulls get
// deltas. Only bans are enforced: a gateway cannot serve a captcha.
func (m *Manager) pollCrowdSec(ctx context.Context) {
	cs := m.cfg.Snapshot().Threat.CrowdSec
	if !cs.Enabled || cs.URL == "" || cs.APIKey == "" {
		return
	}
	m.csMu.Lock()
	startup := m.csStartup || cs.URL != m.csURL || cs.APIKey != m.csKey
	m.csMu.Unlock()

	stream, err := m.fetchStream(ctx, cs.URL, cs.APIKey, startup)
	m.csMu.Lock()
	if err != nil {
		if m.csLastErr != err.Error() {
			m.log("threat: crowdsec: %v", err)
		}
		m.csLastErr = err.Error()
		m.csMu.Unlock()
		return
	}
	m.csLastErr = ""
	m.csLastPull = time.Now()
	m.csStartup = false
	m.csURL, m.csKey = cs.URL, cs.APIKey
	m.csMu.Unlock()

	changed := false
	m.mu.Lock()
	if startup {
		for id, d := range m.decisions {
			if d.Source == crowdsecSource {
				delete(m.decisions, id)
				changed = true
			}
		}
		if err := m.st.DeleteThreatDecisionsBySource(crowdsecSource); err != nil {
			m.log("threat: crowdsec: clear decisions: %v", err)
		}
	}
	now := time.Now()
	ignored := 0
	for _, d := range stream.New {
		if !strings.EqualFold(d.Type, "ban") {
			ignored++
			continue
		}
		p, ok := ParsePrefix(d.Value)
		if !ok || !Usable(p) || (strings.EqualFold(d.Scope, "Ip") == false && strings.EqualFold(d.Scope, "Range") == false) {
			ignored++
			continue
		}
		var until *time.Time
		if d.Duration != "" {
			dur, err := time.ParseDuration(d.Duration)
			if err != nil || dur <= 0 {
				continue
			}
			t := now.Add(dur)
			until = &t
		}
		dec := store.ThreatDecision{
			ID: "cs-" + strconv.FormatInt(d.ID, 10), Value: p.String(), Source: crowdsecSource,
			Reason: d.Scenario, Origin: d.Origin, ExternalID: d.ID, Actor: crowdsecSource,
			Created: now, Until: until,
		}
		m.decisions[dec.ID] = dec
		if err := m.st.PutThreatDecision(dec); err != nil {
			m.log("threat: crowdsec: store decision: %v", err)
		}
		changed = true
	}
	for _, d := range stream.Deleted {
		id := "cs-" + strconv.FormatInt(d.ID, 10)
		if _, ok := m.decisions[id]; ok {
			delete(m.decisions, id)
			_ = m.st.DeleteThreatDecision(id)
			changed = true
			continue
		}
		// Older engines delete by value; match on that as a fallback.
		if p, ok := ParsePrefix(d.Value); ok {
			for id, dec := range m.decisions {
				if dec.Source == crowdsecSource && dec.Value == p.String() {
					delete(m.decisions, id)
					_ = m.st.DeleteThreatDecision(id)
					changed = true
				}
			}
		}
	}
	m.mu.Unlock()
	m.csMu.Lock()
	m.csIgnored += ignored
	m.csMu.Unlock()
	if changed {
		m.rebuild()
	}
}

func (m *Manager) fetchStream(ctx context.Context, base, key string, startup bool) (*csStream, error) {
	url := strings.TrimRight(base, "/") + "/v1/decisions/stream?startup=" + strconv.FormatBool(startup)
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Api-Key", key)
	req.Header.Set("User-Agent", m.ua)
	req.Header.Set("Accept", "application/json")
	resp, err := m.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("local api unreachable: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusUnauthorized, http.StatusForbidden:
		return nil, fmt.Errorf("the local api rejected the bouncer key (http %d)", resp.StatusCode)
	default:
		return nil, fmt.Errorf("local api returned http %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var out csStream
	if len(strings.TrimSpace(string(body))) == 0 || string(body) == "null" {
		return &out, nil
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("local api sent something that is not a decision stream: %w", err)
	}
	return &out, nil
}

// TestCrowdSec checks a URL and key by asking for the full decision state. It
// also marks the poller for a fresh full pull, since the Local API tracks
// stream position per key and this call just consumed it.
func (m *Manager) TestCrowdSec(ctx context.Context, url, key string) (map[string]any, error) {
	if key == "" || strings.Contains(key, "•") {
		key = m.cfg.Snapshot().Threat.CrowdSec.APIKey
	}
	if url == "" {
		url = m.cfg.Snapshot().Threat.CrowdSec.URL
	}
	if url == "" || key == "" {
		return nil, fmt.Errorf("a local api url and a bouncer key are both needed")
	}
	stream, err := m.fetchStream(ctx, url, key, true)
	if err != nil {
		return nil, err
	}
	m.csMu.Lock()
	m.csStartup = true
	m.csMu.Unlock()
	bans := 0
	for _, d := range stream.New {
		if strings.EqualFold(d.Type, "ban") {
			bans++
		}
	}
	return map[string]any{"ok": true, "decisions": len(stream.New), "bans": bans}, nil
}

// crowdsecStatus is the bouncer's view for the UI.
func (m *Manager) crowdsecStatus() map[string]any {
	cs := m.cfg.Snapshot().Threat.CrowdSec
	m.csMu.Lock()
	defer m.csMu.Unlock()
	m.mu.RLock()
	n := 0
	for _, d := range m.decisions {
		if d.Source == crowdsecSource {
			n++
		}
	}
	m.mu.RUnlock()
	out := map[string]any{
		"enabled": cs.Enabled, "url": cs.URL, "configured": cs.URL != "" && cs.APIKey != "",
		"poll_seconds": cs.PollSeconds, "decisions": n, "ignored": m.csIgnored, "last_error": m.csLastErr,
	}
	if !m.csLastPull.IsZero() {
		out["last_pull"] = m.csLastPull
	}
	return out
}
