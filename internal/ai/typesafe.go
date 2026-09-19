package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"time"

	"github.com/Neoo-Blue/orbis/internal/adblock"
	"github.com/Neoo-Blue/orbis/internal/config"
	"github.com/Neoo-Blue/orbis/internal/store"
)

// TypeSafe's System One API takes a state and typed questions and returns
// probabilities, which is the shape the domain judgment already has: the
// model supplies the judgment, the smart-capture code keeps the thresholds.

// typeSafeURL is a variable so tests can point it at a local server.
var typeSafeURL = "https://api.typesafe.ai/v1/systemone"

const typeSafeModel = "jev-latest"

// typeSafeQuestions are asked about one domain's evidence at a time (see
// typeSafeState), so each judgment sees only its own observations.
var typeSafeQuestions = map[string]any{
	"ad": map[string]any{
		"type": "noul",
		"instructions": "This is what a home network observed about the hostname `domain`. Is it " +
			"advertising or tracking infrastructure: ad serving, ad verification, attribution, analytics " +
			"or telemetry beacons, trackers? When `http` is present, a `third_party_ratio` near 1 across " +
			"many `referring_sites` and a tiny `avg_response_bytes` point to beacons and ad networks, and a " +
			"host loaded only from its own site rarely is one. Otherwise judge from the hostname and what " +
			"is known about its operator. A BitTorrent tracker is not a tracker in this sense.",
		"criteria": map[string]string{
			"true":  "Ad network, ad verification, tracker, analytics or telemetry endpoint",
			"false": "Content, API, CDN, authentication, payment, update, time or other service infrastructure",
		},
	},
	"breakage": map[string]any{
		"type":         "choice",
		"instructions": "If the hostname `domain` were blocked by DNS on this network, how likely is it that something a person uses would break?",
		"criteria": map[string]string{
			"low":    "Nothing visible breaks; only ads, tracking or telemetry disappear",
			"medium": "Some pages or apps may misbehave, e.g. consent managers or session replay loaded inline",
			"high":   "Likely breakage: a CDN that also serves site assets, push notifications, sign-in or payment, OS updates, time, certificate or OCSP checks, or a first-party API",
		},
	},
}

type typeSafeAnswer struct {
	Type          string             `json:"type"`
	Noul          float64            `json:"noul"`
	Choice        string             `json:"choice"`
	Probabilities map[string]float64 `json:"probabilities"`
}

type typeSafeResponse struct {
	Model   string                    `json:"model"`
	Answers map[string]typeSafeAnswer `json:"answers"`
	Usage   struct {
		InputTokens  int `json:"input_tokens"`
		OutputTokens int `json:"output_tokens"`
	} `json:"usage"`
}

// typeSafeState is the evidence as Jev sees it. The HTTP fields go in only
// when they were measured: sent as zeros they would read as "first-party".
// The heuristic score stays out so the judgment is independent of it. No
// client addresses: DomainEvidence never carries them in JSON.
func typeSafeState(ev adblock.DomainEvidence) map[string]any {
	st := map[string]any{
		"domain":               ev.Domain,
		"request_count":        ev.Observations,
		"distinct_devices":     ev.DistinctClients,
		"first_seen_hours_ago": math.Round(ev.FirstSeenHoursAgo),
	}
	if ev.ASOrg != "" {
		st["network_operator"] = ev.ASOrg
	}
	if ev.DNSOnly() {
		st["observed"] = "DNS lookups only"
	} else {
		st["http"] = map[string]any{
			"referring_sites":    ev.ReferringSites,
			"third_party_ratio":  ev.ThirdPartyRatio,
			"avg_response_bytes": ev.AvgResponseBytes,
			"sample_paths":       ev.SamplePaths,
		}
	}
	return st
}

// typeSafeKey is the key to use, or "" when TypeSafe is off.
func typeSafeKey(cfg *config.Config) string {
	ts := cfg.Snapshot().AI.TypeSafe
	if !ts.Enabled {
		return ""
	}
	return ts.APIKey
}

// askTypeSafe sends one evaluation. 429 and 5xx (529 is TypeSafe's
// "overloaded") are retried with backoff, as the API docs ask.
func (c *Client) askTypeSafe(ctx context.Context, key string, state, questions any) (*typeSafeResponse, error) {
	body := map[string]any{"state": state, "model": typeSafeModel, "questions": questions}
	var raw []byte
	var err error
	for attempt := 0; ; attempt++ {
		raw, err = c.post(ctx, typeSafeURL, body, map[string]string{"Authorization": "Bearer " + key})
		pe, ok := err.(*ProviderError)
		if !ok || (pe.Status != 429 && pe.Status < 500) || attempt == 2 {
			break
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(time.Duration(1+2*attempt) * time.Second):
		}
	}
	if err != nil {
		return nil, fmt.Errorf("TypeSafe: %w", err)
	}
	var out typeSafeResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("TypeSafe: %w", err)
	}
	return &out, nil
}

// judgeTypeSafe asks about each domain in turn. At ~0.3 s a request a full
// 40-domain pass takes seconds, which a background pass every few minutes
// does not notice. ponytail: sequential; fan out if batches grow past ~200.
func (j *Judge) judgeTypeSafe(ctx context.Context, key string, batch []adblock.DomainEvidence) ([]adblock.DomainVerdict, error) {
	out := make([]adblock.DomainVerdict, 0, len(batch))
	var lastErr error
	tokensIn, tokensOut := 0, 0
	for _, ev := range batch {
		resp, err := j.client.askTypeSafe(ctx, key, typeSafeState(ev), typeSafeQuestions)
		if err != nil {
			if _, retriable := classify(err); !retriable || ctx.Err() != nil {
				// A bad key or a cancelled pass is the same for every domain.
				return nil, err
			}
			lastErr = err
			j.log("judge: TypeSafe: %s: %v", ev.Domain, err)
			continue
		}
		v, err := typeSafeVerdict(ev.Domain, resp)
		if err != nil {
			lastErr = err
			j.log("judge: TypeSafe: %s: %v", ev.Domain, err)
			continue
		}
		tokensIn += resp.Usage.InputTokens
		tokensOut += resp.Usage.OutputTokens
		out = append(out, v)
	}
	if len(out) == 0 && lastErr != nil {
		return nil, lastErr
	}
	j.log("judge: %d/%d TypeSafe verdicts (%d in, %d out tokens)", len(out), len(batch), tokensIn, tokensOut)
	return out, nil
}

func typeSafeVerdict(domain string, r *typeSafeResponse) (adblock.DomainVerdict, error) {
	ad, ok := r.Answers["ad"]
	brk, ok2 := r.Answers["breakage"]
	if !ok || !ok2 || ad.Type != "noul" || brk.Type != "choice" {
		return adblock.DomainVerdict{}, fmt.Errorf("TypeSafe answered without the expected judgments")
	}
	p := clamp01(ad.Noul)
	risk := brk.Choice
	// Blocking the wrong thing is worse than missing an ad, so a strong
	// minority vote for breakage is enough to keep a human in the loop.
	if brk.Probabilities["high"] >= 0.4 {
		risk = "high"
	}
	conf := p
	if p < 0.5 {
		conf = 1 - p
	}
	return adblock.DomainVerdict{
		Domain:       domain,
		IsAdTech:     p >= 0.5,
		Confidence:   conf,
		BreakageRisk: risk,
		Reason:       fmt.Sprintf("TypeSafe: %.0f%% likely ad or tracking, breakage risk %s", math.Round(p*100), risk),
	}, nil
}

// typeSafeTriageQuestions ask what ordinary cause, if any, explains an
// anomaly finding. The answer's "unexplained" share decides the severity.
var typeSafeTriageQuestions = map[string]any{
	"explanation": map[string]any{
		"type": "choice",
		"instructions": "A home-network monitor flagged `finding` for the device `device`. Detectors are " +
			"statistical, so most findings have an ordinary cause. What is the most likely explanation, given " +
			"the device and the destination's name, port, country and network operator?",
		"criteria": map[string]string{
			"updates":     "Software, firmware or configuration checks",
			"sync":        "Cloud sync, backup or file transfer the device is set up for",
			"keepalive":   "Push notifications, messaging, or a connection keepalive",
			"monitoring":  "Status, uptime or health polling",
			"tunnel":      "A VPN, tunnel or remote-access service the owner runs",
			"p2p":         "BitTorrent, Usenet or other peer-to-peer traffic",
			"streaming":   "Media streaming or a smart-TV app",
			"household":   "A household device joining or behaving as its kind normally does",
			"unexplained": "No ordinary explanation fits: possible malware, stalkerware or unwanted remote access",
		},
	},
}

var triageLabels = map[string]string{
	"updates": "software or configuration checks", "sync": "sync or backup", "keepalive": "push or keepalive traffic",
	"monitoring": "status polling", "tunnel": "a tunnel or remote-access service", "p2p": "peer-to-peer traffic",
	"streaming": "streaming", "household": "an ordinary household device", "unexplained": "unexplained",
}

var sevRank = map[string]int{store.SevInfo: 0, store.SevNotice: 1, store.SevWarning: 2, store.SevCritical: 3}

// triageTypeSafe judges each finding on its own. It can only lower what a
// detector said: a finding with no ordinary explanation keeps the detector's
// severity. Nothing is recorded if the key is refused, so the caller can fall
// back to the chat model with the whole batch.
func (a *Analyzer) triageTypeSafe(ctx context.Context, findings []Finding) error {
	key := typeSafeKey(a.cfg)
	devices := map[string]store.Client{}
	if cs, err := a.st.Clients(); err == nil {
		for _, c := range cs {
			devices[c.ID] = c
		}
	}
	notes := make([]string, len(findings))
	for i := range findings {
		f := &findings[i]
		resp, err := a.client.askTypeSafe(ctx, key, triageState(*f, devices[f.ClientID]), typeSafeTriageQuestions)
		if err != nil {
			if _, retriable := classify(err); !retriable || ctx.Err() != nil {
				return err
			}
			a.log("anomaly: TypeSafe: %s: %v", f.Title, err)
			continue
		}
		ans, ok := resp.Answers["explanation"]
		if !ok || ans.Type != "choice" {
			continue
		}
		u := ans.Probabilities["unexplained"]
		switch {
		case u >= 0.5:
		case u >= 0.2:
			if sevRank[f.Severity] > sevRank[store.SevNotice] {
				f.Severity = store.SevNotice
			}
		default:
			f.Severity = store.SevInfo
		}
		notes[i] = fmt.Sprintf("TypeSafe: most likely %s (%.0f%%), %.0f%% unexplained.",
			triageLabels[ans.Choice], math.Round(ans.Probabilities[ans.Choice]*100), math.Round(u*100))
	}
	for i, f := range findings {
		a.record(f, notes[i])
	}
	return nil
}

var ipv4Text = regexp.MustCompile(`\b\d{1,3}(?:\.\d{1,3}){3}\b`)

// redactLAN replaces local addresses in text. Public ones stay: where a
// device was talking to is the evidence.
func redactLAN(s string) string {
	return ipv4Text.ReplaceAllStringFunc(s, func(ip string) string {
		if localDestination(ip) {
			return "a local device"
		}
		return ip
	})
}

// triageState is a finding as TypeSafe sees it, without LAN addresses or
// hardware addresses.
func triageState(f Finding, c store.Client) map[string]any {
	ev := map[string]any{}
	for k, v := range f.Evidence {
		if k == "ip" || k == "mac" || k == "client_ip" {
			continue
		}
		if s, ok := v.(string); ok {
			v = redactLAN(s)
		}
		ev[k] = v
	}
	f.Title, f.Detail = redactLAN(f.Title), redactLAN(f.Detail)
	dev := map[string]any{}
	name := c.Label
	if name == "" {
		name = c.Hostname
	}
	for k, v := range map[string]string{"name": name, "vendor": c.Vendor, "type": c.DeviceType, "os": c.OSGuess} {
		if v != "" && v != "unknown" {
			dev[k] = v
		}
	}
	return map[string]any{
		"finding": map[string]any{"kind": f.Kind, "title": f.Title, "detail": f.Detail, "evidence": ev},
		"device":  dev,
	}
}
