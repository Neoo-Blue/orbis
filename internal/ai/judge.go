package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Neoo-Blue/orbis/internal/adblock"
)

// Judge implements adblock.Judge: it adjudicates the domains the heuristics
// could not decide on their own.
type Judge struct {
	client *Client
	log    func(string, ...any)
}

func NewJudge(c *Client, log func(string, ...any)) *Judge {
	if log == nil {
		log = func(string, ...any) {}
	}
	return &Judge{client: c, log: log}
}

const judgePrompt = `You classify hostnames observed on a home or small-office network as
advertising/tracking infrastructure or as legitimate service infrastructure.

You are given behavioural evidence gathered by the network itself, not a description. Weigh it:

- third_party_ratio near 1.0 with many distinct referring_sites is the signature of an ad
  network or a tracker. A host loaded only from its own site is almost never one.
- Tiny avg_response_bytes (under ~1 KB) with high request counts means beacons.
- name_keywords are suggestive but not decisive on their own. Plenty of legitimate services have
  "metrics" or "analytics" in the name, and plenty of ad servers have neutral names.
- High label entropy with deep subdomains suggests generated hostnames, which ad networks use to
  evade static lists — but CDN shards look identical, so do not over-weight it.

Blocking the wrong thing is worse than missing an ad. Set breakage_risk to "high" when blocking
would plausibly break something the user cares about: a CDN that also serves site assets, a
push-notification endpoint, an auth or payment provider, an OS update or time service, a
certificate/OCSP responder, or a first-party API for a service the user is actively using.
Consent-management and session-replay hosts are tracking, but blocking them sometimes blocks the
page too — mark those "medium".

Answer with a JSON array and nothing else. One object per domain you were given:
[{"domain":"...","is_ad_or_tracking":true,"confidence":0.0-1.0,"reason":"one sentence","breakage_risk":"low|medium|high"}]

confidence is how sure you are of the verdict you gave, not how sure you are that it is an ad.
Keep reason to one sentence naming the evidence that decided it.`

func (j *Judge) JudgeDomains(ctx context.Context, batch []adblock.DomainEvidence) ([]adblock.DomainVerdict, error) {
	if !j.client.Configured() {
		return nil, fmt.Errorf("AI not configured")
	}
	if len(batch) == 0 {
		return nil, nil
	}

	payload, err := json.MarshalIndent(batch, "", "  ")
	if err != nil {
		return nil, err
	}
	msg := fmt.Sprintf("Classify these %d hostnames.\n\n%s", len(batch), payload)

	// The fast model is deliberate: this is a high-volume, well-specified
	// classification with tight output constraints, not open reasoning.
	resp, err := j.client.Complete(ctx, judgePrompt, []Message{{Role: RoleUser, Content: msg}}, nil, true)
	if err != nil {
		return nil, err
	}

	verdicts, err := parseVerdicts(resp.Text)
	if err != nil {
		return nil, fmt.Errorf("could not parse model output: %w", err)
	}

	// Only accept verdicts for domains we actually asked about; a model that
	// invents a hostname must not be able to get it auto-blocked.
	asked := make(map[string]bool, len(batch))
	for _, e := range batch {
		asked[strings.ToLower(e.Domain)] = true
	}
	out := make([]adblock.DomainVerdict, 0, len(verdicts))
	for _, v := range verdicts {
		d := strings.ToLower(strings.TrimSpace(v.Domain))
		if !asked[d] {
			j.log("judge: ignoring verdict for unrequested domain %q", v.Domain)
			continue
		}
		v.Domain = d
		if v.Confidence < 0 {
			v.Confidence = 0
		}
		if v.Confidence > 1 {
			v.Confidence = 1
		}
		out = append(out, v)
	}
	j.log("judge: %d/%d verdicts accepted (%d in, %d out tokens)",
		len(out), len(batch), resp.TokensIn, resp.TokensOut)
	return out, nil
}

// parseVerdicts tolerates the fenced-code-block and preamble habits models
// fall into despite being told to emit bare JSON.
func parseVerdicts(text string) ([]adblock.DomainVerdict, error) {
	s := strings.TrimSpace(text)
	if i := strings.Index(s, "```"); i >= 0 {
		s = s[i+3:]
		if j := strings.IndexByte(s, '\n'); j >= 0 {
			// Drop the language tag on the fence line.
			if !strings.Contains(s[:j], "[") && !strings.Contains(s[:j], "{") {
				s = s[j+1:]
			}
		}
		if k := strings.Index(s, "```"); k >= 0 {
			s = s[:k]
		}
	}
	start := strings.IndexByte(s, '[')
	end := strings.LastIndexByte(s, ']')
	if start < 0 || end <= start {
		return nil, fmt.Errorf("no JSON array found in output")
	}
	var out []adblock.DomainVerdict
	if err := json.Unmarshal([]byte(s[start:end+1]), &out); err != nil {
		return nil, err
	}
	return out, nil
}
