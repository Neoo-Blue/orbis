package adblock

import (
	"context"
	"fmt"
	"math"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Neoo-Blue/orbis/internal/config"
	"github.com/Neoo-Blue/orbis/internal/store"
)

// SmartCapture discovers ad and tracking infrastructure that no subscribed
// list covers. It works from evidence the node already collects — who asked
// for a name, which page referred to it, how the response behaved — scores it
// with explicit heuristics, and escalates only the genuinely ambiguous cases
// to the model. That ordering matters: heuristics are free and deterministic,
// so the model is asked a few dozen hard questions a day rather than tens of
// thousands of easy ones.
type SmartCapture struct {
	st      *store.Store
	cfg     *config.Config
	matcher *Matcher
	mgr     *Manager
	log     func(string, ...any)

	// judge is the AI escalation hook, set by the ai package. Nil means the
	// pipeline runs heuristics-only, which is a supported configuration.
	judge   Judge
	judgeMu sync.RWMutex

	mu sync.Mutex
	// obs accumulates evidence between scoring passes.
	obs map[string]*observation

	onBlock func(domain string, score float64, reason string)
}

// Judge is implemented by the ai package.
type Judge interface {
	JudgeDomains(ctx context.Context, batch []DomainEvidence) ([]DomainVerdict, error)
}

// DomainEvidence is what the model is shown. It is deliberately factual: no
// pre-computed verdict, no leading language, just the observations.
type DomainEvidence struct {
	Domain            string   `json:"domain"`
	Observations      int      `json:"request_count"`
	DistinctClients   int      `json:"distinct_devices"`
	ReferringSites    []string `json:"referring_sites,omitempty"`
	SampleClients     []string `json:"-"`
	FirstSeenHoursAgo float64  `json:"first_seen_hours_ago"`
	AvgResponseBytes  int64    `json:"avg_response_bytes,omitempty"`
	ThirdPartyRatio   float64  `json:"third_party_ratio"`
	SubdomainDepth    int      `json:"subdomain_depth"`
	LabelEntropy      float64  `json:"label_entropy"`
	ASOrg             string   `json:"network_operator,omitempty"`
	KeywordHits       []string `json:"name_keywords,omitempty"`
	SamplePaths       []string `json:"sample_paths,omitempty"`
	HeuristicScore    float64  `json:"heuristic_score"`
}

// DomainVerdict is the model's answer.
type DomainVerdict struct {
	Domain     string  `json:"domain"`
	IsAdTech   bool    `json:"is_ad_or_tracking"`
	Confidence float64 `json:"confidence"`
	Reason     string  `json:"reason"`
	// BreakageRisk lets the model veto a block that would break a site even
	// when the domain genuinely is ad infrastructure (e.g. a CDN that also
	// serves content).
	BreakageRisk string `json:"breakage_risk"`
}

type observation struct {
	domain     string
	count      int
	clients    map[string]struct{}
	referrers  map[string]struct{}
	paths      []string
	firstSeen  time.Time
	lastSeen   time.Time
	bytesTotal int64
	bytesCount int
	firstParty int
	thirdParty int
	asOrg      string
}

func NewSmartCapture(st *store.Store, cfg *config.Config, m *Matcher, mgr *Manager, log func(string, ...any)) *SmartCapture {
	if log == nil {
		log = func(string, ...any) {}
	}
	return &SmartCapture{
		st: st, cfg: cfg, matcher: m, mgr: mgr, log: log,
		obs: make(map[string]*observation),
	}
}

func (s *SmartCapture) SetJudge(j Judge) {
	s.judgeMu.Lock()
	s.judge = j
	s.judgeMu.Unlock()
}

func (s *SmartCapture) SetOnBlock(fn func(string, float64, string)) { s.onBlock = fn }

// ObserveRequest records one sighting. Called from the DNS path (name only)
// and the HTTP/MITM path (name plus referer and response size).
func (s *SmartCapture) ObserveRequest(domain, clientKey, referer, path string, respBytes int64, asOrg string) {
	d := normalize(domain)
	if d == "" || !s.enabled() {
		return
	}
	// Anything already decided is not a candidate.
	if r := s.matcher.Lookup(d); r.Blocked || r.Allowed {
		return
	}
	if isInfrastructure(d) {
		return
	}

	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	// Bound memory: a DNS flood must not be able to grow this map forever.
	if len(s.obs) > 50000 {
		if _, exists := s.obs[d]; !exists {
			return
		}
	}
	o := s.obs[d]
	if o == nil {
		o = &observation{
			domain:    d,
			clients:   map[string]struct{}{},
			referrers: map[string]struct{}{},
			firstSeen: now,
		}
		s.obs[d] = o
	}
	o.count++
	o.lastSeen = now
	if clientKey != "" {
		o.clients[clientKey] = struct{}{}
	}
	if asOrg != "" && o.asOrg == "" {
		o.asOrg = asOrg
	}
	if respBytes > 0 {
		o.bytesTotal += respBytes
		o.bytesCount++
	}
	if path != "" && len(o.paths) < 5 {
		if len(path) > 120 {
			path = path[:120]
		}
		o.paths = append(o.paths, path)
	}
	if referer != "" {
		refHost := normalize(referer)
		if refHost != "" {
			o.referrers[refHost] = struct{}{}
			// "Third party" means the referring page's registrable domain
			// differs from this one; that is the single strongest signal
			// separating an ad server from a site's own asset host.
			if registrable(refHost) == registrable(d) {
				o.firstParty++
			} else {
				o.thirdParty++
			}
		}
	}
}

func (s *SmartCapture) enabled() bool {
	c := s.cfg.Snapshot()
	return c.AdBlock.Enabled && c.AdBlock.SmartCapture.Enabled
}

// Run drives the scoring loop.
func (s *SmartCapture) Run(ctx context.Context) {
	cfg := s.cfg.Snapshot().AdBlock.SmartCapture
	interval := time.Duration(cfg.IntervalMinutes) * time.Minute
	if interval < time.Minute {
		interval = 15 * time.Minute
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := s.Pass(ctx); err != nil {
				s.log("smart-capture: pass failed: %v", err)
			}
		}
	}
}

// Pass flushes accumulated observations into the database, scores everything
// pending, and promotes the confident ones.
func (s *SmartCapture) Pass(ctx context.Context) error {
	if !s.enabled() {
		return nil
	}
	cfg := s.cfg.Snapshot().AdBlock.SmartCapture

	s.mu.Lock()
	batch := s.obs
	s.obs = make(map[string]*observation)
	s.mu.Unlock()

	evidence := make(map[string]DomainEvidence, len(batch))
	for d, o := range batch {
		for i := 0; i < o.count; i++ {
			if err := s.st.ObserveCandidate(d, len(o.clients), len(o.referrers)); err != nil {
				return err
			}
			if i > 50 {
				break // the count column saturates; the score does not need more
			}
		}
		evidence[d] = s.buildEvidence(o)
	}

	pending, err := s.st.PendingCandidates(cfg.MinObservations, 500)
	if err != nil {
		return err
	}
	if len(pending) == 0 {
		return nil
	}

	var ambiguous []DomainEvidence
	scored := 0
	for _, c := range pending {
		ev, ok := evidence[c.Domain]
		if !ok {
			ev = evidenceFromStored(c)
		}
		ev.Domain = c.Domain
		ev.Observations = c.Observations
		ev.DistinctClients = c.DistinctClients
		ev.FirstSeenHoursAgo = time.Since(c.FirstSeen).Hours()

		h := Heuristic(ev)
		ev.HeuristicScore = h
		final := h
		if err := s.st.ScoreCandidate(c.Domain, h, nil, "", final, ev.asMap()); err != nil {
			return err
		}
		scored++

		// The middle band is where a human (or a model) actually adds value.
		// Below it the domain is obviously benign; above it the heuristics
		// already agree with any reasonable reviewer.
		if h >= 0.45 && h < cfg.AutoBlockScore && cfg.UseAI {
			ambiguous = append(ambiguous, ev)
		} else if h >= cfg.AutoBlockScore {
			s.promote(c.Domain, h, fmt.Sprintf("heuristic score %.2f", h), "smart:heuristic")
		}
	}

	if len(ambiguous) > 0 {
		s.judgeMu.RLock()
		j := s.judge
		s.judgeMu.RUnlock()
		if j != nil {
			s.escalate(ctx, j, ambiguous, cfg)
		}
	}
	s.log("smart-capture: scored %d candidates, %d escalated", scored, len(ambiguous))
	return nil
}

func (s *SmartCapture) escalate(ctx context.Context, j Judge, batch []DomainEvidence, cfg config.SmartCaptureConfig) {
	// Highest-uncertainty first, and cap the batch: a model call per pass
	// should cost cents, not dollars.
	sort.Slice(batch, func(i, k int) bool {
		return math.Abs(batch[i].HeuristicScore-0.65) < math.Abs(batch[k].HeuristicScore-0.65)
	})
	if len(batch) > 40 {
		batch = batch[:40]
	}
	verdicts, err := j.JudgeDomains(ctx, batch)
	if err != nil {
		s.log("smart-capture: AI escalation failed: %v", err)
		return
	}
	byDomain := map[string]DomainEvidence{}
	for _, e := range batch {
		byDomain[e.Domain] = e
	}
	for _, v := range verdicts {
		ev, ok := byDomain[v.Domain]
		if !ok {
			continue
		}
		aiScore := v.Confidence
		if !v.IsAdTech {
			aiScore = 1 - v.Confidence
		}
		// Blend rather than replace: the heuristics encode observations the
		// model cannot see, and the model encodes knowledge the heuristics
		// cannot. Weighting the model higher reflects that it is only
		// consulted on cases where the heuristics were unsure.
		final := 0.4*ev.HeuristicScore + 0.6*aiScore
		if strings.EqualFold(v.BreakageRisk, "high") {
			// Never auto-block something the model flagged as breakage-prone;
			// cap it into the review band so a human decides.
			final = math.Min(final, cfg.AutoBlockScore-0.01)
		}
		_ = s.st.ScoreCandidate(v.Domain, ev.HeuristicScore, &aiScore, v.Reason, final, ev.asMap())

		switch {
		case final >= cfg.AutoBlockScore && v.IsAdTech:
			s.promote(v.Domain, final, v.Reason, "smart:ai")
		case final >= cfg.ReviewScore:
			_ = s.st.SetCandidateStatus(v.Domain, store.CandidateReview, "smart:ai")
		default:
			_ = s.st.SetCandidateStatus(v.Domain, store.CandidateDismissed, "smart:ai")
		}
	}
}

// promote turns a candidate into a live block, subject to the daily cap.
func (s *SmartCapture) promote(domain string, score float64, reason, by string) {
	cfg := s.cfg.Snapshot().AdBlock.SmartCapture
	n, err := s.st.AutoBlocksToday()
	if err == nil && cfg.MaxAutoBlocksPerDay > 0 && n >= cfg.MaxAutoBlocksPerDay {
		// Hitting the cap is a signal something is wrong upstream, so it goes
		// to review rather than being silently dropped.
		_ = s.st.SetCandidateStatus(domain, store.CandidateReview, by+":capped")
		return
	}
	if err := s.st.SaveLocalRule(store.LocalRule{
		Domain:   domain,
		Action:   "block",
		Wildcard: true,
		Origin:   strings.TrimPrefix(by, "smart:"),
		Note:     fmt.Sprintf("auto-blocked (%.2f): %s", score, reason),
	}); err != nil {
		s.log("smart-capture: promote %s: %v", domain, err)
		return
	}
	_ = s.st.SetCandidateStatus(domain, store.CandidateBlocked, by)
	if err := s.mgr.Rebuild(); err != nil {
		s.log("smart-capture: rebuild after promote: %v", err)
	}
	s.log("smart-capture: blocked %s (%.2f) — %s", domain, score, reason)
	if s.onBlock != nil {
		s.onBlock(domain, score, reason)
	}
}

// Decide applies an operator's manual verdict from the review queue.
func (s *SmartCapture) Decide(domain, decision, actor string) error {
	switch decision {
	case "block":
		if err := s.st.SaveLocalRule(store.LocalRule{
			Domain: domain, Action: "block", Wildcard: true, Origin: "user",
			Note: "approved from smart-capture queue",
		}); err != nil {
			return err
		}
		if err := s.st.SetCandidateStatus(domain, store.CandidateBlocked, actor); err != nil {
			return err
		}
	case "allow":
		if err := s.st.SaveLocalRule(store.LocalRule{
			Domain: domain, Action: "allow", Wildcard: false, Origin: "user",
			Note: "dismissed from smart-capture queue",
		}); err != nil {
			return err
		}
		if err := s.st.SetCandidateStatus(domain, store.CandidateDismissed, actor); err != nil {
			return err
		}
	case "dismiss":
		return s.st.SetCandidateStatus(domain, store.CandidateDismissed, actor)
	default:
		return fmt.Errorf("unknown decision %q", decision)
	}
	return s.mgr.Rebuild()
}

func (s *SmartCapture) buildEvidence(o *observation) DomainEvidence {
	ev := DomainEvidence{
		Domain:          o.domain,
		Observations:    o.count,
		DistinctClients: len(o.clients),
		SamplePaths:     o.paths,
		ASOrg:           o.asOrg,
		SubdomainDepth:  strings.Count(o.domain, "."),
		LabelEntropy:    labelEntropy(o.domain),
		KeywordHits:     keywordHits(o.domain),
	}
	for r := range o.referrers {
		if len(ev.ReferringSites) < 12 {
			ev.ReferringSites = append(ev.ReferringSites, r)
		}
	}
	sort.Strings(ev.ReferringSites)
	if total := o.firstParty + o.thirdParty; total > 0 {
		ev.ThirdPartyRatio = float64(o.thirdParty) / float64(total)
	}
	if o.bytesCount > 0 {
		ev.AvgResponseBytes = o.bytesTotal / int64(o.bytesCount)
	}
	if !o.firstSeen.IsZero() {
		ev.FirstSeenHoursAgo = time.Since(o.firstSeen).Hours()
	}
	return ev
}

func evidenceFromStored(c store.AdCandidate) DomainEvidence {
	return DomainEvidence{
		Domain:          c.Domain,
		Observations:    c.Observations,
		DistinctClients: c.DistinctClients,
		SubdomainDepth:  strings.Count(c.Domain, "."),
		LabelEntropy:    labelEntropy(c.Domain),
		KeywordHits:     keywordHits(c.Domain),
	}
}

func (e DomainEvidence) asMap() map[string]any {
	return map[string]any{
		"requests":          e.Observations,
		"devices":           e.DistinctClients,
		"referrers":         e.ReferringSites,
		"third_party_ratio": e.ThirdPartyRatio,
		"avg_bytes":         e.AvgResponseBytes,
		"entropy":           e.LabelEntropy,
		"keywords":          e.KeywordHits,
		"as_org":            e.ASOrg,
		"paths":             e.SamplePaths,
	}
}

// ClientKeyFor produces the anonymised per-device key used in evidence, so
// the model never sees a raw address.
func ClientKeyFor(addr netip.Addr) string {
	s := addr.String()
	if len(s) > 6 {
		return s[:6] + "…"
	}
	return s
}
