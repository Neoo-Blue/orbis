package ai

import (
	"context"
	"fmt"
	"math"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Neoo-Blue/orbis/internal/config"
	"github.com/Neoo-Blue/orbis/internal/store"
	"github.com/google/uuid"
)

// AutoUnblockActor marks the allows the unblocker applied on its own, so
// undo and expiry can tell them from the operator's.
const AutoUnblockActor = "typesafe:auto"

// The gates are code, not model output. A name must be blocked only by ad or
// tracking lists; the model says what the host is for; how many lists agree
// tells over-blocking by one aggressive list from a host everyone blocks.
// ponytail: fixed thresholds, tuned on one home network (2026-09-19); make
// them settings if other networks disagree.
const (
	unblockSuggestNeed     = 0.8
	unblockSuggestMaxLists = 3
	unblockAutoNeed        = 0.9
	unblockAutoMaxLists    = 2
	unblockAutoPerDay      = 3
	unblockAutoKeep        = 7 * 24 * time.Hour
	unblockCandidates      = 40
)

// unblockNeeded are host jobs a person notices breaking. "content" suggests
// but never auto-allows: an ad network's image host looks like a CDN.
var unblockNeeded = map[string]bool{"push": true, "signin": true, "app_api": true, "updates": true, "content": true}

var typeSafeUnblockQuestions = map[string]any{
	"function": map[string]any{
		"type":         "choice",
		"instructions": "What is the main job of the hostname `domain`? `device_kinds` are the kinds of devices that looked it up.",
		"criteria": map[string]string{
			"ads":       "Serving or selecting advertisements, ad verification, ad measurement",
			"tracking":  "Cross-site tracking, marketing attribution, analytics or session recording",
			"telemetry": "Usage telemetry, diagnostics, crash or error reporting, performance monitoring sent back to a vendor",
			"push":      "Push-notification delivery or registration for apps or the operating system",
			"signin":    "Sign-in, authentication, account or licence checks",
			"app_api":   "An app's or service's own API that its features call (feeds, messages, settings, feature flags)",
			"content":   "Page, image, video or file delivery, including CDNs serving a site's own assets",
			"updates":   "Software, firmware or component updates and configuration downloads",
			"dns":       "A DNS resolver or DNS-over-HTTPS/TLS endpoint",
			"other":     "None of these",
		},
	},
}

var unblockLabels = map[string]string{
	"push": "push-notification", "signin": "sign-in", "app_api": "app API", "content": "content", "updates": "update",
}

// Unblocker looks at the names devices keep getting refused and asks
// TypeSafe what each is for. A push, sign-in, app-API, update or content host
// that only a few ad lists carry is likely collateral damage: it becomes an
// allow suggestion in the Blocklist specialist's queue, and with auto_unblock
// on, the clearest cases are allowed at once, a few a day, each announced,
// undoable, and withdrawn after a week unless something still uses it.
type Unblocker struct {
	cfg     *config.Config
	client  *Client
	st      *store.Store
	dnsLog  func(since time.Time, blockedOnly bool, search string, limit int) ([]store.DNSQuery, error)
	clients func() []store.Client
	allow   func(domain, note string) error
	revoke  func(domain string) error
	record  func(e store.Event, notify bool)
	log     func(string, ...any)

	mu    sync.Mutex
	asked map[string]time.Time
}

func NewUnblocker(cfg *config.Config, client *Client, st *store.Store,
	dnsLog func(since time.Time, blockedOnly bool, search string, limit int) ([]store.DNSQuery, error),
	clients func() []store.Client, allow func(domain, note string) error, revoke func(domain string) error,
	record func(e store.Event, notify bool), log func(string, ...any)) *Unblocker {
	if log == nil {
		log = func(string, ...any) {}
	}
	if record == nil {
		record = func(store.Event, bool) {}
	}
	return &Unblocker{cfg: cfg, client: client, st: st, dnsLog: dnsLog, clients: clients,
		allow: allow, revoke: revoke, record: record, log: log, asked: map[string]time.Time{}}
}

func (u *Unblocker) Run(ctx context.Context) {
	t := time.NewTimer(5 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if _, _, err := u.Pass(ctx); err != nil && ctx.Err() == nil {
			u.log("unblock: %v", err)
		}
		t.Reset(time.Hour)
	}
}

type blockedName struct {
	domain  string
	lookups int
	clients map[string]bool
	kinds   map[string]bool
	source  string
}

// Pass judges the last day's most-asked blocked names once each and returns
// how many it suggested and how many it allowed.
func (u *Unblocker) Pass(ctx context.Context) (suggested, allowed int, err error) {
	cfg := u.cfg.Snapshot().AI.TypeSafe
	key := typeSafeKey(u.cfg)
	if key == "" || !cfg.Unblock {
		return 0, 0, nil
	}
	u.expire()

	now := time.Now()
	queries, err := u.dnsLog(now.Add(-24*time.Hour), true, "", 4000)
	if err != nil {
		return 0, 0, err
	}
	kindOf := map[string]string{}
	for _, c := range u.clients() {
		kindOf[c.ID] = c.DeviceType
	}
	byName := map[string]*blockedName{}
	for _, q := range queries {
		d := strings.ToLower(strings.TrimSuffix(q.Name, "."))
		b := byName[d]
		if b == nil {
			b = &blockedName{domain: d, clients: map[string]bool{}, kinds: map[string]bool{}}
			byName[d] = b
		}
		b.lookups++
		b.clients[q.ClientIP] = true
		kind := kindOf[q.ClientID]
		if kind == "" {
			kind = "unknown"
		}
		b.kinds[kind] = true
		if q.BlockSource != "" {
			b.source = q.BlockSource
		}
	}
	names := make([]*blockedName, 0, len(byName))
	for _, b := range byName {
		names = append(names, b)
	}
	sort.Slice(names, func(i, j int) bool {
		if len(names[i].clients) != len(names[j].clients) {
			return len(names[i].clients) > len(names[j].clients)
		}
		return names[i].lookups > names[j].lookups
	})

	decided := map[string]bool{}
	if recs, err := u.st.Recommendations("", 500); err == nil {
		for _, r := range recs {
			if r.Kind == "allow" && (r.Status == "accepted" || r.Status == "dismissed") {
				decided[r.Domain] = true
			}
		}
	}
	// The cap counts allows actually made: a week-old one kept because it is
	// still in use is renewed on its recommendation, not re-created here.
	autoToday := 0
	if rules, err := u.st.LocalRules(); err == nil {
		for _, r := range rules {
			if r.Origin == "ai" && r.Action == "allow" && now.Sub(r.CreatedAt) < 24*time.Hour {
				autoToday++
			}
		}
	}

	considered := 0
	for _, b := range names {
		if considered >= unblockCandidates || ctx.Err() != nil {
			break
		}
		if decided[b.domain] || !u.due(b.domain, now) {
			continue
		}
		hits, err := u.st.BlockSources(b.domain)
		if err != nil || !onlyAdLists(hits, b.source) {
			// Policy, bypass, malware and the operator's own blocks are
			// never second-guessed.
			continue
		}
		considered++
		u.mu.Lock()
		u.asked[b.domain] = now
		u.mu.Unlock()

		kinds := make([]string, 0, len(b.kinds))
		for k := range b.kinds {
			kinds = append(kinds, k)
		}
		sort.Strings(kinds)
		resp, err := u.client.askTypeSafe(ctx, key, map[string]any{"domain": b.domain, "device_kinds": kinds}, typeSafeUnblockQuestions)
		if err != nil {
			if _, retriable := classify(err); !retriable || ctx.Err() != nil {
				return suggested, allowed, err
			}
			u.log("unblock: TypeSafe: %s: %v", b.domain, err)
			continue
		}
		ans, ok := resp.Answers["function"]
		if !ok || ans.Type != "choice" {
			continue
		}
		need := 0.0
		for k, p := range ans.Probabilities {
			if unblockNeeded[k] {
				need += p
			}
		}
		if need < unblockSuggestNeed || len(hits) > unblockSuggestMaxLists || !unblockNeeded[ans.Choice] {
			continue
		}
		sources := make([]string, 0, len(hits))
		for _, h := range hits {
			sources = append(sources, h.Source)
		}
		sort.Strings(sources)
		reason := fmt.Sprintf("TypeSafe: a %s host (%.0f%%), blocked only by %s", unblockLabels[ans.Choice],
			math.Round(need*100), strings.Join(sources, ", "))
		rec, err := u.st.UpsertRecommendation(store.Recommendation{
			ID: uuid.NewString(), TS: now, Kind: "allow", Domain: b.domain, Reason: reason, Confidence: need,
			Evidence: map[string]any{"lookups": b.lookups, "devices": len(b.clients), "blocked_by": strings.Join(sources, ", "),
				"function": ans.Choice},
			Model: "typesafe:" + resp.Model,
		})
		if err != nil || rec.Status != "open" {
			continue
		}
		auto := cfg.AutoUnblock && need >= unblockAutoNeed && len(hits) <= unblockAutoMaxLists &&
			ans.Choice != "content" && autoToday < unblockAutoPerDay
		if !auto {
			suggested++
			continue
		}
		if err := u.allow(b.domain, reason); err != nil {
			u.log("unblock: allow %s: %v", b.domain, err)
			suggested++
			continue
		}
		if err := u.st.DecideRecommendation(rec.ID, "accepted", AutoUnblockActor); err != nil {
			return suggested, allowed, err
		}
		autoToday++
		allowed++
		u.record(store.Event{
			ID: uuid.NewString(), TS: now, Severity: store.SevNotice, Category: "ai:unblock",
			Title:  "Unblocked " + b.domain + " automatically",
			Detail: reason + fmt.Sprintf(". %d device(s) were being refused. Undo it on the Assistant page; it is withdrawn after a week unless something still uses it.", len(b.clients)),
			Data:   map[string]any{"domain": b.domain, "function": ans.Choice, "confidence": need},
		}, true)
	}
	if considered > 0 {
		u.log("unblock: judged %d blocked name(s): %d suggested, %d allowed", considered, suggested, allowed)
	}
	if suggested > 0 {
		u.record(store.Event{
			ID: uuid.NewString(), TS: now, Severity: store.SevInfo, Category: "ai:review",
			Title:  fmt.Sprintf("%d unblock suggestion(s) waiting", suggested),
			Detail: "Names a block is probably breaking. Decide on the Assistant page.",
		}, false)
	}
	return suggested, allowed, nil
}

// due is false for a name judged in the last day; its verdict will not have
// changed.
func (u *Unblocker) due(domain string, now time.Time) bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	return now.Sub(u.asked[domain]) >= 24*time.Hour
}

// onlyAdLists is true when every list covering the name is an ad or tracking
// list and the refusal came from one of them.
func onlyAdLists(hits []store.ListHit, source string) bool {
	if len(hits) == 0 {
		return false
	}
	fromList := false
	for _, h := range hits {
		if h.Category != "ads" && h.Category != "tracking" {
			return false
		}
		if h.Source == source {
			fromList = true
		}
	}
	return fromList
}

// expire withdraws automatic allows after a week unless the name is still
// being looked up. A withdrawn one may be suggested again later.
func (u *Unblocker) expire() {
	recs, err := u.st.Recommendations("accepted", 500)
	if err != nil {
		return
	}
	for _, r := range recs {
		if r.DecidedBy != AutoUnblockActor || time.Since(r.DecidedAt) < unblockAutoKeep {
			continue
		}
		if q, err := u.dnsLog(time.Now().Add(-unblockAutoKeep), false, r.Domain, 1); err != nil {
			continue
		} else if len(q) > 0 {
			_ = u.st.DecideRecommendation(r.ID, "accepted", AutoUnblockActor)
			continue
		}
		if err := u.revoke(r.Domain); err != nil {
			u.log("unblock: withdraw %s: %v", r.Domain, err)
			continue
		}
		_ = u.st.DecideRecommendation(r.ID, "expired", AutoUnblockActor)
		u.log("unblock: withdrew the automatic allow for %s after a week unused", r.Domain)
	}
}
