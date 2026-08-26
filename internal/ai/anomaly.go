package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/Neoo-Blue/orbis/internal/config"
	"github.com/Neoo-Blue/orbis/internal/store"
	"github.com/google/uuid"
)

// Analyzer looks for behaviour on the network that is worth a human's
// attention. The detectors below are statistical and deterministic; the model
// is only used to triage what they surface, so a provider outage degrades the
// feature to "still detecting, just not explaining".
type Analyzer struct {
	client *Client
	st     *store.Store
	cfg    *config.Config
	log    func(string, ...any)

	// seenDevices avoids re-alerting on a device every sweep.
	seenDevices map[string]bool
	// raised keys off a finding's identity so the same beacon is not
	// reported every ten minutes forever.
	raised map[string]time.Time
}

func NewAnalyzer(cfg *config.Config, client *Client, st *store.Store, log func(string, ...any)) *Analyzer {
	if log == nil {
		log = func(string, ...any) {}
	}
	return &Analyzer{
		client: client, st: st, cfg: cfg, log: log,
		seenDevices: map[string]bool{},
		raised:      map[string]time.Time{},
	}
}

// Finding is one detection, before triage.
type Finding struct {
	Kind      string         `json:"kind"`
	Severity  string         `json:"severity"`
	Title     string         `json:"title"`
	Detail    string         `json:"detail"`
	ClientID  string         `json:"client_id,omitempty"`
	Evidence  map[string]any `json:"evidence"`
	Score     float64        `json:"score"`
	dedupeKey string
}

func (a *Analyzer) Run(ctx context.Context) {
	cfg := a.cfg.Snapshot().AI.Anomaly
	interval := time.Duration(cfg.IntervalMinutes) * time.Minute
	if interval < time.Minute {
		interval = 10 * time.Minute
	}
	// Seed the known-device set so a restart does not alert on every device
	// that has been on the network for years.
	if clients, err := a.st.Clients(); err == nil {
		for _, c := range clients {
			if time.Since(c.FirstSeen) > time.Hour {
				a.seenDevices[c.ID] = true
			}
		}
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := a.Sweep(ctx); err != nil {
				a.log("anomaly: sweep failed: %v", err)
			}
		}
	}
}

// Sweep runs every detector and records what survives.
func (a *Analyzer) Sweep(ctx context.Context) error {
	cfg := a.cfg.Snapshot().AI.Anomaly
	if !cfg.Enabled {
		return nil
	}
	since := time.Now().Add(-6 * time.Hour)

	var findings []Finding
	findings = append(findings, a.detectNewDevices(cfg)...)

	beacons, err := a.detectBeaconing(since, cfg)
	if err != nil {
		return err
	}
	findings = append(findings, beacons...)

	exfil, err := a.detectExfiltration(since, cfg)
	if err != nil {
		return err
	}
	findings = append(findings, exfil...)

	scans, err := a.detectPortScans(since)
	if err != nil {
		return err
	}
	findings = append(findings, scans...)

	dga, err := a.detectDGA(since)
	if err != nil {
		return err
	}
	findings = append(findings, dga...)

	// Drop anything already reported recently.
	fresh := findings[:0]
	now := time.Now()
	for _, f := range findings {
		if last, ok := a.raised[f.dedupeKey]; ok && now.Sub(last) < 12*time.Hour {
			continue
		}
		a.raised[f.dedupeKey] = now
		fresh = append(fresh, f)
	}
	findings = fresh
	if len(findings) == 0 {
		return nil
	}

	if cfg.UseAI && a.client.Configured() {
		a.triage(ctx, findings)
		return nil
	}
	for _, f := range findings {
		a.record(f, "")
	}
	return nil
}

func (a *Analyzer) record(f Finding, aiNote string) {
	detail := f.Detail
	if aiNote != "" {
		detail = detail + "\n\nAssessment: " + aiNote
	}
	_ = a.st.AddEvent(store.Event{
		ID: uuid.NewString(), TS: time.Now(), Severity: f.Severity,
		Category: "anomaly:" + f.Kind, Title: f.Title, Detail: detail,
		ClientID: f.ClientID, Data: f.Evidence,
	})
}

// detectNewDevices raises the first appearance of a device.
func (a *Analyzer) detectNewDevices(cfg config.AnomalyConfig) []Finding {
	if !cfg.NewDeviceAlert {
		return nil
	}
	clients, err := a.st.Clients()
	if err != nil {
		return nil
	}
	var out []Finding
	for _, c := range clients {
		if a.seenDevices[c.ID] {
			continue
		}
		a.seenDevices[c.ID] = true
		if time.Since(c.FirstSeen) > time.Hour {
			continue
		}
		name := c.Hostname
		if name == "" {
			name = c.Vendor
		}
		if name == "" {
			name = c.IP
		}
		out = append(out, Finding{
			Kind: "new_device", Severity: store.SevNotice,
			Title:    "New device on the network: " + name,
			Detail:   fmt.Sprintf("%s (%s) first appeared at %s. Vendor: %s. Type: %s.", name, c.IP, c.FirstSeen.Format(time.Kitchen), orDash(c.Vendor), orDash(c.DeviceType)),
			ClientID: c.ID, Score: 0.4,
			Evidence:  map[string]any{"ip": c.IP, "mac": c.MAC, "vendor": c.Vendor, "type": c.DeviceType},
			dedupeKey: "newdev:" + c.ID,
		})
	}
	return out
}

// detectBeaconing looks for connections at a suspiciously regular interval,
// which is what command-and-control and stalkerware look like from outside.
// Legitimate software polls too, so periodicity alone is a lead, not a verdict.
func (a *Analyzer) detectBeaconing(since time.Time, cfg config.AnomalyConfig) ([]Finding, error) {
	flows, err := a.st.Flows(store.FlowQuery{Since: &since, Limit: 5000, OrderBy: "started_at"})
	if err != nil {
		return nil, err
	}
	type series struct {
		times    []time.Time
		clientID string
		bytes    int64
	}
	groups := map[string]*series{}
	for _, f := range flows {
		dest := f.Hostname
		if dest == "" {
			dest = f.DstIP
		}
		key := f.ClientID + "|" + dest
		g := groups[key]
		if g == nil {
			g = &series{clientID: f.ClientID}
			groups[key] = g
		}
		g.times = append(g.times, f.StartedAt)
		g.bytes += f.BytesIn + f.BytesOut
	}

	minSamples := cfg.BeaconMinSamples
	if minSamples < 4 {
		minSamples = 6
	}
	tolerance := cfg.BeaconJitterTolerance
	if tolerance <= 0 {
		tolerance = 0.18
	}

	var out []Finding
	for key, g := range groups {
		if len(g.times) < minSamples {
			continue
		}
		sort.Slice(g.times, func(i, j int) bool { return g.times[i].Before(g.times[j]) })
		gaps := make([]float64, 0, len(g.times)-1)
		for i := 1; i < len(g.times); i++ {
			gaps = append(gaps, g.times[i].Sub(g.times[i-1]).Seconds())
		}
		mean, cv := meanCV(gaps)
		// Sub-5-second intervals are a page loading assets, not a beacon.
		if mean < 5 || cv > tolerance {
			continue
		}
		_, dest, _ := strings.Cut(key, "|")
		out = append(out, Finding{
			Kind: "beaconing", Severity: store.SevWarning,
			Title: fmt.Sprintf("Regular check-in pattern to %s", dest),
			Detail: fmt.Sprintf("%d connections at a near-constant %s interval (jitter %.0f%%), %s total. "+
				"Regular intervals are typical of both software update checks and remote-access malware.",
				len(g.times), humanDuration(mean), cv*100, humanBytes(g.bytes)),
			ClientID: g.clientID,
			Score:    0.55 + (tolerance-cv)*1.5,
			Evidence: map[string]any{
				"destination": dest, "connections": len(g.times),
				"interval_seconds": mean, "jitter": cv, "bytes": g.bytes,
			},
			dedupeKey: "beacon:" + key,
		})
	}
	return out, nil
}

// detectExfiltration looks for large sustained uploads to a single new host.
func (a *Analyzer) detectExfiltration(since time.Time, cfg config.AnomalyConfig) ([]Finding, error) {
	threshold := cfg.ExfilBytesThreshold
	if threshold <= 0 {
		threshold = 256 << 20
	}
	flows, err := a.st.Flows(store.FlowQuery{Since: &since, Limit: 5000, OrderBy: "bytes"})
	if err != nil {
		return nil, err
	}
	type agg struct {
		up       int64
		down     int64
		clientID string
		country  string
		org      string
	}
	byDest := map[string]*agg{}
	for _, f := range flows {
		dest := f.Hostname
		if dest == "" {
			dest = f.DstIP
		}
		key := f.ClientID + "|" + dest
		g := byDest[key]
		if g == nil {
			g = &agg{clientID: f.ClientID, country: f.Country, org: f.ASOrg}
			byDest[key] = g
		}
		g.up += f.BytesOut
		g.down += f.BytesIn
	}
	var out []Finding
	for key, g := range byDest {
		if g.up < threshold {
			continue
		}
		// A backup or a video upload has a high up:down ratio too. What makes
		// this worth surfacing is the ratio plus the volume; the operator
		// decides whether it is expected.
		ratio := float64(g.up) / math.Max(float64(g.down), 1)
		if ratio < 4 {
			continue
		}
		_, dest, _ := strings.Cut(key, "|")
		out = append(out, Finding{
			Kind: "large_upload", Severity: store.SevWarning,
			Title: fmt.Sprintf("Large outbound transfer to %s", dest),
			Detail: fmt.Sprintf("%s uploaded versus %s downloaded (%.0f:1) in the last six hours, to %s%s.",
				humanBytes(g.up), humanBytes(g.down), ratio, dest, countrySuffix(g.country, g.org)),
			ClientID: g.clientID, Score: 0.5,
			Evidence: map[string]any{
				"destination": dest, "bytes_up": g.up, "bytes_down": g.down,
				"country": g.country, "network": g.org,
			},
			dedupeKey: "exfil:" + key,
		})
	}
	return out, nil
}

// detectPortScans finds one source touching many distinct ports or hosts.
func (a *Analyzer) detectPortScans(since time.Time) ([]Finding, error) {
	flows, err := a.st.Flows(store.FlowQuery{Since: &since, Limit: 8000})
	if err != nil {
		return nil, err
	}
	type scan struct {
		ports map[int]struct{}
		hosts map[string]struct{}
	}
	bySrc := map[string]*scan{}
	for _, f := range flows {
		s := bySrc[f.SrcIP]
		if s == nil {
			s = &scan{ports: map[int]struct{}{}, hosts: map[string]struct{}{}}
			bySrc[f.SrcIP] = s
		}
		s.ports[f.DstPort] = struct{}{}
		s.hosts[f.DstIP] = struct{}{}
	}
	var out []Finding
	for src, s := range bySrc {
		// A browser opens many ports to few hosts; a scanner opens few ports
		// to many hosts or many ports to one. Both patterns are caught.
		portSweep := len(s.ports) > 100 && len(s.hosts) < 5
		hostSweep := len(s.hosts) > 60 && len(s.ports) < 10
		if !portSweep && !hostSweep {
			continue
		}
		kind := "host sweep"
		if portSweep {
			kind = "port sweep"
		}
		out = append(out, Finding{
			Kind: "scanning", Severity: store.SevWarning,
			Title:     fmt.Sprintf("Possible %s from %s", kind, src),
			Detail:    fmt.Sprintf("%s reached %d distinct ports across %d hosts in six hours.", src, len(s.ports), len(s.hosts)),
			Score:     0.6,
			Evidence:  map[string]any{"source": src, "ports": len(s.ports), "hosts": len(s.hosts)},
			dedupeKey: "scan:" + src,
		})
	}
	return out, nil
}

// detectDGA looks for a client resolving many high-entropy names that mostly
// fail, the classic signature of domain-generation-algorithm malware.
func (a *Analyzer) detectDGA(since time.Time) ([]Finding, error) {
	queries, err := a.st.DNSLog(since, "", false, "", 2000)
	if err != nil {
		return nil, err
	}
	type acc struct {
		total    int
		nxdomain int
		entropy  float64
		samples  []string
		clientID string
	}
	byClient := map[string]*acc{}
	for _, q := range queries {
		key := q.ClientIP
		g := byClient[key]
		if g == nil {
			g = &acc{clientID: q.ClientID}
			byClient[key] = g
		}
		g.total++
		if q.RCode == "NXDOMAIN" {
			g.nxdomain++
			e := nameEntropy(q.Name)
			g.entropy += e
			if e > 3.5 && len(g.samples) < 5 {
				g.samples = append(g.samples, q.Name)
			}
		}
	}
	var out []Finding
	for ip, g := range byClient {
		if g.total < 50 || g.nxdomain < 20 {
			continue
		}
		nxRate := float64(g.nxdomain) / float64(g.total)
		avgEntropy := g.entropy / math.Max(float64(g.nxdomain), 1)
		// A typo or a captive-portal probe produces a few NXDOMAINs. A DGA
		// produces a flood of them, all high-entropy.
		if nxRate < 0.4 || avgEntropy < 3.3 {
			continue
		}
		out = append(out, Finding{
			Kind: "dga", Severity: store.SevCritical,
			Title: fmt.Sprintf("High-entropy failed lookups from %s", ip),
			Detail: fmt.Sprintf("%.0f%% of %d DNS queries returned NXDOMAIN with an average name entropy of %.1f. "+
				"Examples: %s. This pattern is characteristic of malware cycling through generated domains "+
				"to find a live command-and-control host.",
				nxRate*100, g.total, avgEntropy, strings.Join(g.samples, ", ")),
			ClientID: g.clientID, Score: 0.8,
			Evidence: map[string]any{
				"client_ip": ip, "queries": g.total, "nxdomain_rate": nxRate,
				"avg_entropy": avgEntropy, "samples": g.samples,
			},
			dedupeKey: "dga:" + ip,
		})
	}
	return out, nil
}

const triagePrompt = `You triage anomaly detections from a network monitoring appliance. Each was
produced by a statistical detector, so each is a lead rather than a conclusion.

For each finding, judge whether it warrants the operator's attention and say why in one or two
sentences. Most findings on a normal network have a mundane explanation — software update checks
beacon on a schedule, cloud backups upload a lot, a smart TV phones home constantly, a phone that
just joined is a family member's. Say so plainly when that is the likely story; a triage layer
that escalates everything is worse than none.

Escalate when the evidence genuinely does not fit a mundane explanation: beaconing to an
unrecognised host with no product behind it, a large upload from a device that has no business
uploading, DGA-style lookups, or scanning from an IoT device.

Return a JSON array, one object per finding, in the same order:
[{"index":0,"keep":true,"severity":"info|notice|warning|critical","assessment":"..."}]

keep:false means the finding is routine enough to log quietly rather than alert on.`

func (a *Analyzer) triage(ctx context.Context, findings []Finding) {
	payload := make([]map[string]any, 0, len(findings))
	for i, f := range findings {
		payload = append(payload, map[string]any{
			"index": i, "kind": f.Kind, "title": f.Title,
			"detail": f.Detail, "evidence": f.Evidence,
		})
	}
	body, _ := jsonOf(payload, nil)
	resp, err := a.client.Complete(ctx, triagePrompt,
		[]Message{{Role: RoleUser, Content: body}}, nil, true)
	if err != nil {
		a.log("anomaly: triage failed (%v); recording findings unfiltered", err)
		for _, f := range findings {
			a.record(f, "")
		}
		return
	}

	var verdicts []struct {
		Index      int    `json:"index"`
		Keep       bool   `json:"keep"`
		Severity   string `json:"severity"`
		Assessment string `json:"assessment"`
	}
	if err := parseJSONArray(resp.Text, &verdicts); err != nil {
		a.log("anomaly: could not parse triage output (%v); recording unfiltered", err)
		for _, f := range findings {
			a.record(f, "")
		}
		return
	}
	handled := map[int]bool{}
	for _, v := range verdicts {
		if v.Index < 0 || v.Index >= len(findings) {
			continue
		}
		handled[v.Index] = true
		f := findings[v.Index]
		if v.Severity != "" {
			f.Severity = v.Severity
		}
		if !v.Keep {
			// Still recorded, just at info level: an operator reviewing the
			// timeline should be able to see what was dismissed and why.
			f.Severity = store.SevInfo
		}
		a.record(f, v.Assessment)
	}
	// Anything the model skipped still gets recorded; silence is not a verdict.
	for i, f := range findings {
		if !handled[i] {
			a.record(f, "")
		}
	}
}

// ---- math helpers ----

// meanCV returns the mean and the coefficient of variation, which is the
// scale-free measure of regularity beaconing detection needs.
func meanCV(values []float64) (float64, float64) {
	if len(values) == 0 {
		return 0, 1
	}
	var sum float64
	for _, v := range values {
		sum += v
	}
	mean := sum / float64(len(values))
	if mean == 0 {
		return 0, 1
	}
	var variance float64
	for _, v := range values {
		variance += (v - mean) * (v - mean)
	}
	variance /= float64(len(values))
	return mean, math.Sqrt(variance) / mean
}

func nameEntropy(name string) float64 {
	label, _, _ := strings.Cut(strings.TrimSuffix(name, "."), ".")
	if len(label) < 4 {
		return 0
	}
	freq := map[rune]int{}
	for _, r := range label {
		freq[r]++
	}
	n := float64(len(label))
	h := 0.0
	for _, c := range freq {
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return h
}

func humanBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit && exp < 4; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTP"[exp])
}

func humanDuration(seconds float64) string {
	d := time.Duration(seconds) * time.Second
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%.0f second", seconds) + pluralS(seconds)
	case d < time.Hour:
		return fmt.Sprintf("%.0f minute", d.Minutes()) + pluralS(d.Minutes())
	default:
		return fmt.Sprintf("%.1f hour", d.Hours()) + pluralS(d.Hours())
	}
}

func pluralS(v float64) string {
	if v == 1 {
		return ""
	}
	return "s"
}

func countrySuffix(country, org string) string {
	switch {
	case country != "" && org != "":
		return fmt.Sprintf(" (%s, %s)", org, country)
	case country != "":
		return " (" + country + ")"
	case org != "":
		return " (" + org + ")"
	}
	return ""
}

func orDash(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

func parseJSONArray(text string, out any) error {
	s := strings.TrimSpace(text)
	start := strings.IndexByte(s, '[')
	end := strings.LastIndexByte(s, ']')
	if start < 0 || end <= start {
		return fmt.Errorf("no JSON array in output")
	}
	return jsonUnmarshal([]byte(s[start:end+1]), out)
}

// jsonUnmarshal is a thin indirection so the parse helpers above stay
// readable without importing encoding/json at every call site.
func jsonUnmarshal(b []byte, v any) error { return json.Unmarshal(b, v) }
