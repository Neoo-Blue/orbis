// Package netwatch probes the local default gateway and three independent
// public anycast networks every 10 seconds to answer whether connectivity
// trouble sits on the local network or upstream at the internet provider.
package netwatch

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"
	"os"
	"slices"
	"sync"
	"syscall"
	"time"

	"github.com/Neoo-Blue/orbis/internal/config"
	"github.com/Neoo-Blue/orbis/internal/store"
	"github.com/google/uuid"
)

const (
	// ProbeInterval is the cadence between concurrent probe rounds.
	ProbeInterval = 10 * time.Second
	// ProbeTimeout bounds each individual TCP connect attempt.
	ProbeTimeout = 2 * time.Second
	// RingSize holds 24 hours of 10-second samples per target.
	RingSize = 8640

	window5m         = 5 * time.Minute
	window24h        = 24 * time.Hour
	outageRounds     = 3
	maxIncidents     = 50
	maxHistoryPoints = 300
	numTargets       = 4
	routePath        = "/proc/net/route"
)

// State classifies a single target or the overall connection.
type State string

const (
	StateGood     State = "good"
	StateDegraded State = "degraded"
	StateDown     State = "down"
)

// Story names which side of the demarcation point a fault sits on.
type Story string

const (
	StoryAllGood  Story = "ok"
	StoryNetwork  Story = "network"
	StoryProvider Story = "isp"
)

type targetSpec struct {
	id      string
	name    string
	address string
	role    string
}

var publicTargets = [3]targetSpec{
	{id: "1.1.1.1", name: "Cloudflare", address: "1.1.1.1:443", role: "public"},
	{id: "8.8.8.8", name: "Google", address: "8.8.8.8:443", role: "public"},
	{id: "9.9.9.9", name: "Quad9", address: "9.9.9.9:443", role: "public"},
}

var gatewayPorts = [3]string{"53", "80", "443"}

// Sample represents one probe outcome for a single target.
type Sample struct {
	LatencyMS float64
	Loss      bool
}

// TargetStatus is the live view of one probed target over the last 5 minutes
// alongside its 24-hour latency baseline.
type TargetStatus struct {
	ID                  string  `json:"id"`
	Name                string  `json:"name"`
	Address             string  `json:"address"`
	Interface           string  `json:"interface,omitempty"`
	Role                string  `json:"role"`
	State               State   `json:"state"`
	CurrentMS           float64 `json:"current_ms"`
	LastOK              bool    `json:"last_ok"`
	P50MS               float64 `json:"p50_ms"`
	JitterMS            float64 `json:"jitter_ms"`
	LossPercent         float64 `json:"loss_percent"`
	Median24hMS         float64 `json:"median_24h_ms"`
	Samples5m           int     `json:"samples_5m"`
	Samples24h          int     `json:"samples_24h"`
	ConsecutiveFailures int     `json:"consecutive_failures"`
}

// Incident records an outage that opened after all public targets failed for
// three consecutive rounds and closed on the first public reply.
type Incident struct {
	ID              string     `json:"id"`
	StartedAt       time.Time  `json:"started_at"`
	EndedAt         *time.Time `json:"ended_at,omitempty"`
	Ongoing         bool       `json:"ongoing"`
	DurationSeconds int        `json:"duration_seconds"`
	Cause           Story      `json:"cause"`
	Summary         string     `json:"summary"`
	Failed          []string   `json:"failed"`
}

// Status is the JSON snapshot served by GET /api/netwatch/status.
type Status struct {
	State           State          `json:"state"`
	Story           Story          `json:"story"`
	Blame           string         `json:"blame"`
	Headline        string         `json:"headline"`
	Detail          string         `json:"detail"`
	IntervalSeconds int            `json:"interval_seconds"`
	Rounds          int64          `json:"rounds"`
	UpdatedAt       *time.Time     `json:"updated_at,omitempty"`
	Targets         []TargetStatus `json:"targets"`
	Incidents       []Incident     `json:"incidents"`
}

// Point is one bucket on a target's latency and loss timeline.
type Point struct {
	T    int64   `json:"t"`
	MS   float64 `json:"ms"`
	Loss bool    `json:"loss,omitempty"`
}

// TargetSeries is the downsampled timeline for one target.
type TargetSeries struct {
	ID     string  `json:"id"`
	Points []Point `json:"points"`
}

// History is the JSON payload served by GET /api/netwatch/history.
type History struct {
	Hours     int            `json:"hours"`
	From      int64          `json:"from"`
	To        int64          `json:"to"`
	Targets   []TargetSeries `json:"targets"`
	Incidents []Incident     `json:"incidents"`
}

// rawSample carries no pointers so the 540 KB ring buffers are skipped by GC.
type rawSample struct {
	tsMillis int64
	rttMS    float64 // >= 0 when answered, -1 on loss
}

type sampleRing struct {
	buf   [RingSize]rawSample
	head  int
	count int
}

func (r *sampleRing) push(tsMillis int64, rttMS float64) {
	r.buf[r.head] = rawSample{tsMillis: tsMillis, rttMS: rttMS}
	r.head++
	if r.head == RingSize {
		r.head = 0
	}
	if r.count < RingSize {
		r.count++
	}
}

func (r *sampleRing) at(i int) rawSample {
	idx := r.head - r.count + i
	if idx < 0 {
		idx += RingSize
	}
	return r.buf[idx]
}

type dialFunc func(ctx context.Context, addr string, timeout time.Duration) (time.Duration, error)

// Manager runs the probe loop and owns the in-memory sample rings and incidents.
type Manager struct {
	cfg *config.Config
	st  *store.Store
	log func(string, ...any)

	now         func() time.Time
	dial        dialFunc
	routeReader func() ([]byte, error)

	// Owned by the probe loop; avoids allocating a buffer or dial strings per tick.
	routeBuf     [8192]byte
	gwCachedAddr netip.Addr
	gwCachedIP   string
	gwDial       [3]string

	mu            sync.RWMutex
	rings         [numTargets]sampleRing
	medScratch    [RingSize]float64
	targets       [numTargets]TargetStatus
	state         State
	story         Story
	blame         string
	headline      string
	detail        string
	rounds        int64
	updatedAt     time.Time
	gwAddr        string
	gwIface       string
	gwPresent     bool
	pubFailStreak int
	streakStart   time.Time
	streakGWFail  bool
	openInc       *Incident
	closedInc     [maxIncidents]Incident
	incHead       int
	incCount      int
}

func NewManager(cfg *config.Config, st *store.Store, log func(string, ...any)) *Manager {
	if log == nil {
		log = func(string, ...any) {}
	}
	m := &Manager{
		cfg:      cfg,
		st:       st,
		log:      log,
		now:      time.Now,
		dial:     defaultDial,
		state:    StateGood,
		story:    StoryAllGood,
		headline: "Checking your network and internet connection",
		detail:   "Orbis probes your default gateway and three public networks every 10 seconds to separate local issues from provider outages.",
	}
	m.targets[0] = TargetStatus{
		ID:    "gateway",
		Name:  "Default gateway",
		Role:  "gateway",
		State: StateGood,
	}
	for i, spec := range publicTargets {
		m.targets[i+1] = TargetStatus{
			ID:      spec.id,
			Name:    spec.name,
			Address: spec.address,
			Role:    spec.role,
			State:   StateGood,
		}
	}
	return m
}

// Run executes a probe round immediately and then every 10 seconds until ctx ends.
func (m *Manager) Run(ctx context.Context) {
	m.probeRound(ctx)
	t := time.NewTicker(ProbeInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			m.probeRound(ctx)
		}
	}
}

func (m *Manager) probeRound(ctx context.Context) {
	if ctx.Err() != nil {
		return
	}
	gwAddr, gwIfaceBytes, gwOK := m.readDefaultGateway()
	if gwOK && gwAddr != m.gwCachedAddr {
		ip := gwAddr.String()
		m.gwCachedAddr = gwAddr
		m.gwCachedIP = ip
		m.gwDial = [3]string{
			ip + ":" + gatewayPorts[0],
			ip + ":" + gatewayPorts[1],
			ip + ":" + gatewayPorts[2],
		}
	}

	var samples [numTargets]Sample
	var wg sync.WaitGroup
	wg.Add(numTargets - 1)
	for i := 1; i < numTargets; i++ {
		idx := i
		addr := publicTargets[idx-1].address
		go func() {
			defer wg.Done()
			samples[idx] = m.probePublic(ctx, addr)
		}()
	}
	if gwOK {
		samples[0] = m.probeGateway(ctx, m.gwDial)
	} else {
		samples[0] = Sample{Loss: true}
	}
	wg.Wait()
	if ctx.Err() != nil {
		return
	}

	var gwIP string
	if gwOK {
		gwIP = m.gwCachedIP
	}
	m.recordRound(m.now(), gwIP, gwIfaceBytes, gwOK, samples)
}

func (m *Manager) probePublic(ctx context.Context, addr string) Sample {
	rtt, err := m.dial(ctx, addr, ProbeTimeout)
	if err != nil {
		return Sample{Loss: true}
	}
	return Sample{LatencyMS: durationMS(rtt)}
}

// probeGateway tries TCP 53, then 80, then 443. A TCP reset (ECONNREFUSED)
// proves the host received the SYN and answered on the LAN, so it counts as a
// completed round trip even when the router closes all three ports.
func (m *Manager) probeGateway(ctx context.Context, addrs [3]string) Sample {
	for _, addr := range addrs {
		if ctx.Err() != nil {
			return Sample{Loss: true}
		}
		rtt, err := m.dial(ctx, addr, ProbeTimeout)
		if err == nil || isConnRefused(err) {
			return Sample{LatencyMS: durationMS(rtt)}
		}
	}
	return Sample{Loss: true}
}

func defaultDial(ctx context.Context, addr string, timeout time.Duration) (time.Duration, error) {
	d := net.Dialer{Timeout: timeout}
	start := time.Now()
	conn, err := d.DialContext(ctx, "tcp4", addr)
	rtt := time.Since(start)
	if err == nil {
		_ = conn.Close()
	}
	return rtt, err
}

func isConnRefused(err error) bool {
	return err != nil && errors.Is(err, syscall.ECONNREFUSED)
}

func durationMS(d time.Duration) float64 {
	if d < 0 {
		return 0
	}
	return float64(d.Microseconds()) / 1000.0
}

// recordRound ingests one round of samples, recomputes window statistics,
// updates incident state, and persists an event if an outage just closed.
func (m *Manager) recordRound(ts time.Time, gwIP string, gwIface []byte, gwPresent bool, samples [numTargets]Sample) {
	var closed *Incident

	m.mu.Lock()
	tsMillis := ts.UnixMilli()
	m.rounds++
	m.updatedAt = ts
	m.gwPresent = gwPresent
	if gwPresent {
		m.gwAddr = gwIP
		if string(gwIface) != m.gwIface {
			m.gwIface = string(gwIface)
		}
	} else {
		m.gwAddr = ""
		m.gwIface = ""
	}
	m.targets[0].Address = m.gwAddr
	m.targets[0].Interface = m.gwIface

	for i := 0; i < numTargets; i++ {
		s := samples[i]
		t := &m.targets[i]
		if s.Loss {
			m.rings[i].push(tsMillis, -1)
			t.ConsecutiveFailures++
			t.LastOK = false
			t.CurrentMS = 0
		} else {
			ms := s.LatencyMS
			if ms < 0 {
				ms = 0
			}
			m.rings[i].push(tsMillis, ms)
			t.ConsecutiveFailures = 0
			t.LastOK = true
			t.CurrentMS = round2(ms)
		}
		m.updateTargetStats(i, tsMillis)
	}

	m.state, m.story, m.blame, m.headline, m.detail = evaluateVerdict(m.gwPresent, m.targets)
	closed = m.updateIncidents(ts, samples)
	m.mu.Unlock()

	if closed != nil {
		m.persistIncident(*closed)
	}
}

// updateTargetStats refreshes 5-minute p50, jitter, loss percent, 24-hour
// median and classification for target idx using m.medScratch without heap allocation.
func (m *Manager) updateTargetStats(idx int, nowMillis int64) {
	r := &m.rings[idx]
	t := &m.targets[idx]

	cut5m := nowMillis - int64(window5m/time.Millisecond)
	start5m := r.count
	for start5m > 0 && r.at(start5m-1).tsMillis > cut5m {
		start5m--
	}

	total5m := r.count - start5m
	var lost5m, ok5m, jitterPairs int
	var jitterSum, prev float64
	hasPrev := false

	for i := start5m; i < r.count; i++ {
		s := r.at(i)
		if s.rttMS < 0 {
			lost5m++
			continue
		}
		if hasPrev {
			d := s.rttMS - prev
			if d < 0 {
				d = -d
			}
			jitterSum += d
			jitterPairs++
		}
		prev = s.rttMS
		hasPrev = true
		m.medScratch[ok5m] = s.rttMS
		ok5m++
	}

	var p50, jitter, lossPct float64
	if total5m > 0 {
		lossPct = float64(lost5m) * 100.0 / float64(total5m)
	}
	if jitterPairs > 0 {
		jitter = jitterSum / float64(jitterPairs)
	}
	if ok5m > 0 {
		slices.Sort(m.medScratch[:ok5m])
		p50 = medianSorted(m.medScratch[:ok5m])
	}

	cut24h := nowMillis - int64(window24h/time.Millisecond)
	var ok24h, total24h int
	for i := 0; i < r.count; i++ {
		s := r.at(i)
		if s.tsMillis < cut24h {
			continue
		}
		total24h++
		if s.rttMS >= 0 {
			m.medScratch[ok24h] = s.rttMS
			ok24h++
		}
	}
	var med24h float64
	if ok24h > 0 {
		slices.Sort(m.medScratch[:ok24h])
		med24h = medianSorted(m.medScratch[:ok24h])
	}

	t.State = classifyTarget(lossPct, p50, med24h, t.ConsecutiveFailures, total5m)
	t.P50MS = round2(p50)
	t.JitterMS = round2(jitter)
	t.LossPercent = round2(lossPct)
	t.Median24hMS = round2(med24h)
	t.Samples5m = total5m
	t.Samples24h = total24h
}

func classifyTarget(lossPct, p50MS, median24hMS float64, consecutiveFailures, samples5m int) State {
	if samples5m == 0 {
		return StateGood
	}
	if lossPct >= 100 || consecutiveFailures >= outageRounds {
		return StateDown
	}
	if lossPct > 2 || (median24hMS > 0 && p50MS > 3*median24hMS && p50MS > 50) {
		return StateDegraded
	}
	return StateGood
}

func evaluateVerdict(gwPresent bool, targets [numTargets]TargetStatus) (state State, story Story, blame, headline, detail string) {
	gw := targets[0]
	if gw.State != StateGood {
		story = StoryNetwork
		blame = "your network"
		if !gwPresent {
			return StateDown, story, blame,
				"This node has no default gateway on your network",
				"No default route is in the kernel routing table. Check the Ethernet cable, Wi-Fi link, or DHCP lease on your upstream interface."
		}
		if gw.State == StateDown {
			return StateDown, story, blame,
				"Your gateway is not answering, so the problem is on your network",
				"Probes to " + gw.Address + " are failing before traffic ever reaches your internet provider. Check your router power, LAN cable, or switch."
		}
		if gw.LossPercent > 2 {
			return StateDegraded, story, blame,
				"Your local network is dropping traffic to the gateway",
				"Your router at " + gw.Address + " is losing packets on the LAN side, which affects every connection behind it. Check cables, switch ports, or Wi-Fi interference."
		}
		return StateDegraded, story, blame,
			"Your gateway is responding slowly on your local network",
			"Round-trip time to " + gw.Address + " is well above its 24-hour baseline, so delays are starting inside your network rather than at your provider."
	}

	var failingPub, downPub, lossyPub int
	var singleBad string
	for i := 1; i < numTargets; i++ {
		if targets[i].State != StateGood {
			failingPub++
			singleBad = targets[i].Name + " (" + targets[i].ID + ")"
			if targets[i].State == StateDown {
				downPub++
			}
			if targets[i].LossPercent > 2 {
				lossyPub++
			}
		}
	}

	if failingPub >= 2 {
		story = StoryProvider
		blame = "your internet provider"
		if downPub == numTargets-1 {
			return StateDown, story, blame,
				"Your internet provider is down, your network is fine",
				"Your local gateway answers normally, but Cloudflare, Google, and Quad9 are all unreachable beyond it. Check your modem uplink or provider status."
		}
		if lossyPub > 0 || downPub > 0 {
			return StateDegraded, story, blame,
				"Your provider is dropping traffic, your network is fine",
				"Your local gateway is clean, so packet loss is happening upstream on your internet provider's line."
		}
		return StateDegraded, story, blame,
			"Your provider connection is slow, your network is fine",
			"Your local gateway answers at normal speed, while latency to public networks is more than 3x its 24-hour baseline."
	}

	if failingPub == 1 {
		return StateGood, StoryAllGood, "",
			"Your internet is fine",
			"Your gateway and two of three public targets are healthy. " + singleBad + " is degraded on its own, which points to that endpoint rather than your connection."
	}

	return StateGood, StoryAllGood, "",
		"Your internet is fine",
		"Your local gateway and all three public targets are answering normally."
}

func (m *Manager) updateIncidents(ts time.Time, samples [numTargets]Sample) *Incident {
	allPubFailed := samples[1].Loss && samples[2].Loss && samples[3].Loss
	if allPubFailed {
		if m.pubFailStreak == 0 {
			m.streakStart = ts
			m.streakGWFail = samples[0].Loss
		} else if samples[0].Loss {
			m.streakGWFail = true
		}
		m.pubFailStreak++

		if m.openInc == nil && m.pubFailStreak >= outageRounds {
			cause, failed, summary := describeIncident(m.streakGWFail, m.gwAddr)
			dur := int(ts.Sub(m.streakStart).Seconds())
			if dur < 0 {
				dur = 0
			}
			m.openInc = &Incident{
				ID:              uuid.NewString(),
				StartedAt:       m.streakStart,
				Ongoing:         true,
				DurationSeconds: dur,
				Cause:           cause,
				Summary:         summary,
				Failed:          failed,
			}
		} else if m.openInc != nil && samples[0].Loss && m.openInc.Cause != StoryNetwork {
			cause, failed, summary := describeIncident(true, m.gwAddr)
			m.openInc.Cause = cause
			m.openInc.Failed = failed
			m.openInc.Summary = summary
		}
		return nil
	}

	m.pubFailStreak = 0
	m.streakGWFail = false
	if m.openInc == nil {
		return nil
	}

	inc := *m.openInc
	m.openInc = nil
	end := ts
	inc.EndedAt = &end
	inc.Ongoing = false
	dur := int(end.Sub(inc.StartedAt).Seconds())
	if dur < 0 {
		dur = 0
	}
	inc.DurationSeconds = dur

	m.closedInc[m.incHead] = inc
	m.incHead++
	if m.incHead == maxIncidents {
		m.incHead = 0
	}
	if m.incCount < maxIncidents {
		m.incCount++
	}
	return &inc
}

func describeIncident(gwFailed bool, gwAddr string) (Story, []string, string) {
	if gwFailed {
		gwLabel := "gateway"
		if gwAddr != "" {
			gwLabel = "gateway (" + gwAddr + ")"
		}
		return StoryNetwork,
			[]string{gwLabel, "1.1.1.1:443", "8.8.8.8:443", "9.9.9.9:443"},
			"Local gateway and all public targets failed"
	}
	return StoryProvider,
		[]string{"1.1.1.1:443", "8.8.8.8:443", "9.9.9.9:443"},
		"All public targets failed while local gateway answered"
}

func (m *Manager) persistIncident(inc Incident) {
	if m.st == nil || inc.EndedAt == nil {
		return
	}
	title := fmt.Sprintf("Internet outage lasted %s", formatShortDuration(inc.DurationSeconds))
	if inc.Cause == StoryNetwork {
		title = fmt.Sprintf("Local network gateway outage lasted %s", formatShortDuration(inc.DurationSeconds))
	}
	detail := fmt.Sprintf("%s. Started at %s and recovered at %s.",
		inc.Summary,
		inc.StartedAt.UTC().Format(time.RFC3339),
		inc.EndedAt.UTC().Format(time.RFC3339),
	)
	err := m.st.AddEvent(store.Event{
		ID:       inc.ID,
		TS:       *inc.EndedAt,
		Severity: store.SevWarning,
		Category: "internet",
		Title:    title,
		Detail:   detail,
		Data: map[string]any{
			"started_at":       inc.StartedAt.UTC().Format(time.RFC3339),
			"ended_at":         inc.EndedAt.UTC().Format(time.RFC3339),
			"duration_seconds": inc.DurationSeconds,
			"cause":            string(inc.Cause),
			"failed":           inc.Failed,
		},
	})
	if err != nil {
		m.log("netwatch: save incident event: %v", err)
	}
}

func formatShortDuration(sec int) string {
	if sec < 60 {
		return fmt.Sprintf("%ds", sec)
	}
	min := sec / 60
	rem := sec % 60
	if min < 60 {
		if rem == 0 {
			return fmt.Sprintf("%dm", min)
		}
		return fmt.Sprintf("%dm %ds", min, rem)
	}
	h := min / 60
	m := min % 60
	return fmt.Sprintf("%dh %dm", h, m)
}

// Status returns a snapshot of current target metrics, overall verdict, and
// recent incidents (newest first, up to 50).
func (m *Manager) Status() Status {
	m.mu.RLock()
	defer m.mu.RUnlock()

	now := m.now()
	targets := make([]TargetStatus, numTargets)
	copy(targets, m.targets[:])

	incidents := m.collectIncidentsLocked(now, time.Time{})
	var updated *time.Time
	if !m.updatedAt.IsZero() {
		u := m.updatedAt
		updated = &u
	}
	return Status{
		State:           m.state,
		Story:           m.story,
		Blame:           m.blame,
		Headline:        m.headline,
		Detail:          m.detail,
		IntervalSeconds: int(ProbeInterval / time.Second),
		Rounds:          m.rounds,
		UpdatedAt:       updated,
		Targets:         targets,
		Incidents:       incidents,
	}
}

// History returns downsampled timelines (at most 300 points per target) and
// incidents overlapping the last N hours (clamped to 1..24).
func (m *Manager) History(hours int) History {
	if hours <= 0 {
		hours = 6
	}
	if hours > 24 {
		hours = 24
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	now := m.now()
	from := now.Add(-time.Duration(hours) * time.Hour)
	fromMillis := from.UnixMilli()

	series := make([]TargetSeries, numTargets)
	for i := 0; i < numTargets; i++ {
		series[i] = TargetSeries{
			ID:     m.targets[i].ID,
			Points: downsampleRing(&m.rings[i], fromMillis),
		}
	}

	return History{
		Hours:     hours,
		From:      from.Unix(),
		To:        now.Unix(),
		Targets:   series,
		Incidents: m.collectIncidentsLocked(now, from),
	}
}

func (m *Manager) collectIncidentsLocked(now, since time.Time) []Incident {
	total := m.incCount
	if m.openInc != nil {
		total++
	}
	if total == 0 {
		return []Incident{}
	}
	if total > maxIncidents {
		total = maxIncidents
	}
	out := make([]Incident, 0, total)
	if m.openInc != nil {
		inc := *m.openInc
		dur := int(now.Sub(inc.StartedAt).Seconds())
		if dur < 0 {
			dur = 0
		}
		inc.DurationSeconds = dur
		inc.Failed = append([]string{}, inc.Failed...)
		out = append(out, inc)
	}
	// Walk closed incidents newest-first.
	for i := 0; i < m.incCount && len(out) < maxIncidents; i++ {
		idx := m.incHead - 1 - i
		if idx < 0 {
			idx += maxIncidents
		}
		inc := m.closedInc[idx]
		if !since.IsZero() && inc.EndedAt != nil && inc.EndedAt.Before(since) {
			continue
		}
		inc.Failed = append([]string{}, inc.Failed...)
		out = append(out, inc)
	}
	return out
}

func downsampleRing(r *sampleRing, fromMillis int64) []Point {
	start := 0
	for start < r.count && r.at(start).tsMillis < fromMillis {
		start++
	}
	n := r.count - start
	if n <= 0 {
		return []Point{}
	}
	if n <= maxHistoryPoints {
		out := make([]Point, n)
		for i := 0; i < n; i++ {
			s := r.at(start + i)
			if s.rttMS < 0 {
				out[i] = Point{T: s.tsMillis / 1000, MS: -1, Loss: true}
			} else {
				out[i] = Point{T: s.tsMillis / 1000, MS: round2(s.rttMS)}
			}
		}
		return out
	}

	out := make([]Point, maxHistoryPoints)
	for b := 0; b < maxHistoryPoints; b++ {
		lo := start + (b*n)/maxHistoryPoints
		hi := start + ((b+1)*n)/maxHistoryPoints
		var sum float64
		var okCount int
		var hadLoss bool
		for k := lo; k < hi; k++ {
			s := r.at(k)
			if s.rttMS < 0 {
				hadLoss = true
			} else {
				sum += s.rttMS
				okCount++
			}
		}
		midTS := (r.at(lo).tsMillis + r.at(hi-1).tsMillis) / 2000
		if okCount == 0 {
			out[b] = Point{T: midTS, MS: -1, Loss: true}
		} else {
			out[b] = Point{T: midTS, MS: round2(sum / float64(okCount)), Loss: hadLoss}
		}
	}
	return out
}

func medianSorted(sorted []float64) float64 {
	n := len(sorted)
	if n == 0 {
		return 0
	}
	mid := n / 2
	if n%2 == 1 {
		return sorted[mid]
	}
	return (sorted[mid-1] + sorted[mid]) / 2
}

func round2(v float64) float64 {
	return math.Round(v*100) / 100
}

// readDefaultGateway reads /proc/net/route into m.routeBuf without allocating.
func (m *Manager) readDefaultGateway() (netip.Addr, []byte, bool) {
	if m.routeReader != nil {
		data, err := m.routeReader()
		if err != nil {
			return netip.Addr{}, nil, false
		}
		return parseDefaultGateway(data)
	}
	f, err := os.Open(routePath)
	if err != nil {
		return netip.Addr{}, nil, false
	}
	var total int
	for total < len(m.routeBuf) {
		n, rerr := f.Read(m.routeBuf[total:])
		total += n
		if rerr != nil {
			break
		}
	}
	_ = f.Close()
	return parseDefaultGateway(m.routeBuf[:total])
}

// parseDefaultGateway extracts the lowest-metric IPv4 default gateway from the
// contents of /proc/net/route without allocating strings or slices.
func parseDefaultGateway(data []byte) (netip.Addr, []byte, bool) {
	// Skip header line.
	nl := indexByte(data, '\n')
	if nl < 0 {
		return netip.Addr{}, nil, false
	}
	rest := data[nl+1:]

	var (
		bestOK     bool
		bestMetric int
		bestGW     uint32
		bestIface  []byte
	)

	for len(rest) > 0 {
		var line []byte
		if i := indexByte(rest, '\n'); i >= 0 {
			line = rest[:i]
			rest = rest[i+1:]
		} else {
			line = rest
			rest = nil
		}
		if len(line) > 0 && line[len(line)-1] == '\r' {
			line = line[:len(line)-1]
		}
		var fields [8][]byte
		if nextFields(line, fields[:]) < 8 {
			continue
		}
		iface := fields[0]
		if len(iface) == 2 && iface[0] == 'l' && iface[1] == 'o' {
			continue
		}
		dest, ok := parseHex32(fields[1])
		if !ok || dest != 0 {
			continue
		}
		mask, ok := parseHex32(fields[7])
		if !ok || mask != 0 {
			continue
		}
		flags, ok := parseHex32(fields[3])
		if !ok || flags&0x3 != 0x3 {
			continue
		}
		gw, ok := parseHex32(fields[2])
		if !ok || gw == 0 {
			continue
		}
		metric := parseDecInt(fields[6])
		if !bestOK || metric < bestMetric {
			bestOK = true
			bestMetric = metric
			bestGW = gw
			bestIface = iface
		}
	}
	if !bestOK {
		return netip.Addr{}, nil, false
	}
	// /proc/net/route prints __be32 in host byte order (little-endian on ARM/x86).
	addr := netip.AddrFrom4([4]byte{
		byte(bestGW),
		byte(bestGW >> 8),
		byte(bestGW >> 16),
		byte(bestGW >> 24),
	})
	return addr, bestIface, true
}

func indexByte(b []byte, c byte) int {
	for i := 0; i < len(b); i++ {
		if b[i] == c {
			return i
		}
	}
	return -1
}

func nextFields(line []byte, dst [][]byte) int {
	n := 0
	i := 0
	for i < len(line) && n < len(dst) {
		for i < len(line) && (line[i] == ' ' || line[i] == '\t') {
			i++
		}
		if i >= len(line) {
			break
		}
		start := i
		for i < len(line) && line[i] != ' ' && line[i] != '\t' {
			i++
		}
		dst[n] = line[start:i]
		n++
	}
	return n
}

func parseHex32(b []byte) (uint32, bool) {
	if len(b) == 0 || len(b) > 8 {
		return 0, false
	}
	var v uint32
	for i := 0; i < len(b); i++ {
		c := b[i]
		var nib uint32
		switch {
		case c >= '0' && c <= '9':
			nib = uint32(c - '0')
		case c >= 'a' && c <= 'f':
			nib = uint32(c-'a') + 10
		case c >= 'A' && c <= 'F':
			nib = uint32(c-'A') + 10
		default:
			return 0, false
		}
		v = (v << 4) | nib
	}
	return v, true
}

func parseDecInt(b []byte) int {
	var v int
	for i := 0; i < len(b); i++ {
		c := b[i]
		if c < '0' || c > '9' {
			break
		}
		v = v*10 + int(c-'0')
	}
	return v
}
