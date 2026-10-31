package netwatch

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Neoo-Blue/orbis/internal/store"
)

func okSample(ms float64) Sample { return Sample{LatencyMS: ms} }
func lossSample() Sample         { return Sample{Loss: true} }

func feedRound(m *Manager, ts time.Time, gw Sample, p1, p2, p3 Sample) {
	m.now = func() time.Time { return ts }
	m.recordRound(ts, "192.168.1.1", []byte("eth0"), true, [numTargets]Sample{gw, p1, p2, p3})
}

func TestClassifier(t *testing.T) {
	m := NewManager(nil, nil, nil)
	base := time.Date(2026, 10, 31, 8, 0, 0, 0, time.UTC)

	// Build a 1-hour baseline at 12 ms so the 24h median is firmly 12 ms.
	now := base
	for i := 0; i < 360; i++ {
		feedRound(m, now, okSample(1), okSample(12), okSample(14), okSample(16))
		now = now.Add(ProbeInterval)
	}
	st := m.Status()
	for _, tgt := range st.Targets {
		if tgt.State != StateGood {
			t.Fatalf("target %s: got state %q, want good", tgt.ID, tgt.State)
		}
	}

	// Latency > 3x median (42 ms > 36 ms) but NOT over 50 ms stays good.
	for i := 0; i < 30; i++ {
		feedRound(m, now, okSample(1), okSample(42), okSample(14), okSample(16))
		now = now.Add(ProbeInterval)
	}
	if got := m.Status().Targets[1].State; got != StateGood {
		t.Fatalf("p50 42 ms (< 50 ms) classified as %q, want good", got)
	}

	// Latency > 3x 24h median AND > 50 ms (65 ms vs 12 ms median) becomes degraded.
	for i := 0; i < 30; i++ {
		feedRound(m, now, okSample(1), okSample(65), okSample(14), okSample(16))
		now = now.Add(ProbeInterval)
	}
	if got := m.Status().Targets[1].State; got != StateDegraded {
		t.Fatalf("p50 65 ms (median 12 ms) classified as %q, want degraded", got)
	}

	// High latency that is NOT > 3x its own 24h median stays good.
	mSlow := NewManager(nil, nil, nil)
	tSlow := base
	for i := 0; i < 60; i++ {
		feedRound(mSlow, tSlow, okSample(2), okSample(30), okSample(30), okSample(30))
		tSlow = tSlow.Add(ProbeInterval)
	}
	for i := 0; i < 30; i++ {
		feedRound(mSlow, tSlow, okSample(2), okSample(75), okSample(30), okSample(30))
		tSlow = tSlow.Add(ProbeInterval)
	}
	if got := mSlow.Status().Targets[1].State; got != StateGood {
		t.Fatalf("p50 75 ms with ~30 ms 24h median classified as %q, want good", got)
	}

	// Packet loss > 2% (1 drop in 30 rounds = 3.33%) becomes degraded.
	mLoss := NewManager(nil, nil, nil)
	tLoss := base
	for i := 0; i < 29; i++ {
		feedRound(mLoss, tLoss, okSample(1), okSample(10), okSample(10), okSample(10))
		tLoss = tLoss.Add(ProbeInterval)
	}
	feedRound(mLoss, tLoss, okSample(1), lossSample(), okSample(10), okSample(10))
	tgt := mLoss.Status().Targets[1]
	if tgt.State != StateDegraded {
		t.Fatalf("3.33%% loss classified as %q, want degraded (loss=%v)", tgt.State, tgt.LossPercent)
	}

	// Three consecutive failures mark the target down even when earlier samples succeeded.
	tLoss = tLoss.Add(ProbeInterval)
	feedRound(mLoss, tLoss, okSample(1), lossSample(), okSample(10), okSample(10))
	tLoss = tLoss.Add(ProbeInterval)
	feedRound(mLoss, tLoss, okSample(1), lossSample(), okSample(10), okSample(10))
	if got := mLoss.Status().Targets[1].State; got != StateDown {
		t.Fatalf("3 consecutive failures classified as %q, want down", got)
	}
}

func TestJitterAndWindow(t *testing.T) {
	m := NewManager(nil, nil, nil)
	now := time.Date(2026, 10, 31, 9, 0, 0, 0, time.UTC)

	// Gateway: constant 2 ms -> jitter 0.
	// 1.1.1.1: [10, 20, 10, 20] -> diffs [10, 10, 10] -> jitter 10, p50 15.
	// 8.8.8.8: [10, 22, 16, 28] -> diffs [12, 6, 12] -> jitter 10, p50 19.
	seriesA := []float64{10, 20, 10, 20}
	seriesB := []float64{10, 22, 16, 28}
	for i := 0; i < 4; i++ {
		feedRound(m, now, okSample(2), okSample(seriesA[i]), okSample(seriesB[i]), okSample(12))
		now = now.Add(ProbeInterval)
	}

	st := m.Status()
	if st.Targets[0].JitterMS != 0 {
		t.Fatalf("constant gateway jitter = %v, want 0", st.Targets[0].JitterMS)
	}
	if st.Targets[1].JitterMS != 10 || st.Targets[1].P50MS != 15 {
		t.Fatalf("1.1.1.1 got jitter=%v p50=%v, want 10 and 15", st.Targets[1].JitterMS, st.Targets[1].P50MS)
	}
	if st.Targets[2].JitterMS != 10 || st.Targets[2].P50MS != 19 {
		t.Fatalf("8.8.8.8 got jitter=%v p50=%v, want 10 and 19", st.Targets[2].JitterMS, st.Targets[2].P50MS)
	}

	// Advance 30 clean rounds (5 minutes): the earlier jitter ages out of the 5m window.
	for i := 0; i < 30; i++ {
		feedRound(m, now, okSample(2), okSample(11), okSample(11), okSample(11))
		now = now.Add(ProbeInterval)
	}
	st = m.Status()
	if st.Targets[1].Samples5m != 30 {
		t.Fatalf("5m window holds %d samples, want 30", st.Targets[1].Samples5m)
	}
	if st.Targets[1].JitterMS != 0 || st.Targets[1].P50MS != 11 {
		t.Fatalf("after window rollover got jitter=%v p50=%v, want 0 and 11", st.Targets[1].JitterMS, st.Targets[1].P50MS)
	}
}

func TestVerdictStories(t *testing.T) {
	base := time.Date(2026, 10, 31, 10, 0, 0, 0, time.UTC)

	// Story 1: all good (including when a single public endpoint blips on its own).
	m := NewManager(nil, nil, nil)
	now := base
	for i := 0; i < 10; i++ {
		feedRound(m, now, okSample(0.8), okSample(11), okSample(13), okSample(15))
		now = now.Add(ProbeInterval)
	}
	st := m.Status()
	if st.Story != StoryAllGood || st.State != StateGood || st.Blame != "" {
		t.Fatalf("all-good story mismatch: %+v", st)
	}
	if st.Headline != "Your internet is fine" {
		t.Fatalf("unexpected all-good headline: %q", st.Headline)
	}

	// Single public target down while gateway + other two public targets are fine stays all-good.
	for i := 0; i < 3; i++ {
		feedRound(m, now, okSample(0.8), okSample(11), okSample(13), lossSample())
		now = now.Add(ProbeInterval)
	}
	if st = m.Status(); st.Story != StoryAllGood || st.State != StateGood {
		t.Fatalf("isolated single-target outage misattributed: story=%q state=%q", st.Story, st.State)
	}

	// Story 2: gateway failing means "your network", even when public targets fail behind it.
	mNet := NewManager(nil, nil, nil)
	now = base
	for i := 0; i < 3; i++ {
		feedRound(mNet, now, lossSample(), lossSample(), lossSample(), lossSample())
		now = now.Add(ProbeInterval)
	}
	st = mNet.Status()
	if st.Story != StoryNetwork || st.Blame != "your network" || st.State != StateDown {
		t.Fatalf("gateway-down verdict mismatch: story=%q blame=%q state=%q", st.Story, st.Blame, st.State)
	}

	// Story 3: gateway fine while public targets drop traffic means "your internet provider".
	mISP := NewManager(nil, nil, nil)
	now = base
	for i := 0; i < 28; i++ {
		feedRound(mISP, now, okSample(0.9), okSample(12), okSample(14), okSample(16))
		now = now.Add(ProbeInterval)
	}
	for i := 0; i < 2; i++ {
		feedRound(mISP, now, okSample(0.9), lossSample(), lossSample(), okSample(16))
		now = now.Add(ProbeInterval)
	}
	st = mISP.Status()
	if st.Story != StoryProvider || st.Blame != "your internet provider" || st.State != StateDegraded {
		t.Fatalf("isp-degraded verdict mismatch: story=%q blame=%q state=%q", st.Story, st.Blame, st.State)
	}
	if st.Headline != "Your provider is dropping traffic, your network is fine" {
		t.Fatalf("unexpected isp-degraded headline: %q", st.Headline)
	}

	// Full ISP outage: gateway still fine, all 3 public targets down.
	for i := 0; i < 3; i++ {
		feedRound(mISP, now, okSample(0.9), lossSample(), lossSample(), lossSample())
		now = now.Add(ProbeInterval)
	}
	st = mISP.Status()
	if st.Story != StoryProvider || st.Blame != "your internet provider" || st.State != StateDown {
		t.Fatalf("isp-down verdict mismatch: story=%q blame=%q state=%q", st.Story, st.Blame, st.State)
	}
}

func TestIncidentOpenCloseAndPersist(t *testing.T) {
	stDB, err := store.Open(filepath.Join(t.TempDir(), "orbis.db"))
	if err != nil {
		t.Fatalf("open temp store: %v", err)
	}
	defer stDB.Close()

	m := NewManager(nil, stDB, nil)
	base := time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)
	now := base

	// Steady healthy round first.
	feedRound(m, now, okSample(1), okSample(10), okSample(12), okSample(14))
	now = now.Add(ProbeInterval)

	// Rounds 1 and 2 of total public failure: not yet an incident.
	outageStart := now
	feedRound(m, now, okSample(1), lossSample(), lossSample(), lossSample())
	now = now.Add(ProbeInterval)
	feedRound(m, now, okSample(1), lossSample(), lossSample(), lossSample())
	if got := len(m.Status().Incidents); got != 0 {
		t.Fatalf("after 2 failed rounds got %d incidents, want 0", got)
	}

	// Round 3 opens the outage; still unpersisted while ongoing.
	now = now.Add(ProbeInterval)
	feedRound(m, now, okSample(1), lossSample(), lossSample(), lossSample())
	incs := m.Status().Incidents
	if len(incs) != 1 || !incs[0].Ongoing || incs[0].EndedAt != nil {
		t.Fatalf("expected 1 open incident on round 3, got %+v", incs)
	}
	if !incs[0].StartedAt.Equal(outageStart) {
		t.Fatalf("incident StartedAt = %v, want %v", incs[0].StartedAt, outageStart)
	}
	if incs[0].Cause != StoryProvider {
		t.Fatalf("incident Cause = %q, want %q", incs[0].Cause, StoryProvider)
	}
	events, err := stDB.Events(base.Add(-time.Hour), "", false, 20)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 0 {
		t.Fatalf("expected 0 stored events while incident is open, got %d", len(events))
	}

	// Round 4 continues the outage; round 5 has one public reply and closes it.
	now = now.Add(ProbeInterval)
	feedRound(m, now, okSample(1), lossSample(), lossSample(), lossSample())
	now = now.Add(ProbeInterval)
	feedRound(m, now, okSample(1), okSample(11), lossSample(), lossSample())

	incs = m.Status().Incidents
	if len(incs) != 1 || incs[0].Ongoing || incs[0].EndedAt == nil {
		t.Fatalf("expected closed incident on first public success, got %+v", incs)
	}
	if incs[0].DurationSeconds != 40 {
		t.Fatalf("closed incident duration = %ds, want 40s", incs[0].DurationSeconds)
	}

	events, err = stDB.Events(base.Add(-time.Hour), "", false, 20)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 persisted event after incident closed, got %d", len(events))
	}
	if events[0].Category != "internet" || events[0].Severity != store.SevWarning {
		t.Fatalf("unexpected persisted event category/severity: %+v", events[0])
	}

	// Cap in-memory incidents at 50 across 55 outages.
	mCap := NewManager(nil, nil, nil)
	for n := 0; n < 55; n++ {
		for r := 0; r < 3; r++ {
			now = now.Add(ProbeInterval)
			feedRound(mCap, now, lossSample(), lossSample(), lossSample(), lossSample())
		}
		now = now.Add(ProbeInterval)
		feedRound(mCap, now, okSample(1), okSample(10), okSample(10), okSample(10))
	}
	if got := len(mCap.Status().Incidents); got != maxIncidents {
		t.Fatalf("incidents kept in memory = %d, want %d", got, maxIncidents)
	}
}

func TestGatewayRouteAndRefusedProbe(t *testing.T) {
	routeTable := strings.Join([]string{
		"Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT",
		"wlan0\t00000000\t0100A8C0\t0003\t0\t0\t600\t00000000\t0\t0\t0",
		"eth0\t0032A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0",
		"eth0\t00000000\tFE32A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0",
		"tun0\t00000000\t0108000A\t0003\t0\t0\t50\t00000080\t0\t0\t0",
	}, "\n")

	m := NewManager(nil, nil, nil)
	fixedNow := time.Date(2026, 10, 31, 13, 0, 0, 0, time.UTC)
	m.now = func() time.Time { return fixedNow }
	m.routeReader = func() ([]byte, error) { return []byte(routeTable), nil }

	var gatewayTries []string
	var muTries = make(chan string, 10)
	m.dial = func(_ context.Context, addr string, _ time.Duration) (time.Duration, error) {
		if strings.HasPrefix(addr, "192.168.50.254:") {
			muTries <- addr
			if strings.HasSuffix(addr, ":53") {
				return ProbeTimeout, errors.New("i/o timeout")
			}
			if strings.HasSuffix(addr, ":80") {
				return 650 * time.Microsecond, syscall.ECONNREFUSED
			}
		}
		return 11 * time.Millisecond, nil
	}

	m.probeRound(context.Background())
	close(muTries)
	for a := range muTries {
		gatewayTries = append(gatewayTries, a)
	}

	if len(gatewayTries) != 2 || gatewayTries[0] != "192.168.50.254:53" || gatewayTries[1] != "192.168.50.254:80" {
		t.Fatalf("gateway port order = %v, want [:53 :80] stopping on ECONNREFUSED", gatewayTries)
	}
	gw := m.Status().Targets[0]
	if gw.Address != "192.168.50.254" || gw.Interface != "eth0" {
		t.Fatalf("gateway parsed as %s on %s, want 192.168.50.254 on eth0", gw.Address, gw.Interface)
	}
	if !gw.LastOK || gw.CurrentMS != 0.65 {
		t.Fatalf("ECONNREFUSED should count as 0.65 ms RTT, got last_ok=%v current_ms=%v", gw.LastOK, gw.CurrentMS)
	}
}

func TestHistoryDownsampleAndJSONShapes(t *testing.T) {
	m := NewManager(nil, nil, nil)

	// Fresh manager must never marshal nil slices as JSON null.
	rawStatus, err := json.Marshal(m.Status())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(rawStatus), "null") {
		t.Fatalf("fresh Status() marshals null: %s", rawStatus)
	}
	rawHist, err := json.Marshal(m.History(6))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(rawHist), "null") {
		t.Fatalf("fresh History() marshals null: %s", rawHist)
	}

	// Feed 2160 samples (6 hours) with one dropped packet at index 500.
	now := time.Date(2026, 10, 31, 6, 0, 0, 0, time.UTC)
	for i := 0; i < 2160; i++ {
		s := okSample(12)
		if i == 500 {
			s = lossSample()
		}
		feedRound(m, now, okSample(1), s, okSample(14), okSample(16))
		now = now.Add(ProbeInterval)
	}

	h := m.History(6)
	for _, series := range h.Targets {
		if len(series.Points) > maxHistoryPoints {
			t.Fatalf("target %s returned %d points, max is %d", series.ID, len(series.Points), maxHistoryPoints)
		}
		if len(series.Points) != maxHistoryPoints {
			t.Fatalf("target %s returned %d points for 2160 samples, want %d", series.ID, len(series.Points), maxHistoryPoints)
		}
	}
	var sawLossMark bool
	for _, pt := range h.Targets[1].Points {
		if pt.Loss {
			sawLossMark = true
			break
		}
	}
	if !sawLossMark {
		t.Fatal("downsampled 6h series dropped single-packet loss mark")
	}
}

func TestSteadyStateAllocations(t *testing.T) {
	m := NewManager(nil, nil, nil)
	now := time.Date(2026, 10, 31, 14, 0, 0, 0, time.UTC)
	samples := [numTargets]Sample{okSample(1.1), okSample(11.2), okSample(13.4), okSample(15.6)}
	iface := []byte("eth0")

	// Prime cached gateway strings once.
	m.recordRound(now, "192.168.1.1", iface, true, samples)

	allocs := testing.AllocsPerRun(100, func() {
		now = now.Add(ProbeInterval)
		m.recordRound(now, "192.168.1.1", iface, true, samples)
	})
	if allocs > 1 {
		t.Fatalf("recordRound allocated %.2f objects/round, want <= 1", allocs)
	}
}
