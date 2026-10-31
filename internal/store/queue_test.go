package store

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"
)

func openTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func dnsRow() DNSQuery {
	return DNSQuery{TS: time.Now(), Name: "example.com", QType: "A"}
}

func flowRow(i int) Flow {
	now := time.Unix(1_700_000_000, 0)
	return Flow{
		ID:        fmt.Sprintf("f-%d", i),
		StartedAt: now,
		LastSeen:  now,
		Proto:     "tcp",
		SrcIP:     "10.0.0.1",
		DstIP:     "1.1.1.1",
		Direction: DirOutbound,
	}
}

// mustFinish fails the test if fn has not returned within 2s, so a
// regression that blocks on writeMu cannot hang the whole binary.
func mustFinish(t *testing.T, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		fn()
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("queue call blocked on writeMu")
	}
}

func TestQueueDNSDoesNotBlockOnWriteMu(t *testing.T) {
	s := openTestStore(t)
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	mustFinish(t, func() {
		q := dnsRow()
		for i := 0; i < 3*maxBatch; i++ {
			s.QueueDNS(q)
		}
	})
	s.mu.Lock()
	s.dnsBuf = nil
	s.mu.Unlock()
}

func TestQueueDNSCapAndDrain(t *testing.T) {
	s := openTestStore(t)

	func() {
		s.writeMu.Lock()
		defer s.writeMu.Unlock()
		q := dnsRow()
		for i := 0; i < maxPending+10; i++ {
			s.QueueDNS(q)
		}
		st := s.WriteStats()
		if st.Dropped != 10 {
			t.Fatalf("Dropped = %d, want 10", st.Dropped)
		}
		if st.Pending != maxPending {
			t.Fatalf("Pending = %d, want %d", st.Pending, maxPending)
		}
	}()

	// 50k modernc inserts take a few hundred ms normally, but tens of
	// seconds under -race. Eight seconds is enough without it; 30s covers
	// the instrumented path without hanging the suite.
	deadline := time.Now().Add(30 * time.Second)
	var n int
	for {
		if err := s.db.QueryRow(`SELECT count(*) FROM dns_queries`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		// The rows become visible at commit; the counters are bumped just
		// after flush() gets the result, so wait for both.
		if n == maxPending && !s.WriteStats().LastFlushOK.IsZero() {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("dns_queries count = %d, want %d", n, maxPending)
		}
		time.Sleep(50 * time.Millisecond)
	}

	st := s.WriteStats()
	if st.Flushes == 0 {
		t.Fatal("Flushes = 0, want > 0")
	}
	if st.LastFlushOK.IsZero() {
		t.Fatal("LastFlushOK is zero")
	}
	if st.Pending != 0 {
		t.Fatalf("Pending = %d, want 0", st.Pending)
	}
	if st.BusyNanos == 0 {
		t.Fatal("BusyNanos = 0, want > 0")
	}
}

// A batch still being written counts as busy up to now, so a sampler taking
// one reading a minute sees a long catch-up write as busy every minute.
func TestBusyCountsWriteInProgress(t *testing.T) {
	s := openTestStore(t)
	base := s.WriteStats().BusyNanos
	s.busyStart()
	time.Sleep(30 * time.Millisecond)
	mid := s.WriteStats().BusyNanos
	if mid-base < uint64(25*time.Millisecond) {
		t.Fatalf("in-progress write counted %v, want at least 25ms", time.Duration(mid-base))
	}
	time.Sleep(30 * time.Millisecond)
	s.busyEnd()
	end := s.WriteStats().BusyNanos
	if end-base < uint64(55*time.Millisecond) {
		t.Fatalf("finished write counted %v, want at least 55ms", time.Duration(end-base))
	}
	time.Sleep(20 * time.Millisecond)
	if after := s.WriteStats().BusyNanos; after != end {
		t.Fatalf("an idle writer kept counting: %v then %v", time.Duration(end), time.Duration(after))
	}
}

func TestWriteFlowsChunkedUpsert(t *testing.T) {
	s := openTestStore(t)
	flows := make([]Flow, 70)
	for i := range flows {
		f := flowRow(i)
		f.BytesIn, f.BytesOut = int64(i+1), int64(i+2)
		f.Hostname, f.SNI, f.App, f.JA4 = "example.com", "example.com", "web", "fingerprint"
		f.Reason, f.Risk = "original", 0.8
		flows[i] = f
	}
	if err := s.writeFlows(flows); err != nil {
		t.Fatal(err)
	}
	ended := flows[0].StartedAt.Add(time.Minute)
	updates := []Flow{flows[0], flows[32], flows[69]}
	for i := range updates {
		f := &updates[i]
		f.BytesIn, f.BytesOut = 1234, 5678
		f.PacketsIn, f.PacketsOut = 12, 34
		f.EndedAt, f.LastSeen = &ended, ended
		f.Hostname, f.SNI, f.App, f.JA4, f.Reason = "", "", "", "", ""
		f.Risk, f.Verdict, f.Tags = 0.2, VerdictBlock, []string{"updated"}
	}
	if err := s.writeFlows(updates); err != nil {
		t.Fatal(err)
	}
	got, err := s.Flows(FlowQuery{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 70 {
		t.Fatalf("flow count = %d, want 70", len(got))
	}
	updated := map[string]bool{flows[0].ID: true, flows[32].ID: true, flows[69].ID: true}
	for _, f := range got {
		if updated[f.ID] {
			if f.BytesIn != 1234 || f.BytesOut != 5678 || f.PacketsIn != 12 || f.PacketsOut != 34 {
				t.Errorf("%s: counters not replaced: %+v", f.ID, f)
			}
			if f.EndedAt == nil || !f.EndedAt.Equal(ended) || !f.LastSeen.Equal(ended) {
				t.Errorf("%s: timestamps not updated: %+v", f.ID, f)
			}
			if f.Verdict != VerdictBlock || len(f.Tags) != 1 || f.Tags[0] != "updated" {
				t.Errorf("%s: verdict/tags not replaced: %+v", f.ID, f)
			}
		} else if f.EndedAt != nil || f.BytesIn == 1234 || f.BytesOut == 5678 {
			t.Errorf("%s: untouched flow changed: %+v", f.ID, f)
		}
		if f.Hostname != "example.com" || f.SNI != "example.com" || f.App != "web" || f.JA4 != "fingerprint" || f.Reason != "original" || f.Risk != 0.8 {
			t.Errorf("%s: enrichment/risk not preserved: %+v", f.ID, f)
		}
	}
}

func TestPruneChunked(t *testing.T) {
	s := openTestStore(t)
	now := time.Now().Truncate(time.Second)
	old := now.Add(-48 * time.Hour).Unix()
	// Seed LIMIT-sized batches without 45,000 individual fixture inserts.
	for i := 0; i < 45000; i += 20000 {
		n := min(20000, 45000-i)
		if _, err := s.db.Exec(`WITH RECURSIVE seq(n) AS
			(SELECT ? UNION ALL SELECT n+1 FROM seq LIMIT ?)
			INSERT INTO flows (id, started_at, last_seen, proto, src_ip, dst_ip, direction)
			SELECT 'old-' || n, ?, ?, 'tcp', '10.0.0.1', '1.1.1.1', 'outbound' FROM seq`, i, n, old, old); err != nil {
			t.Fatal(err)
		}
		if _, err := s.db.Exec(`WITH RECURSIVE seq(n) AS
			(SELECT 1 UNION ALL SELECT n+1 FROM seq LIMIT ?)
			INSERT INTO dns_queries (ts, name, qtype)
			SELECT ?, 'old.example', 'A' FROM seq`, n, old); err != nil {
			t.Fatal(err)
		}
	}
	recent := []Flow{flowRow(0), flowRow(1)}
	for i := range recent {
		recent[i].StartedAt, recent[i].LastSeen = now, now
	}
	if err := s.writeFlows(recent); err != nil {
		t.Fatal(err)
	}
	if err := s.writeDNS([]DNSQuery{dnsRow(), dnsRow()}); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"flows", "dns_queries"} {
		var n int
		if err := s.db.QueryRow("SELECT count(*) FROM " + table).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != 45002 {
			t.Fatalf("%s seeded count = %d, want 45002", table, n)
		}
	}
	if err := s.Prune(context.Background(), 1, 0); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		"SELECT count(*) FROM flows WHERE started_at < ?",
		"SELECT count(*) FROM dns_queries WHERE ts < ?",
	} {
		var n int
		if err := s.db.QueryRow(q, now.Add(-24*time.Hour).Unix()).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != 0 {
			t.Errorf("%s: %d old rows remain", q, n)
		}
	}
	got, err := s.Flows(FlowQuery{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("recent flow count = %d, want 2", len(got))
	}
	for _, f := range got {
		if (f.ID != recent[0].ID && f.ID != recent[1].ID) || !f.StartedAt.Equal(now) {
			t.Errorf("unexpected surviving flow: %+v", f)
		}
	}
	var n int
	if err := s.db.QueryRow("SELECT count(*) FROM dns_queries").Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Errorf("recent DNS count = %d, want 2", n)
	}
}

func TestPruneCancelled(t *testing.T) {
	s := openTestStore(t)
	if err := s.writeFlows([]Flow{flowRow(0)}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := s.Prune(ctx, 1, 0); !errors.Is(err, context.Canceled) {
		t.Fatalf("Prune = %v, want context.Canceled", err)
	}
	got, err := s.Flows(FlowQuery{})
	if err != nil || len(got) != 1 {
		t.Fatalf("cancelled prune changed flows: count=%d, err=%v", len(got), err)
	}
}

func TestOpenConnectionPragmas(t *testing.T) {
	s := openTestStore(t)
	// Hold connections concurrently so this checks newly opened pooled
	// connections as well as the one used for schema application.
	for i := 0; i < 3; i++ {
		conn, err := s.db.Conn(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		for pragma, want := range map[string]string{
			"journal_mode":       "wal",
			"synchronous":        "1",
			"cache_size":         "-16000",
			"journal_size_limit": "67108864",
			"mmap_size":          "268435456",
			"temp_store":         "2",
		} {
			var got string
			if err := conn.QueryRowContext(context.Background(), "PRAGMA "+pragma).Scan(&got); err != nil {
				t.Fatal(err)
			}
			if got != want {
				t.Errorf("connection %d: %s = %s, want %s", i, pragma, got, want)
			}
		}
	}
}

func TestBackgroundBlockSourceIndex(t *testing.T) {
	t.Parallel()
	s := openTestStore(t)
	const q = "SELECT count(*) FROM sqlite_master WHERE type='index' AND name='idx_block_source'"
	var n int
	if err := s.db.QueryRow(q).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatal("block source index was built synchronously")
	}
	deadline := time.Now().Add(10 * time.Second)
	for n == 0 {
		if time.Now().After(deadline) {
			t.Fatal("background block source index was not built")
		}
		time.Sleep(50 * time.Millisecond)
		if err := s.db.QueryRow(q).Scan(&n); err != nil {
			t.Fatal(err)
		}
	}
}

func TestReplaceListDomainsChunked(t *testing.T) {
	s := openTestStore(t)
	if _, err := s.ReplaceListDomains(context.Background(), "other", "ads", ListEntries{Exact: []string{"keep.example"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ReplaceListDomains(context.Background(), "test", "ads", ListEntries{Exact: []string{"stale.example"}}); err != nil {
		t.Fatal(err)
	}
	e := ListEntries{Important: map[string]bool{}}
	for kind, items := range []*[]string{&e.Exact, &e.Wildcard, &e.Regex, &e.AllowExact, &e.AllowWildcard, &e.AllowRegex} {
		for i := 0; i < 70; i++ {
			d := fmt.Sprintf("entry-%d-%d.example", kind, i)
			*items = append(*items, d)
			e.Important[d] = i%2 == 0
		}
	}
	// A duplicate in a later chunk must still be ignored.
	e.Exact = append(e.Exact, e.Exact[0])
	if _, err := s.ReplaceListDomains(context.Background(), "test", "tracking", e); err != nil {
		t.Fatal(err)
	}
	for kind := EntryExact; kind <= EntryAllowRegex; kind++ {
		var n, important int
		if err := s.db.QueryRow(`SELECT count(*), sum(important) FROM block_domains
			WHERE source='test' AND category='tracking' AND wildcard=?`, kind).Scan(&n, &important); err != nil {
			t.Fatal(err)
		}
		if n != 70 || important != 35 {
			t.Errorf("kind %d: count=%d important=%d, want 70/35", kind, n, important)
		}
	}
	var stale, other int
	if err := s.db.QueryRow("SELECT count(*) FROM block_domains WHERE domain='stale.example'").Scan(&stale); err != nil {
		t.Fatal(err)
	}
	if err := s.db.QueryRow("SELECT count(*) FROM block_domains WHERE source='other' AND domain='keep.example'").Scan(&other); err != nil {
		t.Fatal(err)
	}
	if stale != 0 || other != 1 {
		t.Errorf("replacement affected wrong rows: stale=%d other=%d", stale, other)
	}
}

func TestReplaceListDomainsWritesOnlyTheDifference(t *testing.T) {
	s := openTestStore(t)
	e := ListEntries{Exact: []string{"a.example", "b.example", "c.example"}, Wildcard: []string{"w.example"}}
	if n, err := s.ReplaceListDomains(context.Background(), "test", "ads", e); err != nil || n != 4 {
		t.Fatalf("first load changed %d: %v", n, err)
	}
	if n, err := s.ReplaceListDomains(context.Background(), "test", "ads", e); err != nil || n != 0 {
		t.Fatalf("identical refresh changed %d: %v", n, err)
	}

	// One removed, one added, one moved from exact to wildcard.
	next := ListEntries{Exact: []string{"a.example", "d.example"}, Wildcard: []string{"w.example", "b.example"}}
	if n, err := s.ReplaceListDomains(context.Background(), "test", "ads", next); err != nil || n != 4 {
		t.Fatalf("diff changed %d: %v", n, err)
	}
	got := map[string]int{}
	rows, err := s.db.Query("SELECT domain, wildcard FROM block_domains WHERE source='test'")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var d string
		var k int
		if err := rows.Scan(&d, &k); err != nil {
			t.Fatal(err)
		}
		got[d] = k
	}
	want := map[string]int{"a.example": EntryExact, "d.example": EntryExact, "w.example": EntryWildcard, "b.example": EntryWildcard}
	if len(got) != len(want) {
		t.Fatalf("rows = %v", got)
	}
	for d, k := range want {
		if got[d] != k {
			t.Fatalf("%s kind %d, want %d", d, got[d], k)
		}
	}

	// A category change on the list rewrites its rows.
	if n, err := s.ReplaceListDomains(context.Background(), "test", "tracking", next); err != nil || n != 8 {
		t.Fatalf("recategorised changed %d: %v", n, err)
	}
}

// The log writer must get the lock between chunks of a large refresh, which
// is what stopped a 480k-row list from blocking all logging for 7 minutes.
func TestLargeListRefreshDoesNotStarveTheLogWriter(t *testing.T) {
	s := openTestStore(t)
	const n = listWriteChunk * 12
	e := ListEntries{Exact: make([]string, 0, n)}
	for i := 0; i < n; i++ {
		e.Exact = append(e.Exact, fmt.Sprintf("host-%d.example", i))
	}
	done := make(chan error, 1)
	go func() {
		_, err := s.ReplaceListDomains(context.Background(), "big", "ads", e)
		done <- err
	}()
	var flushed int
	for finished := false; !finished; {
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
			finished = true
		default:
			start := s.WriteStats().Flushes
			s.QueueDNS(DNSQuery{TS: time.Now(), Name: "during.example", QType: "A"})
			s.flush()
			if s.WriteStats().Flushes > start {
				flushed++
			}
		}
	}
	if flushed < 2 {
		t.Fatalf("only %d log flushes got in during the refresh", flushed)
	}
}

func TestShouldTruncateWAL(t *testing.T) {
	for _, c := range []struct {
		frames, copied int
		want           bool
	}{
		{100, 100, false},       // small, leave it
		{344876, 343158, true},  // measured on a Pi: grown and all but copied
		{344876, 100000, false}, // still copying a backlog
		{walTruncateFrames, walTruncateFrames, true},
	} {
		if got := shouldTruncateWAL(c.frames, c.copied); got != c.want {
			t.Errorf("shouldTruncateWAL(%d, %d) = %v", c.frames, c.copied, got)
		}
	}
}

func TestQueueFlowKeepsOneRowPerFlow(t *testing.T) {
	s := openTestStore(t)
	s.writeMu.Lock() // a stalled writer
	first := Flow{ID: "f1", BytesIn: 1, StartedAt: time.Now(), LastSeen: time.Now(), Proto: "tcp", SrcIP: "10.0.0.1", DstIP: "10.0.0.2", Direction: "out", Verdict: "allow"}
	for i := 0; i < 1000; i++ {
		first.BytesIn = int64(i)
		s.QueueFlow(first)
	}
	if got := s.WriteStats().Pending; got != 1 {
		s.writeMu.Unlock()
		t.Fatalf("a stalled writer holds %d rows for one flow", got)
	}
	s.writeMu.Unlock()
	s.flush()
	var bytes int64
	if err := s.db.QueryRow("SELECT bytes_in FROM flows WHERE id='f1'").Scan(&bytes); err != nil {
		t.Fatal(err)
	}
	if bytes != 999 {
		t.Fatalf("bytes_in = %d, want the newest snapshot", bytes)
	}
	// The next batch starts clean.
	s.QueueFlow(first)
	if got := s.WriteStats().Pending; got != 1 {
		t.Fatalf("pending = %d", got)
	}
}

func TestDeleteListRemovesEverything(t *testing.T) {
	s := openTestStore(t)
	e := ListEntries{}
	for i := 0; i < listWriteChunk+10; i++ {
		e.Exact = append(e.Exact, fmt.Sprintf("host-%d.example", i))
	}
	if err := s.UpsertListMeta(ListMeta{Name: "gone", URL: "http://x"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ReplaceListDomains(context.Background(), "gone", "ads", e); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteList("gone"); err != nil {
		t.Fatal(err)
	}
	var rows, metas int
	if err := s.db.QueryRow("SELECT count(*) FROM block_domains").Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if err := s.db.QueryRow("SELECT count(*) FROM list_meta").Scan(&metas); err != nil {
		t.Fatal(err)
	}
	if rows != 0 || metas != 0 {
		t.Fatalf("rows=%d metas=%d", rows, metas)
	}
}

func TestObserveCandidateBatch(t *testing.T) {
	s := openTestStore(t)
	for _, o := range []struct{ n, clients, referrers int }{{3, 2, 4}, {100, 1, 6}, {0, 100, 100}, {-1, 100, 100}} {
		if err := s.ObserveCandidate("example.com", o.n, o.clients, o.referrers); err != nil {
			t.Fatal(err)
		}
	}
	got, err := s.Candidates("", 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Observations != 53 || got[0].DistinctClients != 2 || got[0].DistinctReferrers != 6 {
		t.Fatalf("batched candidate = %+v, want 53 observations, 2 clients, 6 referrers", got)
	}
}

func TestQueueFlowDoesNotBlockOnWriteMu(t *testing.T) {
	s := openTestStore(t)
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	mustFinish(t, func() {
		for i := 0; i < 3*maxBatch; i++ {
			s.QueueFlow(flowRow(i))
		}
	})
	s.mu.Lock()
	s.flowBuf = nil
	s.mu.Unlock()
}

// A flow that was queued twice while a flush was blocked lands in one
// multi-row statement; the later row must win, as it did one row at a time.
func TestWriteFlowsDuplicateIDInOneBatch(t *testing.T) {
	s := openTestStore(t)
	first := flowRow(0)
	first.BytesIn, first.BytesOut, first.Hostname = 10, 20, "example.com"
	second := first
	second.BytesIn, second.BytesOut, second.Hostname = 300, 400, ""
	third := flowRow(1)
	if err := s.writeFlows([]Flow{first, third, second}); err != nil {
		t.Fatal(err)
	}
	got, err := s.Flows(FlowQuery{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("flow count = %d, want 2", len(got))
	}
	for _, f := range got {
		if f.ID != first.ID {
			continue
		}
		if f.BytesIn != 300 || f.BytesOut != 400 {
			t.Fatalf("later duplicate did not win: %+v", f)
		}
		if f.Hostname != "example.com" {
			t.Fatalf("empty hostname in the later row erased the earlier one: %+v", f)
		}
	}
}

func TestAListChangeIsAnnouncedAndUnblessedBeforeItsFirstRow(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	if _, err := s.ReplaceListDomains(ctx, "l", "ads", ListEntries{Exact: []string{"a.example"}}); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertListMeta(ListMeta{Name: "l", URL: "https://example.com/l", ETag: "etag-1"}); err != nil {
		t.Fatal(err)
	}
	notes := 0
	s.OnListChange(func() { notes++ })
	if _, err := s.ReplaceListDomains(ctx, "l", "ads", ListEntries{Exact: []string{"a.example"}}); err != nil || notes != 0 {
		t.Fatalf("no change, %d notes: %v", notes, err)
	}
	if _, err := s.ReplaceListDomains(ctx, "l", "ads", ListEntries{Exact: []string{"b.example"}}); err != nil || notes != 1 {
		t.Fatalf("%d notes: %v", notes, err)
	}
	metas, err := s.ListMetas()
	if err != nil || len(metas) != 1 || metas[0].ETag != "" {
		t.Fatalf("the etag survived a rewrite: %+v %v", metas, err)
	}
}

func TestGeoRepairsKeepWorkingInBatches(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	for i := range geoBatch*2 + 3 {
		f := flowRow(i)
		f.DstIP, f.Country = fmt.Sprintf("10.9.0.%d", i), "AU"
		s.QueueFlow(f)
	}
	local := flowRow(1000)
	local.Direction, local.Country, local.DstIP = "local", "AU", "192.168.1.1"
	s.QueueFlow(local)
	s.flush()

	var ips []string
	for i := range geoBatch*2 + 3 {
		ips = append(ips, fmt.Sprintf("10.9.0.%d", i))
	}
	n, err := s.ClearFlowGeo(ctx, ips)
	if err != nil || n != int64(geoBatch*2+4) {
		t.Fatalf("cleared %d: %v", n, err)
	}
	n, err = s.ApplyGeoUpdates(ctx, []GeoUpdate{{IP: "10.9.0.1", Country: "US"}})
	if err != nil || n != 1 {
		t.Fatalf("updated %d: %v", n, err)
	}
}

func TestABackfillStopsWithTheDaemon(t *testing.T) {
	s := openTestStore(t)
	f := flowRow(1)
	f.Country = "AU"
	s.QueueFlow(f)
	s.flush()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.ClearFlowGeo(ctx, []string{f.DstIP}); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
	if _, err := s.ApplyGeoUpdates(ctx, []GeoUpdate{{IP: f.DstIP, Country: "US"}}); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
}
