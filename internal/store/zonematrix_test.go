package store

import (
	"strings"
	"testing"
	"time"
)

func TestFlowAddrTotalsWindowAndIndex(t *testing.T) {
	s := openTestStore(t)
	now := time.Now()
	recent := now.Add(-15 * time.Minute)
	stale := now.Add(-2 * time.Hour)

	err := s.writeFlows([]Flow{
		{
			ID: "f-recent-1", StartedAt: recent, LastSeen: recent, Proto: "tcp",
			SrcIP: "192.168.1.10", DstIP: "1.1.1.1", Direction: DirOutbound,
			BytesIn: 1000, BytesOut: 500, Verdict: VerdictAllow,
		},
		{
			ID: "f-recent-2", StartedAt: recent.Add(time.Minute), LastSeen: recent, Proto: "tcp",
			SrcIP: "192.168.1.10", DstIP: "1.1.1.1", Direction: DirOutbound,
			BytesIn: 200, BytesOut: 100, Verdict: VerdictBlock,
		},
		{
			ID: "f-stale", StartedAt: stale, LastSeen: stale, Proto: "udp",
			SrcIP: "192.168.1.10", DstIP: "8.8.8.8", Direction: DirOutbound,
			BytesIn: 99999, BytesOut: 99999, Verdict: VerdictAllow,
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	totals, err := s.FlowAddrTotals(now.Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(totals) != 1 {
		t.Fatalf("expected 1 aggregated endpoint pair inside 1h window, got %d: %+v", len(totals), totals)
	}
	got := totals[0]
	if got.SrcIP != "192.168.1.10" || got.DstIP != "1.1.1.1" {
		t.Fatalf("unexpected pair %s -> %s", got.SrcIP, got.DstIP)
	}
	if got.Flows != 2 || got.Bytes != 1800 || got.Blocked != 1 {
		t.Fatalf("unexpected totals: %+v", got)
	}

	// Verify SQLite uses idx_flows_started rather than scanning the flows table.
	rows, err := s.db.Query(`EXPLAIN QUERY PLAN SELECT src_ip, dst_ip, COUNT(*), COALESCE(SUM(bytes_in+bytes_out), 0),
		COALESCE(SUM(CASE WHEN verdict='block' THEN 1 ELSE 0 END), 0)
		FROM flows INDEXED BY idx_flows_started
		WHERE started_at >= ? GROUP BY src_ip, dst_ip`, now.Add(-time.Hour).Unix())
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var plan strings.Builder
	for rows.Next() {
		var id, parent, notused int
		var detail string
		if err := rows.Scan(&id, &parent, &notused, &detail); err != nil {
			t.Fatal(err)
		}
		plan.WriteString(detail + "\n")
	}
	if !strings.Contains(plan.String(), "idx_flows_started") {
		t.Fatalf("query plan did not use idx_flows_started:\n%s", plan.String())
	}
	if strings.Contains(plan.String(), "SCAN flows") && !strings.Contains(plan.String(), "USING INDEX idx_flows_started") {
		t.Fatalf("query plan performed a full table scan:\n%s", plan.String())
	}
}

func TestFlowAddrTotalsMemoised(t *testing.T) {
	s := openTestStore(t)
	now := time.Now()
	recent := now.Add(-5 * time.Minute)

	if err := s.writeFlows([]Flow{{
		ID: "f-1", StartedAt: recent, LastSeen: recent, Proto: "tcp",
		SrcIP: "10.0.0.2", DstIP: "9.9.9.9", Direction: DirOutbound,
		BytesIn: 400, BytesOut: 100, Verdict: VerdictAllow,
	}}); err != nil {
		t.Fatal(err)
	}

	first, err := s.FlowAddrTotals(now.Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 1 || first[0].Bytes != 500 {
		t.Fatalf("unexpected initial result: %+v", first)
	}

	// A second write within the 30 s TTL must not invalidate the cached aggregate.
	if err := s.writeFlows([]Flow{{
		ID: "f-2", StartedAt: recent, LastSeen: recent, Proto: "tcp",
		SrcIP: "10.0.0.3", DstIP: "1.1.1.1", Direction: DirOutbound,
		BytesIn: 1000, BytesOut: 1000, Verdict: VerdictAllow,
	}}); err != nil {
		t.Fatal(err)
	}

	cached, err := s.FlowAddrTotals(time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(cached) != 1 || cached[0].Bytes != 500 {
		t.Fatalf("expected 30s memoised result to return 1 cached row, got %+v", cached)
	}
}
