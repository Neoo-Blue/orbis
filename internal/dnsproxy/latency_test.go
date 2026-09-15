package dnsproxy

import "testing"

func TestAnswerLatencyBuckets(t *testing.T) {
	var h latencyHist
	// 0.4ms and 1ms land in le=1ms; 6ms in 10ms; 50ms on the 50ms bound;
	// 1500ms overflows into +Inf.
	for _, ms := range []float64{0.4, 1, 6, 50, 1500} {
		h.observe(ms)
	}

	cum, sumSec, count := h.snapshot()
	if count != 5 {
		t.Fatalf("count = %d, want 5", count)
	}
	want := [len(dnsAnswerBucketMS) + 1]uint64{2, 2, 3, 3, 4, 4, 4, 4, 4, 5}
	if cum != want {
		t.Fatalf("cumulative buckets = %v, want %v", cum, want)
	}
	for i := 1; i < len(cum); i++ {
		if cum[i] < cum[i-1] {
			t.Fatalf("cumulative counts are not monotone at bucket %d: %v", i, cum)
		}
	}

	// 0.4+1+6+50+1500 ms = 1557.4 ms = 1.5574 s. Microsecond truncation
	// of 0.4ms is 400us, so the sum is exact for these inputs.
	if sumSec < 1.5573 || sumSec > 1.5575 {
		t.Fatalf("sum = %g s, want ~1.5574", sumSec)
	}

	exported := h.export()
	buckets, ok := exported["buckets"].([]map[string]any)
	if !ok || len(buckets) != len(want) {
		t.Fatalf("export buckets = %#v", exported["buckets"])
	}
	if le, _ := buckets[0]["le"].(string); le != "0.001" {
		t.Fatalf("first le = %q, want 0.001", le)
	}
	if le, _ := buckets[len(buckets)-1]["le"].(string); le != "+Inf" {
		t.Fatalf("last le = %q, want +Inf", le)
	}
	var prev int64
	for i, b := range buckets {
		n, _ := b["n"].(int64)
		if n < prev {
			t.Fatalf("exported counts are not monotone at %d: %d < %d", i, n, prev)
		}
		if uint64(n) != want[i] {
			t.Fatalf("exported bucket %d n = %d, want %d", i, n, want[i])
		}
		prev = n
	}
}
