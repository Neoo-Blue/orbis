package store

import (
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
