package flows

import (
	"net/netip"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/Neoo-Blue/orbis/internal/geoip"
	"github.com/Neoo-Blue/orbis/internal/store"
)

func newTestTracker(t *testing.T) (*Tracker, *store.Store) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	tr := NewTracker(st, geoip.New(), 2*time.Minute, 1000)
	tr.SetLocalNets([]string{"192.168.1.0/24"})
	return tr, st
}

// TestObserveDoesNotDeadlock is a regression test for a real deadlock: Observe
// held the tracker's write lock and then called isLocal, which took a read
// lock on the same non-reentrant RWMutex. Every first packet of every new flow
// froze the tracker permanently. A plain call is enough to catch it — the
// deadlock is unconditional — but the timeout keeps a future regression from
// hanging the whole test binary.
func TestObserveDoesNotDeadlock(t *testing.T) {
	tr, _ := newTestTracker(t)

	done := make(chan struct{})
	go func() {
		defer close(done)
		tr.Observe(Observation{
			Key: Key{
				Proto: 6,
				SrcIP: netip.MustParseAddr("192.168.1.50"), SrcPort: 44321,
				DstIP: netip.MustParseAddr("142.250.72.14"), DstPort: 443,
			},
			Bytes: 74, TCPFlags: tcpSYN, At: time.Now(),
		})
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Observe deadlocked on the first packet of a new flow")
	}

	if got := tr.Stats().Active; got != 1 {
		t.Errorf("active flows = %d, want 1", got)
	}
}

// TestConcurrentObserveIsRaceFree exercises the paths a real capture hits from
// several goroutines at once. Run with -race, this catches unsynchronised
// access to the flow table and the stats counters.
func TestConcurrentObserveIsRaceFree(t *testing.T) {
	tr, _ := newTestTracker(t)
	tr.Start()
	defer tr.Stop()

	var wg sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				src := netip.AddrFrom4([4]byte{192, 168, 1, byte(10 + w)})
				dst := netip.AddrFrom4([4]byte{93, 184, byte(i % 251), byte(w)})
				tr.Observe(Observation{
					Key: Key{
						Proto: 6, SrcIP: src, SrcPort: uint16(30000 + i),
						DstIP: dst, DstPort: 443,
					},
					Bytes: 1200, SNI: "example.test", At: time.Now(),
				})
				// The reply direction must land on the same flow.
				tr.Observe(Observation{
					Key: Key{
						Proto: 6, SrcIP: dst, SrcPort: 443,
						DstIP: src, DstPort: uint16(30000 + i),
					},
					Bytes: 5000, At: time.Now(),
				})
			}
		}(worker)
	}

	// Readers run concurrently with writers, which is what the UI does.
	for r := 0; r < 3; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				_ = tr.Active(50)
				_ = tr.ClientRates()
				_ = tr.Stats()
				tr.SetLocalNets([]string{"192.168.1.0/24", "10.0.0.0/8"})
			}
		}()
	}
	wg.Wait()

	stats := tr.Stats()
	if stats.Total == 0 {
		t.Fatal("no flows were recorded")
	}
	// 8 workers x 200 destinations, each seen in both directions, must
	// collapse to one flow per tuple rather than two.
	if stats.Total > 1600 {
		t.Errorf("recorded %d flows for 1600 tuples — reply packets created duplicate flows", stats.Total)
	}
}

func TestKeyCanonicalIsDirectionStable(t *testing.T) {
	a := netip.MustParseAddr("192.168.1.5")
	b := netip.MustParseAddr("1.1.1.1")
	forward := Key{Proto: 6, SrcIP: a, SrcPort: 1234, DstIP: b, DstPort: 443}
	reverse := Key{Proto: 6, SrcIP: b, SrcPort: 443, DstIP: a, DstPort: 1234}

	ca, swappedA := forward.Canonical()
	cb, swappedB := reverse.Canonical()
	if ca != cb {
		t.Errorf("the two directions produced different keys: %v vs %v", ca, cb)
	}
	if swappedA == swappedB {
		t.Error("exactly one direction should report being swapped")
	}
}

func TestIsLocalUsesConfiguredPrefixes(t *testing.T) {
	tr, _ := newTestTracker(t)
	cases := map[string]bool{
		"192.168.1.50": true, // configured prefix
		"10.4.4.4":     true, // RFC1918
		"127.0.0.1":    true, // loopback
		"100.70.0.1":   true, // CGNAT
		"8.8.8.8":      false,
		"1.1.1.1":      false,
	}
	for addr, want := range cases {
		if got := tr.isLocal(netip.MustParseAddr(addr)); got != want {
			t.Errorf("isLocal(%s) = %v, want %v", addr, got, want)
		}
	}
}

func TestReapClosesIdleFlows(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	// A one-nanosecond idle timeout makes every flow immediately stale.
	tr := NewTracker(st, geoip.New(), time.Nanosecond, 100)
	tr.SetLocalNets([]string{"192.168.1.0/24"})

	tr.Observe(Observation{
		Key: Key{Proto: 6, SrcIP: netip.MustParseAddr("192.168.1.9"), SrcPort: 5000,
			DstIP: netip.MustParseAddr("8.8.8.8"), DstPort: 443},
		Bytes: 100, At: time.Now().Add(-time.Hour),
	})
	if tr.Stats().Active != 1 {
		t.Fatal("flow was not created")
	}
	tr.reap()
	if got := tr.Stats().Active; got != 0 {
		t.Errorf("active flows after reap = %d, want 0", got)
	}
}

func TestMaxFlowsIsEnforced(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	tr := NewTracker(st, geoip.New(), time.Minute, 10)

	// A scan must not be able to grow the table without bound.
	for i := 0; i < 100; i++ {
		tr.Observe(Observation{
			Key: Key{Proto: 6, SrcIP: netip.MustParseAddr("192.168.1.9"),
				SrcPort: uint16(1000 + i), DstIP: netip.MustParseAddr("8.8.8.8"), DstPort: 443},
			Bytes: 60, At: time.Now(),
		})
	}
	stats := tr.Stats()
	if stats.Active > 10 {
		t.Errorf("active flows = %d, want at most the configured cap of 10", stats.Active)
	}
	if stats.Dropped == 0 {
		t.Error("flows were dropped but the counter was not incremented")
	}
}

// TestFlowOrientation is a regression test for a bug where the flow's
// direction, service port and byte direction were all taken from the
// canonical (sorted) tuple rather than from who actually opened the
// connection. It hit any flow whose remote address sorted below the local
// one — roughly half of them — and produced inbound-looking rows with the
// client's ephemeral port shown as the destination.
func TestFlowOrientation(t *testing.T) {
	// 192.168.1.50 sorts ABOVE 8.8.8.8, so canonicalisation puts the remote
	// end first. That is exactly the case the old code got wrong.
	local := netip.MustParseAddr("192.168.1.50")
	remote := netip.MustParseAddr("8.8.8.8")

	tests := []struct {
		name  string
		first Observation
	}{
		{
			name: "opened by a SYN",
			first: Observation{
				Key:      Key{Proto: 6, SrcIP: local, SrcPort: 51234, DstIP: remote, DstPort: 443},
				TCPFlags: tcpSYN, Bytes: 60,
			},
		},
		{
			name: "joined mid-stream, inferred from locality",
			first: Observation{
				Key:   Key{Proto: 6, SrcIP: remote, SrcPort: 443, DstIP: local, DstPort: 51234},
				Bytes: 1400,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tr, _ := newTestTracker(t)
			tc.first.At = time.Now()
			tr.Observe(tc.first)

			flows := tr.Active(10)
			if len(flows) != 1 {
				t.Fatalf("got %d flows, want 1", len(flows))
			}
			f := flows[0]
			if f.Direction != "out" {
				t.Errorf("direction = %q, want out — the local device opened this", f.Direction)
			}
			if f.SrcIP != local.String() {
				t.Errorf("src = %s, want the local device %s", f.SrcIP, local)
			}
			if f.DstPort != 443 {
				t.Errorf("dst_port = %d, want the service port 443, not the ephemeral one", f.DstPort)
			}
			if f.DstIP != remote.String() {
				t.Errorf("dst = %s, want %s", f.DstIP, remote)
			}
		})
	}
}

func TestByteDirectionFollowsOrientation(t *testing.T) {
	tr, _ := newTestTracker(t)
	local := netip.MustParseAddr("192.168.1.50")
	remote := netip.MustParseAddr("8.8.8.8")
	out := Key{Proto: 6, SrcIP: local, SrcPort: 51234, DstIP: remote, DstPort: 443}
	in := Key{Proto: 6, SrcIP: remote, SrcPort: 443, DstIP: local, DstPort: 51234}

	tr.Observe(Observation{Key: out, TCPFlags: tcpSYN, Bytes: 60, At: time.Now()})
	tr.Observe(Observation{Key: out, Bytes: 500, At: time.Now()}) // request
	tr.Observe(Observation{Key: in, Bytes: 9000, At: time.Now()}) // response
	tr.Observe(Observation{Key: in, Bytes: 9000, At: time.Now()})

	flows := tr.Active(10)
	if len(flows) != 1 {
		t.Fatalf("the two directions produced %d flows, want 1", len(flows))
	}
	f := flows[0]
	if f.BytesOut != 560 {
		t.Errorf("bytes_out = %d, want 560 (the packets the device sent)", f.BytesOut)
	}
	if f.BytesIn != 18000 {
		t.Errorf("bytes_in = %d, want 18000 (the packets it received)", f.BytesIn)
	}
}

func TestSynAckIsNotTreatedAsAnOpen(t *testing.T) {
	tr, _ := newTestTracker(t)
	local := netip.MustParseAddr("192.168.1.50")
	remote := netip.MustParseAddr("8.8.8.8")

	// The first packet we see is the server's SYN+ACK. The initiator is the
	// other end, and reading the SYN bit alone would get this backwards.
	tr.Observe(Observation{
		Key:      Key{Proto: 6, SrcIP: remote, SrcPort: 443, DstIP: local, DstPort: 51234},
		TCPFlags: tcpSYN | tcpACK, Bytes: 60, At: time.Now(),
	})

	f := tr.Active(10)
	if len(f) != 1 {
		t.Fatalf("got %d flows", len(f))
	}
	if f[0].SrcIP != local.String() || f[0].DstPort != 443 {
		t.Errorf("SYN+ACK oriented the flow backwards: %s:%d -> %s:%d",
			f[0].SrcIP, f[0].SrcPort, f[0].DstIP, f[0].DstPort)
	}
}

func TestConntrackCountersRespectOrientation(t *testing.T) {
	tr, _ := newTestTracker(t)
	local := netip.MustParseAddr("192.168.1.50")
	remote := netip.MustParseAddr("8.8.8.8")

	// conntrack always reports the ORIGINAL direction as the initiator's.
	tr.SyncConntrack([]CTEntry{{
		Proto: 6, SrcIP: local, SrcPort: 51234, DstIP: remote, DstPort: 443,
		BytesOrig: 1000, BytesReply: 50000,
	}})

	f := tr.Active(10)
	if len(f) != 1 {
		t.Fatalf("got %d flows", len(f))
	}
	if f[0].BytesOut != 1000 || f[0].BytesIn != 50000 {
		t.Errorf("bytes out/in = %d/%d, want 1000/50000", f[0].BytesOut, f[0].BytesIn)
	}
	if f[0].Direction != "out" {
		t.Errorf("direction = %q, want out", f[0].Direction)
	}

	// A second sync with grown counters must add the delta, not the total.
	tr.SyncConntrack([]CTEntry{{
		Proto: 6, SrcIP: local, SrcPort: 51234, DstIP: remote, DstPort: 443,
		BytesOrig: 1500, BytesReply: 60000,
	}})
	f = tr.Active(10)
	if f[0].BytesOut != 1500 || f[0].BytesIn != 60000 {
		t.Errorf("after the second sync, out/in = %d/%d, want 1500/60000 (deltas applied once)",
			f[0].BytesOut, f[0].BytesIn)
	}
}
