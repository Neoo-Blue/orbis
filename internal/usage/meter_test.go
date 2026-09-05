package usage

import (
	"testing"
	"time"

	"github.com/Neoo-Blue/orbis/internal/store"
)

func TestSampleCountsDeltasAndNewConnections(t *testing.T) {
	m := NewMeter()
	base := time.Date(2026, 9, 5, 20, 30, 0, 0, time.UTC)
	m.now = func() time.Time { return base }

	f := store.Flow{ID: "f1", ClientID: "tv", Hostname: "rr1.googlevideo.com", BytesIn: 1000, BytesOut: 100}
	m.Sample([]store.Flow{f})
	f.BytesIn, f.BytesOut = 5000, 150
	m.now = func() time.Time { return base.Add(time.Minute) }
	m.Sample([]store.Flow{f})
	// A second device on Netflix appears, and the TV flow is unchanged.
	g := store.Flow{ID: "f2", ClientID: "laptop", SNI: "ipv4-c001.nflxvideo.net", BytesIn: 700}
	m.now = func() time.Time { return base.Add(2 * time.Minute) }
	m.Sample([]store.Flow{f, g})

	rows := m.Drain()
	byKey := map[string]Row{}
	for _, r := range rows {
		byKey[r.ClientID+"|"+r.Service] = r
	}
	yt := byKey["tv|YouTube"]
	if yt.Conns != 1 || yt.BytesIn != 5000 || yt.BytesOut != 150 || yt.Category != "video" {
		t.Fatalf("youtube row = %+v", yt)
	}
	nf := byKey["laptop|Netflix"]
	if nf.Conns != 1 || nf.BytesIn != 700 {
		t.Fatalf("netflix row = %+v", nf)
	}
	if !yt.Bucket.Equal(base.Truncate(time.Hour)) {
		t.Fatalf("bucket = %v", yt.Bucket)
	}
	if len(m.Drain()) != 0 {
		t.Fatal("drain must reset")
	}
}

func TestSampleSplitsAcrossHours(t *testing.T) {
	m := NewMeter()
	h := time.Date(2026, 9, 5, 20, 59, 30, 0, time.UTC)
	m.now = func() time.Time { return h }
	f := store.Flow{ID: "f1", ClientID: "tv", Hostname: "x.nflxvideo.net", BytesIn: 100}
	m.Sample([]store.Flow{f})
	m.now = func() time.Time { return h.Add(time.Minute) } // 21:00:30
	f.BytesIn = 400
	m.Sample([]store.Flow{f})
	rows := m.Drain()
	if len(rows) != 2 {
		t.Fatalf("expected one row per hour, got %d: %+v", len(rows), rows)
	}
	var total int64
	for _, r := range rows {
		total += r.BytesIn
	}
	if total != 400 {
		t.Fatalf("bytes split across hours must sum to the flow total, got %d", total)
	}
}

func TestNoteDNSAndBackfill(t *testing.T) {
	m := NewMeter()
	m.NoteDNS("phone", "pagead2.googlesyndication.com", true)
	m.NoteDNS("phone", "www.tiktok.com", false)
	m.NoteDNS("", "example.com", false)
	rows := m.Drain()
	if len(rows) != 3 {
		t.Fatalf("rows = %+v", rows)
	}
	for _, r := range rows {
		switch r.Service {
		case "Ad/Tracking":
			if r.Lookups != 1 || r.Blocked != 1 || r.ClientID != "phone" {
				t.Fatalf("ads row = %+v", r)
			}
		case "TikTok":
			if r.Blocked != 0 {
				t.Fatalf("tiktok row = %+v", r)
			}
		case "example.com":
			if r.ClientID != "unknown" {
				t.Fatalf("unknown client row = %+v", r)
			}
		}
	}

	back := Backfill(
		[]store.Flow{{ID: "a", ClientID: "tv", Hostname: "a.nflxvideo.net", BytesIn: 10, StartedAt: time.Unix(3600, 0)}},
		[]store.DNSQuery{{ClientIP: "10.0.0.5", Name: "netflix.com", TS: time.Unix(3700, 0)}},
		func(ip string) string { return "tv" },
	)
	if len(back) != 1 || back[0].Conns != 1 || back[0].Lookups != 1 || back[0].BytesIn != 10 {
		t.Fatalf("backfill merged rows = %+v", back)
	}
}
