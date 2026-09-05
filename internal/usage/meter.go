// Package usage turns the live flow table and the query log into per-device,
// per-service counters: how much Netflix the TV pulled this evening, how many
// times the phone looked up TikTok, how much of it was blocked.
//
// Bytes are accounted as deltas between samples of the live table, so a
// three-hour stream lands in the three hours it happened in, not the hour it
// started. Lookups are counted as they happen. Both drain into hourly rows.
package usage

import (
	"sync"
	"time"

	"github.com/Neoo-Blue/orbis/internal/dpi"
	"github.com/Neoo-Blue/orbis/internal/store"
)

// Key identifies one hourly counter.
type Key struct {
	Bucket   int64
	ClientID string
	Service  string
}

// Row is a drained counter ready for the store.
type Row struct {
	Bucket   time.Time
	ClientID string
	Service  string
	Category string
	Conns    int64
	BytesIn  int64
	BytesOut int64
	Lookups  int64
	Blocked  int64
}

type counters struct {
	category string
	conns    int64
	bytesIn  int64
	bytesOut int64
	lookups  int64
	blocked  int64
}

type flowMark struct {
	bytesIn  int64
	bytesOut int64
	lastSeen time.Time
}

// Meter accumulates counters between drains.
type Meter struct {
	mu   sync.Mutex
	acc  map[Key]*counters
	seen map[string]flowMark // flow id -> counters at the last sample
	now  func() time.Time
}

func NewMeter() *Meter {
	return &Meter{acc: map[Key]*counters{}, seen: map[string]flowMark{}, now: time.Now}
}

const bucketSize = time.Hour

func bucketOf(t time.Time) int64 { return t.Truncate(bucketSize).Unix() }

func (m *Meter) get(bucket int64, clientID string, svc dpi.Service) *counters {
	k := Key{Bucket: bucket, ClientID: clientID, Service: svc.Name}
	c := m.acc[k]
	if c == nil {
		c = &counters{category: svc.Category}
		m.acc[k] = c
	}
	return c
}

// NoteDNS counts one lookup. Blocked lookups are counted in both columns so
// "lookups" is always the total and "blocked" the share of it.
func (m *Meter) NoteDNS(clientID, name string, blocked bool) {
	if clientID == "" {
		clientID = "unknown"
	}
	svc := dpi.ServiceFor(name)
	m.mu.Lock()
	c := m.get(bucketOf(m.now()), clientID, svc)
	c.lookups++
	if blocked {
		c.blocked++
	}
	m.mu.Unlock()
}

// Sample reads the live flow table and adds the byte deltas since the last
// sample to the current bucket. A flow seen for the first time also counts as
// one connection. Flows that disappear from the table are forgotten after
// their last mark; their final few seconds of bytes are lost, which is the
// price of not hooking into the tracker's hot path.
func (m *Meter) Sample(flows []store.Flow) {
	now := m.now()
	bucket := bucketOf(now)
	m.mu.Lock()
	defer m.mu.Unlock()
	present := make(map[string]bool, len(flows))
	for i := range flows {
		f := &flows[i]
		present[f.ID] = true
		mark, known := m.seen[f.ID]
		dIn, dOut := f.BytesIn, f.BytesOut
		if known {
			dIn -= mark.bytesIn
			dOut -= mark.bytesOut
			if dIn < 0 {
				dIn = 0
			}
			if dOut < 0 {
				dOut = 0
			}
		}
		m.seen[f.ID] = flowMark{bytesIn: f.BytesIn, bytesOut: f.BytesOut, lastSeen: now}
		if !known || dIn > 0 || dOut > 0 {
			clientID := f.ClientID
			if clientID == "" {
				clientID = "unknown"
			}
			c := m.get(bucket, clientID, serviceForFlow(f))
			if !known {
				c.conns++
			}
			c.bytesIn += dIn
			c.bytesOut += dOut
		}
	}
	// Forget flows that left the table; keep marks for a few minutes so a
	// flow that briefly drops out of a bounded snapshot is not double-counted
	// as new.
	for id, mark := range m.seen {
		if !present[id] && now.Sub(mark.lastSeen) > 10*time.Minute {
			delete(m.seen, id)
		}
	}
}

func serviceForFlow(f *store.Flow) dpi.Service {
	host := f.Hostname
	if host == "" {
		host = f.SNI
	}
	if host == "" && f.App != "" {
		// A capture-time label with no name (e.g. QUIC without a decrypted
		// SNI) still says something.
		return dpi.Service{Name: f.App, Category: dpi.CatOther}
	}
	return dpi.ServiceFor(host)
}

// Drain returns everything accumulated and resets. Rows for past buckets are
// included, so a drain that runs just after the hour still lands the previous
// hour's last minute in the right place.
func (m *Meter) Drain() []Row {
	m.mu.Lock()
	acc := m.acc
	m.acc = map[Key]*counters{}
	m.mu.Unlock()
	out := make([]Row, 0, len(acc))
	for k, c := range acc {
		out = append(out, Row{
			Bucket: time.Unix(k.Bucket, 0), ClientID: k.ClientID, Service: k.Service, Category: c.category,
			Conns: c.conns, BytesIn: c.bytesIn, BytesOut: c.bytesOut, Lookups: c.lookups, Blocked: c.blocked,
		})
	}
	return out
}

// Backfill aggregates historical flows and lookups into rows, attributing a
// flow's whole volume to the hour it started. It is a one-time approximation
// for a node that has history but no rollups yet; live accounting takes over
// from there.
func Backfill(flows []store.Flow, queries []store.DNSQuery, clientOf func(ip string) string) []Row {
	acc := map[Key]*counters{}
	get := func(bucket int64, clientID string, svc dpi.Service) *counters {
		if clientID == "" {
			clientID = "unknown"
		}
		k := Key{Bucket: bucket, ClientID: clientID, Service: svc.Name}
		c := acc[k]
		if c == nil {
			c = &counters{category: svc.Category}
			acc[k] = c
		}
		return c
	}
	for i := range flows {
		f := &flows[i]
		c := get(bucketOf(f.StartedAt), f.ClientID, serviceForFlow(f))
		c.conns++
		c.bytesIn += f.BytesIn
		c.bytesOut += f.BytesOut
	}
	for i := range queries {
		q := &queries[i]
		clientID := ""
		if clientOf != nil {
			clientID = clientOf(q.ClientIP)
		}
		c := get(bucketOf(q.TS), clientID, dpi.ServiceFor(q.Name))
		c.lookups++
		if q.Blocked {
			c.blocked++
		}
	}
	out := make([]Row, 0, len(acc))
	for k, c := range acc {
		out = append(out, Row{
			Bucket: time.Unix(k.Bucket, 0), ClientID: k.ClientID, Service: k.Service, Category: c.category,
			Conns: c.conns, BytesIn: c.bytesIn, BytesOut: c.bytesOut, Lookups: c.lookups, Blocked: c.blocked,
		})
	}
	return out
}
