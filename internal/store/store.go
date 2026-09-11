// Package store is the persistence layer: a single SQLite file holding
// clients, flows, DNS history, rules, events and the assistant transcript.
//
// Writes funnel through a small number of batching helpers because the flow
// path can produce thousands of updates per second and SQLite hates being
// asked to commit each one individually.
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	_ "modernc.org/sqlite"
)

type Store struct {
	db *sql.DB

	// writeMu serialises write transactions. SQLite allows exactly one
	// writer at a time; without this, concurrent bulk imports (nine
	// blocklists refreshing at once) race for the lock and lose on
	// busy_timeout instead of simply queueing. Downloads stay parallel —
	// only the disk-bound commit is serialised.
	writeMu sync.Mutex
	// aggregates memoises the page-polled scans; see memo.go.
	aggregates memo

	// flowBuf batches flow upserts; drained on a ticker or when full.
	mu      sync.Mutex
	flowBuf []Flow
	dnsBuf  []DNSQuery

	closed chan struct{}
	// kick wakes flushLoop when a buffer hits maxBatch. Capacity 1 so
	// QueueFlow/QueueDNS never block on the writer.
	kick chan struct{}
	wg   sync.WaitGroup

	dropped       atomic.Uint64
	flushes       atomic.Uint64
	failedFlushes atomic.Uint64
	lastFlushOK   atomic.Int64 // UnixNano of last committed flow/DNS batch
	dropWarnCount atomic.Uint64
	lastDropWarn  atomic.Int64 // UnixNano of last "writer is behind" line

	// busy is time spent writing log batches. A write still running counts
	// up to now, so a two-minute catch-up transaction reads as two busy
	// minutes to a once-a-minute sampler rather than an idle one and a
	// doubly busy one.
	busyMu    sync.Mutex
	busyNanos uint64
	busySince time.Time // zero when no batch is being written
}

const (
	flushInterval = 2 * time.Second
	maxBatch      = 2000
	// maxPending bounds RAM if the writer falls behind (SD card, blocklist
	// refresh holding writeMu). Past this, new rows are dropped.
	maxPending = 50000
	// insertChunk rows per Exec so a catch-up flush is one SQL round-trip
	// per handful of rows, not one per row.
	insertChunk = 64
)

func Open(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, err
	}
	// _txlock=immediate avoids the "database is locked" upgrade deadlock
	// that a read-then-write transaction can hit under concurrency.
	// A long busy_timeout is a second line of defence behind writeMu, for
	// the case where an external process (a backup, a manual sqlite3 shell)
	// holds the write lock.
	dsn := fmt.Sprintf("file:%s?_pragma=busy_timeout(15000)&_txlock=immediate", path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// modernc/sqlite is safe for concurrent use but SQLite itself serialises
	// writers; a small pool keeps contention predictable.
	db.SetMaxOpenConns(8)
	db.SetMaxIdleConns(4)
	db.SetConnMaxLifetime(time.Hour)

	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("apply schema: %w", err)
	}
	applyMigrations(db)

	s := &Store{db: db, closed: make(chan struct{}), kick: make(chan struct{}, 1)}
	s.wg.Add(1)
	go s.flushLoop()
	return s, nil
}

func (s *Store) DB() *sql.DB { return s.db }

// beginWrite starts a serialised write transaction. Every multi-statement
// write in this package goes through it so two of them can never collide.
func (s *Store) beginWrite() (*sql.Tx, func(), error) {
	s.writeMu.Lock()
	tx, err := s.db.Begin()
	if err != nil {
		s.writeMu.Unlock()
		return nil, func() {}, err
	}
	done := false
	return tx, func() {
		if !done {
			done = true
			s.writeMu.Unlock()
		}
	}, nil
}

func (s *Store) Close() error {
	select {
	case <-s.closed:
	default:
		close(s.closed)
	}
	s.wg.Wait()
	s.flush()
	return s.db.Close()
}

func (s *Store) flushLoop() {
	defer s.wg.Done()
	t := time.NewTicker(flushInterval)
	defer t.Stop()
	for {
		select {
		case <-s.closed:
			return
		case <-t.C:
			s.flush()
		case <-s.kick:
			s.flush()
		}
	}
}

func (s *Store) kickFlush() {
	select {
	case s.kick <- struct{}{}:
	default:
	}
}

// ---------- clients ----------

func (s *Store) UpsertClient(c *Client) error {
	meta, _ := json.Marshal(c.Meta)
	_, err := s.db.Exec(`
		INSERT INTO clients (id, mac, ip, hostname, vendor, os_guess, device_type, label, zone,
			first_seen, last_seen, rx_bytes, tx_bytes, blocked, policy_id, vpn_route, notes, meta)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET
			ip=excluded.ip,
			hostname=COALESCE(NULLIF(excluded.hostname,''), clients.hostname),
			vendor=COALESCE(NULLIF(excluded.vendor,''), clients.vendor),
			os_guess=COALESCE(NULLIF(excluded.os_guess,''), clients.os_guess),
			device_type=COALESCE(NULLIF(excluded.device_type,''), clients.device_type),
			zone=COALESCE(NULLIF(excluded.zone,''), clients.zone),
			last_seen=MAX(excluded.last_seen, clients.last_seen),
			rx_bytes=clients.rx_bytes+excluded.rx_bytes,
			tx_bytes=clients.tx_bytes+excluded.tx_bytes,
			meta=excluded.meta`,
		c.ID, nz(c.MAC), c.IP, c.Hostname, c.Vendor, c.OSGuess, c.DeviceType, c.Label, c.Zone,
		c.FirstSeen.Unix(), c.LastSeen.Unix(), c.RxBytes, c.TxBytes, b2i(c.Blocked),
		c.PolicyID, c.VPNRoute, c.Notes, string(meta))
	return err
}

// SetClientFields updates only the operator-editable columns, leaving the
// counters and timestamps that the capture path owns untouched.
func (s *Store) SetClientFields(id string, label, zone, policyID, vpnRoute, notes *string, blocked *bool) error {
	sets := []string{}
	args := []any{}
	add := func(col string, v any) { sets = append(sets, col+"=?"); args = append(args, v) }
	if label != nil {
		add("label", *label)
	}
	if zone != nil {
		add("zone", *zone)
	}
	if policyID != nil {
		add("policy_id", *policyID)
	}
	if vpnRoute != nil {
		add("vpn_route", *vpnRoute)
	}
	if notes != nil {
		add("notes", *notes)
	}
	if blocked != nil {
		add("blocked", b2i(*blocked))
	}
	if len(sets) == 0 {
		return nil
	}
	args = append(args, id)
	_, err := s.db.Exec("UPDATE clients SET "+strings.Join(sets, ",")+" WHERE id=?", args...)
	return err
}

func (s *Store) Clients() ([]Client, error) {
	rows, err := s.db.Query(`SELECT id, COALESCE(mac,''), ip, hostname, vendor, os_guess, device_type,
		label, zone, first_seen, last_seen, rx_bytes, tx_bytes, blocked,
		COALESCE(policy_id,''), COALESCE(vpn_route,''), COALESCE(notes,''), COALESCE(meta,'{}')
		FROM clients ORDER BY last_seen DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Client
	for rows.Next() {
		var c Client
		var first, last int64
		var blocked int
		var meta string
		if err := rows.Scan(&c.ID, &c.MAC, &c.IP, &c.Hostname, &c.Vendor, &c.OSGuess, &c.DeviceType,
			&c.Label, &c.Zone, &first, &last, &c.RxBytes, &c.TxBytes, &blocked,
			&c.PolicyID, &c.VPNRoute, &c.Notes, &meta); err != nil {
			return nil, err
		}
		c.FirstSeen = time.Unix(first, 0)
		c.LastSeen = time.Unix(last, 0)
		c.Blocked = blocked != 0
		_ = json.Unmarshal([]byte(meta), &c.Meta)
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *Store) Client(id string) (*Client, error) {
	all, err := s.Clients()
	if err != nil {
		return nil, err
	}
	for i := range all {
		if all[i].ID == id {
			return &all[i], nil
		}
	}
	return nil, sql.ErrNoRows
}

func (s *Store) DeleteClient(id string) error {
	_, err := s.db.Exec("DELETE FROM clients WHERE id=?", id)
	return err
}

// ---------- flows ----------

// WriteStats reports how hard the log writer is working, for the overload
// guard and /metrics. Counters are cumulative since Open.
type WriteStats struct {
	Pending       int       // flow + DNS rows waiting in memory
	Dropped       uint64    // rows discarded: queue full or failed batch
	BusyNanos     uint64    // time spent writing flow/DNS batches, lock wait excluded
	Flushes       uint64    // flow/DNS batches committed
	FailedFlushes uint64    // flow/DNS batches whose commit failed
	LastFlushOK   time.Time // when a flow or DNS batch last committed
}

func (s *Store) WriteStats() WriteStats {
	s.mu.Lock()
	pending := len(s.flowBuf) + len(s.dnsBuf)
	s.mu.Unlock()
	var last time.Time
	if ns := s.lastFlushOK.Load(); ns != 0 {
		last = time.Unix(0, ns)
	}
	return WriteStats{
		Pending:       pending,
		Dropped:       s.dropped.Load(),
		BusyNanos:     s.busyTotal(),
		Flushes:       s.flushes.Load(),
		FailedFlushes: s.failedFlushes.Load(),
		LastFlushOK:   last,
	}
}

// QueueFlow buffers a flow upsert. Safe to call from the packet path: it
// never waits on disk or writeMu. A full buffer wakes flushLoop instead.
func (s *Store) QueueFlow(f Flow) {
	s.mu.Lock()
	if len(s.flowBuf) >= maxPending {
		s.mu.Unlock()
		s.noteDropped(1)
		return
	}
	s.flowBuf = append(s.flowBuf, f)
	n := len(s.flowBuf)
	s.mu.Unlock()
	if n >= maxBatch {
		s.kickFlush()
	}
}

func (s *Store) QueueDNS(q DNSQuery) {
	s.mu.Lock()
	if len(s.dnsBuf) >= maxPending {
		s.mu.Unlock()
		s.noteDropped(1)
		return
	}
	s.dnsBuf = append(s.dnsBuf, q)
	n := len(s.dnsBuf)
	s.mu.Unlock()
	if n >= maxBatch {
		s.kickFlush()
	}
}

func (s *Store) noteDropped(n uint64) {
	if n == 0 {
		return
	}
	s.dropped.Add(n)
	s.dropWarnCount.Add(n)
	now := time.Now().UnixNano()
	last := s.lastDropWarn.Load()
	if last != 0 && now-last < int64(time.Minute) {
		return
	}
	if !s.lastDropWarn.CompareAndSwap(last, now) {
		return
	}
	reported := s.dropWarnCount.Swap(0)
	if reported == 0 {
		return
	}
	fmt.Fprintf(os.Stderr, "store: log writer is behind, dropped %d row(s) in the last minute\n", reported)
}

func (s *Store) flush() {
	// Take writeMu before draining so a blocked writer (blocklist refresh)
	// cannot pull rows out of the in-memory cap. Queue* stays within
	// maxPending and Pending stays accurate.
	s.mu.Lock()
	if len(s.flowBuf) == 0 && len(s.dnsBuf) == 0 {
		s.mu.Unlock()
		return
	}
	s.mu.Unlock()

	s.writeMu.Lock()
	s.mu.Lock()
	flows := s.flowBuf
	dns := s.dnsBuf
	s.flowBuf = nil
	s.dnsBuf = nil
	s.mu.Unlock()
	s.writeMu.Unlock()

	if len(flows) > 0 {
		if err := s.writeFlows(flows); err != nil {
			fmt.Fprintf(os.Stderr, "store: flow flush failed: %v\n", err)
			s.noteDropped(uint64(len(flows)))
			s.failedFlushes.Add(1)
		} else {
			s.flushes.Add(1)
			s.lastFlushOK.Store(time.Now().UnixNano())
		}
	}
	if len(dns) > 0 {
		if err := s.writeDNS(dns); err != nil {
			fmt.Fprintf(os.Stderr, "store: dns flush failed: %v\n", err)
			s.noteDropped(uint64(len(dns)))
			s.failedFlushes.Add(1)
		} else {
			s.flushes.Add(1)
			s.lastFlushOK.Store(time.Now().UnixNano())
		}
	}
}

// busyStart and busyEnd bracket the disk work of one log batch, after writeMu
// is held, so time spent waiting behind another writer is not counted.
func (s *Store) busyStart() {
	s.busyMu.Lock()
	s.busySince = time.Now()
	s.busyMu.Unlock()
}

func (s *Store) busyEnd() {
	s.busyMu.Lock()
	if !s.busySince.IsZero() {
		if d := time.Since(s.busySince); d > 0 {
			s.busyNanos += uint64(d)
		}
		s.busySince = time.Time{}
	}
	s.busyMu.Unlock()
}

func (s *Store) busyTotal() uint64 {
	s.busyMu.Lock()
	defer s.busyMu.Unlock()
	total := s.busyNanos
	if !s.busySince.IsZero() {
		if d := time.Since(s.busySince); d > 0 {
			total += uint64(d)
		}
	}
	return total
}

func (s *Store) writeFlows(flows []Flow) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	s.busyStart()
	defer s.busyEnd()
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	stmt, err := tx.Prepare(`
		INSERT INTO flows (id, client_id, started_at, ended_at, last_seen, proto, src_ip, src_port,
			dst_ip, dst_port, direction, hostname, sni, app, ja4, packets_in, packets_out,
			bytes_in, bytes_out, verdict, rule_id, reason, country, city, lat, lon, asn, as_org, risk, tags)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET
			ended_at=excluded.ended_at,
			last_seen=excluded.last_seen,
			hostname=COALESCE(NULLIF(excluded.hostname,''), flows.hostname),
			sni=COALESCE(NULLIF(excluded.sni,''), flows.sni),
			app=COALESCE(NULLIF(excluded.app,''), flows.app),
			ja4=COALESCE(NULLIF(excluded.ja4,''), flows.ja4),
			packets_in=excluded.packets_in,
			packets_out=excluded.packets_out,
			bytes_in=excluded.bytes_in,
			bytes_out=excluded.bytes_out,
			verdict=excluded.verdict,
			reason=COALESCE(NULLIF(excluded.reason,''), flows.reason),
			risk=MAX(excluded.risk, flows.risk),
			tags=excluded.tags`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, f := range flows {
		var ended any
		if f.EndedAt != nil {
			ended = f.EndedAt.Unix()
		}
		if _, err := stmt.Exec(f.ID, nz(f.ClientID), f.StartedAt.Unix(), ended, f.LastSeen.Unix(),
			f.Proto, f.SrcIP, f.SrcPort, f.DstIP, f.DstPort, f.Direction, f.Hostname, f.SNI,
			f.App, f.JA4, f.PacketsIn, f.PacketsOut, f.BytesIn, f.BytesOut, f.Verdict,
			nz(f.RuleID), f.Reason, f.Country, f.City, f.Lat, f.Lon, f.ASN, f.ASOrg, f.Risk,
			jsonStrings(f.Tags)); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) writeDNS(qs []DNSQuery) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	s.busyStart()
	defer s.busyEnd()
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	const dnsCols = 13
	for i := 0; i < len(qs); {
		n := insertChunk
		if len(qs)-i < n {
			n = len(qs) - i
		}
		args := make([]any, 0, n*dnsCols)
		for _, q := range qs[i : i+n] {
			args = append(args, q.TS.Unix(), nz(q.ClientID), q.ClientIP, q.Name, q.QType, q.RCode,
				b2i(q.Blocked), q.BlockSource, jsonStrings(q.CNAMEChain), jsonStrings(q.Answer),
				q.Upstream, q.LatencyMS, b2i(q.Cached))
		}
		q := `INSERT INTO dns_queries
			(ts, client_id, client_ip, name, qtype, rcode, blocked, block_source, cname_chain, answer, upstream, latency_ms, cached)
			VALUES ` + sqlValues(n, dnsCols)
		if _, err := tx.Exec(q, args...); err != nil {
			return err
		}
		i += n
	}
	return tx.Commit()
}

// Flows runs a filtered history query. Filters are composed into a single
// statement rather than post-filtered so a 30-day table stays usable.
func (s *Store) Flows(q FlowQuery) ([]Flow, error) {
	var where []string
	var args []any
	if q.Since != nil {
		where = append(where, "started_at >= ?")
		args = append(args, q.Since.Unix())
	}
	if q.Until != nil {
		where = append(where, "started_at <= ?")
		args = append(args, q.Until.Unix())
	}
	if q.ClientID != "" {
		where = append(where, "client_id = ?")
		args = append(args, q.ClientID)
	}
	if q.Verdict != "" {
		where = append(where, "verdict = ?")
		args = append(args, q.Verdict)
	}
	if q.Country != "" {
		where = append(where, "country = ?")
		args = append(args, q.Country)
	}
	if q.Proto != "" {
		where = append(where, "proto = ?")
		args = append(args, q.Proto)
	}
	if q.Port > 0 {
		where = append(where, "dst_port = ?")
		args = append(args, q.Port)
	}
	if q.MinBytes > 0 {
		where = append(where, "(bytes_in + bytes_out) >= ?")
		args = append(args, q.MinBytes)
	}
	if q.ActiveOnly {
		where = append(where, "ended_at IS NULL")
	}
	if q.Search != "" {
		where = append(where, "(hostname LIKE ? OR sni LIKE ? OR dst_ip LIKE ? OR as_org LIKE ? OR app LIKE ?)")
		p := "%" + q.Search + "%"
		args = append(args, p, p, p, p, p)
	}
	sqlStr := `SELECT id, COALESCE(client_id,''), started_at, ended_at, last_seen, proto, src_ip,
		COALESCE(src_port,0), dst_ip, COALESCE(dst_port,0), direction, COALESCE(hostname,''),
		COALESCE(sni,''), COALESCE(app,''), COALESCE(ja4,''), packets_in, packets_out, bytes_in,
		bytes_out, verdict, COALESCE(rule_id,''), COALESCE(reason,''), COALESCE(country,''),
		COALESCE(city,''), COALESCE(lat,0), COALESCE(lon,0), COALESCE(asn,0), COALESCE(as_org,''),
		risk, COALESCE(tags,'[]') FROM flows`
	if len(where) > 0 {
		sqlStr += " WHERE " + strings.Join(where, " AND ")
	}
	switch q.OrderBy {
	case "bytes":
		sqlStr += " ORDER BY (bytes_in + bytes_out) DESC"
	case "risk":
		sqlStr += " ORDER BY risk DESC, started_at DESC"
	default:
		sqlStr += " ORDER BY started_at DESC"
	}
	limit := q.Limit
	if limit <= 0 || limit > 5000 {
		limit = 500
	}
	sqlStr += fmt.Sprintf(" LIMIT %d OFFSET %d", limit, max(0, q.Offset))

	rows, err := s.db.Query(sqlStr, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanFlows(rows)
}

func scanFlows(rows *sql.Rows) ([]Flow, error) {
	out := []Flow{}
	for rows.Next() {
		var f Flow
		var started, last int64
		var ended sql.NullInt64
		var tags string
		if err := rows.Scan(&f.ID, &f.ClientID, &started, &ended, &last, &f.Proto, &f.SrcIP,
			&f.SrcPort, &f.DstIP, &f.DstPort, &f.Direction, &f.Hostname, &f.SNI, &f.App, &f.JA4,
			&f.PacketsIn, &f.PacketsOut, &f.BytesIn, &f.BytesOut, &f.Verdict, &f.RuleID, &f.Reason,
			&f.Country, &f.City, &f.Lat, &f.Lon, &f.ASN, &f.ASOrg, &f.Risk, &tags); err != nil {
			return nil, err
		}
		f.StartedAt = time.Unix(started, 0)
		f.LastSeen = time.Unix(last, 0)
		if ended.Valid {
			t := time.Unix(ended.Int64, 0)
			f.EndedAt = &t
		}
		_ = json.Unmarshal([]byte(tags), &f.Tags)
		out = append(out, f)
	}
	return out, rows.Err()
}

// TopDestinations powers the "who is my network talking to" panels.
func (s *Store) TopDestinations(since time.Time, clientID string, limit int) ([]map[string]any, error) {
	args := []any{since.Unix()}
	q := `SELECT COALESCE(NULLIF(hostname,''), dst_ip) AS host, COALESCE(country,'') AS country,
		COALESCE(as_org,'') AS org, COUNT(*) AS conns, SUM(bytes_in+bytes_out) AS bytes,
		SUM(CASE WHEN verdict='block' THEN 1 ELSE 0 END) AS blocked,
		AVG(COALESCE(lat,0)) AS lat, AVG(COALESCE(lon,0)) AS lon
		FROM flows WHERE started_at >= ?`
	if clientID != "" {
		q += " AND client_id = ?"
		args = append(args, clientID)
	}
	q += fmt.Sprintf(" GROUP BY host ORDER BY bytes DESC LIMIT %d", clampInt(limit, 1, 500))
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var host, country, org string
		var conns, bytes, blocked int64
		var lat, lon float64
		if err := rows.Scan(&host, &country, &org, &conns, &bytes, &blocked, &lat, &lon); err != nil {
			return nil, err
		}
		out = append(out, map[string]any{
			"host": host, "country": country, "org": org, "connections": conns,
			"bytes": bytes, "blocked": blocked, "lat": lat, "lon": lon,
		})
	}
	return out, rows.Err()
}

// CountryTotals feeds the globe's choropleth / heat layer.
func (s *Store) CountryTotals(since time.Time) ([]map[string]any, error) {
	v, err := s.aggregates.get("countries|"+bucket(since, time.Minute), time.Minute, func() (any, error) {
		return s.countryTotals(since)
	})
	if err != nil {
		return nil, err
	}
	return v.([]map[string]any), nil
}

func (s *Store) countryTotals(since time.Time) ([]map[string]any, error) {
	rows, err := s.db.Query(`SELECT country, COUNT(*) c, SUM(bytes_in+bytes_out) b,
		SUM(CASE WHEN verdict='block' THEN 1 ELSE 0 END) blk, AVG(lat), AVG(lon)
		FROM flows WHERE started_at >= ? AND country != '' GROUP BY country ORDER BY b DESC`, since.Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var country string
		var c, b, blk int64
		var lat, lon sql.NullFloat64
		if err := rows.Scan(&country, &c, &b, &blk, &lat, &lon); err != nil {
			return nil, err
		}
		out = append(out, map[string]any{
			"country": country, "connections": c, "bytes": b, "blocked": blk,
			"lat": lat.Float64, "lon": lon.Float64,
		})
	}
	return out, rows.Err()
}

// ---------- events ----------

func (s *Store) AddEvent(e Event) error {
	data, _ := json.Marshal(e.Data)
	_, err := s.db.Exec(`INSERT OR REPLACE INTO events
		(id, ts, severity, category, title, detail, client_id, flow_id, acknowledged, data)
		VALUES (?,?,?,?,?,?,?,?,?,?)`,
		e.ID, e.TS.Unix(), e.Severity, e.Category, e.Title, e.Detail, nz(e.ClientID),
		nz(e.FlowID), b2i(e.Ack), string(data))
	return err
}

// EventByID fetches one event.
func (s *Store) EventByID(id string) (*Event, error) {
	rows, err := s.db.Query("SELECT id, ts, severity, category, title, COALESCE(detail,''), COALESCE(client_id,''), COALESCE(flow_id,''), acknowledged, COALESCE(data,'{}') FROM events WHERE id = ?", id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	list, err := scanEvents(rows)
	if err != nil || len(list) == 0 {
		return nil, err
	}
	return &list[0], nil
}

func (s *Store) Events(since time.Time, severity string, unackOnly bool, limit int) ([]Event, error) {
	q := "SELECT id, ts, severity, category, title, COALESCE(detail,''), COALESCE(client_id,''), COALESCE(flow_id,''), acknowledged, COALESCE(data,'{}') FROM events WHERE ts >= ?"
	args := []any{since.Unix()}
	if severity != "" {
		q += " AND severity = ?"
		args = append(args, severity)
	}
	if unackOnly {
		q += " AND acknowledged = 0"
	}
	q += fmt.Sprintf(" ORDER BY ts DESC LIMIT %d", clampInt(limit, 1, 2000))
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanEvents(rows)
}

func scanEvents(rows *sql.Rows) ([]Event, error) {
	out := []Event{}
	for rows.Next() {
		var e Event
		var ts int64
		var ack int
		var data string
		if err := rows.Scan(&e.ID, &ts, &e.Severity, &e.Category, &e.Title, &e.Detail,
			&e.ClientID, &e.FlowID, &ack, &data); err != nil {
			return nil, err
		}
		e.TS = time.Unix(ts, 0)
		e.Ack = ack != 0
		_ = json.Unmarshal([]byte(data), &e.Data)
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *Store) AckEvent(id string) error {
	_, err := s.db.Exec("UPDATE events SET acknowledged=1 WHERE id=?", id)
	return err
}

// ---------- audit ----------

func (s *Store) Audit(actor, action, target, before, after, result string) {
	_, _ = s.db.Exec(`INSERT INTO audit_log (ts, actor, action, target, before, after, result)
		VALUES (?,?,?,?,?,?,?)`, time.Now().Unix(), actor, action, target, before, after, result)
}

func (s *Store) AuditLog(limit int) ([]AuditEntry, error) {
	rows, err := s.db.Query(`SELECT id, ts, actor, action, COALESCE(target,''), COALESCE(before,''),
		COALESCE(after,''), COALESCE(result,'') FROM audit_log ORDER BY ts DESC LIMIT ?`,
		clampInt(limit, 1, 1000))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AuditEntry{}
	for rows.Next() {
		var a AuditEntry
		var ts int64
		if err := rows.Scan(&a.ID, &ts, &a.Actor, &a.Action, &a.Target, &a.Before, &a.After, &a.Result); err != nil {
			return nil, err
		}
		a.TS = time.Unix(ts, 0)
		out = append(out, a)
	}
	return out, rows.Err()
}

// ---------- retention ----------

// Prune enforces the retention windows and reclaims space. Called daily.
func (s *Store) Prune(ctx context.Context, flowDays, eventDays int) error {
	now := time.Now()
	if flowDays > 0 {
		cut := now.AddDate(0, 0, -flowDays).Unix()
		if _, err := s.db.ExecContext(ctx, "DELETE FROM flows WHERE started_at < ?", cut); err != nil {
			return err
		}
		if _, err := s.db.ExecContext(ctx, "DELETE FROM dns_queries WHERE ts < ?", cut); err != nil {
			return err
		}
	}
	if eventDays > 0 {
		cut := now.AddDate(0, 0, -eventDays).Unix()
		if _, err := s.db.ExecContext(ctx, "DELETE FROM events WHERE ts < ?", cut); err != nil {
			return err
		}
		if _, err := s.db.ExecContext(ctx, "DELETE FROM audit_log WHERE ts < ?", cut); err != nil {
			return err
		}
	}
	// stats_minute powers sparklines and the analytics charts; keep 14 days.
	_, _ = s.db.ExecContext(ctx, "DELETE FROM stats_minute WHERE bucket < ?", now.Add(-14*24*time.Hour).Unix())
	_, err := s.db.ExecContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)")
	return err
}

// ---------- helpers ----------

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

// nz turns an empty string into SQL NULL so partial unique indexes and
// COALESCE-based upserts behave.
func nz(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func clampInt(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// jsonStrings matches json.Marshal for []string, but skips the encoder
// on the nil path that log rows hit on every insert.
func jsonStrings(v []string) string {
	if v == nil {
		return "null"
	}
	b, _ := json.Marshal(v)
	return string(b)
}

// sqlValues returns n tuples of cols placeholders: "(?,?,?),(?,?,?)".
func sqlValues(n, cols int) string {
	row := "(" + strings.Repeat("?,", cols-1) + "?)"
	if n == 1 {
		return row
	}
	var b strings.Builder
	b.Grow((len(row) + 1) * n)
	for i := 0; i < n; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(row)
	}
	return b.String()
}

// applyMigrations runs each idempotent migration, ignoring the "duplicate
// column name" error that means it has already been applied. Anything else is
// logged to the caller's discretion by being ignored here too: a migration
// that cannot apply must not stop the daemon from starting, because a node
// that will not boot is worse than a node missing one optional column.
func applyMigrations(db *sql.DB) {
	for _, stmt := range migrations {
		// The only expected error is "duplicate column name" on a database
		// that already has it. Anything else is reported once and skipped;
		// refusing to boot over an optional column would be worse.
		if _, err := db.Exec(stmt); err != nil &&
			!strings.Contains(strings.ToLower(err.Error()), "duplicate column") {
			fmt.Fprintf(os.Stderr, "store: migration skipped (%v): %s\n", err, stmt)
		}
	}
}
