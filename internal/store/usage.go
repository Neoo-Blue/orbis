package store

import (
	"database/sql"
	"fmt"
	"strings"
	"time"
)

// Hourly per-device, per-service rollups. Kept separate from flows so a
// week's question ("how much Netflix did the TV watch") is a scan of a few
// thousand rows on an SD card, not a million.

// ServiceStat is one hourly row.
type ServiceStat struct {
	Bucket   time.Time `json:"bucket"`
	ClientID string    `json:"client_id"`
	Service  string    `json:"service"`
	Category string    `json:"category"`
	Conns    int64     `json:"conns"`
	BytesIn  int64     `json:"bytes_in"`
	BytesOut int64     `json:"bytes_out"`
	Lookups  int64     `json:"lookups"`
	Blocked  int64     `json:"blocked"`
}

// AddServiceStats adds counters onto existing rows (or inserts them) in one
// transaction. Callers hand over drained meter rows once a minute.
func (s *Store) AddServiceStats(rows []ServiceStat) error {
	if len(rows) == 0 {
		return nil
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	stmt, err := tx.Prepare(`INSERT INTO service_stats
		(bucket, client_id, service, category, conns, bytes_in, bytes_out, lookups, blocked)
		VALUES (?,?,?,?,?,?,?,?,?)
		ON CONFLICT(bucket, client_id, service) DO UPDATE SET
			category = CASE WHEN excluded.category != '' THEN excluded.category ELSE service_stats.category END,
			conns = conns + excluded.conns, bytes_in = bytes_in + excluded.bytes_in,
			bytes_out = bytes_out + excluded.bytes_out, lookups = lookups + excluded.lookups,
			blocked = blocked + excluded.blocked`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, r := range rows {
		if _, err := stmt.Exec(r.Bucket.Unix(), r.ClientID, r.Service, r.Category,
			r.Conns, r.BytesIn, r.BytesOut, r.Lookups, r.Blocked); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// ServiceStatsEmpty reports whether any rollup exists yet.
func (s *Store) ServiceStatsEmpty() bool {
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM (SELECT 1 FROM service_stats LIMIT 1)`).Scan(&n); err != nil {
		return true
	}
	return n == 0
}

// ServiceTotal is an aggregate over a window.
type ServiceTotal struct {
	Service  string `json:"service"`
	Category string `json:"category"`
	ClientID string `json:"client_id,omitempty"`
	Devices  int    `json:"devices"`
	Conns    int64  `json:"conns"`
	BytesIn  int64  `json:"bytes_in"`
	BytesOut int64  `json:"bytes_out"`
	Lookups  int64  `json:"lookups"`
	Blocked  int64  `json:"blocked"`
	// Spark is bytes per bucket across the window, oldest first, for the
	// list view's sparkline. Filled by ServiceTotals when asked.
	Spark []int64 `json:"spark,omitempty"`
}

// ServiceTotals aggregates by service over [since, until). clientID narrows
// to one device. sparkBuckets > 0 also returns a per-service byte series with
// that many evenly spaced points.
func (s *Store) ServiceTotals(since, until time.Time, clientID string, sparkBuckets int) ([]ServiceTotal, error) {
	where := `bucket >= ? AND bucket < ?`
	args := []any{since.Unix(), until.Unix()}
	if clientID != "" {
		where += ` AND client_id = ?`
		args = append(args, clientID)
	}
	rows, err := s.db.Query(`SELECT service, MAX(category), COUNT(DISTINCT client_id), SUM(conns), SUM(bytes_in),
		SUM(bytes_out), SUM(lookups), SUM(blocked)
		FROM service_stats WHERE `+where+` GROUP BY service
		ORDER BY SUM(bytes_in + bytes_out) DESC, SUM(lookups) DESC`, args...)
	if err != nil {
		return nil, err
	}
	out := []ServiceTotal{}
	index := map[string]int{}
	for rows.Next() {
		var t ServiceTotal
		if err := rows.Scan(&t.Service, &t.Category, &t.Devices, &t.Conns, &t.BytesIn, &t.BytesOut, &t.Lookups, &t.Blocked); err != nil {
			rows.Close()
			return nil, err
		}
		index[t.Service] = len(out)
		out = append(out, t)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if sparkBuckets <= 0 || len(out) == 0 {
		return out, nil
	}
	span := until.Sub(since)
	if span <= 0 {
		return out, nil
	}
	for i := range out {
		out[i].Spark = make([]int64, sparkBuckets)
	}
	srows, err := s.db.Query(`SELECT service, bucket, SUM(bytes_in + bytes_out), SUM(lookups)
		FROM service_stats WHERE `+where+` GROUP BY service, bucket`, args...)
	if err != nil {
		return nil, err
	}
	defer srows.Close()
	for srows.Next() {
		var svc string
		var bucket, bytes, lookups int64
		if err := srows.Scan(&svc, &bucket, &bytes, &lookups); err != nil {
			return nil, err
		}
		i, ok := index[svc]
		if !ok {
			continue
		}
		pos := int(float64(bucket-since.Unix()) / span.Seconds() * float64(sparkBuckets))
		if pos < 0 {
			pos = 0
		}
		if pos >= sparkBuckets {
			pos = sparkBuckets - 1
		}
		// Bytes when the device is visible, lookups otherwise, so DNS-only
		// devices still draw a shape.
		if bytes > 0 {
			out[i].Spark[pos] += bytes
		} else {
			out[i].Spark[pos] += lookups
		}
	}
	return out, srows.Err()
}

// ServiceDevices breaks one service (or all, when service is "") down by
// device over the window.
func (s *Store) ServiceDevices(since, until time.Time, service string) ([]ServiceTotal, error) {
	where := `bucket >= ? AND bucket < ?`
	args := []any{since.Unix(), until.Unix()}
	if service != "" {
		where += ` AND service = ?`
		args = append(args, service)
	}
	rows, err := s.db.Query(`SELECT client_id, COUNT(DISTINCT service), SUM(conns), SUM(bytes_in), SUM(bytes_out),
		SUM(lookups), SUM(blocked)
		FROM service_stats WHERE `+where+` GROUP BY client_id
		ORDER BY SUM(bytes_in + bytes_out) DESC, SUM(lookups) DESC`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ServiceTotal{}
	for rows.Next() {
		var t ServiceTotal
		if err := rows.Scan(&t.ClientID, &t.Devices, &t.Conns, &t.BytesIn, &t.BytesOut, &t.Lookups, &t.Blocked); err != nil {
			return nil, err
		}
		t.Service = service
		out = append(out, t)
	}
	return out, rows.Err()
}

// ServicePoint is one time-series sample.
type ServicePoint struct {
	T        int64 `json:"t"`
	BytesIn  int64 `json:"bytes_in"`
	BytesOut int64 `json:"bytes_out"`
	Conns    int64 `json:"conns"`
	Lookups  int64 `json:"lookups"`
	Blocked  int64 `json:"blocked"`
}

// ServiceSeries returns hourly points for a service and/or device. Empty
// hours are filled with zeros so charts have a continuous axis.
func (s *Store) ServiceSeries(since, until time.Time, clientID, service string) ([]ServicePoint, error) {
	where := `bucket >= ? AND bucket < ?`
	args := []any{since.Unix(), until.Unix()}
	if clientID != "" {
		where += ` AND client_id = ?`
		args = append(args, clientID)
	}
	if service != "" {
		where += ` AND service = ?`
		args = append(args, service)
	}
	rows, err := s.db.Query(`SELECT bucket, SUM(bytes_in), SUM(bytes_out), SUM(conns), SUM(lookups), SUM(blocked)
		FROM service_stats WHERE `+where+` GROUP BY bucket ORDER BY bucket`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	got := map[int64]ServicePoint{}
	for rows.Next() {
		var p ServicePoint
		if err := rows.Scan(&p.T, &p.BytesIn, &p.BytesOut, &p.Conns, &p.Lookups, &p.Blocked); err != nil {
			return nil, err
		}
		got[p.T] = p
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := []ServicePoint{}
	for t := since.Truncate(time.Hour).Unix(); t < until.Unix(); t += 3600 {
		if p, ok := got[t]; ok {
			out = append(out, p)
		} else {
			out = append(out, ServicePoint{T: t})
		}
	}
	return out, nil
}

// DeviceServiceMatrix returns, for every device, its top services in the
// window. limitPerDevice caps the services per device; the rest is summed
// into an "other" row so totals still add up.
func (s *Store) DeviceServiceMatrix(since, until time.Time, limitPerDevice int) (map[string][]ServiceTotal, error) {
	rows, err := s.db.Query(`SELECT client_id, service, MAX(category), SUM(conns), SUM(bytes_in), SUM(bytes_out),
		SUM(lookups), SUM(blocked)
		FROM service_stats WHERE bucket >= ? AND bucket < ?
		GROUP BY client_id, service
		ORDER BY client_id, SUM(bytes_in + bytes_out) DESC, SUM(lookups) DESC`, since.Unix(), until.Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string][]ServiceTotal{}
	rest := map[string]*ServiceTotal{}
	for rows.Next() {
		var t ServiceTotal
		if err := rows.Scan(&t.ClientID, &t.Service, &t.Category, &t.Conns, &t.BytesIn, &t.BytesOut, &t.Lookups, &t.Blocked); err != nil {
			return nil, err
		}
		t.Devices = 1
		if limitPerDevice > 0 && len(out[t.ClientID]) >= limitPerDevice {
			r := rest[t.ClientID]
			if r == nil {
				r = &ServiceTotal{ClientID: t.ClientID, Service: "everything else", Category: "other", Devices: 1}
				rest[t.ClientID] = r
			}
			r.Conns += t.Conns
			r.BytesIn += t.BytesIn
			r.BytesOut += t.BytesOut
			r.Lookups += t.Lookups
			r.Blocked += t.Blocked
			continue
		}
		out[t.ClientID] = append(out[t.ClientID], t)
	}
	for id, r := range rest {
		out[id] = append(out[id], *r)
	}
	return out, rows.Err()
}

// ServiceHosts lists the hostnames behind a service in the window, from the
// flow table, so a drawer can show "which googlevideo nodes" without the
// rollups having to store every host.
func (s *Store) ServiceHosts(since time.Time, clientID string, classify func(host string) string, service string, limit int) ([]map[string]any, error) {
	q := `SELECT COALESCE(NULLIF(hostname,''), NULLIF(sni,''), dst_ip) host, COUNT(*), SUM(bytes_in), SUM(bytes_out)
		FROM flows WHERE started_at >= ?`
	args := []any{since.Unix()}
	if clientID != "" {
		q += ` AND client_id = ?`
		args = append(args, clientID)
	}
	q += ` GROUP BY host ORDER BY SUM(bytes_in + bytes_out) DESC LIMIT 3000`
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var host sql.NullString
		var n, in, outb int64
		if err := rows.Scan(&host, &n, &in, &outb); err != nil {
			return nil, err
		}
		if !host.Valid || classify(host.String) != service {
			continue
		}
		out = append(out, map[string]any{"host": host.String, "conns": n, "bytes_in": in, "bytes_out": outb})
		if len(out) >= limit {
			break
		}
	}
	return out, rows.Err()
}

// PruneServiceStats drops rollups older than keepDays.
func (s *Store) PruneServiceStats(keepDays int) error {
	cutoff := time.Now().AddDate(0, 0, -keepDays).Unix()
	_, err := s.db.Exec(`DELETE FROM service_stats WHERE bucket < ?`, cutoff)
	return err
}

// FlowsForBackfill streams flows since a time in pages, for the one-time
// rollup of history. Kept simple: bounded by limit, ordered by start.
func (s *Store) FlowsForBackfill(since time.Time, limit int) ([]Flow, error) {
	return s.Flows(FlowQuery{Since: &since, Limit: limit, OrderBy: "started_at"})
}

func joinPlaceholders(n int) string {
	if n <= 0 {
		return ""
	}
	return strings.TrimSuffix(strings.Repeat("?,", n), ",")
}

var _ = fmt.Sprintf
var _ = joinPlaceholders
