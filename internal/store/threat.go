package store

import (
	"database/sql"
	"time"
)

// ThreatFeedMeta is what the UI shows per address feed.
type ThreatFeedMeta struct {
	Name      string     `json:"name"`
	URL       string     `json:"url"`
	Category  string     `json:"category"`
	Enabled   bool       `json:"enabled"`
	Entries   int        `json:"entries"`
	Skipped   int        `json:"skipped"`
	FetchedAt *time.Time `json:"fetched_at,omitempty"`
	LastError string     `json:"last_error,omitempty"`
	ETag      string     `json:"-"`
}

// ThreatDecision is a timed ban on an address or range. Source says where it
// came from: manual, assistant, scan (the anomaly detector) or crowdsec.
type ThreatDecision struct {
	ID         string     `json:"id"`
	Value      string     `json:"value"`
	Source     string     `json:"source"`
	Reason     string     `json:"reason,omitempty"`
	Origin     string     `json:"origin,omitempty"`
	ExternalID int64      `json:"external_id,omitempty"`
	Actor      string     `json:"actor,omitempty"`
	Created    time.Time  `json:"created"`
	Until      *time.Time `json:"until,omitempty"`
}

// ThreatHit is one connection that touched a listed address.
type ThreatHit struct {
	ID        int64     `json:"id"`
	TS        time.Time `json:"ts"`
	ClientID  string    `json:"client_id,omitempty"`
	LocalIP   string    `json:"local_ip,omitempty"`
	RemoteIP  string    `json:"remote_ip"`
	Prefix    string    `json:"prefix,omitempty"`
	Source    string    `json:"source"`
	Reason    string    `json:"reason,omitempty"`
	Direction string    `json:"direction"`
	Port      int       `json:"port,omitempty"`
	Proto     string    `json:"proto,omitempty"`
	Enforced  bool      `json:"enforced"`
	FlowID    string    `json:"flow_id,omitempty"`
	Country   string    `json:"country,omitempty"`
	ASOrg     string    `json:"as_org,omitempty"`
}

func (s *Store) UpsertThreatFeed(m ThreatFeedMeta) error {
	var fetched any
	if m.FetchedAt != nil {
		fetched = m.FetchedAt.Unix()
	}
	_, err := s.db.Exec(`INSERT INTO threat_feeds (name, url, category, enabled, entries, skipped, fetched_at, last_error, etag)
		VALUES (?,?,?,?,?,?,?,?,?)
		ON CONFLICT(name) DO UPDATE SET url=excluded.url, category=excluded.category, enabled=excluded.enabled,
			entries=excluded.entries, skipped=excluded.skipped, fetched_at=excluded.fetched_at,
			last_error=excluded.last_error, etag=excluded.etag`,
		m.Name, m.URL, m.Category, b2i(m.Enabled), m.Entries, m.Skipped, fetched, m.LastError, m.ETag)
	return err
}

func (s *Store) SetThreatFeedError(name, msg string) error {
	_, err := s.db.Exec(`UPDATE threat_feeds SET last_error=? WHERE name=?`, msg, name)
	return err
}

func (s *Store) ThreatFeeds() ([]ThreatFeedMeta, error) {
	rows, err := s.db.Query(`SELECT name, url, category, enabled, entries, skipped, fetched_at, last_error, etag
		FROM threat_feeds ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ThreatFeedMeta{}
	for rows.Next() {
		var m ThreatFeedMeta
		var enabled int
		var fetched sql.NullInt64
		if err := rows.Scan(&m.Name, &m.URL, &m.Category, &enabled, &m.Entries, &m.Skipped, &fetched, &m.LastError, &m.ETag); err != nil {
			return nil, err
		}
		m.Enabled = enabled != 0
		if fetched.Valid {
			t := time.Unix(fetched.Int64, 0)
			m.FetchedAt = &t
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// DeleteThreatFeed removes a feed and every entry it contributed.
func (s *Store) DeleteThreatFeed(name string) error {
	tx, done, err := s.beginWrite()
	if err != nil {
		return err
	}
	defer done()
	if _, err := tx.Exec(`DELETE FROM threat_entries WHERE feed=?`, name); err != nil {
		_ = tx.Rollback()
		return err
	}
	if _, err := tx.Exec(`DELETE FROM threat_feeds WHERE name=?`, name); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

// ReplaceThreatEntries swaps a feed's stored prefixes for a fresh parse.
func (s *Store) ReplaceThreatEntries(feed string, prefixes []string) error {
	tx, done, err := s.beginWrite()
	if err != nil {
		return err
	}
	defer done()
	if _, err := tx.Exec(`DELETE FROM threat_entries WHERE feed=?`, feed); err != nil {
		_ = tx.Rollback()
		return err
	}
	stmt, err := tx.Prepare(`INSERT OR IGNORE INTO threat_entries (feed, prefix) VALUES (?,?)`)
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	defer stmt.Close()
	for _, p := range prefixes {
		if _, err := stmt.Exec(feed, p); err != nil {
			_ = tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

// ThreatEntries returns every stored prefix grouped by feed.
func (s *Store) ThreatEntries() (map[string][]string, error) {
	rows, err := s.db.Query(`SELECT feed, prefix FROM threat_entries`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string][]string{}
	for rows.Next() {
		var feed, prefix string
		if err := rows.Scan(&feed, &prefix); err != nil {
			return nil, err
		}
		out[feed] = append(out[feed], prefix)
	}
	return out, rows.Err()
}

func (s *Store) PutThreatDecision(d ThreatDecision) error {
	var until int64
	if d.Until != nil {
		until = d.Until.Unix()
	}
	_, err := s.db.Exec(`INSERT INTO threat_decisions (id, value, source, reason, origin, external_id, actor, created, until)
		VALUES (?,?,?,?,?,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET value=excluded.value, source=excluded.source, reason=excluded.reason,
			origin=excluded.origin, external_id=excluded.external_id, actor=excluded.actor, until=excluded.until`,
		d.ID, d.Value, d.Source, d.Reason, d.Origin, d.ExternalID, d.Actor, d.Created.Unix(), until)
	return err
}

// ThreatDecisions lists decisions; with activeOnly, those not yet expired.
func (s *Store) ThreatDecisions(activeOnly bool) ([]ThreatDecision, error) {
	q := `SELECT id, value, source, reason, origin, external_id, actor, created, until FROM threat_decisions`
	args := []any{}
	if activeOnly {
		q += ` WHERE until = 0 OR until > ?`
		args = append(args, time.Now().Unix())
	}
	q += ` ORDER BY created DESC`
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ThreatDecision{}
	for rows.Next() {
		var d ThreatDecision
		var created, until int64
		if err := rows.Scan(&d.ID, &d.Value, &d.Source, &d.Reason, &d.Origin, &d.ExternalID, &d.Actor, &created, &until); err != nil {
			return nil, err
		}
		d.Created = time.Unix(created, 0)
		if until > 0 {
			t := time.Unix(until, 0)
			d.Until = &t
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func (s *Store) DeleteThreatDecision(id string) error {
	_, err := s.db.Exec(`DELETE FROM threat_decisions WHERE id=?`, id)
	return err
}

// DeleteThreatDecisionsBySource clears every decision from one source, which
// is how a CrowdSec full pull starts from a clean slate.
func (s *Store) DeleteThreatDecisionsBySource(source string) error {
	_, err := s.db.Exec(`DELETE FROM threat_decisions WHERE source=?`, source)
	return err
}

// ExpireThreatDecisions removes decisions whose time has passed and returns
// their ids so the in-memory table can follow.
func (s *Store) ExpireThreatDecisions(now time.Time) ([]string, error) {
	rows, err := s.db.Query(`SELECT id FROM threat_decisions WHERE until > 0 AND until <= ?`, now.Unix())
	if err != nil {
		return nil, err
	}
	ids := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	rows.Close()
	if len(ids) > 0 {
		_, err = s.db.Exec(`DELETE FROM threat_decisions WHERE until > 0 AND until <= ?`, now.Unix())
	}
	return ids, err
}

func (s *Store) AddThreatHit(h ThreatHit) error {
	_, err := s.db.Exec(`INSERT INTO threat_hits (ts, client_id, local_ip, remote_ip, prefix, source, reason, direction, port, proto, enforced, flow_id, country, as_org)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		h.TS.Unix(), h.ClientID, h.LocalIP, h.RemoteIP, h.Prefix, h.Source, h.Reason, h.Direction, h.Port, h.Proto, b2i(h.Enforced), h.FlowID, h.Country, h.ASOrg)
	return err
}

func (s *Store) ThreatHits(since time.Time, limit int) ([]ThreatHit, error) {
	if limit <= 0 || limit > 2000 {
		limit = 500
	}
	rows, err := s.db.Query(`SELECT id, ts, client_id, local_ip, remote_ip, prefix, source, reason, direction, port, proto, enforced, flow_id, country, as_org
		FROM threat_hits WHERE ts >= ? ORDER BY ts DESC LIMIT ?`, since.Unix(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ThreatHit{}
	for rows.Next() {
		var h ThreatHit
		var ts int64
		var enforced int
		if err := rows.Scan(&h.ID, &ts, &h.ClientID, &h.LocalIP, &h.RemoteIP, &h.Prefix, &h.Source, &h.Reason, &h.Direction, &h.Port, &h.Proto, &enforced, &h.FlowID, &h.Country, &h.ASOrg); err != nil {
			return nil, err
		}
		h.TS = time.Unix(ts, 0)
		h.Enforced = enforced != 0
		out = append(out, h)
	}
	return out, rows.Err()
}

// ThreatHitCount returns how many hits landed since a time, and how many of
// those were actually dropped.
func (s *Store) ThreatHitCount(since time.Time) (total, enforced int, err error) {
	err = s.db.QueryRow(`SELECT COUNT(*), COALESCE(SUM(enforced),0) FROM threat_hits WHERE ts >= ?`, since.Unix()).Scan(&total, &enforced)
	return
}

func (s *Store) PruneThreatHits(before time.Time) error {
	_, err := s.db.Exec(`DELETE FROM threat_hits WHERE ts < ?`, before.Unix())
	return err
}
