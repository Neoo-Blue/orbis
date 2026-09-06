package store

import "time"

// IDSAlert is one scenario firing for one address.
type IDSAlert struct {
	ID       int64      `json:"id"`
	TS       time.Time  `json:"ts"`
	IP       string     `json:"ip"`
	Scenario string     `json:"scenario"`
	Count    int        `json:"count"`
	Source   string     `json:"source"`
	Host     string     `json:"host,omitempty"`
	Sample   string     `json:"sample,omitempty"`
	Action   string     `json:"action"`
	BanUntil *time.Time `json:"ban_until,omitempty"`
	Country  string     `json:"country,omitempty"`
	ASOrg    string     `json:"as_org,omitempty"`
}

func (s *Store) AddIDSAlert(a IDSAlert) error {
	var until int64
	if a.BanUntil != nil {
		until = a.BanUntil.Unix()
	}
	_, err := s.db.Exec(`INSERT INTO ids_alerts (ts, ip, scenario, count, source, host, sample, action, ban_until, country, as_org)
		VALUES (?,?,?,?,?,?,?,?,?,?,?)`, a.TS.Unix(), a.IP, a.Scenario, a.Count, a.Source, a.Host, a.Sample, a.Action, until, a.Country, a.ASOrg)
	return err
}

func (s *Store) IDSAlerts(since time.Time, limit int) ([]IDSAlert, error) {
	if limit <= 0 || limit > 2000 {
		limit = 300
	}
	rows, err := s.db.Query(`SELECT id, ts, ip, scenario, count, source, host, sample, action, ban_until, country, as_org
		FROM ids_alerts WHERE ts >= ? ORDER BY ts DESC LIMIT ?`, since.Unix(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []IDSAlert{}
	for rows.Next() {
		var a IDSAlert
		var ts, until int64
		if err := rows.Scan(&a.ID, &ts, &a.IP, &a.Scenario, &a.Count, &a.Source, &a.Host, &a.Sample, &a.Action, &until, &a.Country, &a.ASOrg); err != nil {
			return nil, err
		}
		a.TS = time.Unix(ts, 0)
		if until > 0 {
			t := time.Unix(until, 0)
			a.BanUntil = &t
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// IDSBanCount says how many times an address was banned in a window, for
// escalation.
func (s *Store) IDSBanCount(ip string, since time.Time) (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM ids_alerts WHERE ip=? AND ts >= ? AND action='ban'`, ip, since.Unix()).Scan(&n)
	return n, err
}

// IDSAlertCounts totals alerts by scenario since a time.
func (s *Store) IDSAlertCounts(since time.Time) (map[string]int, int, error) {
	rows, err := s.db.Query(`SELECT scenario, COUNT(*), SUM(CASE WHEN action='ban' THEN 1 ELSE 0 END) FROM ids_alerts WHERE ts >= ? GROUP BY scenario`, since.Unix())
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := map[string]int{}
	bans := 0
	for rows.Next() {
		var k string
		var n, b int
		if err := rows.Scan(&k, &n, &b); err != nil {
			return nil, 0, err
		}
		out[k] = n
		bans += b
	}
	return out, bans, rows.Err()
}

func (s *Store) PruneIDSAlerts(before time.Time) error {
	_, err := s.db.Exec(`DELETE FROM ids_alerts WHERE ts < ?`, before.Unix())
	return err
}
