package store

import "time"

// SetPause records when a device's block should lift. A zero time clears it.
func (s *Store) SetPause(clientID string, until time.Time) error {
	if until.IsZero() {
		_, err := s.db.Exec(`DELETE FROM client_pauses WHERE client_id=?`, clientID)
		return err
	}
	_, err := s.db.Exec(`INSERT INTO client_pauses (client_id, until) VALUES (?,?)
		ON CONFLICT(client_id) DO UPDATE SET until=excluded.until`, clientID, until.Unix())
	return err
}

// Pauses returns every timed pause, so the UI can show "until 9pm".
func (s *Store) Pauses() (map[string]time.Time, error) {
	rows, err := s.db.Query(`SELECT client_id, until FROM client_pauses`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]time.Time{}
	for rows.Next() {
		var id string
		var until int64
		if err := rows.Scan(&id, &until); err != nil {
			return nil, err
		}
		out[id] = time.Unix(until, 0)
	}
	return out, rows.Err()
}

// ExpiredPauses lists devices whose pause has passed.
func (s *Store) ExpiredPauses(now time.Time) ([]string, error) {
	rows, err := s.db.Query(`SELECT client_id FROM client_pauses WHERE until <= ?`, now.Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}
