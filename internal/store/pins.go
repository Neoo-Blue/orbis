package store

import "time"

// PinBypass is a remembered decision that a client rejects the proxy's
// certificate for a name, so the proxy splices instead of breaking the app.
type PinBypass struct {
	Client string    `json:"client"`
	Name   string    `json:"name"`
	Until  time.Time `json:"until"`
	Fails  int       `json:"fails"`
}

func (s *Store) SavePinBypass(client, name string, until time.Time) error {
	_, err := s.db.Exec(`INSERT INTO pin_bypasses (client, name, until, fails) VALUES (?,?,?,2)
		ON CONFLICT(client, name) DO UPDATE SET until=excluded.until`, client, name, until.Unix())
	return err
}

// PinBypasses returns the bypasses still in force and drops the expired ones.
func (s *Store) PinBypasses() ([]PinBypass, error) {
	now := time.Now().Unix()
	_, _ = s.db.Exec(`DELETE FROM pin_bypasses WHERE until < ?`, now)
	rows, err := s.db.Query(`SELECT client, name, until, fails FROM pin_bypasses WHERE until >= ?`, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []PinBypass{}
	for rows.Next() {
		var b PinBypass
		var until int64
		if err := rows.Scan(&b.Client, &b.Name, &until, &b.Fails); err != nil {
			return nil, err
		}
		b.Until = time.Unix(until, 0)
		out = append(out, b)
	}
	return out, rows.Err()
}
