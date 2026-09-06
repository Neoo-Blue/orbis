package store

import "time"

// LANService is one listening service on a device on this network.
type LANService struct {
	Host      string    `json:"host"`
	Port      int       `json:"port"`
	Proto     string    `json:"proto"`
	Name      string    `json:"name"`
	Kind      string    `json:"kind"`
	Category  string    `json:"category,omitempty"`
	Title     string    `json:"title,omitempty"`
	Server    string    `json:"server,omitempty"`
	Scheme    string    `json:"scheme,omitempty"`
	Source    string    `json:"source"`
	Container string    `json:"container,omitempty"`
	Image     string    `json:"image,omitempty"`
	Sensitive bool      `json:"sensitive"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	Online    bool      `json:"online"`
}

// PortForward is a forward this node created: a DNAT rule in its own ruleset
// (method nft) or a mapping on the upstream router (method upnp).
type PortForward struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Proto      string     `json:"proto"`
	ExtPort    int        `json:"ext_port"`
	Host       string     `json:"host"`
	Port       int        `json:"port"`
	Method     string     `json:"method"`
	RuleID     string     `json:"rule_id,omitempty"`
	LeaseUntil *time.Time `json:"lease_until,omitempty"`
	Created    time.Time  `json:"created"`
	Actor      string     `json:"actor,omitempty"`
}

// UpsertLANService records a service, keeping first_seen from the earlier row.
func (s *Store) UpsertLANService(v LANService) error {
	_, err := s.db.Exec(`INSERT INTO lan_services (host, port, proto, name, kind, category, title, server, scheme, source, container, image, sensitive, first_seen, last_seen, online)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(host, port, proto) DO UPDATE SET
			name=CASE WHEN excluded.name<>'' THEN excluded.name ELSE lan_services.name END,
			kind=excluded.kind, category=excluded.category,
			title=CASE WHEN excluded.title<>'' THEN excluded.title ELSE lan_services.title END,
			server=CASE WHEN excluded.server<>'' THEN excluded.server ELSE lan_services.server END,
			scheme=CASE WHEN excluded.scheme<>'' THEN excluded.scheme ELSE lan_services.scheme END,
			source=excluded.source,
			container=CASE WHEN excluded.container<>'' THEN excluded.container ELSE lan_services.container END,
			image=CASE WHEN excluded.image<>'' THEN excluded.image ELSE lan_services.image END,
			sensitive=excluded.sensitive, last_seen=excluded.last_seen, online=excluded.online`,
		v.Host, v.Port, v.Proto, v.Name, v.Kind, v.Category, v.Title, v.Server, v.Scheme, v.Source, v.Container, v.Image,
		b2i(v.Sensitive), v.FirstSeen.Unix(), v.LastSeen.Unix(), b2i(v.Online))
	return err
}

// MarkLANServicesOffline flags services on a host that a scan did not find.
func (s *Store) MarkLANServicesOffline(host string, seenPorts []int, proto string) error {
	rows, err := s.db.Query(`SELECT port FROM lan_services WHERE host=? AND proto=? AND online=1`, host, proto)
	if err != nil {
		return err
	}
	seen := map[int]bool{}
	for _, p := range seenPorts {
		seen[p] = true
	}
	var gone []int
	for rows.Next() {
		var p int
		if err := rows.Scan(&p); err == nil && !seen[p] {
			gone = append(gone, p)
		}
	}
	rows.Close()
	for _, p := range gone {
		if _, err := s.db.Exec(`UPDATE lan_services SET online=0 WHERE host=? AND port=? AND proto=?`, host, p, proto); err != nil {
			return err
		}
	}
	return nil
}

// LANServices lists everything ever seen, online first, then by host and port.
func (s *Store) LANServices() ([]LANService, error) {
	rows, err := s.db.Query(`SELECT host, port, proto, name, kind, category, title, server, scheme, source, container, image, sensitive, first_seen, last_seen, online
		FROM lan_services ORDER BY online DESC, host, port`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []LANService{}
	for rows.Next() {
		var v LANService
		var sensitive, online int
		var first, last int64
		if err := rows.Scan(&v.Host, &v.Port, &v.Proto, &v.Name, &v.Kind, &v.Category, &v.Title, &v.Server, &v.Scheme, &v.Source, &v.Container, &v.Image, &sensitive, &first, &last, &online); err != nil {
			return nil, err
		}
		v.Sensitive, v.Online = sensitive != 0, online != 0
		v.FirstSeen, v.LastSeen = time.Unix(first, 0), time.Unix(last, 0)
		out = append(out, v)
	}
	return out, rows.Err()
}

// PruneLANServices forgets services not seen for a while.
func (s *Store) PruneLANServices(before time.Time) error {
	_, err := s.db.Exec(`DELETE FROM lan_services WHERE last_seen < ?`, before.Unix())
	return err
}

func (s *Store) PutPortForward(f PortForward) error {
	var lease int64
	if f.LeaseUntil != nil {
		lease = f.LeaseUntil.Unix()
	}
	_, err := s.db.Exec(`INSERT INTO port_forwards (id, name, proto, ext_port, host, port, method, rule_id, lease_until, created, actor)
		VALUES (?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET name=excluded.name, lease_until=excluded.lease_until, rule_id=excluded.rule_id`,
		f.ID, f.Name, f.Proto, f.ExtPort, f.Host, f.Port, f.Method, f.RuleID, lease, f.Created.Unix(), f.Actor)
	return err
}

func (s *Store) DeletePortForward(id string) error {
	_, err := s.db.Exec(`DELETE FROM port_forwards WHERE id=?`, id)
	return err
}

func (s *Store) PortForwards() ([]PortForward, error) {
	rows, err := s.db.Query(`SELECT id, name, proto, ext_port, host, port, method, rule_id, lease_until, created, actor FROM port_forwards ORDER BY created DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []PortForward{}
	for rows.Next() {
		var f PortForward
		var lease, created int64
		if err := rows.Scan(&f.ID, &f.Name, &f.Proto, &f.ExtPort, &f.Host, &f.Port, &f.Method, &f.RuleID, &lease, &created, &f.Actor); err != nil {
			return nil, err
		}
		f.Created = time.Unix(created, 0)
		if lease > 0 {
			t := time.Unix(lease, 0)
			f.LeaseUntil = &t
		}
		out = append(out, f)
	}
	return out, rows.Err()
}
