package store

import (
	"strings"
	"time"
)

// GeoSet is the cached address ranges of one country.
type GeoSet struct {
	Country string
	V4      []string
	V6      []string
	Built   time.Time
	DBSize  int64
}

func (s *Store) PutGeoSet(g GeoSet) error {
	_, err := s.db.Exec(`INSERT INTO geo_sets (country, v4, v6, built, db_size) VALUES (?,?,?,?,?)
		ON CONFLICT(country) DO UPDATE SET v4=excluded.v4, v6=excluded.v6, built=excluded.built, db_size=excluded.db_size`,
		g.Country, strings.Join(g.V4, "\n"), strings.Join(g.V6, "\n"), g.Built.Unix(), g.DBSize)
	return err
}

func (s *Store) GeoSet(country string) (*GeoSet, error) {
	var g GeoSet
	var v4, v6 string
	var built int64
	err := s.db.QueryRow(`SELECT country, v4, v6, built, db_size FROM geo_sets WHERE country=?`, country).Scan(&g.Country, &v4, &v6, &built, &g.DBSize)
	if err != nil {
		return nil, err
	}
	if v4 != "" {
		g.V4 = strings.Split(v4, "\n")
	}
	if v6 != "" {
		g.V6 = strings.Split(v6, "\n")
	}
	g.Built = time.Unix(built, 0)
	return &g, nil
}
