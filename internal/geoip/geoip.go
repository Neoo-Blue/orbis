// Package geoip resolves an IP address to a coordinate, country and network
// operator so the globe has something to draw arcs between.
//
// The good path is a MaxMind-format .mmdb (DB-IP's free City + ASN builds
// work and need no signup). When none is installed the coarse RIR fallback
// keeps the globe populated at continent resolution rather than showing an
// empty sphere, and Source() reports which one answered so the UI can say so.
package geoip

import (
	"net"
	"net/netip"
	"strings"
	"sync"

	"github.com/oschwald/maxminddb-golang"
)

type Location struct {
	Country     string  `json:"country"`
	CountryName string  `json:"country_name,omitempty"`
	City        string  `json:"city,omitempty"`
	Lat         float64 `json:"lat"`
	Lon         float64 `json:"lon"`
	ASN         int     `json:"asn,omitempty"`
	ASOrg       string  `json:"as_org,omitempty"`
	Private     bool    `json:"private"`
	// Anycast marks an address served from many sites at once, where the
	// coordinates are the operator's region rather than a real machine.
	Anycast  bool   `json:"anycast,omitempty"`
	Accuracy string `json:"accuracy"` // "city" | "country" | "region" | "anycast" | "none"
}

type Resolver struct {
	mu    sync.RWMutex
	city  *maxminddb.Reader
	asn   *maxminddb.Reader
	cache map[netip.Addr]Location
	// cacheOrder is a simple FIFO ring so the cache cannot grow unbounded
	// on a scanned network.
	cacheOrder []netip.Addr
	maxCache   int
}

func New() *Resolver {
	return &Resolver{cache: make(map[netip.Addr]Location), maxCache: 20000}
}

// LoadCity opens a City-style mmdb. An empty path is not an error; it just
// leaves the resolver on the fallback path.
func (r *Resolver) LoadCity(path string) error {
	if path == "" {
		return nil
	}
	db, err := maxminddb.Open(path)
	if err != nil {
		return err
	}
	r.mu.Lock()
	if r.city != nil {
		r.city.Close()
	}
	r.city = db
	r.cache = make(map[netip.Addr]Location)
	r.cacheOrder = nil
	r.mu.Unlock()
	return nil
}

func (r *Resolver) LoadASN(path string) error {
	if path == "" {
		return nil
	}
	db, err := maxminddb.Open(path)
	if err != nil {
		return err
	}
	r.mu.Lock()
	if r.asn != nil {
		r.asn.Close()
	}
	r.asn = db
	r.mu.Unlock()
	return nil
}

func (r *Resolver) Close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.city != nil {
		r.city.Close()
		r.city = nil
	}
	if r.asn != nil {
		r.asn.Close()
		r.asn = nil
	}
}

// Source describes which backing data is live, for the settings page.
func (r *Resolver) Source() map[string]any {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := map[string]any{"city_db": r.city != nil, "asn_db": r.asn != nil}
	if r.city != nil {
		out["city_build"] = r.city.Metadata.DatabaseType
		out["city_nodes"] = r.city.Metadata.NodeCount
	}
	if r.asn != nil {
		out["asn_build"] = r.asn.Metadata.DatabaseType
	}
	if r.city == nil {
		out["accuracy"] = "region (no database installed)"
	} else {
		out["accuracy"] = "city"
	}
	return out
}

// mmdb record shapes. Only the fields we use are declared, which keeps the
// decoder from allocating the rest of a City record on every lookup.
type cityRecord struct {
	City struct {
		Names map[string]string `maxminddb:"names"`
	} `maxminddb:"city"`
	Country struct {
		ISOCode string            `maxminddb:"iso_code"`
		Names   map[string]string `maxminddb:"names"`
	} `maxminddb:"country"`
	Location struct {
		Latitude  float64 `maxminddb:"latitude"`
		Longitude float64 `maxminddb:"longitude"`
	} `maxminddb:"location"`
	Continent struct {
		Code  string            `maxminddb:"code"`
		Names map[string]string `maxminddb:"names"`
	} `maxminddb:"continent"`
}

type asnRecord struct {
	Number int    `maxminddb:"autonomous_system_number"`
	Org    string `maxminddb:"autonomous_system_organization"`
	// DB-IP's free ASN build uses different keys.
	ASNAlt int    `maxminddb:"asn"`
	OrgAlt string `maxminddb:"as_name"`
}

func (r *Resolver) Lookup(ipStr string) Location {
	addr, err := netip.ParseAddr(ipStr)
	if err != nil {
		return Location{Accuracy: "none"}
	}
	return r.LookupAddr(addr)
}

func (r *Resolver) LookupAddr(addr netip.Addr) Location {
	if IsPrivate(addr) {
		return Location{Private: true, Accuracy: "none", Country: "", City: "Local"}
	}
	r.mu.RLock()
	if loc, ok := r.cache[addr]; ok {
		r.mu.RUnlock()
		return loc
	}
	city, asnDB := r.city, r.asn
	r.mu.RUnlock()

	loc := Location{Accuracy: "none"}
	ip := net.IP(addr.AsSlice())

	// Anycast first. Consulting the database for 1.1.1.1 yields Australia,
	// because that is where the prefix is registered, and no amount of
	// post-processing recovers the intent from that answer.
	if ac, ok := LookupAnycast(addr); ok {
		loc = ac
		if asnDB != nil {
			var rec asnRecord
			if err := asnDB.Lookup(ip, &rec); err == nil {
				if rec.Number != 0 {
					loc.ASN = rec.Number
				} else {
					loc.ASN = rec.ASNAlt
				}
				if org := firstNonEmpty(rec.Org, rec.OrgAlt); org != "" {
					loc.ASOrg = org
				}
			}
		}
		r.mu.Lock()
		r.cache[addr] = loc
		r.cacheOrder = append(r.cacheOrder, addr)
		r.mu.Unlock()
		return loc
	}

	if city != nil {
		var rec cityRecord
		if err := city.Lookup(ip, &rec); err == nil {
			loc.Country = rec.Country.ISOCode
			loc.CountryName = rec.Country.Names["en"]
			loc.City = rec.City.Names["en"]
			loc.Lat = rec.Location.Latitude
			loc.Lon = rec.Location.Longitude
			if loc.Lat != 0 || loc.Lon != 0 {
				loc.Accuracy = "city"
				if loc.City == "" {
					loc.Accuracy = "country"
				}
			}
			// Some free builds carry a country but no coordinates.
			if loc.Accuracy == "none" && loc.Country != "" {
				if c, ok := countryCentroid[loc.Country]; ok {
					loc.Lat, loc.Lon = c[0], c[1]
					loc.Accuracy = "country"
				}
			}
		}
	}
	if loc.Accuracy == "none" {
		if c, ok := fallbackRegion(addr); ok {
			loc = c
		}
	}
	if asnDB != nil {
		var rec asnRecord
		if err := asnDB.Lookup(ip, &rec); err == nil {
			loc.ASN = rec.Number
			loc.ASOrg = rec.Org
			if loc.ASN == 0 {
				loc.ASN = rec.ASNAlt
			}
			if loc.ASOrg == "" {
				loc.ASOrg = rec.OrgAlt
			}
		}
	}

	r.mu.Lock()
	if len(r.cacheOrder) >= r.maxCache {
		evict := r.cacheOrder[0]
		r.cacheOrder = r.cacheOrder[1:]
		delete(r.cache, evict)
	}
	r.cache[addr] = loc
	r.cacheOrder = append(r.cacheOrder, addr)
	r.mu.Unlock()
	return loc
}

// bogons are the address ranges that are not globally routable. Anything in
// them must never be geolocated: a placement would draw an arc from the local
// network to a random continent, which is worse than showing nothing.
var bogons = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),       // "this network"
	netip.MustParsePrefix("10.0.0.0/8"),      // RFC 1918
	netip.MustParsePrefix("100.64.0.0/10"),   // carrier-grade NAT
	netip.MustParsePrefix("127.0.0.0/8"),     // loopback
	netip.MustParsePrefix("169.254.0.0/16"),  // link-local
	netip.MustParsePrefix("172.16.0.0/12"),   // RFC 1918
	netip.MustParsePrefix("192.0.0.0/24"),    // IETF protocol assignments
	netip.MustParsePrefix("192.0.2.0/24"),    // TEST-NET-1
	netip.MustParsePrefix("192.168.0.0/16"),  // RFC 1918
	netip.MustParsePrefix("198.18.0.0/15"),   // benchmarking
	netip.MustParsePrefix("198.51.100.0/24"), // TEST-NET-2
	netip.MustParsePrefix("203.0.113.0/24"),  // TEST-NET-3
	netip.MustParsePrefix("224.0.0.0/4"),     // multicast
	netip.MustParsePrefix("240.0.0.0/4"),     // reserved, and 255.255.255.255 with it
	netip.MustParsePrefix("::/128"),          // unspecified
	netip.MustParsePrefix("::1/128"),         // loopback
	netip.MustParsePrefix("64:ff9b::/96"),    // NAT64
	netip.MustParsePrefix("100::/64"),        // discard-only
	netip.MustParsePrefix("2001:db8::/32"),   // documentation
	netip.MustParsePrefix("fc00::/7"),        // unique local
	netip.MustParsePrefix("fe80::/10"),       // link-local
	netip.MustParsePrefix("ff00::/8"),        // multicast
}

// IsPrivate reports whether an address should be treated as local — that is,
// anything not globally routable. It is the single gate deciding whether a
// destination gets a position on the map at all.
func IsPrivate(addr netip.Addr) bool {
	if !addr.IsValid() {
		return true
	}
	// Unmap first, or a v4-mapped v6 address (::ffff:192.168.1.1) sails past
	// every IPv4 prefix below.
	addr = addr.Unmap()

	if addr.IsLoopback() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() ||
		addr.IsMulticast() || addr.IsUnspecified() || addr.IsPrivate() ||
		addr.IsInterfaceLocalMulticast() {
		return true
	}
	for _, p := range bogons {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

func IsPrivateString(ip string) bool {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return true
	}
	return IsPrivate(addr)
}

// fallbackRegion maps an address to the RIR that administers its block and
// returns that region's centroid. This is deliberately coarse: it puts an
// arc on the right continent so the globe is not blank, and Accuracy is set
// to "region" so the UI can label it as an estimate.
func fallbackRegion(addr netip.Addr) (Location, bool) {
	if !addr.Is4() {
		// IPv6 RIR blocks are allocated from 2001:: onwards in ranges that
		// map cleanly enough for a continent-level guess.
		s := addr.String()
		switch {
		case strings.HasPrefix(s, "2001:4") || strings.HasPrefix(s, "2600:") || strings.HasPrefix(s, "2604:") || strings.HasPrefix(s, "2605:") || strings.HasPrefix(s, "2607:") || strings.HasPrefix(s, "2620:"):
			return regionLoc("ARIN"), true
		case strings.HasPrefix(s, "2a0") || strings.HasPrefix(s, "2001:6") || strings.HasPrefix(s, "2001:7"):
			return regionLoc("RIPE"), true
		case strings.HasPrefix(s, "240") || strings.HasPrefix(s, "2001:2") || strings.HasPrefix(s, "2001:3"):
			return regionLoc("APNIC"), true
		case strings.HasPrefix(s, "2800:"):
			return regionLoc("LACNIC"), true
		case strings.HasPrefix(s, "2c0"):
			return regionLoc("AFRINIC"), true
		}
		return regionLoc("ARIN"), true
	}
	first := addr.As4()[0]
	rir := rirForFirstOctet(first)
	return regionLoc(rir), true
}

// rirForFirstOctet is a compressed view of IANA's /8 registry. It is a
// heuristic — plenty of /8s are shared — but it is right far more often than
// it is wrong at continent resolution.
func rirForFirstOctet(b byte) string {
	switch {
	case b >= 1 && b <= 2, b == 14, b >= 27 && b <= 27, b >= 36 && b <= 43,
		b >= 49 && b <= 61, b >= 101 && b <= 126, b >= 150 && b <= 153,
		b >= 175 && b <= 183, b >= 202 && b <= 223:
		return "APNIC"
	case b >= 3 && b <= 13, b >= 15 && b <= 24, b >= 26 && b <= 26,
		b >= 28 && b <= 35, b >= 44 && b <= 48, b >= 63 && b <= 76,
		b >= 96 && b <= 100, b >= 128 && b <= 143, b >= 155 && b <= 174,
		b >= 184 && b <= 192, b >= 198 && b <= 199, b >= 204 && b <= 209:
		return "ARIN"
	case b == 25, b >= 62 && b <= 62, b >= 77 && b <= 95, b >= 145 && b <= 149,
		b >= 176 && b <= 176, b >= 193 && b <= 197, b >= 212 && b <= 213,
		b >= 217 && b <= 217:
		return "RIPE"
	case b >= 186 && b <= 187, b >= 189 && b <= 190, b == 200, b == 201:
		return "LACNIC"
	case b == 41, b == 102, b == 105, b == 154, b == 197:
		return "AFRINIC"
	}
	return "ARIN"
}

func regionLoc(rir string) Location {
	c := rirCentroid[rir]
	return Location{Country: "", City: rir + " region", Lat: c[0], Lon: c[1], Accuracy: "region"}
}

var rirCentroid = map[string][2]float64{
	"ARIN":    {39.0, -98.0},  // North America
	"RIPE":    {50.0, 10.0},   // Europe / Middle East
	"APNIC":   {20.0, 110.0},  // Asia-Pacific
	"LACNIC":  {-15.0, -60.0}, // Latin America
	"AFRINIC": {2.0, 20.0},    // Africa
}

// countryCentroid backfills coordinates when a database has a country code
// but no lat/lon (common in country-only free builds).
var countryCentroid = map[string][2]float64{
	"US": {39.8, -98.6}, "CA": {56.1, -106.3}, "MX": {23.6, -102.6}, "BR": {-14.2, -51.9},
	"AR": {-38.4, -63.6}, "CL": {-35.7, -71.5}, "CO": {4.6, -74.3}, "PE": {-9.2, -75.0},
	"GB": {55.4, -3.4}, "IE": {53.4, -8.2}, "FR": {46.2, 2.2}, "DE": {51.2, 10.5},
	"NL": {52.1, 5.3}, "BE": {50.5, 4.5}, "ES": {40.5, -3.7}, "PT": {39.4, -8.2},
	"IT": {41.9, 12.6}, "CH": {46.8, 8.2}, "AT": {47.5, 14.6}, "SE": {60.1, 18.6},
	"NO": {60.5, 8.5}, "FI": {61.9, 25.7}, "DK": {56.3, 9.5}, "PL": {51.9, 19.1},
	"CZ": {49.8, 15.5}, "RO": {45.9, 25.0}, "UA": {48.4, 31.2}, "RU": {61.5, 105.3},
	"TR": {38.96, 35.2}, "GR": {39.1, 21.8}, "IL": {31.05, 34.85}, "AE": {23.4, 53.8},
	"SA": {23.9, 45.1}, "IN": {20.6, 79.0}, "PK": {30.4, 69.3}, "BD": {23.7, 90.4},
	"CN": {35.9, 104.2}, "JP": {36.2, 138.3}, "KR": {35.9, 127.8}, "TW": {23.7, 121.0},
	"HK": {22.4, 114.1}, "SG": {1.35, 103.8}, "MY": {4.2, 101.98}, "TH": {15.9, 101.0},
	"VN": {14.06, 108.3}, "ID": {-0.8, 113.9}, "PH": {12.9, 121.8}, "AU": {-25.3, 133.8},
	"NZ": {-40.9, 174.9}, "ZA": {-30.6, 22.9}, "NG": {9.1, 8.7}, "EG": {26.8, 30.8},
	"KE": {-0.02, 37.9}, "MA": {31.8, -7.1}, "IS": {64.96, -19.0}, "LU": {49.8, 6.1},
	"BG": {42.7, 25.5}, "HU": {47.2, 19.5}, "SK": {48.7, 19.7}, "HR": {45.1, 15.2},
	"RS": {44.0, 21.0}, "LT": {55.2, 23.9}, "LV": {56.9, 24.6}, "EE": {58.6, 25.0},
	"MD": {47.4, 28.4}, "BY": {53.7, 27.95}, "KZ": {48.02, 66.9}, "IR": {32.4, 53.7},
	"IQ": {33.2, 43.7}, "QA": {25.4, 51.2}, "KW": {29.3, 47.5}, "JO": {30.6, 36.2},
	"LB": {33.9, 35.9}, "CY": {35.1, 33.4}, "MT": {35.9, 14.4}, "SI": {46.15, 15.0},
	"AL": {41.2, 20.2}, "GE": {42.3, 43.4}, "AM": {40.1, 45.0}, "AZ": {40.1, 47.6},
	"UZ": {41.4, 64.6}, "LK": {7.9, 80.8}, "NP": {28.4, 84.1}, "MM": {21.9, 95.96},
	"KH": {12.6, 104.99}, "LA": {19.9, 102.5}, "MN": {46.9, 103.8}, "UY": {-32.5, -55.8},
	"PY": {-23.4, -58.4}, "BO": {-16.3, -63.6}, "EC": {-1.8, -78.2}, "VE": {6.4, -66.6},
	"CR": {9.7, -83.8}, "PA": {8.5, -80.8}, "GT": {15.8, -90.2}, "DO": {18.7, -70.2},
	"CU": {21.5, -77.8}, "JM": {18.1, -77.3}, "TT": {10.7, -61.2}, "PR": {18.2, -66.6},
	"GH": {7.9, -1.0}, "CI": {7.5, -5.5}, "SN": {14.5, -14.5}, "TZ": {-6.4, 34.9},
	"UG": {1.4, 32.3}, "ET": {9.1, 40.5}, "ZW": {-19.0, 29.2}, "ZM": {-13.1, 27.8},
	"AO": {-11.2, 17.9}, "DZ": {28.0, 1.7}, "TN": {33.9, 9.6}, "LY": {26.3, 17.2},
}

// CountryName maps an ISO code to a display name for the UI, falling back to
// the code itself so an unknown country still renders.
func CountryName(code string) string {
	if n, ok := countryNames[strings.ToUpper(code)]; ok {
		return n
	}
	return code
}

var countryNames = map[string]string{
	"US": "United States", "CA": "Canada", "MX": "Mexico", "BR": "Brazil", "AR": "Argentina",
	"GB": "United Kingdom", "IE": "Ireland", "FR": "France", "DE": "Germany", "NL": "Netherlands",
	"BE": "Belgium", "ES": "Spain", "PT": "Portugal", "IT": "Italy", "CH": "Switzerland",
	"AT": "Austria", "SE": "Sweden", "NO": "Norway", "FI": "Finland", "DK": "Denmark",
	"PL": "Poland", "CZ": "Czechia", "RO": "Romania", "UA": "Ukraine", "RU": "Russia",
	"TR": "Türkiye", "GR": "Greece", "IL": "Israel", "AE": "United Arab Emirates",
	"SA": "Saudi Arabia", "IN": "India", "CN": "China", "JP": "Japan", "KR": "South Korea",
	"TW": "Taiwan", "HK": "Hong Kong", "SG": "Singapore", "MY": "Malaysia", "TH": "Thailand",
	"VN": "Vietnam", "ID": "Indonesia", "PH": "Philippines", "AU": "Australia",
	"NZ": "New Zealand", "ZA": "South Africa", "NG": "Nigeria", "EG": "Egypt", "KE": "Kenya",
}
