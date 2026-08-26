package geoip

import (
	"net/netip"
	"testing"
)

func TestAnycastResolversAreNotWhereTheyAreRegistered(t *testing.T) {
	// 1.1.1.1 is registered to APNIC in Australia and every GeoIP database
	// says Sydney or Brisbane. It is Cloudflare's, served from everywhere.
	// This was the single biggest distortion on the globe: as the node's own
	// DoT upstream it accounted for 20k flows, all drawn to Australia.
	cases := []struct {
		ip      string
		country string
		org     string
	}{
		{"1.1.1.1", "US", "Cloudflare"},
		{"1.0.0.1", "US", "Cloudflare"},
		{"1.1.1.2", "US", "Cloudflare"},
		{"8.8.8.8", "US", "Google"},
		{"8.8.4.4", "US", "Google"},
		{"9.9.9.9", "CH", "Quad9"},
		{"208.67.222.222", "US", "OpenDNS"},
		{"94.140.14.14", "CY", "AdGuard"},
	}
	for _, tc := range cases {
		loc, ok := LookupAnycast(netip.MustParseAddr(tc.ip))
		if !ok {
			t.Errorf("%s should be recognised as anycast", tc.ip)
			continue
		}
		if loc.Country != tc.country {
			t.Errorf("%s: country = %q, want %q", tc.ip, loc.Country, tc.country)
		}
		if loc.ASOrg != tc.org {
			t.Errorf("%s: org = %q, want %q", tc.ip, loc.ASOrg, tc.org)
		}
		if !loc.Anycast {
			t.Errorf("%s: Anycast flag should be set so the UI can say the location is approximate", tc.ip)
		}
		if loc.Lat == 0 && loc.Lon == 0 {
			t.Errorf("%s: needs real coordinates or the arc is culled as degenerate", tc.ip)
		}
	}
}

func TestOrdinaryAddressesAreNotTreatedAsAnycast(t *testing.T) {
	// Neighbours of the anycast prefixes must not be swept up: 1.1.2.1 is a
	// different /24 entirely and belongs to whoever the database says.
	for _, ip := range []string{"1.1.2.1", "8.8.9.9", "9.9.10.1", "142.250.72.14", "93.184.216.34"} {
		if _, ok := LookupAnycast(netip.MustParseAddr(ip)); ok {
			t.Errorf("%s must not be treated as anycast", ip)
		}
	}
}

func TestIsAnycastHandlesGarbage(t *testing.T) {
	if IsAnycast("not-an-ip") {
		t.Error("garbage input must not report as anycast")
	}
	if !IsAnycast("1.1.1.1") {
		t.Error("1.1.1.1 should report as anycast")
	}
}
