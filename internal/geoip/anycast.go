package geoip

import "net/netip"

// Anycast correction.
//
// A GeoIP database answers the question "where is this prefix registered",
// which for anycast is not the same question as "where is the machine". The
// worst offender is 1.1.1.1: the prefix belongs to APNIC, whose registered
// address is in Australia, so every database places Cloudflare's resolver in
// Sydney or Brisbane. It is served from hundreds of sites worldwide and the
// one answering you is a few milliseconds away.
//
// This matters more than a wrong label. A node using 1.1.1.1 as its upstream
// resolver opens tens of thousands of connections to it, so the mistake makes
// Australia the busiest country on the globe by an order of magnitude and
// buries everything real. Correcting it is the difference between a map that
// informs and one that misleads.
//
// The location used is the operator's primary region, not the registry's. That
// is still an approximation, and the Anycast flag says so, but it is an
// approximation that points at the right continent.

// anycastEntry describes a well-known anycast service.
type anycastEntry struct {
	Prefix  netip.Prefix
	Org     string
	Country string
	City    string
	Lat     float64
	Lon     float64
}

// anycastRanges covers the public resolvers and a few well-known anycast
// services that dominate a home network's connection log. It is deliberately
// a short curated list rather than an attempt at every anycast prefix on the
// internet: these are the ones that actually distort a household's map.
var anycastRanges = []anycastEntry{
	// Cloudflare public DNS. Registered to APNIC in Australia, operated from
	// San Francisco, served from everywhere.
	{netip.MustParsePrefix("1.1.1.0/24"), "Cloudflare", "US", "Anycast (Cloudflare)", 37.7749, -122.4194},
	{netip.MustParsePrefix("1.0.0.0/24"), "Cloudflare", "US", "Anycast (Cloudflare)", 37.7749, -122.4194},
	{netip.MustParsePrefix("2606:4700:4700::/48"), "Cloudflare", "US", "Anycast (Cloudflare)", 37.7749, -122.4194},

	// Google Public DNS.
	{netip.MustParsePrefix("8.8.8.0/24"), "Google", "US", "Anycast (Google DNS)", 37.4220, -122.0841},
	{netip.MustParsePrefix("8.8.4.0/24"), "Google", "US", "Anycast (Google DNS)", 37.4220, -122.0841},
	{netip.MustParsePrefix("2001:4860:4860::/48"), "Google", "US", "Anycast (Google DNS)", 37.4220, -122.0841},

	// Quad9.
	{netip.MustParsePrefix("9.9.9.0/24"), "Quad9", "CH", "Anycast (Quad9)", 47.3769, 8.5417},
	{netip.MustParsePrefix("149.112.112.0/24"), "Quad9", "CH", "Anycast (Quad9)", 47.3769, 8.5417},
	{netip.MustParsePrefix("2620:fe::/48"), "Quad9", "CH", "Anycast (Quad9)", 47.3769, 8.5417},

	// OpenDNS / Cisco Umbrella.
	{netip.MustParsePrefix("208.67.222.0/24"), "OpenDNS", "US", "Anycast (OpenDNS)", 37.7749, -122.4194},
	{netip.MustParsePrefix("208.67.220.0/24"), "OpenDNS", "US", "Anycast (OpenDNS)", 37.7749, -122.4194},

	// AdGuard DNS.
	{netip.MustParsePrefix("94.140.14.0/24"), "AdGuard", "CY", "Anycast (AdGuard)", 34.6857, 33.0353},
	{netip.MustParsePrefix("94.140.15.0/24"), "AdGuard", "CY", "Anycast (AdGuard)", 34.6857, 33.0353},

	// NextDNS.
	{netip.MustParsePrefix("45.90.28.0/24"), "NextDNS", "US", "Anycast (NextDNS)", 37.7749, -122.4194},
	{netip.MustParsePrefix("45.90.30.0/24"), "NextDNS", "US", "Anycast (NextDNS)", 37.7749, -122.4194},

	// ControlD.
	{netip.MustParsePrefix("76.76.2.0/24"), "ControlD", "CA", "Anycast (ControlD)", 43.6532, -79.3832},
	{netip.MustParsePrefix("76.76.10.0/24"), "ControlD", "CA", "Anycast (ControlD)", 43.6532, -79.3832},

	// Level3 / Lumen legacy resolvers, still widely hardcoded in devices.
	{netip.MustParsePrefix("4.2.2.0/24"), "Lumen", "US", "Anycast (Level3 DNS)", 39.7392, -104.9903},

	// CleanBrowsing.
	{netip.MustParsePrefix("185.228.168.0/24"), "CleanBrowsing", "US", "Anycast (CleanBrowsing)", 37.7749, -122.4194},
	{netip.MustParsePrefix("185.228.169.0/24"), "CleanBrowsing", "US", "Anycast (CleanBrowsing)", 37.7749, -122.4194},

	// Mullvad DNS.
	{netip.MustParsePrefix("194.242.2.0/24"), "Mullvad", "SE", "Anycast (Mullvad DNS)", 55.6050, 13.0038},
}

// LookupAnycast returns a corrected location for a known anycast address.
//
// It is checked before the database, not after, because the database always
// has an answer for these and that answer is always the registry's country.
func LookupAnycast(addr netip.Addr) (Location, bool) {
	addr = addr.Unmap()
	for _, e := range anycastRanges {
		if e.Prefix.Contains(addr) {
			return Location{
				Country:     e.Country,
				CountryName: CountryName(e.Country),
				City:        e.City,
				Lat:         e.Lat,
				Lon:         e.Lon,
				ASOrg:       e.Org,
				Accuracy:    "anycast",
				Anycast:     true,
			}, true
		}
	}
	return Location{}, false
}

// IsAnycast reports whether an address string is a known anycast service.
func IsAnycast(ipStr string) bool {
	addr, err := netip.ParseAddr(ipStr)
	if err != nil {
		return false
	}
	_, ok := LookupAnycast(addr)
	return ok
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
