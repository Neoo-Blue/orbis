package geoip

import (
	"net/netip"
	"testing"
)

// TestIsPrivateCoversBogons pins the gate that decides whether a destination
// gets a position on the map. An address that is not globally routable must
// never be placed: an arc from the local network to a random continent is
// worse than drawing nothing.
func TestIsPrivateCoversBogons(t *testing.T) {
	private := []string{
		"0.0.0.0", "0.1.2.3",
		"10.0.0.1", "172.16.5.5", "172.31.255.254", "192.168.1.1",
		"100.64.0.1", "100.127.255.255", // CGNAT
		"127.0.0.1", "169.254.1.1",
		"192.0.2.1", "198.51.100.1", "203.0.113.1", // documentation ranges
		"198.18.0.1",                     // benchmarking
		"224.0.0.251", "239.255.255.250", // multicast
		"240.0.0.1", "255.255.255.255", // reserved and broadcast
		"::", "::1", "fe80::1", "fc00::1", "fd00::abcd", "ff02::fb",
		"2001:db8::1",        // documentation
		"::ffff:192.168.1.1", // v4-mapped private, the classic bypass
	}
	for _, ip := range private {
		if !IsPrivate(netip.MustParseAddr(ip)) {
			t.Errorf("%s should be treated as local", ip)
		}
	}

	public := []string{
		"8.8.8.8", "1.1.1.1", "142.250.72.14", "172.15.0.1", "172.32.0.1",
		"100.63.255.255", "100.128.0.1", // just outside CGNAT
		"9.9.9.9", "2606:4700::1111", "2001:4860:4860::8888",
	}
	for _, ip := range public {
		if IsPrivate(netip.MustParseAddr(ip)) {
			t.Errorf("%s should be treated as globally routable", ip)
		}
	}
}

func TestLookupNeverPlacesLocalAddresses(t *testing.T) {
	r := New()
	for _, ip := range []string{"192.168.1.50", "255.255.255.255", "224.0.0.251", "fe80::1", "10.0.0.1"} {
		loc := r.Lookup(ip)
		if !loc.Private {
			t.Errorf("%s was not marked private", ip)
		}
		if loc.Lat != 0 || loc.Lon != 0 || loc.Country != "" {
			t.Errorf("%s was given a position: %+v", ip, loc)
		}
	}
}

func TestWellKnownNames(t *testing.T) {
	cases := map[string]string{
		"224.0.0.251":     "mDNS (Bonjour)",
		"ff02::fb":        "mDNS (Bonjour)",
		"239.255.255.250": "SSDP (UPnP discovery)",
		"255.255.255.255": "broadcast",
		"8.8.8.8":         "",
	}
	for ip, want := range cases {
		if got := WellKnownName(ip); got != want {
			t.Errorf("WellKnownName(%s) = %q, want %q", ip, got, want)
		}
	}
	// Anything multicast should at least get a generic label rather than a
	// bare address in the connection log.
	if WellKnownName("232.1.2.3") == "" {
		t.Error("an unlisted multicast group got no label at all")
	}
}

func TestFallbackKeepsTheGlobePopulated(t *testing.T) {
	// With no database installed, a public address still has to land
	// somewhere plausible, flagged as an estimate.
	r := New()
	loc := r.Lookup("8.8.8.8")
	if loc.Lat == 0 && loc.Lon == 0 {
		t.Error("a public address with no database got no position at all")
	}
	if loc.Accuracy != "region" {
		t.Errorf("accuracy = %q, want region so the UI can label it an estimate", loc.Accuracy)
	}
}
