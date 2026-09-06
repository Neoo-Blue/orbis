package country

import (
	"net/netip"
	"testing"
)

func TestAggregate(t *testing.T) {
	in := []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/25"), netip.MustParsePrefix("10.0.0.128/25"), // siblings -> /24
		netip.MustParsePrefix("10.0.1.0/24"),  // then /23 with the /24 above
		netip.MustParsePrefix("10.0.1.64/26"), // contained
		netip.MustParsePrefix("192.0.2.0/24"),
		netip.MustParsePrefix("192.0.3.0/24"), // sibling -> 192.0.2.0/23
		netip.MustParsePrefix("198.51.100.0/24"),
		netip.MustParsePrefix("198.51.101.0/25"), // not a full sibling; stays
	}
	out := Aggregate(in)
	want := []string{"10.0.0.0/23", "192.0.2.0/23", "198.51.100.0/24", "198.51.101.0/25"}
	if len(out) != len(want) {
		t.Fatalf("got %v, want %v", out, want)
	}
	for i, p := range out {
		if p.String() != want[i] {
			t.Errorf("entry %d = %s, want %s", i, p, want[i])
		}
	}
	for _, ip := range []string{"10.0.0.5", "10.0.1.200", "192.0.3.9", "198.51.101.3"} {
		a := netip.MustParseAddr(ip)
		hit := false
		for _, p := range out {
			if p.Contains(a) {
				hit = true
			}
		}
		if !hit {
			t.Errorf("%s lost during aggregation", ip)
		}
	}
	if len(Aggregate(nil)) != 0 {
		t.Error("empty in, empty out")
	}
}
