package threat

import (
	"net/netip"
	"strings"
	"testing"
)

func TestParseFeedFormats(t *testing.T) {
	in := `# Spamhaus DROP List
; comment style two
1.2.3.0/24 ; SBL123
5.6.7.8
2001:db8::/32
2a06:e480::/29 ; SBLv6
10.0.0.0/8
0.0.0.0/8
224.0.0.0/3
192.168.1.5
1.2.3.0/24
not-an-address
9.9.9.9 extra fields here
`
	got, skipped := ParseFeed(strings.NewReader(in))
	want := []string{"1.2.3.0/24", "5.6.7.8/32", "2a06:e480::/29", "9.9.9.9/32"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i, p := range got {
		if p.String() != want[i] {
			t.Errorf("entry %d = %s, want %s", i, p, want[i])
		}
	}
	// 2001:db8 (documentation), 10/8, 0/8, 224/3, 192.168.1.5, not-an-address.
	if skipped != 6 {
		t.Errorf("skipped = %d, want 6", skipped)
	}
}

func TestUsableRefusesTheWholeInternet(t *testing.T) {
	for _, s := range []string{"0.0.0.0/0", "1.0.0.0/7", "::/0", "2000::/8", "100.64.0.1", "127.0.0.1", "fe80::1", "fd00::1"} {
		p, _ := ParsePrefix(s)
		if Usable(p) {
			t.Errorf("%s should not be enforceable", s)
		}
	}
	for _, s := range []string{"8.8.8.8", "1.2.3.0/24", "2a06:e480::/29", "203.0.112.0/24"} {
		p, _ := ParsePrefix(s)
		if !Usable(p) {
			t.Errorf("%s should be enforceable", s)
		}
	}
}

func TestTableLookupAndAllow(t *testing.T) {
	entries := []Entry{
		{Prefix: netip.MustParsePrefix("1.2.3.0/24"), Source: "drop", Reason: "hijacked"},
		{Prefix: netip.MustParsePrefix("5.6.7.8/32"), Source: "feodo", Reason: "c2"},
		{Prefix: netip.MustParsePrefix("9.0.0.0/8"), Source: "wide"},
		{Prefix: netip.MustParsePrefix("2a06:e480::/29"), Source: "dropv6"},
		{Prefix: netip.MustParsePrefix("2a06:e480::1/128"), Source: "dup-host"},
		{Prefix: netip.MustParsePrefix("20.30.0.0/16"), Source: "allowed-away"},
	}
	allow := []netip.Prefix{netip.MustParsePrefix("20.30.40.50/32")}
	tab, excluded := Build(entries, allow)
	if excluded != 1 {
		t.Errorf("excluded = %d, want 1 (the /16 overlapping an allowed host)", excluded)
	}
	if tab.Len() != 5 {
		t.Errorf("len = %d, want 5", tab.Len())
	}
	cases := map[string]string{
		"1.2.3.77":        "drop",
		"5.6.7.8":         "feodo",
		"9.200.1.1":       "wide",
		"2a06:e480::abcd": "dropv6",
		"2a06:e480::1":    "dup-host",
	}
	for ip, src := range cases {
		e, ok := tab.Lookup(netip.MustParseAddr(ip))
		if !ok || e.Source != src {
			t.Errorf("%s -> %v %q, want %q", ip, ok, e.Source, src)
		}
	}
	for _, ip := range []string{"1.2.4.1", "20.30.40.50", "20.30.1.1", "8.8.8.8", "2a06:e470::1"} {
		if _, ok := tab.Lookup(netip.MustParseAddr(ip)); ok {
			t.Errorf("%s should not be listed", ip)
		}
	}
	v4, v6 := tab.Elements()
	if len(v4) != 3 || len(v6) != 2 {
		t.Errorf("elements = %d v4, %d v6; want 3 and 2: %v %v", len(v4), len(v6), v4, v6)
	}
	if v4[0] != "1.2.3.0/24" || v4[1] != "5.6.7.8" {
		t.Errorf("elements should be sorted with hosts as bare addresses: %v", v4)
	}
	var nilTable *Table
	if _, ok := nilTable.Lookup(netip.MustParseAddr("1.2.3.4")); ok {
		t.Error("a nil table must answer not listed")
	}
}
