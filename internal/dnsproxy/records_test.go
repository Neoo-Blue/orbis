package dnsproxy

import (
	"testing"

	"github.com/miekg/dns"
)

func TestLocalRecordAnswersByType(t *testing.T) {
	rs := BuildRecordSet([]LocalRecord{
		{Name: "nas.home", Type: "A", Value: "192.168.50.100"},
		{Name: "nas.home", Type: "AAAA", Value: "fd00::100"},
	})
	a := rs.Lookup("nas.home.", dns.TypeA)
	if len(a) != 1 {
		t.Fatalf("want 1 A record, got %d", len(a))
	}
	if a[0].(*dns.A).A.String() != "192.168.50.100" {
		t.Fatalf("wrong A: %v", a[0])
	}
	aaaa := rs.Lookup("nas.home.", dns.TypeAAAA)
	if len(aaaa) != 1 || aaaa[0].(*dns.AAAA).AAAA.String() != "fd00::100" {
		t.Fatalf("wrong AAAA: %v", aaaa)
	}
	// An A query must not return the AAAA and vice versa.
	if len(rs.Lookup("nas.home.", dns.TypeMX)) != 0 {
		t.Fatal("no MX exists for this name")
	}
}

func TestCNAMEShadowsOtherTypes(t *testing.T) {
	// A CNAME is returned for any query type; the client re-queries the target.
	rs := BuildRecordSet([]LocalRecord{{Name: "www.home", Type: "CNAME", Value: "nas.home"}})
	for _, qt := range []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeMX} {
		got := rs.Lookup("www.home.", qt)
		if len(got) != 1 {
			t.Fatalf("CNAME should answer %s, got %d", dns.TypeToString[qt], len(got))
		}
		if _, ok := got[0].(*dns.CNAME); !ok {
			t.Fatalf("expected CNAME, got %T", got[0])
		}
	}
}

func TestWildcardMatchesSubdomains(t *testing.T) {
	rs := BuildRecordSet([]LocalRecord{{Name: "*.lab", Type: "A", Value: "10.0.0.1"}})
	if len(rs.Lookup("anything.lab.", dns.TypeA)) != 1 {
		t.Fatal("wildcard should match a subdomain")
	}
	if len(rs.Lookup("deep.nested.lab.", dns.TypeA)) != 1 {
		t.Fatal("wildcard should match a deep subdomain")
	}
	if len(rs.Lookup("lab.", dns.TypeA)) != 1 {
		t.Fatal("wildcard base should match the bare name too")
	}
	if len(rs.Lookup("other.net.", dns.TypeA)) != 0 {
		t.Fatal("wildcard must not match an unrelated name")
	}
}

func TestExactBeatsWildcard(t *testing.T) {
	rs := BuildRecordSet([]LocalRecord{
		{Name: "*.lab", Type: "A", Value: "10.0.0.1"},
		{Name: "special.lab", Type: "A", Value: "10.0.0.99"},
	})
	got := rs.Lookup("special.lab.", dns.TypeA)
	if len(got) != 1 || got[0].(*dns.A).A.String() != "10.0.0.99" {
		t.Fatalf("exact record should win over wildcard, got %v", got)
	}
}

func TestMXAndSRVCarryNumericFields(t *testing.T) {
	rs := BuildRecordSet([]LocalRecord{
		{Name: "home", Type: "MX", Value: "mail.home", Priority: 10},
		{Name: "_sip._tcp.home", Type: "SRV", Value: "sip.home", Priority: 5, Weight: 20, Port: 5060},
	})
	mx := rs.Lookup("home.", dns.TypeMX)
	if len(mx) != 1 || mx[0].(*dns.MX).Preference != 10 {
		t.Fatalf("MX preference lost: %v", mx)
	}
	srv := rs.Lookup("_sip._tcp.home.", dns.TypeSRV)
	if len(srv) != 1 {
		t.Fatal("SRV not found")
	}
	r := srv[0].(*dns.SRV)
	if r.Priority != 5 || r.Weight != 20 || r.Port != 5060 {
		t.Fatalf("SRV fields lost: %+v", r)
	}
}

func TestValidateRejectsBadRecords(t *testing.T) {
	if ValidateRecord(LocalRecord{Name: "x", Type: "A", Value: "not-an-ip"}) == "" {
		t.Error("a non-address A record must be rejected")
	}
	if ValidateRecord(LocalRecord{Name: "x", Type: "AAAA", Value: "1.2.3.4"}) == "" {
		t.Error("a v4 address in an AAAA record must be rejected")
	}
	if ValidateRecord(LocalRecord{Name: "x", Type: "SRV", Value: "t", Port: 0}) == "" {
		t.Error("an SRV record with no port must be rejected")
	}
	if ValidateRecord(LocalRecord{Name: "x", Type: "WEIRD", Value: "y"}) == "" {
		t.Error("an unsupported type must be rejected")
	}
	if ValidateRecord(LocalRecord{Name: "x", Type: "A", Value: "192.168.1.1"}) != "" {
		t.Error("a valid A record must pass")
	}
}

func TestLongTXTIsChunked(t *testing.T) {
	long := ""
	for i := 0; i < 600; i++ {
		long += "a"
	}
	rs := BuildRecordSet([]LocalRecord{{Name: "k.home", Type: "TXT", Value: long}})
	got := rs.Lookup("k.home.", dns.TypeTXT)
	if len(got) != 1 {
		t.Fatal("TXT not found")
	}
	txt := got[0].(*dns.TXT).Txt
	if len(txt) < 3 {
		t.Fatalf("a 600-byte TXT must split into 255-byte chunks, got %d chunk(s)", len(txt))
	}
	for _, seg := range txt {
		if len(seg) > 255 {
			t.Fatalf("a TXT chunk exceeded 255 bytes: %d", len(seg))
		}
	}
}
