package ai

import "testing"

func TestHitsForKeepsOnlyThatAddress(t *testing.T) {
	rows := []map[string]any{
		{"remote_ip": "172.111.139.145", "local_ip": "192.168.50.111"},
		{"remote_ip": "35.186.224.24", "local_ip": "192.168.50.163"},
		{"remote_ip": "1.2.3.4", "local_ip": "192.168.50.163"},
	}
	if got := hitsFor(rows, "35.186.224.24"); len(got) != 1 || got[0]["local_ip"] != "192.168.50.163" {
		t.Fatalf("remote match: %v", got)
	}
	if got := hitsFor(rows, "192.168.50.163"); len(got) != 2 {
		t.Fatalf("local match: %v", got)
	}
	if got := hitsFor(rows, "9.9.9.9"); len(got) != 0 {
		t.Fatalf("no match: %v", got)
	}
	if got := hitsFor(nil, "9.9.9.9"); got != nil {
		t.Fatalf("nil rows: %v", got)
	}
}
