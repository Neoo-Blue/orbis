package config

import "testing"

func BenchmarkSnapshot(b *testing.B) {
	c := Default()
	for i := 0; i < 55; i++ {
		c.AdBlock.Lists = append(c.AdBlock.Lists, BlockList{Name: "list", URL: "https://example.com/list.txt", Enabled: true, Category: "ads"})
	}
	for i := 0; i < 40; i++ {
		c.DNS.Records = append(c.DNS.Records, DNSRecord{Type: "A", Name: "host.lan", Value: "192.168.1.1"})
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = c.Snapshot()
	}
}
