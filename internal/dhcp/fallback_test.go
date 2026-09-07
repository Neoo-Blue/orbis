package dhcp

import (
	"testing"

	"github.com/Neoo-Blue/orbis/internal/config"
)

func TestFallbackDNS(t *testing.T) {
	cfg := config.Default().Snapshot()
	cfg.DNS.Upstreams = []string{"tls://9.9.9.9:853", "https://cloudflare-dns.com/dns-query"}
	cfg.Safety.FallbackDNS = "auto"
	if ip := FallbackDNS(cfg); ip == nil || ip.String() != "9.9.9.9" {
		t.Errorf("auto should pick the first public upstream address, got %v", ip)
	}
	cfg.DNS.Upstreams = []string{"https://dns.example/dns-query"}
	if ip := FallbackDNS(cfg); ip == nil || ip.String() != "1.1.1.1" {
		t.Errorf("no addressable upstream should fall back to 1.1.1.1, got %v", ip)
	}
	cfg.DNS.Upstreams = []string{"192.168.1.1:53"}
	if ip := FallbackDNS(cfg); ip == nil || ip.String() != "1.1.1.1" {
		t.Errorf("a private upstream is not a fallback the internet can answer from, got %v", ip)
	}
	cfg.Safety.FallbackDNS = "none"
	if ip := FallbackDNS(cfg); ip != nil {
		t.Errorf("none should hand out nothing, got %v", ip)
	}
	cfg.Safety.FallbackDNS = "8.8.4.4"
	if ip := FallbackDNS(cfg); ip == nil || ip.String() != "8.8.4.4" {
		t.Errorf("an explicit address is used as given, got %v", ip)
	}
}
