package lifeboat

import (
	"net/netip"
	"testing"
	"time"

	"github.com/Neoo-Blue/orbis/internal/config"
)

func TestBroadcastAndSubnet(t *testing.T) {
	p := netip.MustParsePrefix("192.168.50.0/24")
	bc, ok := broadcast(p)
	if !ok || bc.String() != "192.168.50.255" {
		t.Errorf("broadcast: %v %v", bc, ok)
	}
	scope := config.DHCPScope{Subnet: "192.168.50.0/24"}
	if !inSubnet(scope, netip.MustParseAddr("192.168.50.7")) || inSubnet(scope, netip.MustParseAddr("10.0.0.1")) {
		t.Errorf("inSubnet wrong")
	}
}

func TestLeasesKeepTheirAddress(t *testing.T) {
	l := &Lifeboat{leases: map[string]lease{}, byIP: map[netip.Addr]string{}, log: func(string, ...any) {}}
	a := netip.MustParseAddr("192.168.50.40")
	l.grant("aa:bb", a)
	if l.takenByOther(a, "aa:bb") {
		t.Errorf("a device's own lease is not taken by another")
	}
	if !l.takenByOther(a, "cc:dd") {
		t.Errorf("another device must not get the same address")
	}
	l.leases["aa:bb"] = lease{ip: a, expires: time.Now().Add(-time.Minute)}
	if l.takenByOther(a, "cc:dd") {
		t.Errorf("an expired lease frees the address")
	}
}

func TestReservedAddresses(t *testing.T) {
	l := &Lifeboat{leases: map[string]lease{}, byIP: map[netip.Addr]string{}, log: func(string, ...any) {}}
	scope := config.DHCPScope{Subnet: "192.168.50.0/24", Gateway: "192.168.50.1", Interface: "nonexistent0"}
	for _, ip := range []string{"192.168.50.1", "192.168.50.0", "192.168.50.255"} {
		if !l.reserved(scope, netip.MustParseAddr(ip)) {
			t.Errorf("%s should be reserved", ip)
		}
	}
	if l.reserved(scope, netip.MustParseAddr("192.168.50.20")) {
		t.Errorf("an ordinary address is not reserved")
	}
}

func TestResolversFallBackToPublic(t *testing.T) {
	cfg := config.Default().Snapshot()
	l := &Lifeboat{cfg: cfg}
	ups, fb := l.resolvers()
	if len(fb) != 3 {
		t.Errorf("want three public fallbacks, got %d", len(fb))
	}
	_ = ups
}
