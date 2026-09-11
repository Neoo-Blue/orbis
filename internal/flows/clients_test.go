package flows

import (
	"net/netip"
	"path/filepath"
	"testing"

	"github.com/Neoo-Blue/orbis/internal/store"
)

// A device that takes a new DHCP lease keeps its identity, and whoever needs
// to follow it (interception) hears about the move.
func TestRegistryReportsAddressMoves(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	r := NewClientRegistry(st, nil)

	type move struct {
		mac      string
		from, to netip.Addr
	}
	var moves []move
	r.SetOnMove(func(mac string, from, to netip.Addr) { moves = append(moves, move{mac, from, to}) })

	old := netip.MustParseAddr("192.168.50.31")
	now := netip.MustParseAddr("192.168.50.43")
	first := r.Observe(old, "5C:B2:6D:06:6D:64", "")
	if len(moves) != 0 {
		t.Fatalf("a new device is not a move, got %v", moves)
	}
	r.Observe(old, "5c:b2:6d:06:6d:64", "")
	if len(moves) != 0 {
		t.Fatalf("the same address again is not a move, got %v", moves)
	}
	second := r.Observe(now, "5c:b2:6d:06:6d:64", "")
	if len(moves) != 1 || moves[0].from != old || moves[0].to != now || moves[0].mac != "5c:b2:6d:06:6d:64" {
		t.Fatalf("moves = %v, want one .31 -> .43", moves)
	}
	if first.ID != second.ID {
		t.Fatal("a device keeps its id across an address change")
	}
	if c := r.ByMAC("5C:B2:6D:06:6D:64"); c == nil || c.IP != now.String() {
		t.Fatalf("ByMAC = %+v, want the device at %s", c, now)
	}
	if c := r.ByIP(old); c != nil {
		t.Fatalf("the old address should no longer map to the device, got %+v", c)
	}

	// A device known only by address has no identity to follow.
	r.Observe(netip.MustParseAddr("192.168.50.60"), "", "")
	r.Observe(netip.MustParseAddr("192.168.50.61"), "", "")
	if len(moves) != 1 {
		t.Fatalf("MAC-less observations are not moves, got %v", moves)
	}
}
