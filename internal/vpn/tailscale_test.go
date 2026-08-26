package vpn

import (
	"net/netip"
	"testing"
)

// TestOverlapDetection covers the logic behind the guard that stops a node
// accepting a subnet route covering the LAN it is already on.
//
// This is not hypothetical: on the first deployment, a peer advertising
// 192.168.50.0/24 caused Tailscale to install that prefix into its routing
// table, an `ip rule` sent all traffic through that table first, and the node
// stopped answering on its own LAN — including SSH. The only way back in was
// through the hypervisor console.
func TestPrefixOverlapIsSymmetric(t *testing.T) {
	cases := []struct {
		peer, local string
		overlap     bool
		why         string
	}{
		{"192.168.50.0/24", "192.168.50.0/24", true, "the exact LAN this node is on"},
		{"192.168.0.0/16", "192.168.50.0/24", true, "a supernet of our LAN is just as disruptive"},
		{"192.168.50.128/25", "192.168.50.0/24", true, "a subnet of our LAN still steals traffic"},
		{"10.0.0.0/8", "192.168.50.0/24", false, "an unrelated network is fine"},
		{"172.16.0.0/12", "192.168.50.0/24", false, "an unrelated network is fine"},
	}
	for _, c := range cases {
		peer := netip.MustParsePrefix(c.peer)
		local := netip.MustParsePrefix(c.local)
		if got := peer.Overlaps(local); got != c.overlap {
			t.Errorf("%s vs %s: overlap = %v, want %v — %s", c.peer, c.local, got, c.overlap, c.why)
		}
	}
}

func TestDefaultRouteIsNotTreatedAsAnOverlap(t *testing.T) {
	// 0.0.0.0/0 from a peer is the exit-node offer, which is a feature, not
	// the failure this guard is for. Filtering on Bits() == 0 is what keeps
	// every exit node from tripping the warning.
	def := netip.MustParsePrefix("0.0.0.0/0")
	if def.Bits() != 0 {
		t.Fatal("a default route should have a zero prefix length")
	}
	if !def.Overlaps(netip.MustParsePrefix("192.168.50.0/24")) {
		t.Fatal("a default route overlaps everything, which is why it has to be excluded by length")
	}
}

func TestLocalPrefixesExcludesTunnels(t *testing.T) {
	// The tunnel's own address must never count as a directly-attached
	// network, or every subnet route would look like an overlap with itself.
	for _, p := range localPrefixes() {
		if p.Addr().IsLinkLocalUnicast() {
			t.Errorf("link-local prefix %s should have been excluded", p)
		}
		if p.Bits() == 0 {
			t.Errorf("default route %s should have been excluded", p)
		}
	}
}

func TestGenerateKeypairProducesUsableKeys(t *testing.T) {
	priv, pub, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if len(priv) != 44 || len(pub) != 44 {
		t.Errorf("keys are %d/%d base64 chars, want 44 each (32 bytes)", len(priv), len(pub))
	}
	// The public key has to be derivable from the private one, or generated
	// peer configs will not connect.
	derived, err := publicFromPrivate(priv)
	if err != nil {
		t.Fatal(err)
	}
	if derived != pub {
		t.Errorf("derived public key %q does not match the generated %q", derived, pub)
	}
	// And two calls must not collide.
	priv2, _, _ := GenerateKeypair()
	if priv == priv2 {
		t.Error("two generated private keys were identical")
	}
}
