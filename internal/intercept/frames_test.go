package intercept

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"
)

// The restore frames must never carry the router's MAC as their Ethernet
// source (switches would learn the router on this node's port), must reach
// only the device, and must tell it the router's real MAC for the gateway.
func TestTruthFramesKeepOurSourceMAC(t *testing.T) {
	dev := Target{IP: netip.MustParseAddr("192.168.50.43"), MAC: mustMAC(laptop)}
	frames := truthFrames(selfMAC, gwMAC, gw, dev)
	if len(frames) != 2 {
		t.Fatalf("got %d frames, want a reply and an announcement", len(frames))
	}
	for i, f := range frames {
		if len(f) != 42 {
			t.Fatalf("frame %d is %d bytes", i, len(f))
		}
		if !bytes.Equal(f[0:6], dev.MAC) {
			t.Errorf("frame %d Ethernet destination %x, want the device only", i, f[0:6])
		}
		if !bytes.Equal(f[6:12], selfMAC) {
			t.Errorf("frame %d Ethernet source %x, want this node's MAC, never the router's", i, f[6:12])
		}
		if binary.BigEndian.Uint16(f[12:14]) != etherTypeARP {
			t.Errorf("frame %d is not ARP", i)
		}
		p := f[14:]
		if !bytes.Equal(p[8:14], gwMAC) {
			t.Errorf("frame %d ARP sender MAC %x, want the router's", i, p[8:14])
		}
		if netip.AddrFrom4([4]byte(p[14:18])) != gw {
			t.Errorf("frame %d ARP sender IP is not the gateway", i)
		}
	}
	reply, announce := frames[0][14:], frames[1][14:]
	if binary.BigEndian.Uint16(reply[6:8]) != arpOpReply || netip.AddrFrom4([4]byte(reply[24:28])) != dev.IP {
		t.Error("the reply must be addressed to the device's current address")
	}
	if binary.BigEndian.Uint16(announce[6:8]) != arpOpRequest || netip.AddrFrom4([4]byte(announce[24:28])) != gw ||
		!bytes.Equal(announce[18:24], make([]byte, 6)) {
		t.Error("the announcement must be a gratuitous request for the gateway")
	}
}
