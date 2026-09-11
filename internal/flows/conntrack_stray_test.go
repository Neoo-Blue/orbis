package flows

import (
	"net/netip"
	"testing"
	"time"
)

// Only one-way connections from a local device to the internet are strays: a
// device sending through this node while its replies go around it.
func TestConntrackReportsOneWayLANConnections(t *testing.T) {
	tr, _ := newTestTracker(t)
	p := NewConntrackPoller(tr, time.Second, nil)
	var got []netip.Addr
	p.SetStrayHook(func(src netip.Addr) { got = append(got, src) })

	ip := netip.MustParseAddr
	p.reportStrays([]CTEntry{
		{Proto: 17, SrcIP: ip("192.168.1.24"), DstIP: ip("208.54.5.195"), DstPort: 4500, Unreplied: true},
		{Proto: 6, SrcIP: ip("192.168.1.24"), DstIP: ip("52.48.87.174"), DstPort: 443, Unreplied: true}, // same device once
		{Proto: 6, SrcIP: ip("192.168.1.43"), DstIP: ip("52.48.87.174"), DstPort: 443},                  // replies seen: NATed or ours
		{Proto: 6, SrcIP: ip("45.33.32.156"), DstIP: ip("192.168.1.75"), DstPort: 22, Unreplied: true},  // inbound probe
		{Proto: 17, SrcIP: ip("192.168.1.30"), DstIP: ip("192.168.1.1"), DstPort: 53, Unreplied: true},  // stays on the LAN
	})
	if len(got) != 1 || got[0] != ip("192.168.1.24") {
		t.Fatalf("strays = %v, want only 192.168.1.24 once", got)
	}
}

func TestProcConntrackLineMarksUnreplied(t *testing.T) {
	line := "ipv4     2 udp      17 27 src=192.168.1.24 dst=208.54.5.195 sport=49754 dport=4500 [UNREPLIED] " +
		"src=208.54.5.195 dst=192.168.1.24 sport=4500 dport=49754 mark=0 zone=0 use=2"
	e, _, ok := parseConntrackLine(line)
	if !ok || !e.Unreplied {
		t.Fatalf("parsed %+v ok=%v, want an unreplied entry", e, ok)
	}
	line = "ipv4     2 tcp      6 431999 ESTABLISHED src=192.168.1.43 dst=52.48.87.174 sport=4417 dport=443 " +
		"src=52.48.87.174 dst=192.168.1.75 sport=443 dport=4417 [ASSURED] mark=0 zone=0 use=2"
	e, _, ok = parseConntrackLine(line)
	if !ok || e.Unreplied {
		t.Fatalf("parsed %+v ok=%v, want a replied entry", e, ok)
	}
}
