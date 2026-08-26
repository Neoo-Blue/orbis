package topology

import (
	"testing"
	"time"
)

func timeZero() time.Time { return time.Time{} }

func TestProxmoxGuestFromMAC(t *testing.T) {
	v := Classify(Signals{IP: "192.168.50.230", MAC: "bc:24:11:eb:92:08"})
	if !v.Virtual {
		t.Fatal("bc:24:11 is a Proxmox-minted MAC and must be flagged virtual")
	}
	if v.Platform != "Proxmox VE" {
		t.Fatalf("platform = %q, want Proxmox VE", v.Platform)
	}
	if v.Confidence != Inferred {
		t.Fatalf("a MAC prefix identifies the platform, not the guest; want inferred, got %q", v.Confidence)
	}
}

func TestHyperVGuestFromMAC(t *testing.T) {
	v := Classify(Signals{IP: "10.0.0.5", MAC: "00:15:5D:01:02:03"})
	if v.Platform != "Hyper-V" || !v.Virtual {
		t.Fatalf("00:15:5d is Microsoft's dynamic range, got %+v", v)
	}
}

func TestProxmoxHostFromOpenPort(t *testing.T) {
	// 8006 is only ever Proxmox, so an answer settles it outright.
	v := Classify(Signals{IP: "192.168.50.202", MAC: "58:47:ca:7d:25:ab",
		OpenPorts: []int{22, 8006}, Scanned: true})
	if v.Role != RoleHypervisor {
		t.Fatalf("role = %q, want hypervisor", v.Role)
	}
	if v.Confidence != Confirmed {
		t.Fatalf("an answering service is proof, want confirmed, got %q", v.Confidence)
	}
}

func TestGatewayBeatsEverything(t *testing.T) {
	v := Classify(Signals{IP: "192.168.50.1", MAC: "bc:24:11:00:00:01",
		OpenPorts: []int{8006}, Scanned: true, IsGateway: true})
	if v.Role != RoleGateway || v.Confidence != Confirmed {
		t.Fatalf("the default route is a fact, not an inference: %+v", v)
	}
}

func TestVirtualServerReportsAsServerNotVM(t *testing.T) {
	// A guest that answers on a service port is more usefully described by
	// what it does than by the fact it is virtual.
	v := Classify(Signals{IP: "192.168.50.203", MAC: "bc:24:11:79:bf:c6",
		OpenPorts: []int{22, 80}, Scanned: true})
	if v.Role == RoleVM {
		t.Fatal("a guest running services should be classified by its services")
	}
	if !v.Virtual {
		t.Fatal("it is still virtual, and the map should say so")
	}
}

func TestScannedButSilentIsRecorded(t *testing.T) {
	v := Classify(Signals{IP: "192.168.50.99", MAC: "aa:bb:cc:dd:ee:ff", Scanned: true})
	found := false
	for _, e := range v.Evidence {
		if e == "scanned, nothing listening on the probed ports" {
			found = true
		}
	}
	if !found {
		t.Fatal("a silent device is different from an unscanned one and must say so")
	}
}

func TestSingleHostAdoptsItsGuests(t *testing.T) {
	devices := []DeviceInput{
		{ID: "host", IP: "192.168.50.202", MAC: "58:47:ca:7d:25:ab"},
		{ID: "g1", IP: "192.168.50.203", MAC: "bc:24:11:79:bf:c6"},
		{ID: "g2", IP: "192.168.50.221", MAC: "bc:24:11:1e:6d:3e"},
	}
	ports := map[string][]int{"192.168.50.202": {8006}}
	g := Build(devices, nil, ports, "192.168.50.1", timeZero())

	parents := map[string]string{}
	for _, n := range g.Nodes {
		parents[n.ID] = n.ParentID
	}
	if parents["g1"] != "host" || parents["g2"] != "host" {
		t.Fatalf("guests should attach to the only Proxmox host: %+v", parents)
	}
	hosts := 0
	for _, e := range g.Edges {
		if e.Kind == "hosts" {
			hosts++
		}
	}
	if hosts != 2 {
		t.Fatalf("expected 2 hosting edges, got %d", hosts)
	}
}

func TestTwoHostsRefuseToGuess(t *testing.T) {
	// A guest's MAC says "Proxmox", not "which Proxmox". With two hosts the
	// honest output is no edge plus an explanation.
	devices := []DeviceInput{
		{ID: "h1", IP: "192.168.50.202", MAC: "58:47:ca:00:00:01"},
		{ID: "h2", IP: "192.168.50.204", MAC: "58:47:ca:00:00:02"},
		{ID: "g1", IP: "192.168.50.203", MAC: "bc:24:11:79:bf:c6"},
	}
	ports := map[string][]int{
		"192.168.50.202": {8006},
		"192.168.50.204": {8006},
	}
	g := Build(devices, nil, ports, "192.168.50.1", timeZero())
	for _, n := range g.Nodes {
		if n.ID == "g1" && n.ParentID != "" {
			t.Fatalf("must not pick a host arbitrarily, got parent %q", n.ParentID)
		}
	}
	if len(g.Notes) == 0 {
		t.Fatal("an unattributable guest must be explained, not silently orphaned")
	}
}

func TestTrafficSplitsByDirection(t *testing.T) {
	devices := []DeviceInput{
		{ID: "a", IP: "192.168.50.10"},
		{ID: "b", IP: "192.168.50.11"},
	}
	flows := []FlowInput{{SrcIP: "192.168.50.10", DstIP: "192.168.50.11", Bytes: 500, Conns: 2}}
	g := Build(devices, flows, nil, "192.168.50.1", timeZero())
	byID := map[string]Node{}
	for _, n := range g.Nodes {
		byID[n.ID] = n
	}
	if byID["a"].BytesOut != 500 || byID["a"].ConnsOut != 2 {
		t.Fatalf("source should count as outbound: %+v", byID["a"])
	}
	if byID["b"].BytesIn != 500 || byID["b"].ConnsIn != 2 {
		t.Fatalf("destination should count as inbound: %+v", byID["b"])
	}
}

func TestExternalFlowsMakeNoInternalEdge(t *testing.T) {
	devices := []DeviceInput{{ID: "a", IP: "192.168.50.10"}}
	flows := []FlowInput{{SrcIP: "192.168.50.10", DstIP: "1.1.1.1", Bytes: 100, Conns: 1, External: true}}
	g := Build(devices, flows, nil, "192.168.50.1", timeZero())
	for _, e := range g.Edges {
		if e.Kind == "traffic" {
			t.Fatal("a conversation with the internet belongs on the globe, not the LAN map")
		}
	}
	if g.Nodes[0].ExtConns != 1 {
		t.Fatal("external connections should still be counted on the node")
	}
}
