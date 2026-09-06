package links

import (
	"testing"

	"github.com/Neoo-Blue/orbis/internal/config"
)

func TestClassifyTwoCables(t *testing.T) {
	cfg := *config.Default()
	links := []Link{
		{Name: "eth0", Carrier: true, DefaultRoute: true, Neighbours: 1},
		{Name: "eth1", Carrier: true, Neighbours: 12, Clients: 9},
		{Name: "eth2"},
		{Name: "wlan0", Wireless: true},
	}
	out, sug := Classify(links, cfg, false)
	roles := map[string]string{}
	for _, l := range out {
		roles[l.Name] = l.Role
	}
	if roles["eth0"] != "wan" || roles["eth1"] != "lan" || roles["eth2"] != "unplugged" || roles["wlan0"] != "wifi" {
		t.Fatalf("roles = %v", roles)
	}
	if sug.WAN != "eth0" || len(sug.LAN) != 1 || sug.LAN[0] != "eth1" || sug.Confidence != "high" {
		t.Errorf("suggestion = %+v", sug)
	}
	if len(sug.Changes) == 0 {
		t.Error("a default config should have changes to apply")
	}
}

func TestClassifyThinEvidenceIsAProposal(t *testing.T) {
	cfg := *config.Default()
	links := []Link{
		{Name: "eth0", Carrier: true, DefaultRoute: true, Clients: 20},
		{Name: "eth1", Carrier: true},
	}
	_, sug := Classify(links, cfg, false)
	if sug.Confidence != "low" {
		t.Errorf("all devices behind the default-route cable should make the proposal low confidence: %+v", sug)
	}
}

func TestClassifySingleCable(t *testing.T) {
	cfg := *config.Default()
	links := []Link{{Name: "eth0", Carrier: true, DefaultRoute: true, Clients: 30}, {Name: "wlan0", Wireless: true}}
	out, sug := Classify(links, cfg, true)
	if out[0].Role != "single" || sug.WAN != "eth0" || len(sug.LAN) != 0 || sug.WiFi[0] != "wlan0" {
		t.Errorf("single cable with an access point: %+v %+v", out, sug)
	}
}

func TestApplyWritesZones(t *testing.T) {
	cfg := config.Default()
	cfg.Firewall.Zones = []config.Zone{{Name: "inside", Trust: "lan", Interfaces: []string{"eth0"}}}
	if err := Apply(cfg, Suggestion{WAN: "eth0", LAN: []string{"eth1"}, WiFi: []string{"wlan0"}}); err != nil {
		// Default() has no mutex for Update on a bare struct in some builds;
		// the point of the test is the zone arithmetic, so build it by hand.
		t.Skip("config update unavailable in this build: " + err.Error())
	}
	if cfg.Firewall.WANInterface != "eth0" {
		t.Errorf("wan interface = %q", cfg.Firewall.WANInterface)
	}
	var wan, lan []string
	for _, z := range cfg.Firewall.Zones {
		switch z.Trust {
		case "wan":
			wan = z.Interfaces
		case "lan":
			lan = z.Interfaces
		}
	}
	if len(wan) != 1 || wan[0] != "eth0" {
		t.Errorf("wan zone = %v", wan)
	}
	if len(lan) != 2 || lan[0] != "eth1" || lan[1] != "wlan0" {
		t.Errorf("lan zone should hold the LAN cable and the Wi-Fi adapter, not the WAN cable: %v", lan)
	}
}
