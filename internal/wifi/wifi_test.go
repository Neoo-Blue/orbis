package wifi

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/Neoo-Blue/orbis/internal/config"
)

func TestRenderHostapd(t *testing.T) {
	cfg := config.WiFiConfig{SSID: "Orbis", Passphrase: "correct horse", Country: "US", Hidden: true, WPA3: true}
	conf := renderHostapd(cfg, "wlan0", "5", 36)
	for _, want := range []string{"interface=wlan0", "ssid=Orbis", "country_code=US", "hw_mode=a", "channel=36", "ieee80211ac=1", "ignore_broadcast_ssid=1", "wpa_key_mgmt=WPA-PSK SAE", "wpa_passphrase=correct horse"} {
		if !strings.Contains(conf, want) {
			t.Errorf("missing %q in:\n%s", want, conf)
		}
	}
	conf = renderHostapd(config.WiFiConfig{SSID: "x", Passphrase: "12345678", Mode: "bridge", Bridge: "br0"}, "wlan0", "2.4", 6)
	if !strings.Contains(conf, "bridge=br0") || !strings.Contains(conf, "hw_mode=g") || strings.Contains(conf, "country_code") {
		t.Errorf("bridge / 2.4 GHz rendering wrong:\n%s", conf)
	}
}

func TestScopeFor(t *testing.T) {
	s := scopeFor(config.WiFiConfig{}, "wlan0", netip.MustParsePrefix("192.168.60.1/24"))
	if s.Subnet != "192.168.60.0/24" || s.Gateway != "192.168.60.1" || s.RangeStart != "192.168.60.50" || s.RangeEnd != "192.168.60.248" || s.DNS[0] != "192.168.60.1" || s.Interface != "wlan0" {
		t.Errorf("scope = %+v", s)
	}
}

func TestGeneratePassphrase(t *testing.T) {
	p := GeneratePassphrase()
	if len(p) != 14 || strings.ContainsAny(p, "0O1lI") {
		t.Errorf("passphrase %q should be 14 unambiguous characters", p)
	}
}
