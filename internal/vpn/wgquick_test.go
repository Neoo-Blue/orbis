package vpn

import (
	"strings"
	"testing"
)

// Providers all distribute a wg-quick file, so parsing one correctly is the
// difference between "paste this" and "retype five base64 fields and hope".
func TestParseWGQuickRealProviderConfig(t *testing.T) {
	conf := `# Mullvad WireGuard configuration
[Interface]
PrivateKey = qJfZ8lM0kQvXH3nR7tYuIoP2aSdFgHjKlZxCvBnM1QE=
Address = 10.64.212.13/32,fc00:bbbb:bbbb:bb01::1:d40c/128
DNS = 10.64.0.1
MTU = 1370
PostUp = iptables -I OUTPUT ! -o %i -m mark ! --mark $(wg show %i fwmark) -j REJECT
PreDown = iptables -D OUTPUT ! -o %i -j REJECT

[Peer]
PublicKey = mLpQrStUvWxYz0123456789AbCdEfGhIjKlMnOpQrSt=
PresharedKey = ZxCvBnMaSdFgHjKlQwErTyUiOpZxCvBnMaSdFgHjKlM=
AllowedIPs = 0.0.0.0/0,::/0
Endpoint = 193.138.218.74:51820
PersistentKeepalive = 25
`
	got, err := ParseWGQuick(conf)
	if err != nil {
		t.Fatalf("a standard provider config failed to parse: %v", err)
	}
	if got.PrivateKey != "qJfZ8lM0kQvXH3nR7tYuIoP2aSdFgHjKlZxCvBnM1QE=" {
		t.Errorf("private key = %q — note it ends in '=' and must survive the key/value split", got.PrivateKey)
	}
	if len(got.Addresses) != 2 {
		t.Errorf("addresses = %v, want both the v4 and v6 entries", got.Addresses)
	}
	if got.MTU != 1370 {
		t.Errorf("MTU = %d, want 1370 — providers set this for a reason", got.MTU)
	}
	if got.Endpoint != "193.138.218.74:51820" {
		t.Errorf("endpoint = %q", got.Endpoint)
	}
	if got.PresharedKey == "" {
		t.Error("the preshared key was dropped")
	}
	if got.Keepalive != 25 {
		t.Errorf("keepalive = %d, want 25", got.Keepalive)
	}
	// The hooks are arbitrary shell from a third party and must not be run.
	if len(got.Ignored) == 0 {
		t.Error("PostUp/PreDown were not recorded as ignored, so the operator would not know they were dropped")
	}
	joined := strings.Join(got.Ignored, ",")
	if !strings.Contains(joined, "postup") || !strings.Contains(joined, "predown") {
		t.Errorf("ignored = %v, want the hooks named", got.Ignored)
	}
}

func TestParseWGQuickRejectsUnusableConfigs(t *testing.T) {
	cases := map[string]string{
		"no private key": "[Interface]\nAddress = 10.0.0.2/32\n\n[Peer]\nPublicKey = abc\nEndpoint = 1.2.3.4:1\n",
		"no peer key":    "[Interface]\nPrivateKey = qJfZ8lM0kQvXH3nR7tYuIoP2aSdFgHjKlZxCvBnM1QE=\nAddress = 10.0.0.2/32\n\n[Peer]\nEndpoint = 1.2.3.4:1\n",
		"no endpoint":    "[Interface]\nPrivateKey = qJfZ8lM0kQvXH3nR7tYuIoP2aSdFgHjKlZxCvBnM1QE=\nAddress = 10.0.0.2/32\n\n[Peer]\nPublicKey = abc\n",
		"no address":     "[Interface]\nPrivateKey = qJfZ8lM0kQvXH3nR7tYuIoP2aSdFgHjKlZxCvBnM1QE=\n\n[Peer]\nPublicKey = abc\nEndpoint = 1.2.3.4:1\n",
		"bad key":        "[Interface]\nPrivateKey = not-a-key\nAddress = 10.0.0.2/32\n\n[Peer]\nPublicKey = abc\nEndpoint = 1.2.3.4:1\n",
	}
	for name, conf := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseWGQuick(conf); err == nil {
				t.Error("expected a rejection with an actionable message")
			}
		})
	}
}

func TestParseWGQuickRefusesMultiPeerMesh(t *testing.T) {
	// Silently using only the first peer of a mesh config would produce a
	// tunnel that half works, which is harder to debug than a refusal.
	conf := `[Interface]
PrivateKey = qJfZ8lM0kQvXH3nR7tYuIoP2aSdFgHjKlZxCvBnM1QE=
Address = 10.0.0.2/32

[Peer]
PublicKey = aaa
Endpoint = 1.2.3.4:51820
AllowedIPs = 10.0.0.1/32

[Peer]
PublicKey = bbb
Endpoint = 5.6.7.8:51820
AllowedIPs = 10.0.0.3/32
`
	_, err := ParseWGQuick(conf)
	if err == nil {
		t.Fatal("a multi-peer config was accepted")
	}
	if !strings.Contains(err.Error(), "peers") {
		t.Errorf("error %q should explain that only a single upstream is supported", err)
	}
}

func TestParseWGQuickDefaultsAllowedIPs(t *testing.T) {
	conf := `[Interface]
PrivateKey = qJfZ8lM0kQvXH3nR7tYuIoP2aSdFgHjKlZxCvBnM1QE=
Address = 10.0.0.2/32

[Peer]
PublicKey = aaa
Endpoint = 1.2.3.4:51820
`
	got, err := ParseWGQuick(conf)
	if err != nil {
		t.Fatal(err)
	}
	// "Route my traffic through this" is the intent of importing a provider
	// config, so a missing AllowedIPs defaults to everything.
	if len(got.AllowedIPs) == 0 || got.AllowedIPs[0] != "0.0.0.0/0" {
		t.Errorf("AllowedIPs = %v, want a full-tunnel default", got.AllowedIPs)
	}
}

func TestRenderMasksSecrets(t *testing.T) {
	tun := &WGTunnel{
		PrivateKey: "supersecretkey", PresharedKey: "alsosecret",
		Addresses: []string{"10.0.0.2/32"}, PeerPublicKey: "peerkey",
		Endpoint: "1.2.3.4:51820", AllowedIPs: []string{"0.0.0.0/0"},
	}
	masked := tun.RenderWGQuick(true)
	if strings.Contains(masked, "supersecretkey") || strings.Contains(masked, "alsosecret") {
		t.Error("secrets survived masking")
	}
	if !strings.Contains(masked, "peerkey") {
		t.Error("the peer's public key should not be masked — it is public")
	}
	full := tun.RenderWGQuick(false)
	if !strings.Contains(full, "supersecretkey") {
		t.Error("the unmasked render dropped the private key")
	}
}

func TestSpecificityOrdersRoutes(t *testing.T) {
	// A per-device rule has to beat "all devices", or turning on whole-network
	// routing would silently override every exception the operator set.
	if specificity("192.168.1.5") <= specificity("192.168.1.0/24") {
		t.Error("a single address should be more specific than its subnet")
	}
	if specificity("192.168.1.0/24") <= specificity("all") {
		t.Error("a subnet should be more specific than the all-devices rule")
	}
	if specificity("all") != -1 {
		t.Errorf("all = %d, want the lowest priority", specificity("all"))
	}
}

func TestSanitizeIfnameProducesValidNames(t *testing.T) {
	for input, want := range map[string]string{
		"Mullvad — Amsterdam": "mullvadamsterdam",
		"proton-vpn":          "protonvpn",
		"!!!":                 "tun",
	} {
		if got := sanitizeIfname(input); got != want {
			t.Errorf("sanitizeIfname(%q) = %q, want %q", input, got, want)
		}
	}
}
