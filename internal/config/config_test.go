package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDefaultIsSafeOnFreshInstall(t *testing.T) {
	c := Default()
	// The whole install story depends on this: a freshly installed node must
	// not change how the network behaves until someone asks it to.
	if c.Mode != ModeObserve {
		t.Error("default mode is not observe")
	}
	if c.Firewall.Enabled {
		t.Error("the firewall is enabled by default")
	}
	if c.DHCP.Enabled {
		t.Error("DHCP is enabled by default — this would fight the existing server")
	}
	if c.MITM.Enabled {
		t.Error("TLS interception is enabled by default")
	}
	if c.VPN.Server.Enabled || c.Tailscale.Enabled {
		t.Error("a VPN is enabled by default")
	}
	if c.AI.Enabled {
		t.Error("the assistant is enabled by default — it needs a key the operator has not given yet")
	}
	if c.AI.AllowWrite {
		t.Error("the assistant has write access by default")
	}
	if err := c.Validate(); err != nil {
		t.Errorf("the default config does not validate: %v", err)
	}
}

func TestValidateCatchesFootguns(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*Config)
		wantErr string
	}{
		{"bad mode", func(c *Config) { c.Mode = "sideways" }, "observe or inline"},
		{"bad dns listen", func(c *Config) { c.DNS.Listen = []string{"noport"} }, "dns.listen"},
		{"bad dhcp subnet", func(c *Config) {
			c.DHCP.Scopes = []DHCPScope{{Name: "x", Subnet: "not-a-cidr", RangeStart: "1.1.1.1", RangeEnd: "1.1.1.2"}}
		}, "subnet"},
		{"bad dhcp range", func(c *Config) {
			c.DHCP.Scopes = []DHCPScope{{Name: "x", Subnet: "10.0.0.0/24", RangeStart: "nope", RangeEnd: "10.0.0.9"}}
		}, "range_start"},
		{"bad forward policy", func(c *Config) { c.Firewall.DefaultForward = "maybe" }, "default_forward"},
		{"inline without wan", func(c *Config) {
			c.Mode = ModeInline
			c.Firewall.Enabled = true
			c.Firewall.WANInterface = ""
		}, "wan_interface"},
		{"steering without exit node", func(c *Config) {
			c.Tailscale.Enabled = true
			c.Tailscale.SteerClients = []string{"192.168.1.5"}
			c.Tailscale.ExitNode = ""
		}, "exit_node"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := Default()
			tc.mutate(c)
			err := c.Validate()
			if err == nil {
				t.Fatalf("expected an error mentioning %q", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error %q does not mention %q", err, tc.wantErr)
			}
		})
	}
}

func TestUpdateRollsBackInvalidChanges(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "orbis.yaml")
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	original := c.DNS.Strategy

	err = c.Update(func(cfg *Config) {
		cfg.DNS.Strategy = "changed"
		cfg.Firewall.DefaultForward = "invalid"
	})
	if err == nil {
		t.Fatal("an invalid update was accepted")
	}
	// A rejected update must leave nothing behind, or the daemon ends up
	// running a configuration nobody chose.
	if c.DNS.Strategy != original {
		t.Errorf("a rejected update left DNS.Strategy = %q", c.DNS.Strategy)
	}
	if c.Firewall.DefaultForward != "drop" {
		t.Errorf("a rejected update left DefaultForward = %q", c.Firewall.DefaultForward)
	}
}

func TestLoadPreservesDefaultsForOmittedKeys(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "orbis.yaml")
	// A minimal file: everything not mentioned should keep its default
	// rather than becoming a zero value.
	if err := os.WriteFile(path, []byte("mode: observe\nnode:\n  name: partial\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.Node.Name != "partial" {
		t.Errorf("Node.Name = %q, want the value from the file", c.Node.Name)
	}
	if c.DNS.CacheSize == 0 {
		t.Error("an omitted key became a zero value instead of keeping its default")
	}
	if len(c.AdBlock.Lists) == 0 {
		t.Error("the default blocklist set was lost")
	}
}

func TestRedactedHidesEverySecret(t *testing.T) {
	c := Default()
	c.AI.APIKey = "sk-super-secret"
	c.API.SessionKey = "session-secret"
	c.API.AdminHash = "$2a$12$hash"
	c.VPN.Server.PrivateKey = "wg-private"
	c.Tailscale.AuthKey = "tskey-auth-secret"
	c.VPN.Client = []WGClientConfig{{Name: "vpn", PrivateKey: "client-private", PeerPSK: "psk"}}

	r := c.Redacted()
	for name, got := range map[string]string{
		"AI.APIKey":         r.AI.APIKey,
		"API.SessionKey":    r.API.SessionKey,
		"API.AdminHash":     r.API.AdminHash,
		"VPN private key":   r.VPN.Server.PrivateKey,
		"Tailscale AuthKey": r.Tailscale.AuthKey,
		"client private":    r.VPN.Client[0].PrivateKey,
		"client psk":        r.VPN.Client[0].PeerPSK,
	} {
		if strings.Contains(got, "secret") || strings.Contains(got, "private") ||
			strings.Contains(got, "psk") || strings.Contains(got, "$2a$") {
			t.Errorf("%s leaked through Redacted(): %q", name, got)
		}
	}
	// Redaction must not mutate the live config.
	if c.AI.APIKey != "sk-super-secret" {
		t.Error("Redacted() mutated the original config")
	}
}

func TestSaveIsAtomic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "orbis.yaml")
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Save(); err != nil {
		t.Fatal(err)
	}
	// The temp file used for the atomic rename must not survive.
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Error("a .tmp file was left behind")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	// The file holds API keys and WireGuard private keys.
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("config permissions are %o, want 600", perm)
	}
}

func TestSnapshotIsReadOnly(t *testing.T) {
	dir := t.TempDir()
	c, err := Load(filepath.Join(dir, "orbis.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	snap := c.Snapshot()
	if snap.Live() {
		t.Error("a snapshot reports itself as the live configuration")
	}
	// Writing a snapshot back would silently discard concurrent changes, so
	// it has to fail rather than appear to work.
	if err := snap.Save(); err == nil {
		t.Error("saving a snapshot was allowed")
	}
	if err := snap.Update(func(*Config) {}); err == nil {
		t.Error("updating a snapshot was allowed")
	}
	if !c.Live() {
		t.Error("taking a snapshot broke the live configuration")
	}
}
