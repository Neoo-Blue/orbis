package firewall

import (
	"strings"
	"testing"

	"github.com/Neoo-Blue/orbis/internal/config"
	"github.com/Neoo-Blue/orbis/internal/store"
)

func testConfig() config.Config {
	c := config.Default()
	c.Mode = config.ModeInline
	c.Firewall.Enabled = true
	c.Firewall.WANInterface = "eth0"
	c.Firewall.Zones = []config.Zone{
		{Name: "lan", Interfaces: []string{"eth1"}, Subnets: []string{"192.168.1.0/24"}, Trust: "lan"},
		{Name: "iot", Interfaces: []string{"eth2"}, Subnets: []string{"192.168.9.0/24"}, Trust: "iot"},
		{Name: "wan", Interfaces: []string{"eth0"}, Trust: "wan"},
	}
	return *c
}

func TestRenderProducesAtomicReplace(t *testing.T) {
	out, err := renderRuleset(testConfig(), nil)
	if err != nil {
		t.Fatal(err)
	}
	// The delete-then-create pair inside one file is what makes the load
	// atomic. Losing it means a window where the box is unprotected.
	if !strings.Contains(out, "table inet orbis\ndelete table inet orbis") {
		t.Error("ruleset does not begin with an atomic table replace")
	}
	if strings.Count(out, "table inet orbis {") != 1 {
		t.Error("expected exactly one table definition")
	}
	// Braces must balance or nft rejects the whole file.
	if strings.Count(out, "{") != strings.Count(out, "}") {
		t.Errorf("unbalanced braces: %d open, %d close", strings.Count(out, "{"), strings.Count(out, "}"))
	}
}

func TestRenderIsolatesUntrustedZones(t *testing.T) {
	out, err := renderRuleset(testConfig(), nil)
	if err != nil {
		t.Fatal(err)
	}
	// An IoT zone must be denied every other local zone *before* it is
	// allowed out to the internet, or "allow out" also permits lateral
	// movement to the LAN.
	dropIdx := strings.Index(out, `iifname @zone_iot oifname @zone_lan counter drop`)
	acceptIdx := strings.Index(out, `iifname @zone_iot oifname "eth0" counter accept`)
	if dropIdx < 0 {
		t.Fatal("IoT is not isolated from the LAN")
	}
	if acceptIdx < 0 {
		t.Fatal("IoT has no internet egress rule")
	}
	if dropIdx > acceptIdx {
		t.Error("the isolation rule comes after the egress rule, so lateral traffic would be accepted first")
	}
}

func TestRenderAntiLockout(t *testing.T) {
	cfg := testConfig()
	out, _ := renderRuleset(cfg, nil)
	if !strings.Contains(out, "orbis anti-lockout") {
		t.Error("anti-lockout rule missing when enabled")
	}
	if !strings.Contains(out, "policy drop") {
		t.Error("the input chain should default to drop")
	}

	cfg.Firewall.AntiLockout = false
	out, _ = renderRuleset(cfg, nil)
	if strings.Contains(out, "orbis anti-lockout") {
		t.Error("anti-lockout rule present when disabled")
	}
}

func TestRenderEscapesRuleNames(t *testing.T) {
	// A rule name is operator-supplied text that ends up inside an nftables
	// comment string. Unescaped quotes would break out of the string and
	// inject ruleset syntax.
	rules := []store.Rule{{
		ID: "r1", Enabled: true, Chain: "forward", Action: "drop",
		Name: `evil" ; drop table inet orbis; comment "`, Position: 10, Log: true,
	}}
	out, err := renderRuleset(testConfig(), rules)
	if err != nil {
		t.Fatal(err)
	}
	// The property that matters is structural: the name must not be able to
	// terminate its comment string or introduce a new statement.
	if strings.Count(out, "delete table inet orbis") != 1 {
		t.Error("an extra table statement appeared")
	}
	if strings.Count(out, `"`)%2 != 0 {
		t.Error("unbalanced quotes — a name escaped its string")
	}
	for _, dangerous := range []string{";", "{", "}", `"`, "\\"} {
		if strings.Contains(commentBodyFor(out, "r1"), dangerous) {
			t.Errorf("the rendered comment still contains %q", dangerous)
		}
	}
}

// commentBodyFor extracts the comment text emitted for a rule id.
func commentBodyFor(ruleset, id string) string {
	marker := `comment "` + id + `|`
	i := strings.Index(ruleset, marker)
	if i < 0 {
		return ""
	}
	rest := ruleset[i+len(marker):]
	end := strings.IndexByte(rest, '"')
	if end < 0 {
		return rest
	}
	return rest[:end]
}

func TestRenderRuleFields(t *testing.T) {
	rules := []store.Rule{{
		ID: "abc", Enabled: true, Chain: "forward", Action: "reject",
		Name: "block iot to nas", SrcZone: "iot", Dst: "192.168.1.10",
		Proto: "tcp", DstPort: "445,139", Position: 10,
	}}
	out, err := renderRuleset(testConfig(), rules)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"iifname @zone_iot", "ip daddr 192.168.1.10",
		"meta l4proto tcp", "tcp dport { 445, 139 }", "reject", `comment "abc|`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered ruleset is missing %q", want)
		}
	}
}

func TestDisabledRulesAreNotRendered(t *testing.T) {
	rules := []store.Rule{{
		ID: "off", Enabled: false, Chain: "forward", Action: "drop",
		Name: "disabled rule", Position: 10,
	}}
	out, _ := renderRuleset(testConfig(), rules)
	if strings.Contains(out, "off|disabled rule") {
		t.Error("a disabled rule was rendered")
	}
}

func TestScheduleMatch(t *testing.T) {
	cases := map[string][]string{
		"mon-fri 09:00-17:00": {`meta day { "monday", "tuesday", "wednesday", "thursday", "friday" }`, `meta hour "09:00"-"17:00"`},
		"sat-sun":             {`meta day { "saturday", "sunday" }`},
		"22:00-06:00":         {`meta hour "22:00"-"06:00"`},
	}
	for spec, wants := range cases {
		got := scheduleMatch(spec)
		for _, want := range wants {
			if !strings.Contains(got, want) {
				t.Errorf("scheduleMatch(%q) = %q, missing %q", spec, got, want)
			}
		}
	}
	if got := scheduleMatch("nonsense"); got != "" {
		t.Errorf("scheduleMatch(nonsense) = %q, want empty", got)
	}
}

func TestSanitizeProducesValidIdentifiers(t *testing.T) {
	cases := map[string]string{
		"lan":          "lan",
		"Guest WiFi":   "guest_wifi",
		"2nd-floor":    "z2nd_floor",
		"":             "zone",
		"a.b/c":        "a_b_c",
	}
	for in, want := range cases {
		if got := sanitize(in); got != want {
			t.Errorf("sanitize(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestTailscaleRulesAppearOnlyWhenEnabled(t *testing.T) {
	cfg := testConfig()
	out, _ := renderRuleset(cfg, nil)
	if strings.Contains(out, "tailscale0") {
		t.Error("tailscale rules rendered while Tailscale is disabled")
	}

	cfg.Tailscale.Enabled = true
	out, _ = renderRuleset(cfg, nil)
	for _, want := range []string{
		`iifname "tailscale0" accept`,          // input: reach this node over the tailnet
		`iifname "tailscale0" counter accept`,  // forward: act as an exit node
		`oifname "tailscale0" counter accept`,  // forward: steer clients out
		`oifname "tailscale0" counter masquerade`, // NAT steered LAN sources
		"udp dport 41641 accept",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("tailscale ruleset is missing %q", want)
		}
	}
}

func TestObserveModeRendersButDoesNotClaimApplied(t *testing.T) {
	cfg := testConfig()
	cfg.Mode = config.ModeObserve
	// Rendering must still work in observe mode so the preview pane has
	// something to show; it is Apply that refuses.
	out, err := renderRuleset(cfg, nil)
	if err != nil || len(out) == 0 {
		t.Fatalf("render failed in observe mode: %v", err)
	}
}

func TestParseCounters(t *testing.T) {
	raw := []byte(`{"nftables":[
	  {"metainfo":{"version":"1.0.6"}},
	  {"rule":{"family":"inet","table":"orbis","chain":"forward",
	    "comment":"rule-abc|block iot",
	    "expr":[{"match":{"left":{"payload":{}}}},{"counter":{"packets":42,"bytes":7331}},{"drop":null}]}},
	  {"rule":{"family":"inet","table":"orbis","chain":"forward","comment":"no-pipe",
	    "expr":[{"counter":{"packets":1,"bytes":2}}]}}
	]}`)
	counters, err := parseCounters(raw)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := counters["rule-abc"]
	if !ok {
		t.Fatal("counter for rule-abc not found")
	}
	if got[0] != 42 || got[1] != 7331 {
		t.Errorf("counters = %v, want [42 7331]", got)
	}
	if _, ok := counters["no-pipe"]; ok {
		t.Error("a comment without an id separator should be ignored")
	}
}
