package config

import (
	"encoding/json"
	"testing"
)

// TestJSONShapeMatchesYAML pins the wire format the web UI reads. The struct
// carries yaml tags for the config file; without matching json tags,
// encoding/json falls back to Go field names and every settings page reads
// undefined — which is exactly the bug this test exists to prevent.
func TestJSONShapeMatchesYAML(t *testing.T) {
	c := Default()
	c.AI.APIKey = "sk-should-not-appear"
	c.Tailscale.AuthKey = "tskey-should-not-appear"
	c.VPN.Server.PrivateKey = "wg-should-not-appear"

	raw, err := json.Marshal(c.Redacted())
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}

	for _, key := range []string{
		"mode", "node", "api", "store", "capture", "dns",
		"adblock", "mitm", "firewall", "dhcp", "vpn", "tailscale", "ai", "geoip", "issues",
	} {
		if _, ok := m[key]; !ok {
			t.Errorf("top-level key %q is missing from the JSON encoding", key)
		}
	}

	nested := map[string][]string{
		"node":      {"name", "timezone", "latitude", "longitude", "locate_public_ip", "ui_mode"},
		"dns":       {"enabled", "upstreams", "strategy", "cache_size", "sinkhole_ipv4", "local_domain", "block_ede", "log_queries", "records", "shortcuts"},
		"adblock":   {"enabled", "lists", "allowlist", "denylist", "sni_blocking", "cname_uncloak", "block_dns_bypass", "smart_capture"},
		"mitm":      {"enabled", "intercept_hosts", "bypass_hosts", "only_clients", "filters", "listen_http", "listen_tls", "ca_dir"},
		"firewall":  {"enabled", "zones", "wan_interface", "default_forward", "log_dropped", "ipv6", "flow_offload", "anti_lockout"},
		"dhcp":      {"enabled", "scopes", "static"},
		"tailscale": {"enabled", "hostname", "advertise_exit_node", "exit_node", "exit_node_allow_lan", "steer_clients", "advertise_routes", "accept_routes", "accept_dns", "ssh"},
		"ai":        {"enabled", "provider", "base_url", "model", "fast_model", "max_tokens", "allow_write", "anomaly", "prefer_free", "auto_discover", "model_chain", "fast_model_chain", "probe_interval_hours", "free_daily_budget", "brief", "review"},
		"capture":   {"enabled", "interfaces", "snaplen", "conntrack"},
		"store":     {"path", "flow_retention_days", "event_retention_days"},
		"geoip":     {"city_db", "asn_db"},
		"issues":    {"enabled", "auto_capture", "redact_extra", "github"},
	}
	for parent, keys := range nested {
		obj, ok := m[parent].(map[string]any)
		if !ok {
			t.Errorf("%q did not encode as an object", parent)
			continue
		}
		for _, k := range keys {
			if _, ok := obj[k]; !ok {
				t.Errorf("%s.%s is missing from the JSON encoding", parent, k)
			}
		}
	}

	// The nested groups the UI reads directly.
	if sc, ok := m["adblock"].(map[string]any)["smart_capture"].(map[string]any); ok {
		for _, k := range []string{"enabled", "use_ai", "auto_block_score", "review_score", "min_observations", "interval_minutes", "max_auto_blocks_per_day"} {
			if _, ok := sc[k]; !ok {
				t.Errorf("adblock.smart_capture.%s is missing", k)
			}
		}
	} else {
		t.Error("adblock.smart_capture did not encode as an object")
	}
	if f, ok := m["mitm"].(map[string]any)["filters"].(map[string]any); ok {
		for _, k := range []string{"youtube", "generic_json_ads", "html_cosmetic", "tracker_beacons"} {
			if _, ok := f[k]; !ok {
				t.Errorf("mitm.filters.%s is missing", k)
			}
		}
	} else {
		t.Error("mitm.filters did not encode as an object")
	}
	if v, ok := m["vpn"].(map[string]any)["server"].(map[string]any); ok {
		for _, k := range []string{"enabled", "listen_port", "address", "endpoint", "dns", "mtu"} {
			if _, ok := v[k]; !ok {
				t.Errorf("vpn.server.%s is missing", k)
			}
		}
	} else {
		t.Error("vpn.server did not encode as an object")
	}

	// Redaction has to hold on the JSON path too, not just on the struct.
	for _, secret := range []string{"sk-should-not-appear", "tskey-should-not-appear", "wg-should-not-appear"} {
		if contains(string(raw), secret) {
			t.Errorf("%q leaked into the JSON encoding", secret)
		}
	}
}

func contains(haystack, needle string) bool {
	return len(needle) > 0 && len(haystack) >= len(needle) &&
		func() bool {
			for i := 0; i+len(needle) <= len(haystack); i++ {
				if haystack[i:i+len(needle)] == needle {
					return true
				}
			}
			return false
		}()
}
