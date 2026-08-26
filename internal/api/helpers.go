package api

import (
	"bytes"
	"fmt"
	"image/color"
	"image/png"
	"net"
	"sort"
	"strings"

	"github.com/Neoo-Blue/orbis/internal/config"
	"github.com/skip2/go-qrcode"
)

// qrPNG renders a WireGuard config as a QR code. Typing a 44-character base64
// key into a phone by hand is how people end up not using the VPN they set up.
func qrPNG(payload string) ([]byte, error) {
	q, err := qrcode.New(payload, qrcode.Medium)
	if err != nil {
		return nil, err
	}
	// High contrast on a light background: phone cameras struggle with the
	// dark-on-dark theme the rest of the UI uses.
	q.BackgroundColor = color.White
	q.ForegroundColor = color.Black
	img := q.Image(512)
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// InterfaceInfo describes a NIC for the zone/interface pickers.
type InterfaceInfo struct {
	Name      string   `json:"name"`
	MAC       string   `json:"mac,omitempty"`
	Up        bool     `json:"up"`
	Loopback  bool     `json:"loopback"`
	MTU       int      `json:"mtu"`
	Addresses []string `json:"addresses"`
	Virtual   bool     `json:"virtual"`
}

func listInterfaces() []InterfaceInfo {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	virtualPrefixes := []string{"docker", "br-", "veth", "virbr", "cni", "flannel", "kube", "wg", "tailscale", "zt", "tun", "tap"}
	out := make([]InterfaceInfo, 0, len(ifaces))
	for _, i := range ifaces {
		info := InterfaceInfo{
			Name: i.Name, MAC: i.HardwareAddr.String(),
			Up: i.Flags&net.FlagUp != 0, Loopback: i.Flags&net.FlagLoopback != 0,
			MTU: i.MTU, Addresses: []string{},
		}
		for _, p := range virtualPrefixes {
			if strings.HasPrefix(i.Name, p) {
				info.Virtual = true
				break
			}
		}
		if addrs, err := i.Addrs(); err == nil {
			for _, a := range addrs {
				info.Addresses = append(info.Addresses, a.String())
			}
		}
		out = append(out, info)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// applyConfigPatch maps dotted keys onto the config struct. Only the listed
// paths are writable: the alternative — reflecting over the whole struct —
// would let an API call point the store at a new file or unbind the API,
// which are not recoverable from a browser.
func applyConfigPatch(cfg *config.Config, patch map[string]any) ([]string, error) {
	applied := make([]string, 0, len(patch))
	err := cfg.Update(func(c *config.Config) {
		for key, raw := range patch {
			if setConfigKey(c, key, raw) {
				applied = append(applied, key)
			}
		}
	})
	if err != nil {
		return nil, err
	}
	if len(applied) == 0 {
		return nil, fmt.Errorf("no writable settings in request")
	}
	sort.Strings(applied)
	return applied, nil
}

func setConfigKey(c *config.Config, key string, raw any) bool {
	switch key {
	case "mode":
		if v, ok := raw.(string); ok && (v == "observe" || v == "inline") {
			c.Mode = config.Mode(v)
			return true
		}
	case "node.name":
		return setStr(&c.Node.Name, raw)
	case "node.timezone":
		return setStr(&c.Node.Timezone, raw)
	case "node.locate_public_ip":
		return setBool(&c.Node.LocatePublicIP, raw)
	case "node.latitude":
		return setFloat(&c.Node.Latitude, raw)
	case "node.longitude":
		return setFloat(&c.Node.Longitude, raw)

	case "dns.enabled":
		return setBool(&c.DNS.Enabled, raw)
	case "dns.upstreams":
		return setStrSlice(&c.DNS.Upstreams, raw)
	case "dns.strategy":
		return setStr(&c.DNS.Strategy, raw)
	case "dns.log_queries":
		return setBool(&c.DNS.LogQueries, raw)
	case "dns.block_ede":
		return setBool(&c.DNS.BlockEDE, raw)
	case "dns.sinkhole_ipv4":
		return setStr(&c.DNS.SinkholeIPv4, raw)
	case "dns.sinkhole_ipv6":
		return setStr(&c.DNS.SinkholeIPv6, raw)
	case "dns.local_domain":
		return setStr(&c.DNS.LocalDomain, raw)
	case "dns.cache_size":
		return setInt(&c.DNS.CacheSize, raw)
	case "dns.min_ttl":
		return setInt(&c.DNS.MinTTL, raw)
	case "dns.max_ttl":
		return setInt(&c.DNS.MaxTTL, raw)

	case "adblock.enabled":
		return setBool(&c.AdBlock.Enabled, raw)
	case "adblock.sni_blocking":
		return setBool(&c.AdBlock.SNIBlocking, raw)
	case "adblock.cname_uncloak":
		return setBool(&c.AdBlock.CNAMEUncloak, raw)
	case "adblock.block_dns_bypass":
		return setBool(&c.AdBlock.BlockDNSBypass, raw)
	case "adblock.update_interval_hours":
		return setInt(&c.AdBlock.UpdateIntervalHours, raw)
	case "adblock.allowlist":
		return setStrSlice(&c.AdBlock.Allowlist, raw)
	case "adblock.denylist":
		return setStrSlice(&c.AdBlock.Denylist, raw)
	case "adblock.smart_capture.enabled":
		return setBool(&c.AdBlock.SmartCapture.Enabled, raw)
	case "adblock.smart_capture.use_ai":
		return setBool(&c.AdBlock.SmartCapture.UseAI, raw)
	case "adblock.smart_capture.auto_block_score":
		return setFloat(&c.AdBlock.SmartCapture.AutoBlockScore, raw)
	case "adblock.smart_capture.review_score":
		return setFloat(&c.AdBlock.SmartCapture.ReviewScore, raw)
	case "adblock.smart_capture.min_observations":
		return setInt(&c.AdBlock.SmartCapture.MinObservations, raw)
	case "adblock.smart_capture.interval_minutes":
		return setInt(&c.AdBlock.SmartCapture.IntervalMinutes, raw)
	case "adblock.smart_capture.max_auto_blocks_per_day":
		return setInt(&c.AdBlock.SmartCapture.MaxAutoBlocksPerDay, raw)

	case "mitm.enabled":
		return setBool(&c.MITM.Enabled, raw)
	case "mitm.intercept_hosts":
		return setStrSlice(&c.MITM.InterceptHosts, raw)
	case "mitm.bypass_hosts":
		return setStrSlice(&c.MITM.BypassHosts, raw)
	case "mitm.only_clients":
		return setStrSlice(&c.MITM.OnlyClients, raw)
	case "mitm.filters.youtube":
		return setBool(&c.MITM.Filters.YouTube, raw)
	case "mitm.filters.generic_json_ads":
		return setBool(&c.MITM.Filters.GenericJSONAds, raw)
	case "mitm.filters.html_cosmetic":
		return setBool(&c.MITM.Filters.HTMLCosmetic, raw)
	case "mitm.filters.tracker_beacons":
		return setBool(&c.MITM.Filters.TrackerBeacons, raw)

	case "firewall.enabled":
		return setBool(&c.Firewall.Enabled, raw)
	case "firewall.wan_interface":
		return setStr(&c.Firewall.WANInterface, raw)
	case "firewall.default_forward":
		if v, ok := raw.(string); ok && (v == "accept" || v == "drop") {
			c.Firewall.DefaultForward = v
			return true
		}
	case "firewall.log_dropped":
		return setBool(&c.Firewall.LogDropped, raw)
	case "firewall.ipv6":
		return setBool(&c.Firewall.IPv6, raw)
	case "firewall.flow_offload":
		return setBool(&c.Firewall.FlowOffload, raw)
	case "firewall.anti_lockout":
		return setBool(&c.Firewall.AntiLockout, raw)
	case "firewall.zones":
		return setZones(&c.Firewall.Zones, raw)

	case "dhcp.enabled":
		return setBool(&c.DHCP.Enabled, raw)
	case "dhcp.scopes":
		return setScopes(&c.DHCP.Scopes, raw)
	case "dhcp.static":
		return setStatics(&c.DHCP.Static, raw)

	case "vpn.server.enabled":
		return setBool(&c.VPN.Server.Enabled, raw)
	case "vpn.server.listen_port":
		return setInt(&c.VPN.Server.ListenPort, raw)
	case "vpn.server.address":
		return setStr(&c.VPN.Server.Address, raw)
	case "vpn.server.endpoint":
		return setStr(&c.VPN.Server.Endpoint, raw)
	case "vpn.server.dns":
		return setStrSlice(&c.VPN.Server.DNS, raw)
	case "vpn.server.mtu":
		return setInt(&c.VPN.Server.MTU, raw)

	case "tailscale.enabled":
		return setBool(&c.Tailscale.Enabled, raw)
	case "tailscale.advertise_exit_node":
		return setBool(&c.Tailscale.AdvertiseExitNode, raw)
	case "tailscale.exit_node":
		return setStr(&c.Tailscale.ExitNode, raw)
	case "tailscale.exit_node_allow_lan":
		return setBool(&c.Tailscale.ExitNodeAllowLAN, raw)
	case "tailscale.advertise_routes":
		return setStrSlice(&c.Tailscale.AdvertiseRoutes, raw)
	case "tailscale.accept_routes":
		return setBool(&c.Tailscale.AcceptRoutes, raw)
	case "tailscale.accept_dns":
		return setBool(&c.Tailscale.AcceptDNS, raw)
	case "tailscale.hostname":
		return setStr(&c.Tailscale.Hostname, raw)
	case "tailscale.ssh":
		return setBool(&c.Tailscale.SSH, raw)
	case "tailscale.steer_clients":
		return setStrSlice(&c.Tailscale.SteerClients, raw)

	case "ai.enabled":
		return setBool(&c.AI.Enabled, raw)
	case "ai.provider":
		return setStr(&c.AI.Provider, raw)
	case "ai.base_url":
		return setStr(&c.AI.BaseURL, raw)
	case "ai.api_key":
		// A masked value coming back from a round-trip must not overwrite
		// the real key with bullets.
		if v, ok := raw.(string); ok && !strings.Contains(v, "•") {
			c.AI.APIKey = v
			return true
		}
	case "ai.model":
		return setStr(&c.AI.Model, raw)
	case "ai.fast_model":
		return setStr(&c.AI.FastModel, raw)
	case "ai.max_tokens":
		return setInt(&c.AI.MaxTokens, raw)
	case "ai.allow_write":
		return setBool(&c.AI.AllowWrite, raw)
	case "ai.anomaly.enabled":
		return setBool(&c.AI.Anomaly.Enabled, raw)
	case "ai.anomaly.use_ai":
		return setBool(&c.AI.Anomaly.UseAI, raw)
	case "ai.anomaly.new_device_alert":
		return setBool(&c.AI.Anomaly.NewDeviceAlert, raw)
	case "ai.anomaly.interval_minutes":
		return setInt(&c.AI.Anomaly.IntervalMinutes, raw)

	case "capture.enabled":
		return setBool(&c.Capture.Enabled, raw)
	case "capture.interfaces":
		return setStrSlice(&c.Capture.Interfaces, raw)
	case "capture.snaplen":
		return setInt(&c.Capture.SnapLen, raw)
	case "capture.conntrack":
		return setBool(&c.Capture.Conntrack, raw)

	case "store.flow_retention_days":
		return setInt(&c.Store.FlowRetentionDays, raw)
	case "store.event_retention_days":
		return setInt(&c.Store.EventRetentionDays, raw)

	case "geoip.city_db":
		return setStr(&c.GeoIP.CityDB, raw)
	case "geoip.asn_db":
		return setStr(&c.GeoIP.ASNDB, raw)
	}
	return false
}

func setStr(dst *string, raw any) bool {
	if v, ok := raw.(string); ok {
		*dst = v
		return true
	}
	return false
}

func setBool(dst *bool, raw any) bool {
	if v, ok := raw.(bool); ok {
		*dst = v
		return true
	}
	return false
}

func setInt(dst *int, raw any) bool {
	if v, ok := raw.(float64); ok {
		*dst = int(v)
		return true
	}
	return false
}

func setFloat(dst *float64, raw any) bool {
	if v, ok := raw.(float64); ok {
		*dst = v
		return true
	}
	return false
}

func setStrSlice(dst *[]string, raw any) bool {
	arr, ok := raw.([]any)
	if !ok {
		return false
	}
	out := make([]string, 0, len(arr))
	for _, item := range arr {
		if s, ok := item.(string); ok && strings.TrimSpace(s) != "" {
			out = append(out, strings.TrimSpace(s))
		}
	}
	*dst = out
	return true
}

func setZones(dst *[]config.Zone, raw any) bool {
	arr, ok := raw.([]any)
	if !ok {
		return false
	}
	out := make([]config.Zone, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		z := config.Zone{}
		setStr(&z.Name, m["name"])
		setStr(&z.Trust, m["trust"])
		setStrSlice(&z.Interfaces, m["interfaces"])
		setStrSlice(&z.Subnets, m["subnets"])
		if z.Name != "" {
			out = append(out, z)
		}
	}
	*dst = out
	return true
}

func setScopes(dst *[]config.DHCPScope, raw any) bool {
	arr, ok := raw.([]any)
	if !ok {
		return false
	}
	out := make([]config.DHCPScope, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		s := config.DHCPScope{}
		setStr(&s.Name, m["name"])
		setStr(&s.Interface, m["interface"])
		setStr(&s.Subnet, m["subnet"])
		setStr(&s.RangeStart, m["range_start"])
		setStr(&s.RangeEnd, m["range_end"])
		setStr(&s.Gateway, m["gateway"])
		setStr(&s.Domain, m["domain"])
		setStrSlice(&s.DNS, m["dns"])
		setStrSlice(&s.NTP, m["ntp"])
		setInt(&s.LeaseHours, m["lease_hours"])
		setInt(&s.MTU, m["mtu"])
		if s.Name != "" && s.Subnet != "" {
			out = append(out, s)
		}
	}
	*dst = out
	return true
}

func setStatics(dst *[]config.DHCPStatic, raw any) bool {
	arr, ok := raw.([]any)
	if !ok {
		return false
	}
	out := make([]config.DHCPStatic, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		s := config.DHCPStatic{}
		setStr(&s.MAC, m["mac"])
		setStr(&s.IP, m["ip"])
		setStr(&s.Hostname, m["hostname"])
		if s.MAC != "" && s.IP != "" {
			out = append(out, s)
		}
	}
	*dst = out
	return true
}

// timezoneCentroid places the node on the globe from its configured timezone,
// which is the least-bad guess that requires no external lookup and leaks
// nothing. The UI labels it as approximate.
var timezoneCentroid = map[string][2]float64{
	"America/Los_Angeles": {34.05, -118.24}, "America/Denver": {39.74, -104.99},
	"America/Chicago": {41.88, -87.63}, "America/New_York": {40.71, -74.01},
	"America/Toronto": {43.65, -79.38}, "America/Vancouver": {49.28, -123.12},
	"America/Mexico_City": {19.43, -99.13}, "America/Sao_Paulo": {-23.55, -46.63},
	"America/Argentina/Buenos_Aires": {-34.6, -58.38}, "America/Bogota": {4.71, -74.07},
	"Europe/London": {51.51, -0.13}, "Europe/Dublin": {53.35, -6.26},
	"Europe/Paris": {48.86, 2.35}, "Europe/Berlin": {52.52, 13.4},
	"Europe/Amsterdam": {52.37, 4.9}, "Europe/Madrid": {40.42, -3.7},
	"Europe/Rome": {41.9, 12.5}, "Europe/Zurich": {47.38, 8.54},
	"Europe/Stockholm": {59.33, 18.07}, "Europe/Oslo": {59.91, 10.75},
	"Europe/Helsinki": {60.17, 24.94}, "Europe/Warsaw": {52.23, 21.01},
	"Europe/Moscow": {55.76, 37.62}, "Europe/Istanbul": {41.01, 28.98},
	"Europe/Lisbon": {38.72, -9.14}, "Europe/Prague": {50.08, 14.44},
	"Europe/Vienna": {48.21, 16.37}, "Europe/Brussels": {50.85, 4.35},
	"Asia/Tokyo": {35.68, 139.69}, "Asia/Seoul": {37.57, 126.98},
	"Asia/Shanghai": {31.23, 121.47}, "Asia/Hong_Kong": {22.32, 114.17},
	"Asia/Singapore": {1.35, 103.82}, "Asia/Bangkok": {13.76, 100.5},
	"Asia/Jakarta": {-6.21, 106.85}, "Asia/Manila": {14.6, 120.98},
	"Asia/Kolkata": {19.08, 72.88}, "Asia/Dubai": {25.2, 55.27},
	"Asia/Jerusalem": {31.78, 35.22}, "Asia/Taipei": {25.03, 121.57},
	"Australia/Sydney": {-33.87, 151.21}, "Australia/Melbourne": {-37.81, 144.96},
	"Australia/Perth": {-31.95, 115.86}, "Pacific/Auckland": {-36.85, 174.76},
	"Africa/Johannesburg": {-26.2, 28.05}, "Africa/Cairo": {30.04, 31.24},
	"Africa/Lagos": {6.52, 3.38}, "Africa/Nairobi": {-1.29, 36.82},
	"UTC": {51.48, 0.0},
}
