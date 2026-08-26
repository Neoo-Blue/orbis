// Package config holds the on-disk configuration for orbisd.
//
// The file is YAML at /etc/orbis/orbis.yaml. Every subsystem is opt-in: a
// freshly installed node comes up in "observe" mode where it watches traffic
// that happens to reach it but never takes over routing, DNS, or DHCP for the
// network. Flipping a subsystem to enabled is an explicit act.
package config

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sync"

	"github.com/Neoo-Blue/orbis/internal/netconf"
	"gopkg.in/yaml.v3"
)

// Mode controls how aggressively the node inserts itself into the network.
type Mode string

const (
	// ModeObserve watches only. No nftables ruleset is installed, no DHCP
	// offers are sent, and DNS answers are served only to clients that
	// deliberately point at us. This is the install default.
	ModeObserve Mode = "observe"
	// ModeInline makes the node a real gateway: nftables forwarding + NAT,
	// DHCP authoritative, DNS enforced.
	ModeInline Mode = "inline"
)

type Config struct {
	Mode      Mode            `yaml:"mode" json:"mode"`
	Node      NodeConfig      `yaml:"node" json:"node"`
	Network   NetworkConfig   `yaml:"network" json:"network"`
	API       APIConfig       `yaml:"api" json:"api"`
	Store     StoreConfig     `yaml:"store" json:"store"`
	Capture   CaptureConfig   `yaml:"capture" json:"capture"`
	DNS       DNSConfig       `yaml:"dns" json:"dns"`
	AdBlock   AdBlockConfig   `yaml:"adblock" json:"adblock"`
	MITM      MITMConfig      `yaml:"mitm" json:"mitm"`
	YouTube   YouTubeConfig   `yaml:"youtube" json:"youtube"`
	Firewall  FirewallConfig  `yaml:"firewall" json:"firewall"`
	DHCP      DHCPConfig      `yaml:"dhcp" json:"dhcp"`
	VPN       VPNConfig       `yaml:"vpn" json:"vpn"`
	Tailscale TailscaleConfig `yaml:"tailscale" json:"tailscale"`
	AI        AIConfig        `yaml:"ai" json:"ai"`
	GeoIP     GeoIPConfig     `yaml:"geoip" json:"geoip"`

	// path and mu are runtime state, not configuration. mu is a pointer so
	// that a Snapshot — which is a by-value copy — does not carry a copied
	// lock; snapshots set it to nil and are read-only by construction.
	path string
	mu   *sync.RWMutex
}

// lock/unlock tolerate a nil mutex so the same methods work on a snapshot.
func (c *Config) lock() {
	if c.mu != nil {
		c.mu.Lock()
	}
}
func (c *Config) unlock() {
	if c.mu != nil {
		c.mu.Unlock()
	}
}
func (c *Config) rlock() {
	if c.mu != nil {
		c.mu.RLock()
	}
}
func (c *Config) runlock() {
	if c.mu != nil {
		c.mu.RUnlock()
	}
}

// Live reports whether this Config is the daemon's authoritative instance
// rather than a snapshot.
func (c *Config) Live() bool { return c.mu != nil }

// NetworkConfig covers interfaces Orbis creates itself, as opposed to ones
// the host already provides.
type NetworkConfig struct {
	// VLANs are 802.1Q tagged interfaces. Each becomes a normal interface
	// that zones, DHCP scopes and firewall rules can refer to by name.
	VLANs []netconf.VLAN `yaml:"vlans" json:"vlans"`
}

type NodeConfig struct {
	Name     string `yaml:"name" json:"name"`
	DataDir  string `yaml:"data_dir" json:"data_dir"`
	Timezone string `yaml:"timezone" json:"timezone"`
	// Latitude/Longitude pin this node on the globe. When both are zero the
	// node discovers its own public address and geolocates it locally.
	Latitude  float64 `yaml:"latitude" json:"latitude"`
	Longitude float64 `yaml:"longitude" json:"longitude"`
	// LocatePublicIP allows the node to learn its own public address, so the
	// globe can place it correctly when it sits behind NAT. The lookup is a
	// DNS query that asks a resolver to echo the source address it saw; the
	// geolocation itself happens against the local database, so the node's
	// position is never transmitted. Turn it off to make no outbound query
	// at all — the globe then falls back to the timezone centroid.
	LocatePublicIP bool `yaml:"locate_public_ip" json:"locate_public_ip"`
}

type APIConfig struct {
	Listen       string   `yaml:"listen" json:"listen"`
	WebRoot      string   `yaml:"web_root" json:"web_root"`
	TrustedProxy []string `yaml:"trusted_proxies" json:"trusted_proxies"`
	// SessionKey is generated on first boot if empty.
	SessionKey string `yaml:"session_key" json:"session_key"`
	// AdminHash is a bcrypt hash. Empty means the setup wizard is unlocked.
	AdminHash string `yaml:"admin_hash" json:"admin_hash"`
	AllowCORS bool   `yaml:"allow_cors" json:"allow_cors"`
}

type StoreConfig struct {
	Path string `yaml:"path" json:"path"`
	// FlowRetentionDays bounds the size of the flow history table.
	FlowRetentionDays  int `yaml:"flow_retention_days" json:"flow_retention_days"`
	EventRetentionDays int `yaml:"event_retention_days" json:"event_retention_days"`
}

// Zone describes a named group of interfaces with a default posture.
type Zone struct {
	Name       string   `yaml:"name" json:"name"`
	Interfaces []string `yaml:"interfaces" json:"interfaces"`
	// Subnets is informational; used to attribute flows to a zone when the
	// capture path cannot see the interface directly.
	Subnets []string `yaml:"subnets" json:"subnets"`
	// Trust is one of "wan", "lan", "guest", "iot", "vpn", "dmz".
	Trust string `yaml:"trust" json:"trust"`
}

type CaptureConfig struct {
	Enabled bool `yaml:"enabled" json:"enabled"`
	// Interfaces to sniff. Empty means every non-loopback interface.
	Interfaces []string `yaml:"interfaces" json:"interfaces"`
	// SnapLen caps bytes copied per packet. 512 is enough for a TLS
	// ClientHello with a long SNI plus HTTP request headers.
	SnapLen int `yaml:"snaplen" json:"snaplen"`
	// BlockSizeKB / NumBlocks size the AF_PACKET ring buffer.
	BlockSizeKB int `yaml:"block_size_kb" json:"block_size_kb"`
	NumBlocks   int `yaml:"num_blocks" json:"num_blocks"`
	// BPF is an optional extra filter appended to the built-in one.
	BPF string `yaml:"bpf" json:"bpf"`
	// Conntrack polls /proc/net/nf_conntrack for byte counters that the
	// userspace sniffer cannot see (offloaded / forwarded fast path).
	Conntrack         bool `yaml:"conntrack" json:"conntrack"`
	ConntrackInterval int  `yaml:"conntrack_interval_sec" json:"conntrack_interval_sec"`
	// FlowIdleTimeout closes a flow that has seen no packets for N seconds.
	FlowIdleTimeout int `yaml:"flow_idle_timeout_sec" json:"flow_idle_timeout_sec"`
	// MaxActiveFlows is a hard cap so a scan cannot exhaust memory.
	MaxActiveFlows int `yaml:"max_active_flows" json:"max_active_flows"`
}

type DNSConfig struct {
	Enabled bool `yaml:"enabled" json:"enabled"`
	// Listen addresses for plain DNS (udp+tcp).
	Listen []string `yaml:"listen" json:"listen"`
	// Upstreams accept plain (1.1.1.1:53), DoT (tls://1.1.1.1:853) and
	// DoH (https://cloudflare-dns.com/dns-query) forms.
	Upstreams []string `yaml:"upstreams" json:"upstreams"`
	// Strategy: "parallel" races every upstream, "sequential" tries in order.
	Strategy  string `yaml:"strategy" json:"strategy"`
	CacheSize int    `yaml:"cache_size" json:"cache_size"`
	MinTTL    int    `yaml:"min_ttl" json:"min_ttl"`
	MaxTTL    int    `yaml:"max_ttl" json:"max_ttl"`
	// BlockTTL is the TTL handed out for sinkholed answers.
	BlockTTL int `yaml:"block_ttl" json:"block_ttl"`
	// SinkholeIPv4/6 are returned for blocked names. Empty => NXDOMAIN.
	SinkholeIPv4 string `yaml:"sinkhole_ipv4" json:"sinkhole_ipv4"`
	SinkholeIPv6 string `yaml:"sinkhole_ipv6" json:"sinkhole_ipv6"`
	// LogQueries records every query in the store. Costs disk.
	LogQueries bool `yaml:"log_queries" json:"log_queries"`
	// LocalDomain is appended to DHCP hostnames for local resolution.
	LocalDomain string `yaml:"local_domain" json:"local_domain"`
	// BlockEDE emits an Extended DNS Error explaining the block.
	BlockEDE bool `yaml:"block_ede" json:"block_ede"`
}

type AdBlockConfig struct {
	Enabled bool `yaml:"enabled" json:"enabled"`
	// Lists are subscription URLs (hosts / ABP / domain-list formats).
	Lists []BlockList `yaml:"lists" json:"lists"`
	// UpdateIntervalHours controls list refresh cadence.
	UpdateIntervalHours int `yaml:"update_interval_hours" json:"update_interval_hours"`
	// Allowlist / Denylist are local overrides, evaluated before lists.
	Allowlist []string `yaml:"allowlist" json:"allowlist"`
	Denylist  []string `yaml:"denylist" json:"denylist"`
	// SNIBlocking terminates TLS/QUIC sessions whose SNI matches a rule.
	// This catches hardcoded-IP and DoH-bypassing clients that never ask
	// our resolver.
	SNIBlocking bool `yaml:"sni_blocking" json:"sni_blocking"`
	// SmartCapture runs the heuristic + AI ad-domain discovery pipeline.
	SmartCapture SmartCaptureConfig `yaml:"smart_capture" json:"smart_capture"`
	// CNAMEUncloak follows CNAME chains and re-checks each hop, defeating
	// first-party CNAME trackers.
	CNAMEUncloak bool `yaml:"cname_uncloak" json:"cname_uncloak"`
	// BlockDNSBypass sinkholes known public DoH endpoints so clients cannot
	// route around the resolver.
	BlockDNSBypass bool `yaml:"block_dns_bypass" json:"block_dns_bypass"`
}

type BlockList struct {
	Name    string `yaml:"name" json:"name"`
	URL     string `yaml:"url" json:"url"`
	Enabled bool   `yaml:"enabled" json:"enabled"`
	// Category tags the list for per-client policy ("ads", "malware",
	// "tracking", "adult", "social").
	Category string `yaml:"category" json:"category"`
}

type SmartCaptureConfig struct {
	Enabled bool `yaml:"enabled" json:"enabled"`
	// MinObservations before a candidate domain is scored at all.
	MinObservations int `yaml:"min_observations" json:"min_observations"`
	// AutoBlockScore is the confidence at or above which a discovered
	// domain is promoted to a live block without human review.
	AutoBlockScore float64 `yaml:"auto_block_score" json:"auto_block_score"`
	// ReviewScore is the floor for surfacing a candidate in the UI queue.
	ReviewScore float64 `yaml:"review_score" json:"review_score"`
	// UseAI sends the top unresolved candidates to the model for a verdict.
	UseAI bool `yaml:"use_ai" json:"use_ai"`
	// IntervalMinutes between scoring passes.
	IntervalMinutes int `yaml:"interval_minutes" json:"interval_minutes"`
	// MaxAutoBlocksPerDay is a safety valve against runaway auto-blocking.
	MaxAutoBlocksPerDay int `yaml:"max_auto_blocks_per_day" json:"max_auto_blocks_per_day"`
}

// MITMConfig drives the TLS-intercepting proxy. This is what makes in-stream
// ad removal (YouTube, Twitch, in-app) possible: DNS and SNI blocking cannot
// help when ads and content share a hostname.
type MITMConfig struct {
	Enabled bool `yaml:"enabled" json:"enabled"`
	// ListenHTTP / ListenTLS are the transparent-redirect targets.
	ListenHTTP string `yaml:"listen_http" json:"listen_http"`
	ListenTLS  string `yaml:"listen_tls" json:"listen_tls"`
	// CADir holds the generated root CA that clients must trust.
	CADir string `yaml:"ca_dir" json:"ca_dir"`
	// InterceptHosts is an allowlist of SNI patterns to decrypt. Everything
	// else is spliced through untouched. Narrow by default on purpose:
	// intercepting banking or app-pinned traffic breaks clients.
	InterceptHosts []string `yaml:"intercept_hosts" json:"intercept_hosts"`
	// BypassHosts always wins over InterceptHosts (pinned apps, banks).
	BypassHosts []string `yaml:"bypass_hosts" json:"bypass_hosts"`
	// OnlyClients limits interception to specific IP/MACs. Empty = all
	// clients whose traffic is redirected here.
	OnlyClients []string `yaml:"only_clients" json:"only_clients"`
	// BlockQUIC rejects UDP/443 for intercepted zones so YouTube and Chrome,
	// which default to HTTP/3 over QUIC, fall back to the TCP path the proxy
	// can actually see. Without it the InnerTube filter silently does nothing
	// on modern clients even with the CA installed.
	BlockQUIC bool `yaml:"block_quic" json:"block_quic"`
	// Filters toggles the individual response rewriters.
	Filters MITMFilters `yaml:"filters" json:"filters"`
}

type MITMFilters struct {
	// YouTube strips ad slots from the /youtubei/v1/player response and
	// neuters ad-tracking pings. Works on web, mobile web and the native
	// apps (which use the same InnerTube API).
	YouTube bool `yaml:"youtube" json:"youtube"`
	// GenericJSONAds removes common ad payload keys from JSON responses of
	// hosts matching InterceptHosts.
	GenericJSONAds bool `yaml:"generic_json_ads" json:"generic_json_ads"`
	// HTMLCosmetic injects an element-hiding stylesheet into HTML.
	HTMLCosmetic bool `yaml:"html_cosmetic" json:"html_cosmetic"`
	// TrackerBeacons drops known analytics/beacon requests outright.
	TrackerBeacons bool `yaml:"tracker_beacons" json:"tracker_beacons"`
}

// YouTubeConfig groups the YouTube-specific ad controls that do not belong to
// the generic MITM proxy. The Lounge engine is the no-CA path: it drives the
// player on cast-capable devices (TVs, Apple TV, consoles) instead of rewriting
// the encrypted stream, so it needs nothing installed on the device.
type YouTubeConfig struct {
	Lounge LoungeConfig `yaml:"lounge" json:"lounge"`
}

type LoungeConfig struct {
	Enabled bool `yaml:"enabled" json:"enabled"`
	// AutoDiscover scans the LAN for cast-capable screens and adopts the ones
	// that expose a screen id over DIAL, with no manual pairing.
	AutoDiscover bool `yaml:"auto_discover" json:"auto_discover"`
	// SkipAds sends the skip command as soon as an ad becomes skippable.
	SkipAds bool `yaml:"skip_ads" json:"skip_ads"`
	// MuteAds silences the player for the (often unskippable) opening seconds.
	MuteAds bool `yaml:"mute_ads" json:"mute_ads"`
	// SkipCategories are SponsorBlock categories to seek past (in-video
	// sponsor reads, intros, self-promo). Separate from Google's own ads.
	SkipCategories []string `yaml:"skip_categories" json:"skip_categories"`
	// MinSkipLength drops SponsorBlock segments shorter than this many seconds.
	MinSkipLength float64 `yaml:"min_skip_length" json:"min_skip_length"`
	// SponsorBlockAPI overrides the segment database base URL.
	SponsorBlockAPI string `yaml:"sponsorblock_api" json:"sponsorblock_api"`
	// Devices are the paired/adopted screens. ScreenID is a durable control
	// credential, which is why the config file is mode 0600.
	Devices []LoungeDevice `yaml:"devices" json:"devices"`
}

type LoungeDevice struct {
	ScreenID string  `yaml:"screen_id" json:"screen_id"`
	Name     string  `yaml:"name" json:"name"`
	Offset   float64 `yaml:"offset" json:"offset"`
}

type FirewallConfig struct {
	Enabled bool   `yaml:"enabled" json:"enabled"`
	Zones   []Zone `yaml:"zones" json:"zones"`
	// WANInterface is used for masquerade + default-route policy.
	WANInterface string `yaml:"wan_interface" json:"wan_interface"`
	// DefaultForward is "accept" or "drop" for inter-zone traffic without
	// a matching rule.
	DefaultForward string `yaml:"default_forward" json:"default_forward"`
	// LogDropped mirrors drops into the event stream via nflog.
	LogDropped bool `yaml:"log_dropped" json:"log_dropped"`
	NFLogGroup int  `yaml:"nflog_group" json:"nflog_group"`
	// IPv6 enables the ip6 table alongside ip.
	IPv6 bool `yaml:"ipv6" json:"ipv6"`
	// FlowOffload enables software/hardware flowtable fast-pathing. Turning
	// this on bypasses per-packet inspection for established flows.
	FlowOffload bool `yaml:"flow_offload" json:"flow_offload"`
	// AntiLockout keeps a permanent accept for the management address so a
	// bad ruleset cannot orphan the box.
	AntiLockout bool `yaml:"anti_lockout" json:"anti_lockout"`
}

type DHCPConfig struct {
	Enabled bool         `yaml:"enabled" json:"enabled"`
	Scopes  []DHCPScope  `yaml:"scopes" json:"scopes"`
	Static  []DHCPStatic `yaml:"static" json:"static"`
}

type DHCPScope struct {
	Name       string   `yaml:"name" json:"name"`
	Interface  string   `yaml:"interface" json:"interface"`
	Subnet     string   `yaml:"subnet" json:"subnet"`
	RangeStart string   `yaml:"range_start" json:"range_start"`
	RangeEnd   string   `yaml:"range_end" json:"range_end"`
	Gateway    string   `yaml:"gateway" json:"gateway"`
	DNS        []string `yaml:"dns" json:"dns"`
	Domain     string   `yaml:"domain" json:"domain"`
	LeaseHours int      `yaml:"lease_hours" json:"lease_hours"`
	MTU        int      `yaml:"mtu" json:"mtu"`
	NTP        []string `yaml:"ntp" json:"ntp"`
}

type DHCPStatic struct {
	MAC      string `yaml:"mac" json:"mac"`
	IP       string `yaml:"ip" json:"ip"`
	Hostname string `yaml:"hostname" json:"hostname"`
}

type VPNConfig struct {
	Server WGServerConfig   `yaml:"server" json:"server"`
	Client []WGClientConfig `yaml:"clients" json:"clients"`
	// Tunnels are outbound WireGuard connections this node routes traffic
	// through. Devices are then assigned to one, so "send the TV through the
	// VPN and leave everything else alone" is expressible.
	Tunnels []TunnelConfig `yaml:"tunnels" json:"tunnels"`
	// Routes assigns sources to tunnels. A source is an address, a CIDR, or
	// the literal "all" for every LAN prefix.
	Routes []EgressRoute `yaml:"routes" json:"routes"`
}

// TunnelConfig is an outbound WireGuard tunnel, normally imported from a
// provider's wg-quick file.
type TunnelConfig struct {
	Name          string   `yaml:"name" json:"name"`
	Enabled       bool     `yaml:"enabled" json:"enabled"`
	Interface     string   `yaml:"interface" json:"interface"`
	PrivateKey    string   `yaml:"private_key" json:"private_key"`
	Addresses     []string `yaml:"addresses" json:"addresses"`
	DNS           []string `yaml:"dns" json:"dns"`
	MTU           int      `yaml:"mtu" json:"mtu"`
	PeerPublicKey string   `yaml:"peer_public_key" json:"peer_public_key"`
	PresharedKey  string   `yaml:"preshared_key" json:"preshared_key"`
	Endpoint      string   `yaml:"endpoint" json:"endpoint"`
	AllowedIPs    []string `yaml:"allowed_ips" json:"allowed_ips"`
	Keepalive     int      `yaml:"keepalive" json:"keepalive"`
	RouteTable    int      `yaml:"route_table" json:"route_table"`
	// KillSwitch drops steered traffic when the tunnel is down rather than
	// letting it fall back to the WAN unprotected.
	KillSwitch bool   `yaml:"kill_switch" json:"kill_switch"`
	Note       string `yaml:"note" json:"note"`
}

type EgressRoute struct {
	Source   string `yaml:"source" json:"source"`
	TargetID string `yaml:"target" json:"target"`
	Label    string `yaml:"label" json:"label"`
}

type WGServerConfig struct {
	Enabled    bool   `yaml:"enabled" json:"enabled"`
	Interface  string `yaml:"interface" json:"interface"`
	ListenPort int    `yaml:"listen_port" json:"listen_port"`
	PrivateKey string `yaml:"private_key" json:"private_key"`
	Address    string `yaml:"address" json:"address"`
	// Endpoint is the public host:port handed to generated peer configs.
	Endpoint string   `yaml:"endpoint" json:"endpoint"`
	DNS      []string `yaml:"dns" json:"dns"`
	MTU      int      `yaml:"mtu" json:"mtu"`
}

// WGClientConfig is an outbound tunnel (this node as a WireGuard client),
// used for policy-based routing of selected LAN clients through a provider.
type WGClientConfig struct {
	Name       string   `yaml:"name" json:"name"`
	Enabled    bool     `yaml:"enabled" json:"enabled"`
	Interface  string   `yaml:"interface" json:"interface"`
	PrivateKey string   `yaml:"private_key" json:"private_key"`
	Address    string   `yaml:"address" json:"address"`
	PeerPubkey string   `yaml:"peer_pubkey" json:"peer_pubkey"`
	PeerPSK    string   `yaml:"peer_psk" json:"peer_psk"`
	Endpoint   string   `yaml:"endpoint" json:"endpoint"`
	AllowedIPs []string `yaml:"allowed_ips" json:"allowed_ips"`
	Keepalive  int      `yaml:"keepalive" json:"keepalive"`
	MTU        int      `yaml:"mtu" json:"mtu"`
	// RouteTable is the policy routing table id for clients steered here.
	RouteTable int `yaml:"route_table" json:"route_table"`
	// KillSwitch drops steered traffic when the tunnel is down instead of
	// leaking it to the WAN.
	KillSwitch bool `yaml:"kill_switch" json:"kill_switch"`
}

// TailscaleConfig drives the tailscale CLI. Tailscale complements WireGuard
// here rather than replacing it: WireGuard is the self-hosted path with no
// third party, Tailscale is the zero-config path that traverses CGNAT.
type TailscaleConfig struct {
	Enabled bool `yaml:"enabled" json:"enabled"`
	// Hostname the node registers under in the tailnet.
	Hostname string `yaml:"hostname" json:"hostname"`
	// AuthKey allows unattended enrolment. Leave empty to log in via URL.
	AuthKey string `yaml:"auth_key" json:"auth_key"`
	// LoginServer points at Headscale or another coordination server.
	LoginServer string `yaml:"login_server" json:"login_server"`

	// AdvertiseExitNode offers this node as an exit node for the tailnet, so
	// remote devices can egress through this network. Requires approval in
	// the Tailscale admin console before it carries any traffic.
	AdvertiseExitNode bool `yaml:"advertise_exit_node" json:"advertise_exit_node"`
	// ExitNode is the peer whose egress this node should use, by name or IP.
	// Empty means route normally out the WAN.
	ExitNode string `yaml:"exit_node" json:"exit_node"`
	// ExitNodeAllowLAN keeps the local network reachable while an exit node
	// is selected. Without it, choosing an exit node cuts off this box's
	// own UI from LAN clients.
	ExitNodeAllowLAN bool `yaml:"exit_node_allow_lan" json:"exit_node_allow_lan"`
	// SteerClients lists LAN addresses or CIDRs whose traffic is policy-routed
	// through the selected exit node. Empty means only this node's own
	// traffic uses it.
	SteerClients []string `yaml:"steer_clients" json:"steer_clients"`

	// AdvertiseRoutes turns this node into a subnet router for the listed
	// CIDRs, so tailnet devices reach the LAN without a client on each host.
	AdvertiseRoutes []string `yaml:"advertise_routes" json:"advertise_routes"`
	// AcceptRoutes accepts subnet routes other nodes advertise. Off by
	// default, and deliberately so: if any tailnet node advertises a prefix
	// that covers this node's own LAN, accepting it sends locally-destined
	// traffic into the tunnel and the node drops off its own network. The
	// UI refuses to enable it silently when that overlap exists.
	AcceptRoutes bool `yaml:"accept_routes" json:"accept_routes"`
	// AcceptDNS lets the tailnet override DNS. Off by default: accepting it
	// would bypass this node's own filtering resolver.
	AcceptDNS bool `yaml:"accept_dns" json:"accept_dns"`
	// SSH enables Tailscale SSH to this node.
	SSH bool `yaml:"ssh" json:"ssh"`
	// ShieldsUp blocks all incoming tailnet connections to this node.
	ShieldsUp bool `yaml:"shields_up" json:"shields_up"`
	// RouteTable is the policy-routing table id used when steering clients.
	RouteTable int `yaml:"route_table" json:"route_table"`
}

type AIConfig struct {
	Enabled bool `yaml:"enabled" json:"enabled"`
	// Provider: "anthropic", "openai", "openrouter", "ollama".
	Provider string `yaml:"provider" json:"provider"`
	BaseURL  string `yaml:"base_url" json:"base_url"`
	APIKey   string `yaml:"api_key" json:"api_key"`
	Model    string `yaml:"model" json:"model"`
	// FastModel handles high-volume classification (ad scoring, anomaly
	// triage); Model handles chat and reasoning.
	FastModel string `yaml:"fast_model" json:"fast_model"`
	MaxTokens int    `yaml:"max_tokens" json:"max_tokens"`
	// AllowWrite lets the assistant call mutating tools. Off means the
	// assistant can inspect and propose but every change needs a click.
	AllowWrite bool `yaml:"allow_write" json:"allow_write"`
	// Anomaly turns on the background behavioural analyser.
	Anomaly AnomalyConfig `yaml:"anomaly" json:"anomaly"`
}

type AnomalyConfig struct {
	Enabled bool `yaml:"enabled" json:"enabled"`
	// IntervalMinutes between sweeps of the flow table.
	IntervalMinutes int `yaml:"interval_minutes" json:"interval_minutes"`
	// BeaconMinSamples is how many periodic connections are needed before
	// a beaconing verdict is possible.
	BeaconMinSamples int `yaml:"beacon_min_samples" json:"beacon_min_samples"`
	// BeaconJitterTolerance is the max coefficient of variation of the
	// inter-arrival gap that still counts as periodic.
	BeaconJitterTolerance float64 `yaml:"beacon_jitter_tolerance" json:"beacon_jitter_tolerance"`
	// NewDeviceAlert raises an event the first time a MAC is seen.
	NewDeviceAlert bool `yaml:"new_device_alert" json:"new_device_alert"`
	// ExfilBytesThreshold is the upload volume to a single new destination
	// that trips a data-egress alert.
	ExfilBytesThreshold int64 `yaml:"exfil_bytes_threshold" json:"exfil_bytes_threshold"`
	// UseAI escalates the top-scoring anomalies to the model for triage.
	UseAI bool `yaml:"use_ai" json:"use_ai"`
}

type GeoIPConfig struct {
	// CityDB / ASNDB are MaxMind-format .mmdb paths. When absent, the
	// bundled coarse allocation table is used so the globe still works.
	CityDB string `yaml:"city_db" json:"city_db"`
	ASNDB  string `yaml:"asn_db" json:"asn_db"`
}

// Default returns a configuration that is safe to write on a fresh install:
// everything that would change how the network behaves is off.
func Default() *Config {
	return &Config{
		mu:   &sync.RWMutex{},
		Mode: ModeObserve,
		Node: NodeConfig{
			Name:           "orbis",
			DataDir:        "/var/lib/orbis",
			Timezone:       "UTC",
			LocatePublicIP: true,
		},
		API: APIConfig{
			Listen:    ":8080",
			WebRoot:   "/usr/share/orbis/web",
			AllowCORS: false,
		},
		Store: StoreConfig{
			Path:               "/var/lib/orbis/orbis.db",
			FlowRetentionDays:  14,
			EventRetentionDays: 60,
		},
		Capture: CaptureConfig{
			Enabled:           true,
			SnapLen:           512,
			BlockSizeKB:       1024,
			NumBlocks:         32,
			Conntrack:         true,
			ConntrackInterval: 2,
			FlowIdleTimeout:   120,
			MaxActiveFlows:    65536,
		},
		DNS: DNSConfig{
			Enabled:      true,
			Listen:       []string{"0.0.0.0:53"},
			Upstreams:    []string{"tls://1.1.1.1:853", "tls://9.9.9.9:853"},
			Strategy:     "parallel",
			CacheSize:    50000,
			MinTTL:       60,
			MaxTTL:       86400,
			BlockTTL:     10,
			SinkholeIPv4: "0.0.0.0",
			SinkholeIPv6: "::",
			LogQueries:   true,
			LocalDomain:  "lan",
			BlockEDE:     true,
		},
		AdBlock: AdBlockConfig{
			Enabled:             true,
			UpdateIntervalHours: 24,
			SNIBlocking:         true,
			CNAMEUncloak:        true,
			BlockDNSBypass:      true,
			Lists:               DefaultLists(),
			SmartCapture: SmartCaptureConfig{
				Enabled:             true,
				MinObservations:     8,
				AutoBlockScore:      0.92,
				ReviewScore:         0.55,
				UseAI:               true,
				IntervalMinutes:     15,
				MaxAutoBlocksPerDay: 200,
			},
		},
		MITM: MITMConfig{
			Enabled:    false,
			ListenHTTP: "0.0.0.0:3128",
			ListenTLS:  "0.0.0.0:3129",
			CADir:      "/var/lib/orbis/ca",
			InterceptHosts: []string{
				"*.youtube.com", "youtube.com", "*.googlevideo.com",
				"*.youtube-nocookie.com", "youtubei.googleapis.com",
				"*.ytimg.com",
			},
			BypassHosts: []string{
				"*.apple.com", "*.icloud.com", "*.windowsupdate.com",
				"*.bank*", "*.chase.com", "*.paypal.com", "*.gov",
			},
			BlockQUIC: true,
			Filters: MITMFilters{
				YouTube:        true,
				GenericJSONAds: true,
				HTMLCosmetic:   false,
				TrackerBeacons: true,
			},
		},
		YouTube: YouTubeConfig{
			Lounge: LoungeConfig{
				Enabled:      false,
				AutoDiscover: true,
				SkipAds:      true,
				MuteAds:      true,
				SkipCategories: []string{
					"sponsor", "selfpromo", "interaction",
					"intro", "outro", "preview", "music_offtopic",
				},
				MinSkipLength:   1,
				SponsorBlockAPI: "https://sponsor.ajay.app/api/",
			},
		},
		Firewall: FirewallConfig{
			Enabled:        false,
			DefaultForward: "drop",
			LogDropped:     true,
			NFLogGroup:     100,
			IPv6:           true,
			FlowOffload:    false,
			AntiLockout:    true,
		},
		DHCP: DHCPConfig{Enabled: false},
		VPN: VPNConfig{
			Server: WGServerConfig{
				Enabled:    false,
				Interface:  "wg0",
				ListenPort: 51820,
				Address:    "10.66.0.1/24",
				MTU:        1420,
			},
		},
		Tailscale: TailscaleConfig{
			Enabled:          false,
			AcceptRoutes:     false,
			AcceptDNS:        false,
			ExitNodeAllowLAN: true,
			RouteTable:       52,
		},
		AI: AIConfig{
			Enabled:    false,
			Provider:   "anthropic",
			Model:      "claude-sonnet-5",
			FastModel:  "claude-haiku-4-5-20251001",
			MaxTokens:  4096,
			AllowWrite: false,
			Anomaly: AnomalyConfig{
				Enabled:               true,
				IntervalMinutes:       10,
				BeaconMinSamples:      6,
				BeaconJitterTolerance: 0.18,
				NewDeviceAlert:        true,
				ExfilBytesThreshold:   256 << 20,
				UseAI:                 false,
			},
		},
	}
}

// DefaultLists is the out-of-the-box subscription set. Every entry is a
// widely mirrored, permissively licensed list.
func DefaultLists() []BlockList {
	return []BlockList{
		{Name: "StevenBlack unified", URL: "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts", Enabled: true, Category: "ads"},
		{Name: "AdGuard DNS filter", URL: "https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt", Enabled: true, Category: "ads"},
		{Name: "OISD small", URL: "https://small.oisd.nl/domainswild", Enabled: true, Category: "ads"},
		{Name: "Peter Lowe ad/tracking", URL: "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext", Enabled: true, Category: "tracking"},
		{Name: "URLhaus malware", URL: "https://urlhaus.abuse.ch/downloads/hostfile/", Enabled: true, Category: "malware"},
		{Name: "Phishing Army", URL: "https://phishing.army/download/phishing_army_blocklist_extended.txt", Enabled: true, Category: "malware"},
		{Name: "Hagezi multi PRO", URL: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/pro.txt", Enabled: false, Category: "ads"},
		{Name: "Hagezi TIF (threat intel)", URL: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/tif.txt", Enabled: false, Category: "malware"},
		{Name: "Hagezi DoH bypass", URL: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/doh.txt", Enabled: true, Category: "bypass"},
	}
}

// Load reads a config file, filling unset fields from Default.
func Load(path string) (*Config, error) {
	c := Default()
	c.path = path

	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		if err := c.Save(); err != nil {
			return nil, fmt.Errorf("write initial config: %w", err)
		}
		return c, nil
	}
	if err != nil {
		return nil, err
	}
	// Decoding onto the defaults means an omitted key keeps its default
	// rather than becoming a zero value.
	if err := yaml.Unmarshal(raw, c); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	// Decoding replaced the struct's fields; the mutex is unexported and
	// therefore untouched, but be explicit rather than relying on that.
	if c.mu == nil {
		c.mu = &sync.RWMutex{}
	}
	c.path = path
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Config) Path() string { return c.path }

// Validate catches the misconfigurations that would otherwise surface as a
// confusing runtime failure.
func (c *Config) Validate() error {
	if c.Mode != ModeObserve && c.Mode != ModeInline {
		return fmt.Errorf("mode must be observe or inline, got %q", c.Mode)
	}
	if c.Store.Path == "" {
		return fmt.Errorf("store.path is required")
	}
	for _, l := range c.DNS.Listen {
		if _, _, err := net.SplitHostPort(l); err != nil {
			return fmt.Errorf("dns.listen %q: %w", l, err)
		}
	}
	for _, s := range c.DHCP.Scopes {
		if _, _, err := net.ParseCIDR(s.Subnet); err != nil {
			return fmt.Errorf("dhcp scope %q subnet %q: %w", s.Name, s.Subnet, err)
		}
		if net.ParseIP(s.RangeStart) == nil || net.ParseIP(s.RangeEnd) == nil {
			return fmt.Errorf("dhcp scope %q: range_start/range_end must be IPs", s.Name)
		}
	}
	seenVLAN := map[string]bool{}
	seenTag := map[string]bool{}
	for _, v := range c.Network.VLANs {
		if err := v.Validate(); err != nil {
			return fmt.Errorf("network.vlans: %w", err)
		}
		name := v.DefaultName()
		if seenVLAN[name] {
			return fmt.Errorf("two VLANs would both be called %q", name)
		}
		seenVLAN[name] = true
		// The same tag twice on one parent is a configuration mistake that
		// the kernel reports as a confusing "file exists".
		key := fmt.Sprintf("%s/%d", v.Parent, v.ID)
		if seenTag[key] {
			return fmt.Errorf("VLAN %d is defined twice on %s", v.ID, v.Parent)
		}
		seenTag[key] = true
	}

	if c.Firewall.DefaultForward != "accept" && c.Firewall.DefaultForward != "drop" {
		return fmt.Errorf("firewall.default_forward must be accept or drop")
	}
	seenTunnels := map[string]bool{}
	for _, t := range c.VPN.Tunnels {
		if t.Name == "" {
			return fmt.Errorf("every VPN tunnel needs a name")
		}
		if seenTunnels[t.Name] {
			return fmt.Errorf("two VPN tunnels are both named %q", t.Name)
		}
		seenTunnels[t.Name] = true
		for _, a := range t.Addresses {
			if _, err := netip.ParsePrefix(a); err != nil {
				if _, err2 := netip.ParseAddr(a); err2 != nil {
					return fmt.Errorf("tunnel %q address %q is not an address or CIDR", t.Name, a)
				}
			}
		}
	}
	for _, r := range c.VPN.Routes {
		// "all" and the Tailscale pseudo-target are both valid without a
		// matching tunnel entry.
		if r.TargetID == "" || r.TargetID == "wan" || r.TargetID == "tailscale" {
			continue
		}
		if !seenTunnels[r.TargetID] {
			return fmt.Errorf("a device is routed through %q, which is not a configured tunnel", r.TargetID)
		}
	}

	// Steering clients with no exit node selected silently does nothing,
	// which reads to an operator as "the feature is broken".
	if c.Tailscale.Enabled && len(c.Tailscale.SteerClients) > 0 && c.Tailscale.ExitNode == "" {
		return fmt.Errorf("tailscale.steer_clients requires tailscale.exit_node to be set")
	}
	// Inline mode without a WAN interface produces a ruleset that NATs
	// nothing and silently blackholes the LAN.
	if c.Mode == ModeInline && c.Firewall.Enabled && c.Firewall.WANInterface == "" {
		return fmt.Errorf("inline mode requires firewall.wan_interface")
	}
	return nil
}

// Save writes the config atomically so a crash mid-write cannot leave the
// node without a parseable configuration.
func (c *Config) Save() error {
	if c.mu == nil {
		// Writing a snapshot back would silently discard whatever the live
		// config changed in the meantime.
		return fmt.Errorf("cannot save a configuration snapshot")
	}
	c.lock()
	defer c.unlock()
	if c.path == "" {
		return fmt.Errorf("config has no path")
	}
	if err := os.MkdirAll(filepath.Dir(c.path), 0o750); err != nil {
		return err
	}
	out, err := yaml.Marshal(c)
	if err != nil {
		return err
	}
	tmp := c.path + ".tmp"
	if err := os.WriteFile(tmp, out, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, c.path)
}

// Update applies fn under the write lock, validates the result, and persists.
// A failed validation rolls back so a bad API call cannot wedge the daemon.
func (c *Config) Update(fn func(*Config)) error {
	if c.mu == nil {
		return fmt.Errorf("cannot update a configuration snapshot")
	}
	c.lock()
	before, err := yaml.Marshal(c)
	if err != nil {
		c.unlock()
		return err
	}
	fn(c)
	if err := c.Validate(); err != nil {
		// Roll the whole struct back rather than leaving a partially
		// applied change behind.
		_ = yaml.Unmarshal(before, c)
		c.unlock()
		return err
	}
	c.unlock()
	return c.Save()
}

// Snapshot returns a deep copy safe to hand to a goroutine or serialise.
func (c *Config) Snapshot() Config {
	c.rlock()
	defer c.runlock()
	out, _ := yaml.Marshal(c)
	var cp Config
	_ = yaml.Unmarshal(out, &cp)
	cp.path = c.path
	// mu stays nil: the result is a read-only value copy, and leaving it nil
	// makes an accidental Save or Update on it fail loudly.
	return cp
}

// Redacted returns a snapshot with secrets replaced, for the API surface.
func (c *Config) Redacted() Config {
	cp := c.Snapshot()
	const mask = "••••••••"
	if cp.AI.APIKey != "" {
		cp.AI.APIKey = mask
	}
	if cp.API.SessionKey != "" {
		cp.API.SessionKey = mask
	}
	if cp.API.AdminHash != "" {
		cp.API.AdminHash = mask
	}
	if cp.VPN.Server.PrivateKey != "" {
		cp.VPN.Server.PrivateKey = mask
	}
	if cp.Tailscale.AuthKey != "" {
		cp.Tailscale.AuthKey = mask
	}
	for i := range cp.VPN.Tunnels {
		if cp.VPN.Tunnels[i].PrivateKey != "" {
			cp.VPN.Tunnels[i].PrivateKey = mask
		}
		if cp.VPN.Tunnels[i].PresharedKey != "" {
			cp.VPN.Tunnels[i].PresharedKey = mask
		}
	}
	for i := range cp.VPN.Client {
		if cp.VPN.Client[i].PrivateKey != "" {
			cp.VPN.Client[i].PrivateKey = mask
		}
		if cp.VPN.Client[i].PeerPSK != "" {
			cp.VPN.Client[i].PeerPSK = mask
		}
	}
	return cp
}
