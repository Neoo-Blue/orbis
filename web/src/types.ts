export type Mode = 'observe' | 'inline'
export type Verdict = 'allow' | 'block' | 'filtered' | 'pending'

export interface Client {
  id: string
  mac?: string
  ip: string
  hostname?: string
  vendor?: string
  os_guess?: string
  device_type?: string
  label?: string
  zone?: string
  first_seen: string
  last_seen: string
  rx_bytes: number
  tx_bytes: number
  blocked: boolean
  policy_id?: string
  vpn_route?: string
  notes?: string
  meta?: Record<string, string>
  online: boolean
  active_flows: number
  rate_in: number
  rate_out: number
}

export interface Flow {
  id: string
  client_id?: string
  started_at: string
  ended_at?: string
  last_seen: string
  proto: string
  src_ip: string
  src_port: number
  dst_ip: string
  dst_port: number
  direction: 'in' | 'out' | 'local'
  hostname?: string
  sni?: string
  app?: string
  ja4?: string
  packets_in: number
  packets_out: number
  bytes_in: number
  bytes_out: number
  verdict: Verdict
  rule_id?: string
  reason?: string
  country?: string
  city?: string
  lat: number
  lon: number
  asn?: number
  as_org?: string
  risk: number
  tags?: string[]
}

export interface DNSQuery {
  id: number
  ts: string
  client_id?: string
  client_ip: string
  name: string
  qtype: string
  rcode: string
  blocked: boolean
  block_source?: string
  cname_chain?: string[]
  answer?: string[]
  upstream?: string
  latency_ms: number
  cached: boolean
}

export interface Rule {
  id: string
  position: number
  enabled: boolean
  name: string
  description?: string
  chain: string
  action: string
  src_zone?: string
  dst_zone?: string
  src?: string
  dst?: string
  proto?: string
  src_port?: string
  dst_port?: string
  schedule?: string
  log: boolean
  counter_pkts: number
  counter_bytes: number
  origin: string
  created_at: string
  updated_at: string
}

export interface EventItem {
  id: string
  ts: string
  severity: 'info' | 'notice' | 'warning' | 'critical'
  category: string
  title: string
  detail?: string
  client_id?: string
  flow_id?: string
  acknowledged: boolean
  data?: Record<string, unknown>
}

export interface AdCandidate {
  domain: string
  first_seen: string
  last_seen: string
  observations: number
  distinct_clients: number
  distinct_referrers: number
  heuristic_score: number
  ai_score?: number
  ai_reason?: string
  final_score: number
  status: 'candidate' | 'review' | 'blocked' | 'dismissed'
  decided_by?: string
  decided_at?: string
  features?: Record<string, unknown>
}

export interface LocalRule {
  domain: string
  action: 'block' | 'allow'
  wildcard: boolean
  origin: string
  note?: string
  created_at: string
}

export interface BlockList {
  name: string
  url: string
  category: string
  enabled: boolean
  entries: number
  last_updated?: string
  last_error?: string
}

export interface Lease {
  mac: string
  ip: string
  hostname?: string
  scope?: string
  starts: string
  expires: string
  static: boolean
  client_id?: string
  vendor_class?: string
  fingerprint?: string
}

export interface WGPeer {
  id: string
  name: string
  public_key: string
  address: string
  allowed_ips: string[]
  enabled: boolean
  dns: string[]
  keepalive: number
  last_handshake?: string
  rx_bytes: number
  tx_bytes: number
  endpoint?: string
  created_at: string
  note?: string
}

export interface TailscaleNode {
  id: string
  name: string
  dns_name: string
  addresses: string[]
  os?: string
  online: boolean
  exit_node_option: boolean
  is_exit_node: boolean
  last_seen?: string
  rx_bytes: number
  tx_bytes: number
  routes?: string[]
}

export interface TailscaleStatus {
  available: boolean
  running: boolean
  backend_state: string
  auth_url?: string
  self?: TailscaleNode
  peers: TailscaleNode[]
  exit_node_in_use?: string
  advertising_exit_node: boolean
  exit_node_approved: boolean
  advertised_routes: string[]
  approved_routes: string[]
  pending_routes: string[]
  tailnet_name?: string
  magic_dns_suffix?: string
  version?: string
  last_error?: string
  available_exit_nodes: TailscaleNode[]
}

export interface Policy {
  id: string
  name: string
  description?: string
  categories: string[]
  allowlist: string[]
  denylist: string[]
  safe_search: boolean
  block_doh: boolean
  unfiltered?: boolean
  blocked_services?: string[]
  schedule?: string
  created_at: string
  updated_at: string
}

// ---- simple interface ----

export interface Health {
  resources?: NodeResources
  level: 'ok' | 'attention' | 'problem'
  headline: string
  points: Array<{ level: 'ok' | 'attention' | 'problem'; text: string }>
  devices_online: number
  devices_total: number
  devices_paused: number
  blocked_today: number
  protection_on: boolean
  youtube_tv: boolean
  mode: string
  brief?: { headline: string; body: string; ts: string; severity: string }
}

export interface ServiceBundle { id: string; name: string; domains: number }

export interface DNSShortcut { name: string; target: string; mode: 'redirect' | 'proxy'; note?: string }

export interface Summary {
  flows: number
  flows_blocked: number
  bytes_in: number
  bytes_out: number
  dns_queries: number
  dns_blocked: number
  dns_cached: number
  block_rate: number
  clients: number
  clients_online: number
  open_alerts: number
  ad_candidates: number
  blocklist_entries: number
  active_flows: number
  flows_seen: number
  sni_extracted: number
  quic_decrypted: number
  mode: Mode
  uptime_seconds: number
}

export interface SysctlStatus {
  key: string
  want: string
  current: string
  ok: boolean
  why: string
  critical: boolean
  error?: string
}

export interface UpdateRelease {
  tag: string
  version: string
  name: string
  notes: string
  url: string
  published_at: string
  assets: { name: string; url: string; size: number }[]
}

export interface UpdateStatus {
  current: string
  method: 'systemd' | 'binary' | 'docker' | 'dev' | 'unknown'
  can_apply: boolean
  state: 'idle' | 'checking' | 'downloading' | 'verifying' | 'installing' | 'restarting' | 'installed' | 'error'
  progress: number
  error?: string
  check_error?: string
  checked_at?: string
  arch: string
  available: boolean
  latest?: UpdateRelease
}

export interface NodeResources {
  sampled_at: string
  process_cpu_percent: number
  host_cpu_percent: number
  cores: number
  rss_bytes: number
  heap_bytes: number
  go_sys_bytes: number
  goroutines: number
  mem_total_bytes: number
  mem_available_bytes: number
  load1: number
  load5: number
  load15: number
  temp_c?: number
  throttled?: string
  uptime_seconds: number
}

export interface SystemStatus {
  mode: Mode
  node: string
  version?: string
  uptime_sec: number
  resources?: NodeResources
  capture: Record<string, number | boolean>
  dns: Record<string, unknown>
  dhcp: Record<string, unknown>
  firewall: Record<string, unknown>
  vpn: Record<string, unknown>
  tailscale: TailscaleStatus
  adblock: Record<string, unknown>
  geoip: Record<string, unknown>
  bus: Record<string, unknown>
  sysctl: SysctlStatus[]
  self?: Record<string, unknown>
  filter_proxy: Record<string, unknown>
  ca?: Record<string, unknown>
  ai: Record<string, unknown>
}

export interface GlobeArc {
  id: string
  client_id?: string
  direction: 'in' | 'out' | 'local'
  bytes_in: number
  bytes_out: number
  start_lat: number
  start_lng: number
  end_lat: number
  end_lng: number
  label: string
  app?: string
  country?: string
  city?: string
  org?: string
  verdict: Verdict
  bytes: number
  port: number
  proto: string
  risk: number
  started: number
  active: boolean
  src: string
  dst: string
}

export interface GlobeData {
  home: { lat: number; lng: number; label: string }
  arcs: GlobeArc[]
  countries: Array<{ country: string; connections: number; bytes: number; blocked: number; lat: number; lon: number }>
  mode: string
}

export interface ChatTurn {
  kind: 'text' | 'tool_call' | 'tool_result' | 'error' | 'done'
  text?: string
  tool?: string
  input?: unknown
  result?: string
  is_error?: boolean
  model?: string
}

// ---- assistant plumbing ----

export interface AIModelInfo {
  id: string
  name: string
  free: boolean
  context: number
  max_output: number
  tools: boolean
  reasoning: boolean
  structured: boolean
  tool_ok: boolean | null
  json_ok: boolean | null
  latency_ms: number
  chat_rank: number
  fast_rank: number
  last_error: string
  last_probe?: string
  cooldown_until?: string
  requests_today?: number
  failures_today?: number
  tokens_out_today?: number
  reasoning_locked?: boolean
}

export interface AIModelsStatus {
  provider: string
  openrouter: boolean
  prefer_free: boolean
  auto_discover: boolean
  configured: boolean
  enabled: boolean
  model: string
  fast_model: string
  models: AIModelInfo[]
  chat_chain: string[]
  fast_chain: string[]
  usage: Array<{ model: string; requests: number; failures: number; tokens_in: number; tokens_out: number }>
  requests_today: number
  free_today: number
  free_budget: number
  free_cap: number
  probing: boolean
  probe_error: string
  last_probe?: string
  day: string
}

export interface Recommendation {
  id: string
  ts: string
  kind: 'allow' | 'block' | 'investigate'
  domain: string
  reason: string
  confidence: number
  evidence?: Record<string, unknown>
  status: 'open' | 'accepted' | 'dismissed' | 'expired'
  decided_at?: string
  decided_by?: string
  model?: string
}

export interface AINote {
  id: string
  ts: string
  note: string
  source: string
}

export interface Issue {
  id: string
  fingerprint: string
  first_seen: string
  last_seen: string
  occurrences: number
  severity: 'info' | 'notice' | 'warning' | 'critical'
  category: string
  title: string
  detail: string
  diagnostics?: string
  source: 'auto' | 'user' | 'assistant'
  status: 'open' | 'reported' | 'dismissed' | 'resolved'
  github_number?: number
  github_url?: string
  reported_at?: string
  last_error?: string
}

export interface IssuesResponse {
  issues: Issue[]
  recording: { enabled: boolean; auto_capture: boolean }
  github: { enabled: boolean; repo: string; ready: boolean; via: 'token' | 'relay'; auto_report: boolean; max_per_day: number }
}

// ---- services ----

export interface ServiceTotal {
  service: string
  category: string
  client_id?: string
  devices: number
  conns: number
  bytes_in: number
  bytes_out: number
  lookups: number
  blocked: number
  spark?: number[]
}

export interface ServiceDevice {
  client_id: string
  name: string
  ip?: string
  mac?: string
  vendor?: string
  type?: string
  online?: boolean
  services: number | ServiceTotal[]
  conns: number
  bytes_in: number
  bytes_out: number
  lookups: number
  blocked: number
  bytes_visible: boolean
  intercepted?: boolean
}

export interface ServicePoint {
  t: number
  bytes_in: number
  bytes_out: number
  conns: number
  lookups: number
  blocked: number
}

export interface ServicesResponse {
  since: string
  until: string
  client_id: string
  services: ServiceTotal[]
  devices: ServiceDevice[]
  mode: string
  catalogue: number
}

export interface ServiceDetail {
  service: string
  since: string
  until: string
  devices: Array<{ client_id: string; name: string; ip?: string; conns: number; bytes_in: number; bytes_out: number; lookups: number; blocked: number; bytes_visible: boolean }>
  series: ServicePoint[]
  hosts: Array<{ host: string; conns: number; bytes_in: number; bytes_out: number }>
}

export interface AIBrief {
  id: string
  ts: string
  hours: number
  model: string
  severity: 'info' | 'notice' | 'warning'
  headline: string
  body: string
}

export interface ChatMessage {
  id: string
  conversation: string
  ts: string
  role: 'user' | 'assistant' | 'tool'
  content: string
  tool_calls?: string
  tool_result?: string
  model?: string
}

export interface InterfaceInfo {
  name: string
  mac?: string
  up: boolean
  loopback: boolean
  mtu: number
  addresses: string[]
  virtual: boolean
}

export interface AuditEntry {
  id: number
  ts: string
  actor: string
  action: string
  target?: string
  before?: string
  after?: string
  result?: string
}

/** Config mirrors the daemon's YAML, with secrets already masked. */
export interface AppConfig {
  mode: Mode
  node: {
    name: string; data_dir: string; timezone: string
    latitude: number; longitude: number; locate_public_ip: boolean
    ui_mode?: string; onboarded_mode?: string
  }
  api: { listen: string; web_root: string; allow_cors: boolean }
  store: { path: string; flow_retention_days: number; event_retention_days: number }
  capture: {
    enabled: boolean; interfaces: string[]; snaplen: number
    conntrack: boolean; conntrack_interval_sec: number
    flow_idle_timeout_sec: number; max_active_flows: number
  }
  dns: {
    enabled: boolean; listen: string[]; upstreams: string[]; strategy: string
    cache_size: number; min_ttl: number; max_ttl: number; block_ttl: number
    sinkhole_ipv4: string; sinkhole_ipv6: string; log_queries: boolean
    local_domain: string; block_ede: boolean
  }
  adblock: {
    enabled: boolean; lists: BlockList[]; update_interval_hours: number
    allowlist: string[]; denylist: string[]; sni_blocking: boolean
    cname_uncloak: boolean; block_dns_bypass: boolean; streaming_ads: boolean
    smart_capture: {
      enabled: boolean; min_observations: number; auto_block_score: number
      review_score: number; use_ai: boolean; interval_minutes: number
      max_auto_blocks_per_day: number
    }
  }
  mitm: {
    enabled: boolean; listen_http: string; listen_tls: string; ca_dir: string
    intercept_hosts: string[]; bypass_hosts: string[]; only_clients: string[]
    filters: {
      youtube: boolean; youtube_in_page: boolean; youtube_sponsorblock: boolean
      generic_json_ads: boolean; html_cosmetic: boolean; tracker_beacons: boolean
    }
  }
  firewall: {
    enabled: boolean
    zones: Array<{ name: string; interfaces: string[]; subnets: string[]; trust: string }>
    wan_interface: string; default_forward: string; log_dropped: boolean
    nflog_group: number; ipv6: boolean; flow_offload: boolean; anti_lockout: boolean
  }
  dhcp: {
    enabled: boolean
    scopes: Array<{
      name: string; interface: string; subnet: string; range_start: string; range_end: string
      gateway: string; dns: string[]; domain: string; lease_hours: number; mtu: number; ntp: string[]
    }>
    static: Array<{ mac: string; ip: string; hostname: string }>
  }
  vpn: {
    server: {
      enabled: boolean; interface: string; listen_port: number; address: string
      endpoint: string; dns: string[]; mtu: number
    }
    clients: Array<{
      name: string; enabled: boolean; interface: string; address: string
      peer_pubkey: string; endpoint: string; allowed_ips: string[]
      keepalive: number; mtu: number; route_table: number; kill_switch: boolean
    }>
  }
  tailscale: {
    enabled: boolean; hostname: string; auth_key: string; login_server: string
    advertise_exit_node: boolean; exit_node: string; exit_node_allow_lan: boolean
    steer_clients: string[]; advertise_routes: string[]; accept_routes: boolean
    accept_dns: boolean; ssh: boolean; shields_up: boolean; route_table: number
  }
  ai: {
    enabled: boolean; provider: string; base_url: string; api_key: string
    model: string; fast_model: string; max_tokens: number; allow_write: boolean
    anomaly: {
      enabled: boolean; interval_minutes: number; beacon_min_samples: number
      beacon_jitter_tolerance: number; new_device_alert: boolean
      exfil_bytes_threshold: number; use_ai: boolean
    }
    prefer_free: boolean; auto_discover: boolean
    model_chain: string[]; fast_model_chain: string[]
    probe_interval_hours: number; free_daily_budget: number
    brief: { enabled: boolean; interval_hours: number; notify: boolean }
    review: { enabled: boolean; interval_hours: number; max_suggestions: number }
  }
  issues: {
    enabled: boolean; auto_capture: boolean; redact_extra: string[]
    github: {
      enabled: boolean; repo: string; token: string; relay_url: string
      auto_report: boolean; max_per_day: number; include_diagnostics: boolean
    }
  }
  geoip: { city_db: string; asn_db: string }
  threat: {
    enabled: boolean; feeds: ThreatFeedConfig[]; update_interval_hours: number
    block_outbound: boolean; block_inbound: boolean; allow: string[]; auto_ban_scanners: boolean
    crowdsec: { enabled: boolean; url: string; api_key: string; poll_seconds: number }
  }
  discover: {
    enabled: boolean; interval_hours: number; extra_ports: number[]
    docker: Array<{ name: string; url: string; enabled: boolean }>; upnp: boolean
  }
  wifi: {
    enabled: boolean; interface: string; ssid: string; passphrase: string; band: string; channel: number
    country: string; hidden: boolean; isolate_clients: boolean; mode: string; bridge: string; subnet: string
    lan_access: boolean; wpa3: boolean
  }
  country: {
    enabled: boolean; mode: 'block' | 'allow'; countries: string[]; block_outbound: boolean; block_inbound: boolean
    dns: boolean; exempt_clients: string[]; exempt_domains: string[]; exempt_ips: string[]
  }
  ids: { enabled: boolean; journal: boolean; syslog_listen: string; flows: boolean; ignore: string[]; ban_multiplier: number }
}

// ---- hosted apps, storage, port forwards ----

export interface LANService {
  host: string
  port: number
  proto: string
  name: string
  kind: 'app' | 'admin' | 'storage' | 'infra' | 'web' | 'other'
  category?: string
  title?: string
  server?: string
  scheme?: string
  source: 'scan' | 'docker'
  container?: string
  image?: string
  sensitive: boolean
  first_seen: string
  last_seen: string
  online: boolean
}

export interface HostedHost {
  ID: string
  IP: string
  Name: string
  Vendor?: string
  DeviceType?: string
  MAC?: string
  Online: boolean
  LastSeen: string
  services: LANService[]
  docker: boolean
  storage: boolean
}

export interface StorageDevice {
  ID: string
  IP: string
  Name: string
  Vendor?: string
  DeviceType?: string
  Online: boolean
  protocols: Array<{ name: string; port: number }>
  web_ui?: string
  users: Array<{ ip: string; connections: number; bytes_in: number; bytes_out: number }>
  bytes_in: number
  bytes_out: number
  exposed: string[]
}

export interface PortForward {
  id: string
  name: string
  proto: string
  ext_port: number
  host: string
  port: number
  method: 'nft' | 'upnp'
  rule_id?: string
  lease_until?: string
  created: string
  actor?: string
}

export interface RouterInfo {
  upnp_enabled: boolean
  found?: boolean
  error?: string
  model?: string
  name?: string
  external_ip?: string
  mappings?: Array<{ ext_port: number; proto: string; host: string; port: number; description: string; enabled: boolean; lease_seconds: number; ours: boolean }>
  mappings_error?: string
}

export interface HostedResponse {
  scanning: boolean
  last_scan?: string
  last_error?: string
  enabled: boolean
  interval_hours: number
  hosts: HostedHost[]
  docker: Array<{ name: string; url: string; enabled: boolean }>
  forwarding: { inline: boolean; upnp: boolean }
}

// ---- cables, wi-fi, countries ----

export interface NetLink {
  name: string
  mac: string
  wireless: boolean
  carrier: boolean
  up: boolean
  speed_mbps?: number
  addresses: string[]
  default_route: boolean
  neighbours: number
  clients: number
  role: 'wan' | 'lan' | 'wifi' | 'unplugged' | 'single' | ''
  configured: 'wan' | 'lan' | 'none'
  confidence: 'high' | 'low' | ''
  evidence: string[]
}

export interface LinkSuggestion {
  wan: string
  lan: string[]
  wifi: string[]
  confidence: 'high' | 'low'
  changes: string[]
  reason: string
}

export interface LinksResponse {
  links: NetLink[]
  suggestion: LinkSuggestion
  auto_assign: boolean
  mode: string
  wan_interface: string
}

export interface WiFiClient {
  mac: string
  name?: string
  ip?: string
  signal_dbm?: number
  rx_bytes: number
  tx_bytes: number
  connected_seconds: number
}

export interface WiFiStatus {
  enabled: boolean
  running: boolean
  interface: string
  ssid: string
  mode: string
  subnet: string
  error: string
  restarts: number
  hostapd_available: boolean
  iw_available: boolean
  adapters: string[]
  hostapd_log?: string
  since?: string
  clients?: WiFiClient[]
  channel?: number
  channel_info?: string
  type?: string
  passphrase?: string
  config?: { band: string; channel: number; country: string; hidden: boolean; isolate_clients: boolean; bridge: string; lan_access: boolean; wpa3: boolean; interface: string }
}

export interface CountryStatus {
  enabled: boolean
  mode: 'block' | 'allow'
  countries: string[]
  block_outbound: boolean
  block_inbound: boolean
  dns: boolean
  exempt_clients: string[]
  exempt_domains: string[]
  exempt_ips: string[]
  set_sizes: Record<string, number>
  set_total: number
  building: boolean
  error: string
  counters: Record<string, number>
  packet_sets: boolean
  last_build?: string
  enforcement: { mode: string; inline: boolean; nft_available: boolean; intercepted_clients: number; detect_only: boolean }
  seen?: Array<{ country: string; connections: number; bytes: number; blocked: number }>
}

// ---- intrusion detection ----

export interface IDSAlert {
  id: number
  ts: string
  ip: string
  scenario: string
  count: number
  source: string
  host?: string
  sample?: string
  action: 'ban' | 'reported' | 'ban-failed'
  ban_until?: string
  country?: string
  as_org?: string
}

export interface IDSStatus {
  enabled: boolean
  journal: boolean
  auth_log: string
  flows: boolean
  lines: number
  hits: number
  bans_since_start: number
  ignore: string[]
  ban_multiplier: number
  last_line?: string
  syslog: { listen: string; running: boolean; error?: string; received?: number; hosts?: string[] }
  rules: Array<{ kind: string; title: string; threshold: number; window_seconds: number; ban_seconds: number }>
  alerts_24h?: Record<string, number>
  bans_24h?: number
  alerts: IDSAlert[]
  offenders: Array<{ ip: string; country?: string; as_org?: string; alerts: number; bans: number; last: string; scenarios: string[] }>
  enforcement: { mode: string; inline: boolean; nft_available: boolean; intercepted_clients: number; detect_only: boolean }
}

// ---- threat intelligence ----

export interface ThreatFeedConfig { name: string; url: string; enabled: boolean; category: string }

export interface ThreatFeed extends ThreatFeedConfig {
  entries: number
  skipped: number
  fetched_at?: string
  last_error?: string
}

export interface ThreatDecision {
  id: string
  value: string
  source: string
  reason?: string
  origin?: string
  external_id?: number
  actor?: string
  created: string
  until?: string
}

export interface ThreatHit {
  id: number
  ts: string
  client_id?: string
  local_ip?: string
  remote_ip: string
  prefix?: string
  source: string
  reason?: string
  direction: 'in' | 'out'
  port?: number
  proto?: string
  enforced: boolean
  flow_id?: string
  country?: string
  as_org?: string
}

export interface ThreatStatus {
  enabled: boolean
  block_outbound: boolean
  block_inbound: boolean
  entries: number
  excluded_by_allow: number
  decisions: number
  decisions_by_source: Record<string, number>
  hits_24h: number
  dropped_24h: number
  hits_since_start: number
  auto_ban_scanners: boolean
  update_interval_hours: number
  allow: string[]
  last_build?: string
  crowdsec: {
    enabled: boolean; url: string; configured: boolean; poll_seconds: number
    decisions: number; ignored: number; last_error: string; last_pull?: string
  }
  enforcement: { mode: string; inline: boolean; nft_available: boolean; intercepted_clients: number; detect_only: boolean }
}

// ---- YouTube (Lounge engine) ----

export interface AdRecord {
  at: string
  ad_video_id: string
  content_video_id: string
  duration: number
  watched: number
  skippable: boolean
  bumper: boolean
  muted: boolean
  attempts: number
  reloaded: boolean
  outcome: 'skipped' | 'played' | 'abandoned' | 'lost'
  reason: string
}

export interface LoungeDeviceStats {
  screen_id: string
  name: string
  connected: boolean
  online: boolean
  video_id: string
  position: number
  ad_active: boolean
  ads_handled: number
  ads_skipped: number
  ads_lost: number
  reloads: number
  reloads_resisted: number
  segments_skipped: number
  segments_muted: number
  segments_loaded: number
  seconds_saved: number
  last_error?: string
  last_event?: string
  last_event_at?: string
  recent: AdRecord[]
}

export interface DiscoveredScreen {
  name: string
  model: string
  location: string
  host: string
  screen_id: string
  app_state: string
}

export interface CoverageRow {
  device_class: string
  engine: string
  no_ca: boolean
  covered: boolean
  note: string
}

export interface YouTubeStatus {
  enabled: boolean
  auto_discover: boolean
  skip_ads: boolean
  mute_ads: boolean
  reload_unskippable: boolean
  categories: string[]
  devices: LoungeDeviceStats[]
  discovered: DiscoveredScreen[]
  coverage: CoverageRow[]
}

export interface LoungeDevice {
  screen_id: string
  name: string
  offset: number
}

// ---- notifications ----

export interface Webhook {
  name: string; enabled: boolean; url: string
  format?: string; headers?: Record<string, string>
}

export interface NotifyConfig {
  enabled: boolean
  min_severity: string
  dedupe_minutes: number
  webhooks: Webhook[]
  email: {
    enabled: boolean; host: string; port: number
    username: string; password: string; from: string; to: string[]
  }
}

// ---- gateway ----

export interface StaticRoute {
  name: string; enabled: boolean; destination: string
  gateway?: string; interface?: string; metric?: number; table?: number
}

export interface WANLink {
  name: string; enabled: boolean; interface: string
  gateway?: string; priority: number; weight?: number; probes?: string[]
}

export interface MultiWANConfig {
  enabled: boolean; links: WANLink[]
  interval_seconds: number; failures_to_down: number
  successes_to_up: number; load_balance: boolean
}

export interface LinkState {
  name: string; interface: string; gateway: string
  up: boolean; active: boolean; latency_ms: number; loss_percent: number
  consecutive_failures: number; consecutive_successes: number
  last_change: string; last_error?: string
}

export interface WANStatus {
  config: MultiWANConfig; running: boolean; active: string; links: LinkState[]
}

export interface ShapingConfig {
  enabled: boolean; interface: string
  upload_kbps: number; download_kbps: number
  headroom_percent: number; overhead?: string
  discipline: string; prioritise_interactive: boolean
}

export interface ShapingStatus {
  applied: boolean; interface: string; discipline: string
  egress_kbps: number; ingress_kbps: number; qdisc?: string; detail?: string
}

export interface PortMapping {
  protocol: string; client: string
  internal_port: number; external_port: number
  expires: string; created: string
}

// ---- tools ----

export interface PingResult {
  target: string; sent: number; received: number; loss_percent: number
  min_ms: number; avg_ms: number; max_ms: number; raw: string
}

export interface TracerouteHop {
  hop: number; host: string; address: string; rtts: string[]
}

export interface SpeedResult {
  download_mbps: number; upload_mbps: number
  latency_ms: number; jitter_ms: number
  server: string; ran_at: string; note?: string
}

// ---- ask on first connection ----

export interface ConsentRequest {
  id: string; client_id: string; client_ip: string; host: string
  dst_ip: string; port: number; proto: string; app?: string
  country?: string; as_org?: string
  first_seen: string; last_seen: string; count: number
}

export interface ConsentRule {
  client_id: string; host: string
  decision: 'allow' | 'deny'; decided_at: string; scope: string
}

export interface ConsentStatus {
  enrolled: string[]; pending: ConsentRequest[]; rules: ConsentRule[]
}

// ---- DNS tooling ----

export interface DiagnoseStep {
  stage: string
  hit: boolean
  verdict: 'allow' | 'block' | 'none'
  detail: string
  rule?: string
  source?: string
}

export interface Diagnosis {
  domain: string
  verdict: 'allow' | 'block'
  reason: string
  steps: DiagnoseStep[]
  cname_chain: string[] | null
  answers: string[] | null
  policy: string
}

export interface ImportResult {
  exact: number
  wildcard: number
  total: number
  sample: string[]
  risky: string[] | null
  action: string
  dry_run: boolean
  imported: number
}

// ---- onboarding ----

export interface PlacementCheck {
  name: string
  status: 'ok' | 'warn' | 'fail'
  detail: string
  fix?: string
}

export interface OnboardingState {
  links?: { links: NetLink[]; suggestion: LinkSuggestion } | null
  onboarded: boolean
  mode: string
  password_set: boolean
  node_name: string
  current_mode: string
  placement: PlacementCheck[]
  interfaces: InterfaceInfo[]
  dns_enabled: boolean
  dhcp_enabled: boolean
  adblock: boolean
  lounge_enabled: boolean
}

// ---- topology ----

export interface TopoNode {
  id: string
  ip: string
  mac?: string
  hostname?: string
  label: string
  vendor?: string
  role: string
  platform?: string
  confidence: 'confirmed' | 'inferred' | 'guessed'
  evidence?: string[]
  virtual: boolean
  parent_id?: string
  parent_basis?: string
  services?: string[]
  online: boolean
  bytes_in: number
  bytes_out: number
  conns_in: number
  conns_out: number
  external_conns: number
  last_seen?: string
}

export interface TopoEdge {
  from: string
  to: string
  kind: 'hosts' | 'traffic'
  bytes?: number
  conns?: number
  direction?: string
}

export interface TopoGraph {
  nodes: TopoNode[]
  edges: TopoEdge[]
  subnet?: string
  scanned_at?: string
  notes?: string[]
}

// ---- ARP interception ----

export interface InterceptConfig {
  enabled: boolean
  lan_interface: string
  gateway: string
  clients: Record<string, string>
  redirect_dns: boolean
  redirect_http: boolean
}

export interface InterceptStats {
  running: boolean
  interface: string
  gateway: string
  gateway_mac: string
  targets: number
  reasserts: number
  restores: number
  last_reassert?: string
  started_at?: string
}

export interface InterceptStatus {
  config: InterceptConfig
  stats: InterceptStats
  gateway: string
}

// ---- local DNS records ----

export interface DNSRecord {
  name: string
  type: string
  value: string
  ttl?: number
  priority?: number
  weight?: number
  port?: number
}

// ---- alerts & reports ----

export interface AlertRule {
  id: string
  name: string
  enabled: boolean
  type: string
  match: string
  threshold: number
  severity: string
  cooldown_minutes: number
}

export interface ReportData {
  node: string
  window: string
  generated_at: string
  dns_queries: number
  dns_blocked: number
  block_rate: number
  devices: number
  new_devices: string[]
  bytes_in: number
  bytes_out: number
  top_talkers: Array<{ label: string; value: number }>
  top_blocked: Array<{ label: string; value: number }>
  top_countries: Array<{ label: string; value: number }>
}

export interface BuiltinList {
  id: string
  name: string
  entries: number
  enabled: boolean
  category: string
  key: string
  description: string
}
