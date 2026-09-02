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
  schedule?: string
  created_at: string
  updated_at: string
}

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

export interface SystemStatus {
  mode: Mode
  node: string
  uptime_sec: number
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
  }
  geoip: { city_db: string; asn_db: string }
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
  outcome: 'skipped' | 'played' | 'lost'
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
