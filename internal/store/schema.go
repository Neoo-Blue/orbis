package store

// schema is applied at every boot. Each statement must be idempotent; the
// migrations slice below carries anything that cannot be expressed that way.
const schema = `
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA foreign_keys = ON;
PRAGMA busy_timeout = 5000;

-- Devices seen on the network, keyed by MAC when we have one and by IP when
-- we do not (routed traffic, VPN peers).
CREATE TABLE IF NOT EXISTS clients (
  id            TEXT PRIMARY KEY,
  mac           TEXT,
  ip            TEXT,
  hostname      TEXT,
  vendor        TEXT,
  os_guess      TEXT,
  device_type   TEXT,
  label         TEXT,
  zone          TEXT,
  first_seen    INTEGER NOT NULL,
  last_seen     INTEGER NOT NULL,
  rx_bytes      INTEGER NOT NULL DEFAULT 0,
  tx_bytes      INTEGER NOT NULL DEFAULT 0,
  blocked       INTEGER NOT NULL DEFAULT 0,
  policy_id     TEXT,
  vpn_route     TEXT,
  notes         TEXT,
  meta          TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_clients_mac ON clients(mac) WHERE mac IS NOT NULL AND mac != '';
CREATE INDEX IF NOT EXISTS idx_clients_ip ON clients(ip);
CREATE INDEX IF NOT EXISTS idx_clients_last ON clients(last_seen DESC);

-- One row per completed (or periodically checkpointed) connection.
CREATE TABLE IF NOT EXISTS flows (
  id            TEXT PRIMARY KEY,
  client_id     TEXT,
  started_at    INTEGER NOT NULL,
  ended_at      INTEGER,
  last_seen     INTEGER NOT NULL,
  proto         TEXT NOT NULL,
  src_ip        TEXT NOT NULL,
  src_port      INTEGER,
  dst_ip        TEXT NOT NULL,
  dst_port      INTEGER,
  direction     TEXT NOT NULL,
  hostname      TEXT,
  sni           TEXT,
  app           TEXT,
  ja4           TEXT,
  packets_in    INTEGER NOT NULL DEFAULT 0,
  packets_out   INTEGER NOT NULL DEFAULT 0,
  bytes_in      INTEGER NOT NULL DEFAULT 0,
  bytes_out     INTEGER NOT NULL DEFAULT 0,
  verdict       TEXT NOT NULL DEFAULT 'allow',
  rule_id       TEXT,
  reason        TEXT,
  country       TEXT,
  city          TEXT,
  lat           REAL,
  lon           REAL,
  asn           INTEGER,
  as_org        TEXT,
  risk          REAL NOT NULL DEFAULT 0,
  tags          TEXT
);
CREATE INDEX IF NOT EXISTS idx_flows_started ON flows(started_at DESC);
CREATE INDEX IF NOT EXISTS idx_flows_client ON flows(client_id, started_at DESC);
CREATE INDEX IF NOT EXISTS idx_flows_dst ON flows(dst_ip);
CREATE INDEX IF NOT EXISTS idx_flows_host ON flows(hostname);
CREATE INDEX IF NOT EXISTS idx_flows_verdict ON flows(verdict, started_at DESC);
CREATE INDEX IF NOT EXISTS idx_flows_country ON flows(country);

-- DNS query log. Separate from flows because a single flow can be preceded
-- by many lookups and we want to keep them at a different retention.
CREATE TABLE IF NOT EXISTS dns_queries (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  ts            INTEGER NOT NULL,
  client_id     TEXT,
  client_ip     TEXT,
  name          TEXT NOT NULL,
  qtype         TEXT NOT NULL,
  rcode         TEXT,
  blocked       INTEGER NOT NULL DEFAULT 0,
  block_source  TEXT,
  cname_chain   TEXT,
  answer        TEXT,
  upstream      TEXT,
  latency_ms    REAL,
  cached        INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_dns_ts ON dns_queries(ts DESC);
CREATE INDEX IF NOT EXISTS idx_dns_name ON dns_queries(name);
CREATE INDEX IF NOT EXISTS idx_dns_client ON dns_queries(client_id, ts DESC);
CREATE INDEX IF NOT EXISTS idx_dns_blocked ON dns_queries(blocked, ts DESC);

-- Firewall rules, ordered within a chain by position.
CREATE TABLE IF NOT EXISTS rules (
  id            TEXT PRIMARY KEY,
  position      INTEGER NOT NULL,
  enabled       INTEGER NOT NULL DEFAULT 1,
  name          TEXT NOT NULL,
  description   TEXT,
  chain         TEXT NOT NULL,
  action        TEXT NOT NULL,
  src_zone      TEXT,
  dst_zone      TEXT,
  src           TEXT,
  dst           TEXT,
  proto         TEXT,
  src_port      TEXT,
  dst_port      TEXT,
  schedule      TEXT,
  log           INTEGER NOT NULL DEFAULT 0,
  counter_pkts  INTEGER NOT NULL DEFAULT 0,
  counter_bytes INTEGER NOT NULL DEFAULT 0,
  origin        TEXT NOT NULL DEFAULT 'user',
  created_at    INTEGER NOT NULL,
  updated_at    INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_rules_pos ON rules(chain, position);

-- Per-client / per-group filtering policy.
CREATE TABLE IF NOT EXISTS policies (
  id            TEXT PRIMARY KEY,
  name          TEXT NOT NULL,
  description   TEXT,
  categories    TEXT NOT NULL DEFAULT '[]',
  allowlist     TEXT NOT NULL DEFAULT '[]',
  denylist      TEXT NOT NULL DEFAULT '[]',
  safe_search   INTEGER NOT NULL DEFAULT 0,
  block_doh     INTEGER NOT NULL DEFAULT 1,
  schedule      TEXT,
  created_at    INTEGER NOT NULL,
  updated_at    INTEGER NOT NULL
);

-- Events: everything worth surfacing in the timeline or alerting on.
CREATE TABLE IF NOT EXISTS events (
  id            TEXT PRIMARY KEY,
  ts            INTEGER NOT NULL,
  severity      TEXT NOT NULL,
  category      TEXT NOT NULL,
  title         TEXT NOT NULL,
  detail        TEXT,
  client_id     TEXT,
  flow_id       TEXT,
  acknowledged  INTEGER NOT NULL DEFAULT 0,
  data          TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts DESC);
CREATE INDEX IF NOT EXISTS idx_events_sev ON events(severity, ts DESC);
CREATE INDEX IF NOT EXISTS idx_events_ack ON events(acknowledged, ts DESC);

-- Aggregated blocklist domains. source is the list name; a domain present in
-- several lists gets one row per list so removing a list is clean.
CREATE TABLE IF NOT EXISTS block_domains (
  domain        TEXT NOT NULL,
  source        TEXT NOT NULL,
  category      TEXT,
  wildcard      INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (domain, source)
);
CREATE INDEX IF NOT EXISTS idx_block_domain ON block_domains(domain);

CREATE TABLE IF NOT EXISTS list_meta (
  name          TEXT PRIMARY KEY,
  url           TEXT NOT NULL,
  category      TEXT,
  enabled       INTEGER NOT NULL DEFAULT 1,
  entries       INTEGER NOT NULL DEFAULT 0,
  last_updated  INTEGER,
  last_error    TEXT,
  etag          TEXT
);

-- Smart-capture candidates: domains observed in the wild that look like ad
-- or tracking infrastructure but are not on any subscribed list.
CREATE TABLE IF NOT EXISTS ad_candidates (
  domain        TEXT PRIMARY KEY,
  first_seen    INTEGER NOT NULL,
  last_seen     INTEGER NOT NULL,
  observations  INTEGER NOT NULL DEFAULT 0,
  distinct_clients INTEGER NOT NULL DEFAULT 0,
  distinct_referrers INTEGER NOT NULL DEFAULT 0,
  heuristic_score REAL NOT NULL DEFAULT 0,
  ai_score      REAL,
  ai_reason     TEXT,
  final_score   REAL NOT NULL DEFAULT 0,
  status        TEXT NOT NULL DEFAULT 'candidate',
  decided_by    TEXT,
  decided_at    INTEGER,
  features      TEXT
);
CREATE INDEX IF NOT EXISTS idx_adc_status ON ad_candidates(status, final_score DESC);
CREATE INDEX IF NOT EXISTS idx_adc_score ON ad_candidates(final_score DESC);

-- Locally authored block/allow entries, including smart-capture promotions.
CREATE TABLE IF NOT EXISTS local_rules (
  domain        TEXT PRIMARY KEY,
  action        TEXT NOT NULL,
  wildcard      INTEGER NOT NULL DEFAULT 0,
  origin        TEXT NOT NULL DEFAULT 'user',
  note          TEXT,
  created_at    INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS dhcp_leases (
  mac           TEXT PRIMARY KEY,
  ip            TEXT NOT NULL,
  hostname      TEXT,
  scope         TEXT,
  starts        INTEGER NOT NULL,
  expires       INTEGER NOT NULL,
  static        INTEGER NOT NULL DEFAULT 0,
  client_id     TEXT,
  vendor_class  TEXT,
  fingerprint   TEXT
);
CREATE INDEX IF NOT EXISTS idx_lease_ip ON dhcp_leases(ip);
CREATE INDEX IF NOT EXISTS idx_lease_exp ON dhcp_leases(expires);

CREATE TABLE IF NOT EXISTS wg_peers (
  id            TEXT PRIMARY KEY,
  name          TEXT NOT NULL,
  public_key    TEXT NOT NULL UNIQUE,
  private_key   TEXT,
  preshared_key TEXT,
  address       TEXT NOT NULL,
  allowed_ips   TEXT,
  enabled       INTEGER NOT NULL DEFAULT 1,
  dns           TEXT,
  keepalive     INTEGER NOT NULL DEFAULT 25,
  last_handshake INTEGER,
  rx_bytes      INTEGER NOT NULL DEFAULT 0,
  tx_bytes      INTEGER NOT NULL DEFAULT 0,
  endpoint      TEXT,
  created_at    INTEGER NOT NULL,
  note          TEXT
);

-- Chat transcript, so the assistant has continuity across page loads and
-- restarts and the operator has an audit trail of what it changed.
CREATE TABLE IF NOT EXISTS chat_messages (
  id            TEXT PRIMARY KEY,
  conversation  TEXT NOT NULL,
  ts            INTEGER NOT NULL,
  role          TEXT NOT NULL,
  content       TEXT NOT NULL,
  tool_calls    TEXT,
  tool_result   TEXT,
  model         TEXT,
  tokens_in     INTEGER,
  tokens_out    INTEGER
);
CREATE INDEX IF NOT EXISTS idx_chat_conv ON chat_messages(conversation, ts);

-- Rolling per-minute counters powering the sparklines without scanning flows.
CREATE TABLE IF NOT EXISTS stats_minute (
  bucket        INTEGER NOT NULL,
  metric        TEXT NOT NULL,
  value         REAL NOT NULL,
  PRIMARY KEY (bucket, metric)
);
CREATE INDEX IF NOT EXISTS idx_stats_bucket ON stats_minute(bucket DESC);

-- Audit trail for every mutating action, whether from UI, API, or assistant.
CREATE TABLE IF NOT EXISTS audit_log (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  ts            INTEGER NOT NULL,
  actor         TEXT NOT NULL,
  action        TEXT NOT NULL,
  target        TEXT,
  before        TEXT,
  after         TEXT,
  result        TEXT
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts DESC);
`
