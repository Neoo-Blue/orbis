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

// migrations carry changes that CREATE TABLE IF NOT EXISTS cannot express.
// Each runs on every open and must be idempotent; an "duplicate column name"
// error is the expected outcome on an already-migrated database and is
// swallowed by applyMigrations rather than treated as a failure.
//
// Adding a column here is the only supported way to extend an existing table:
// the schema block above is never re-applied to a database that already has
// the table, so a field added there alone would silently never appear on a
// node that has been running.
var migrations = []string{
	`ALTER TABLE policies ADD COLUMN blocked_services TEXT NOT NULL DEFAULT '[]'`,
	`ALTER TABLE policies ADD COLUMN unfiltered INTEGER NOT NULL DEFAULT 0`,
	`ALTER TABLE dns_queries ADD COLUMN policy TEXT`,
	`CREATE TABLE IF NOT EXISTS consent_rules (
		client_id  TEXT NOT NULL,
		host       TEXT NOT NULL,
		decision   TEXT NOT NULL,
		scope      TEXT NOT NULL,
		decided_at INTEGER NOT NULL,
		PRIMARY KEY (client_id, host, scope)
	)`,
	// The assistant's model catalogue and probe results, so a restart keeps
	// yesterday's ranking instead of running blind until the next probe.
	`CREATE TABLE IF NOT EXISTS ai_models (
		id          TEXT PRIMARY KEY,
		name        TEXT NOT NULL DEFAULT '',
		free        INTEGER NOT NULL DEFAULT 0,
		context     INTEGER NOT NULL DEFAULT 0,
		max_output  INTEGER NOT NULL DEFAULT 0,
		tools       INTEGER NOT NULL DEFAULT 0,
		reasoning   INTEGER NOT NULL DEFAULT 0,
		structured  INTEGER NOT NULL DEFAULT 0,
		tool_ok     INTEGER,
		json_ok     INTEGER,
		latency_ms  INTEGER NOT NULL DEFAULT 0,
		last_probe  INTEGER NOT NULL DEFAULT 0,
		last_error  TEXT NOT NULL DEFAULT '',
		chat_rank   INTEGER NOT NULL DEFAULT 0,
		fast_rank   INTEGER NOT NULL DEFAULT 0
	)`,
	// Per-day, per-model request counters. The free tier has a daily cap, and
	// the router needs to know how much of it is spent across restarts.
	`CREATE TABLE IF NOT EXISTS ai_usage (
		day        TEXT NOT NULL,
		model      TEXT NOT NULL,
		requests   INTEGER NOT NULL DEFAULT 0,
		failures   INTEGER NOT NULL DEFAULT 0,
		tokens_in  INTEGER NOT NULL DEFAULT 0,
		tokens_out INTEGER NOT NULL DEFAULT 0,
		PRIMARY KEY (day, model)
	)`,
	// Periodic network briefs written by the assistant.
	`CREATE TABLE IF NOT EXISTS ai_briefs (
		id        TEXT PRIMARY KEY,
		ts        INTEGER NOT NULL,
		hours     INTEGER NOT NULL,
		model     TEXT NOT NULL DEFAULT '',
		severity  TEXT NOT NULL DEFAULT 'info',
		headline  TEXT NOT NULL,
		body      TEXT NOT NULL
	)`,
	`CREATE INDEX IF NOT EXISTS idx_ai_briefs_ts ON ai_briefs(ts)`,
	// Problems recorded on this node, scrubbed, with their GitHub state.
	`CREATE TABLE IF NOT EXISTS issues (
		id            TEXT PRIMARY KEY,
		fingerprint   TEXT NOT NULL UNIQUE,
		first_seen    INTEGER NOT NULL,
		last_seen     INTEGER NOT NULL,
		occurrences   INTEGER NOT NULL DEFAULT 1,
		severity      TEXT NOT NULL,
		category      TEXT NOT NULL,
		title         TEXT NOT NULL,
		detail        TEXT NOT NULL DEFAULT '',
		diagnostics   TEXT NOT NULL DEFAULT '',
		source        TEXT NOT NULL DEFAULT 'auto',
		status        TEXT NOT NULL DEFAULT 'open',
		github_number INTEGER NOT NULL DEFAULT 0,
		github_url    TEXT NOT NULL DEFAULT '',
		reported_at   INTEGER NOT NULL DEFAULT 0,
		last_error    TEXT NOT NULL DEFAULT ''
	)`,
	`CREATE INDEX IF NOT EXISTS idx_issues_last ON issues(last_seen)`,
	// The assistant's standing recommendations and the operator's decisions
	// on them: the memory that stops the same suggestion coming back.
	`CREATE TABLE IF NOT EXISTS ai_recommendations (
		id          TEXT PRIMARY KEY,
		ts          INTEGER NOT NULL,
		kind        TEXT NOT NULL,
		domain      TEXT NOT NULL,
		reason      TEXT NOT NULL DEFAULT '',
		confidence  REAL NOT NULL DEFAULT 0,
		evidence    TEXT NOT NULL DEFAULT '{}',
		status      TEXT NOT NULL DEFAULT 'open',
		decided_at  INTEGER NOT NULL DEFAULT 0,
		decided_by  TEXT NOT NULL DEFAULT '',
		model       TEXT NOT NULL DEFAULT '',
		UNIQUE (kind, domain)
	)`,
	// Timed internet pauses per device: the block is lifted when until passes.
	`CREATE TABLE IF NOT EXISTS client_pauses (
		client_id TEXT PRIMARY KEY,
		until     INTEGER NOT NULL
	)`,
	// Pinned-app bypasses learned by the filter proxy, kept across restarts.
	`CREATE TABLE IF NOT EXISTS pin_bypasses (
		client TEXT NOT NULL,
		name   TEXT NOT NULL,
		until  INTEGER NOT NULL,
		fails  INTEGER NOT NULL DEFAULT 0,
		PRIMARY KEY (client, name)
	)`,
	// Hourly per-device, per-service rollups behind the Services page.
	`CREATE TABLE IF NOT EXISTS service_stats (
		bucket     INTEGER NOT NULL,
		client_id  TEXT NOT NULL,
		service    TEXT NOT NULL,
		category   TEXT NOT NULL DEFAULT '',
		conns      INTEGER NOT NULL DEFAULT 0,
		bytes_in   INTEGER NOT NULL DEFAULT 0,
		bytes_out  INTEGER NOT NULL DEFAULT 0,
		lookups    INTEGER NOT NULL DEFAULT 0,
		blocked    INTEGER NOT NULL DEFAULT 0,
		PRIMARY KEY (bucket, client_id, service)
	)`,
	`CREATE INDEX IF NOT EXISTS idx_service_stats_service ON service_stats(service, bucket)`,
	`CREATE INDEX IF NOT EXISTS idx_service_stats_client ON service_stats(client_id, bucket)`,
	// Free-text facts the operator (or the assistant, when asked) wants
	// remembered about this network. Fed to every prompt.
	`CREATE TABLE IF NOT EXISTS ai_notes (
		id      TEXT PRIMARY KEY,
		ts      INTEGER NOT NULL,
		note    TEXT NOT NULL,
		source  TEXT NOT NULL DEFAULT 'operator'
	)`,
}
