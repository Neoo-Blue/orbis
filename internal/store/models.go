package store

import "time"

type Client struct {
	ID         string            `json:"id"`
	MAC        string            `json:"mac,omitempty"`
	IP         string            `json:"ip"`
	Hostname   string            `json:"hostname,omitempty"`
	Vendor     string            `json:"vendor,omitempty"`
	OSGuess    string            `json:"os_guess,omitempty"`
	DeviceType string            `json:"device_type,omitempty"`
	Label      string            `json:"label,omitempty"`
	Zone       string            `json:"zone,omitempty"`
	FirstSeen  time.Time         `json:"first_seen"`
	LastSeen   time.Time         `json:"last_seen"`
	RxBytes    int64             `json:"rx_bytes"`
	TxBytes    int64             `json:"tx_bytes"`
	Blocked    bool              `json:"blocked"`
	PolicyID   string            `json:"policy_id,omitempty"`
	VPNRoute   string            `json:"vpn_route,omitempty"`
	Notes      string            `json:"notes,omitempty"`
	Meta       map[string]string `json:"meta,omitempty"`

	// Derived, not persisted.
	Online      bool    `json:"online"`
	ActiveFlows int     `json:"active_flows"`
	RateIn      float64 `json:"rate_in"`
	RateOut     float64 `json:"rate_out"`
}

// Direction of a flow relative to the local network.
const (
	DirOutbound = "out"
	DirInbound  = "in"
	DirLocal    = "local"
)

// Verdicts a flow can carry.
const (
	VerdictAllow    = "allow"
	VerdictBlock    = "block"
	VerdictFiltered = "filtered" // allowed, but content was modified
	VerdictPending  = "pending"  // awaiting an interactive decision
)

type Flow struct {
	ID         string     `json:"id"`
	ClientID   string     `json:"client_id,omitempty"`
	StartedAt  time.Time  `json:"started_at"`
	EndedAt    *time.Time `json:"ended_at,omitempty"`
	LastSeen   time.Time  `json:"last_seen"`
	Proto      string     `json:"proto"`
	SrcIP      string     `json:"src_ip"`
	SrcPort    int        `json:"src_port"`
	DstIP      string     `json:"dst_ip"`
	DstPort    int        `json:"dst_port"`
	Direction  string     `json:"direction"`
	Hostname   string     `json:"hostname,omitempty"`
	SNI        string     `json:"sni,omitempty"`
	App        string     `json:"app,omitempty"`
	JA4        string     `json:"ja4,omitempty"`
	PacketsIn  int64      `json:"packets_in"`
	PacketsOut int64      `json:"packets_out"`
	BytesIn    int64      `json:"bytes_in"`
	BytesOut   int64      `json:"bytes_out"`
	Verdict    string     `json:"verdict"`
	RuleID     string     `json:"rule_id,omitempty"`
	Reason     string     `json:"reason,omitempty"`
	Country    string     `json:"country,omitempty"`
	City       string     `json:"city,omitempty"`
	Lat        float64    `json:"lat"`
	Lon        float64    `json:"lon"`
	ASN        int        `json:"asn,omitempty"`
	ASOrg      string     `json:"as_org,omitempty"`
	Risk       float64    `json:"risk"`
	Tags       []string   `json:"tags,omitempty"`
}

// Active reports whether the flow is still open.
func (f *Flow) Active() bool { return f.EndedAt == nil }

type DNSQuery struct {
	ID          int64     `json:"id"`
	TS          time.Time `json:"ts"`
	ClientID    string    `json:"client_id,omitempty"`
	ClientIP    string    `json:"client_ip"`
	Name        string    `json:"name"`
	QType       string    `json:"qtype"`
	RCode       string    `json:"rcode"`
	Blocked     bool      `json:"blocked"`
	BlockSource string    `json:"block_source,omitempty"`
	CNAMEChain  []string  `json:"cname_chain,omitempty"`
	Answer      []string  `json:"answer,omitempty"`
	Upstream    string    `json:"upstream,omitempty"`
	LatencyMS   float64   `json:"latency_ms"`
	Cached      bool      `json:"cached"`
}

type Rule struct {
	ID           string    `json:"id"`
	Position     int       `json:"position"`
	Enabled      bool      `json:"enabled"`
	Name         string    `json:"name"`
	Description  string    `json:"description,omitempty"`
	Chain        string    `json:"chain"`
	Action       string    `json:"action"`
	SrcZone      string    `json:"src_zone,omitempty"`
	DstZone      string    `json:"dst_zone,omitempty"`
	Src          string    `json:"src,omitempty"`
	Dst          string    `json:"dst,omitempty"`
	Proto        string    `json:"proto,omitempty"`
	SrcPort      string    `json:"src_port,omitempty"`
	DstPort      string    `json:"dst_port,omitempty"`
	Schedule     string    `json:"schedule,omitempty"`
	Log          bool      `json:"log"`
	CounterPkts  int64     `json:"counter_pkts"`
	CounterBytes int64     `json:"counter_bytes"`
	Origin       string    `json:"origin"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

type Policy struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	Categories  []string  `json:"categories"`
	Allowlist   []string  `json:"allowlist"`
	Denylist    []string  `json:"denylist"`
	SafeSearch  bool      `json:"safe_search"`
	BlockDoH    bool      `json:"block_doh"`
	Schedule    string    `json:"schedule,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

const (
	SevInfo     = "info"
	SevNotice   = "notice"
	SevWarning  = "warning"
	SevCritical = "critical"
)

type Event struct {
	ID       string         `json:"id"`
	TS       time.Time      `json:"ts"`
	Severity string         `json:"severity"`
	Category string         `json:"category"`
	Title    string         `json:"title"`
	Detail   string         `json:"detail,omitempty"`
	ClientID string         `json:"client_id,omitempty"`
	FlowID   string         `json:"flow_id,omitempty"`
	Ack      bool           `json:"acknowledged"`
	Data     map[string]any `json:"data,omitempty"`
}

type ListMeta struct {
	Name        string     `json:"name"`
	URL         string     `json:"url"`
	Category    string     `json:"category"`
	Enabled     bool       `json:"enabled"`
	Entries     int        `json:"entries"`
	LastUpdated *time.Time `json:"last_updated,omitempty"`
	LastError   string     `json:"last_error,omitempty"`
	ETag        string     `json:"-"`
}

// AdCandidate statuses.
const (
	CandidateNew       = "candidate"
	CandidateReview    = "review"
	CandidateBlocked   = "blocked"
	CandidateDismissed = "dismissed"
)

type AdCandidate struct {
	Domain            string         `json:"domain"`
	FirstSeen         time.Time      `json:"first_seen"`
	LastSeen          time.Time      `json:"last_seen"`
	Observations      int            `json:"observations"`
	DistinctClients   int            `json:"distinct_clients"`
	DistinctReferrers int            `json:"distinct_referrers"`
	HeuristicScore    float64        `json:"heuristic_score"`
	AIScore           *float64       `json:"ai_score,omitempty"`
	AIReason          string         `json:"ai_reason,omitempty"`
	FinalScore        float64        `json:"final_score"`
	Status            string         `json:"status"`
	DecidedBy         string         `json:"decided_by,omitempty"`
	DecidedAt         *time.Time     `json:"decided_at,omitempty"`
	Features          map[string]any `json:"features,omitempty"`
}

type LocalRule struct {
	Domain    string    `json:"domain"`
	Action    string    `json:"action"` // block | allow
	Wildcard  bool      `json:"wildcard"`
	Origin    string    `json:"origin"` // user | smart | ai | import
	Note      string    `json:"note,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

type Lease struct {
	MAC         string    `json:"mac"`
	IP          string    `json:"ip"`
	Hostname    string    `json:"hostname,omitempty"`
	Scope       string    `json:"scope,omitempty"`
	Starts      time.Time `json:"starts"`
	Expires     time.Time `json:"expires"`
	Static      bool      `json:"static"`
	ClientID    string    `json:"client_id,omitempty"`
	VendorClass string    `json:"vendor_class,omitempty"`
	Fingerprint string    `json:"fingerprint,omitempty"`
}

type WGPeer struct {
	ID            string     `json:"id"`
	Name          string     `json:"name"`
	PublicKey     string     `json:"public_key"`
	PrivateKey    string     `json:"-"`
	PresharedKey  string     `json:"-"`
	Address       string     `json:"address"`
	AllowedIPs    []string   `json:"allowed_ips"`
	Enabled       bool       `json:"enabled"`
	DNS           []string   `json:"dns"`
	Keepalive     int        `json:"keepalive"`
	LastHandshake *time.Time `json:"last_handshake,omitempty"`
	RxBytes       int64      `json:"rx_bytes"`
	TxBytes       int64      `json:"tx_bytes"`
	Endpoint      string     `json:"endpoint,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
	Note          string     `json:"note,omitempty"`
}

type ChatMessage struct {
	ID           string    `json:"id"`
	Conversation string    `json:"conversation"`
	TS           time.Time `json:"ts"`
	Role         string    `json:"role"`
	Content      string    `json:"content"`
	ToolCalls    string    `json:"tool_calls,omitempty"`
	ToolResult   string    `json:"tool_result,omitempty"`
	Model        string    `json:"model,omitempty"`
	TokensIn     int       `json:"tokens_in,omitempty"`
	TokensOut    int       `json:"tokens_out,omitempty"`
}

type AuditEntry struct {
	ID     int64     `json:"id"`
	TS     time.Time `json:"ts"`
	Actor  string    `json:"actor"`
	Action string    `json:"action"`
	Target string    `json:"target,omitempty"`
	Before string    `json:"before,omitempty"`
	After  string    `json:"after,omitempty"`
	Result string    `json:"result,omitempty"`
}

// FlowQuery is the filter set backing the history table and globe replay.
type FlowQuery struct {
	Since      *time.Time
	Until      *time.Time
	ClientID   string
	Verdict    string
	Search     string
	Country    string
	Proto      string
	Port       int
	MinBytes   int64
	ActiveOnly bool
	Limit      int
	Offset     int
	OrderBy    string // "started_at" | "bytes" | "risk"
}
