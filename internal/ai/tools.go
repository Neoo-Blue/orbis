package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Neoo-Blue/orbis/internal/config"
	"github.com/Neoo-Blue/orbis/internal/store"
	"github.com/google/uuid"
)

// Backend is everything the assistant is allowed to touch. Keeping it as an
// interface means the tool layer cannot reach past what was deliberately
// exposed, and it makes the whole thing testable without a live firewall.
type Backend interface {
	Summary(since time.Time) (map[string]any, error)
	Clients() []store.Client
	ActiveFlows(limit int) []store.Flow
	QueryFlows(q store.FlowQuery) ([]store.Flow, error)
	TopDestinations(since time.Time, clientID string, limit int) ([]map[string]any, error)
	DNSLog(since time.Time, clientID string, blockedOnly bool, search string, limit int) ([]store.DNSQuery, error)
	TopBlocked(since time.Time, limit int) ([]map[string]any, error)
	Events(since time.Time, severity string, unackOnly bool, limit int) ([]store.Event, error)
	Rules() ([]store.Rule, error)
	SystemStatus() map[string]any
	AdCandidates(status string, minScore float64, limit int) ([]store.AdCandidate, error)

	// DiagnoseDomain traces why a name is blocked or allowed: rewrites,
	// per-device policy, blocklists and CNAME uncloaking, in resolver order.
	DiagnoseDomain(ctx context.Context, domain, clientID string, resolve bool) (map[string]any, error)
	// LookupIP places an address: country, city, network operator, reverse
	// name, and whether it is one of our own devices.
	LookupIP(ip string) (map[string]any, error)
	// YouTubeStatus is the Lounge ad-skipping engine's state.
	YouTubeStatus() any
	// Series reads a per-minute metric, optionally downsampled to buckets.
	Series(metric string, since time.Time, buckets int) ([]map[string]any, error)
	CountryTotals(since time.Time) ([]map[string]any, error)
	Leases() ([]store.Lease, error)
	AuditLog(limit int) ([]store.AuditEntry, error)

	// ServiceUsage is the per-service, per-device rollup (bytes, connections,
	// lookups, blocked) over a window.
	ServiceUsage(since time.Time, clientID, service string) (map[string]any, error)

	// Shortcuts: names for things on a port, served by the node itself.
	Shortcuts() []config.DNSShortcut
	SaveShortcut(sc config.DNSShortcut, actor string) (config.DNSShortcut, error)
	DeleteShortcut(name, actor string) error

	// Memory: operator notes and the specialist's standing suggestions.
	Notes(limit int) ([]store.Note, error)
	SaveNote(note, source string) (*store.Note, error)
	DeleteNote(id string) error
	Recommendations(status string, limit int) ([]store.Recommendation, error)
	DecideRecommendation(id, decision, actor string) (*store.Recommendation, error)
	// ReportIssue records a problem (scrubbed) and files it when reporting
	// is enabled.
	ReportIssue(ctx context.Context, title, detail, actor string) (*store.Issue, error)

	// Mutating operations.
	AddRule(r *store.Rule) error
	DeleteRule(id string) error
	SetRuleEnabled(id string, enabled bool) error
	BlockDomain(domain string, wildcard bool, note string) error
	AllowDomain(domain string, note string) error
	SetClientBlocked(clientID string, blocked bool) error
	SetClientLabel(clientID, label string) error
	ApplyFirewall(ctx context.Context) error
	DecideCandidate(domain, decision, actor string) error
	FlushDNSCache(domain string) int
	RefreshBlocklists(ctx context.Context) error
}

// Tools returns the tool catalogue. Mutating tools are only included when the
// operator has granted write access.
func Tools(allowWrite bool) []ToolDef {
	all := []ToolDef{
		{
			Name: "get_network_summary",
			Description: "Overall network state: connection counts, blocked counts, DNS stats, " +
				"client counts, open alerts, and byte totals for a time window. Start here for " +
				"broad questions like \"how is the network doing\".",
			Schema: objSchema(map[string]any{
				"hours": numProp("Time window in hours (default 24, max 720)"),
			}, nil),
		},
		{
			Name: "list_clients",
			Description: "Every device known to the network with its identity (MAC, vendor, OS " +
				"guess, device type), live throughput, active connection count, and whether it " +
				"is currently blocked.",
			Schema: objSchema(map[string]any{
				"online_only": boolProp("Only devices seen in the last five minutes"),
				"search":      strProp("Filter by hostname, label, IP, MAC or vendor substring"),
			}, nil),
		},
		{
			Name: "list_connections",
			Description: "Connection records. Use active_only for what is happening right now, " +
				"or a time window for history. Each record has source, destination, hostname/SNI, " +
				"bytes, country, network operator and the allow/block verdict.",
			Schema: objSchema(map[string]any{
				"active_only": boolProp("Only currently-open connections"),
				"client_id":   strProp("Restrict to one device"),
				"hours":       numProp("Look back this many hours (ignored when active_only)"),
				"search":      strProp("Match hostname, SNI, destination IP, app or network operator"),
				"verdict":     enumProp("Filter by verdict", []string{"allow", "block", "filtered"}),
				"country":     strProp("Two-letter country code"),
				"min_bytes":   numProp("Only connections that moved at least this many bytes"),
				"limit":       numProp("Max records (default 50, max 500)"),
				"order_by":    enumProp("Sort order", []string{"recent", "bytes", "risk"}),
			}, nil),
		},
		{
			Name: "top_destinations",
			Description: "Which hosts the network (or one device) talks to most, ranked by bytes, " +
				"with connection counts and how many were blocked.",
			Schema: objSchema(map[string]any{
				"hours":     numProp("Time window in hours (default 24)"),
				"client_id": strProp("Restrict to one device"),
				"limit":     numProp("How many destinations (default 20, max 100)"),
			}, nil),
		},
		{
			Name: "dns_log",
			Description: "Recent DNS lookups with the answer, whether it was blocked, and which " +
				"list blocked it. This is the fastest way to answer \"why is X not loading\" and " +
				"\"what is this device looking up\".",
			Schema: objSchema(map[string]any{
				"hours":        numProp("Time window in hours (default 1)"),
				"client_id":    strProp("Restrict to one device"),
				"blocked_only": boolProp("Only blocked lookups"),
				"search":       strProp("Domain substring"),
				"limit":        numProp("Max records (default 50, max 300)"),
			}, nil),
		},
		{
			Name:        "top_blocked_domains",
			Description: "The domains being blocked most often, with the list responsible.",
			Schema: objSchema(map[string]any{
				"hours": numProp("Time window in hours (default 24)"),
				"limit": numProp("How many (default 20, max 100)"),
			}, nil),
		},
		{
			Name:        "list_events",
			Description: "Security and operational events: new devices, anomalies, policy changes, service failures.",
			Schema: objSchema(map[string]any{
				"hours":      numProp("Time window in hours (default 24)"),
				"severity":   enumProp("Minimum severity", []string{"info", "notice", "warning", "critical"}),
				"unack_only": boolProp("Only unacknowledged events"),
				"limit":      numProp("Max records (default 50)"),
			}, nil),
		},
		{
			Name:        "list_firewall_rules",
			Description: "The configured firewall rules in evaluation order, with hit counters.",
			Schema:      objSchema(map[string]any{}, nil),
		},
		{
			Name: "system_status",
			Description: "Health of every subsystem: capture, DNS, DHCP, firewall, VPN, filter " +
				"proxy, blocklists, and whether the node is in observe or inline mode.",
			Schema: objSchema(map[string]any{}, nil),
		},
		{
			Name: "list_ad_candidates",
			Description: "Domains the smart-capture pipeline flagged as probable ad or tracking " +
				"infrastructure, with the evidence and score behind each.",
			Schema: objSchema(map[string]any{
				"status":    enumProp("Filter by status", []string{"candidate", "review", "blocked", "dismissed"}),
				"min_score": numProp("Minimum final score 0-1"),
				"limit":     numProp("Max records (default 30)"),
			}, nil),
		},
		{
			Name: "device_detail",
			Description: "Everything about one device in one call: identity, whether it is " +
				"online, what it talked to most, what was blocked for it, and its recent " +
				"events. Pass client_id when known, otherwise a search term (name, IP, MAC, " +
				"vendor). Use this before answering \"what is the TV doing\".",
			Schema: objSchema(map[string]any{
				"client_id": strProp("The device id"),
				"search":    strProp("Find the device by hostname, label, IP, MAC or vendor"),
				"hours":     numProp("Time window in hours (default 24, max 720)"),
			}, nil),
		},
		{
			Name: "explain_domain",
			Description: "Why a domain is blocked or allowed on this network, as a trace in the " +
				"order the resolver decides: rewrites, per-device policy, the blocklists " +
				"(with the list and rule that matched), and CNAME uncloaking. The definitive " +
				"answer to \"why is X not loading\" and \"is Y blocked\".",
			Schema: objSchema(map[string]any{
				"domain":    strProp("The hostname to explain"),
				"client_id": strProp("Optional device, so per-device policy is included"),
				"resolve":   boolProp("Also resolve the name through this node to follow CNAMEs (default true)"),
			}, []string{"domain"}),
		},
		{
			Name: "lookup_ip",
			Description: "Who an IP address belongs to: country, city, network operator (ASN), " +
				"reverse DNS, whether it is anycast, whether it is a device on this network, " +
				"and the recent connections to it.",
			Schema: objSchema(map[string]any{
				"ip": strProp("IPv4 or IPv6 address"),
			}, []string{"ip"}),
		},
		{
			Name: "youtube_status",
			Description: "The YouTube ad-skipping engine: paired televisions, whether each is " +
				"online, and per-screen ad counts (skipped, played, time saved). Use for any " +
				"question about YouTube ads on TVs.",
			Schema: objSchema(map[string]any{}, nil),
		},
		{
			Name: "traffic_timeline",
			Description: "A metric over time as evenly spaced points, for questions like " +
				"\"when was the network busiest\" or \"did blocking spike overnight\".",
			Schema: objSchema(map[string]any{
				"metric": enumProp("Which series", []string{
					"throughput_in", "throughput_out", "dns_queries_total", "dns_blocked_total", "flows_active",
				}),
				"hours":  numProp("Look back this many hours (default 6, max 168)"),
				"points": numProp("How many points to return (default 24, max 200)"),
			}, []string{"metric"}),
		},
		{
			Name:        "country_breakdown",
			Description: "Traffic by destination country: connections, bytes and blocked count per country.",
			Schema: objSchema(map[string]any{
				"hours": numProp("Time window in hours (default 24)"),
				"limit": numProp("How many countries (default 15, max 50)"),
			}, nil),
		},
		{
			Name:        "dhcp_leases",
			Description: "Current DHCP leases handed out by this node: address, MAC, hostname, expiry, static or dynamic.",
			Schema:      objSchema(map[string]any{}, nil),
		},
		{
			Name: "audit_log",
			Description: "Who changed what: every configuration change made through the UI, " +
				"the API or the assistant, newest first.",
			Schema: objSchema(map[string]any{
				"limit":  numProp("Max entries (default 50, max 300)"),
				"search": strProp("Filter by action, target or actor substring"),
			}, nil),
		},
		{
			Name: "service_usage",
			Description: "Per-app and per-service usage: bytes down/up, connections, DNS lookups and " +
				"blocked lookups, grouped by service (Netflix, YouTube, TikTok, Windows Update, a " +
				"registrable domain for unknown names). Pass client_id for one device's breakdown, " +
				"service for one service's breakdown by device (with hourly points and the hosts " +
				"behind it), or neither for the whole network. Bytes exist only for devices whose " +
				"traffic passes through this node; the others show lookups.",
			Schema: objSchema(map[string]any{
				"hours":     numProp("Time window in hours (default 24, max 720)"),
				"client_id": strProp("Restrict to one device"),
				"service":   strProp("One service name exactly as shown, e.g. \"YouTube\""),
			}, nil),
		},
		{
			Name: "list_shortcuts",
			Description: "Names Orbis serves for things on the network that live on a port, e.g. " +
				"deep.seek -> http://192.168.50.223:8080. Typing the name in a browser lands on the target.",
			Schema: objSchema(map[string]any{}, nil),
		},
		{
			Name: "list_recommendations",
			Description: "The blocklist specialist's standing suggestions: domains that look " +
				"wrongly blocked (allow), new ad or tracking hosts worth blocking (block), and " +
				"things worth a look (investigate), each with the evidence. Open ones await a " +
				"decision; accepted and dismissed ones are the operator's memory.",
			Schema: objSchema(map[string]any{
				"status": enumProp("Filter", []string{"open", "accepted", "dismissed", "expired"}),
				"limit":  numProp("Max items (default 30)"),
			}, nil),
		},
		{
			Name: "list_notes",
			Description: "Facts the operator asked to be remembered about this network (which " +
				"device is whose, what a service is for, what not to block). Check these before " +
				"calling anything suspicious.",
			Schema: objSchema(map[string]any{}, nil),
		},
		{
			Name: "remember",
			Description: "Remember a fact about this network for future conversations, briefs and " +
				"reviews. Use when the operator tells you something worth keeping: \"the NAS backs " +
				"up to Backblaze at 3am\", \"192.168.50.24 is my phone\". One fact per call.",
			Schema: objSchema(map[string]any{
				"note": strProp("The fact, in one or two sentences"),
			}, []string{"note"}),
		},
		{
			Name:        "forget_note",
			Description: "Delete a remembered fact by id (from list_notes).",
			Schema: objSchema(map[string]any{
				"id": strProp("The note id"),
			}, []string{"id"}),
		},

		// ---- mutating ----
		{
			Name: "add_shortcut",
			Description: "Give something on the network a name that includes its port: " +
				"add_shortcut(name=\"deep.seek\", target=\"192.168.50.223:8080\") makes http://deep.seek " +
				"open that service. DNS cannot carry a port, so Orbis answers the name itself and redirects " +
				"(default) or relays (mode=proxy, the address bar keeps the name).",
			Mutating: true,
			Schema: objSchema(map[string]any{
				"name":   strProp("The name to type, e.g. deep.seek or nas.lan"),
				"target": strProp("Where it goes: host:port or a URL"),
				"mode":   enumProp("redirect (default) or proxy", []string{"redirect", "proxy"}),
				"note":   strProp("Optional note"),
			}, []string{"name", "target"}),
		},
		{
			Name:        "remove_shortcut",
			Description: "Remove a shortcut by name.",
			Mutating:    true,
			Schema:      objSchema(map[string]any{"name": strProp("The shortcut name")}, []string{"name"}),
		},
		{
			Name: "decide_recommendation",
			Description: "Accept or dismiss one of the specialist's suggestions. Accepting an " +
				"allow suggestion adds the domain to the allowlist; accepting a block suggestion " +
				"blocks it and its subdomains. Dismissing is remembered so it is not suggested again.",
			Mutating: true,
			Schema: objSchema(map[string]any{
				"id":       strProp("The recommendation id"),
				"decision": enumProp("What to do", []string{"accept", "dismiss"}),
			}, []string{"id", "decision"}),
		},
		{
			Name: "report_problem",
			Description: "Record a problem with Orbis itself (a feature misbehaving, a wrong " +
				"block that keeps coming back, a crash) so it can be fixed. The report is " +
				"scrubbed of addresses, device names and keys on this node; if GitHub reporting " +
				"is enabled it is filed on the project's issue board.",
			Mutating: true,
			Schema: objSchema(map[string]any{
				"title":  strProp("One line: what is wrong"),
				"detail": strProp("What was expected, what happened, how to reproduce"),
			}, []string{"title", "detail"}),
		},
		{
			Name: "block_domain",
			Description: "Add a domain to the local blocklist. Use wildcard to also cover every " +
				"subdomain. Takes effect immediately for new lookups.",
			Mutating: true,
			Schema: objSchema(map[string]any{
				"domain":   strProp("The domain to block"),
				"wildcard": boolProp("Also block all subdomains (default true)"),
				"note":     strProp("Why this was blocked — shown in the UI and audit log"),
			}, []string{"domain"}),
		},
		{
			Name: "allow_domain",
			Description: "Add a domain to the local allowlist, overriding every subscribed " +
				"blocklist. Use this to fix overblocking.",
			Mutating: true,
			Schema: objSchema(map[string]any{
				"domain": strProp("The domain to allow"),
				"note":   strProp("Why this exception exists"),
			}, []string{"domain"}),
		},
		{
			Name: "add_firewall_rule",
			Description: "Create a firewall rule. Rules are evaluated in position order within " +
				"their chain. Call apply_firewall afterwards to make it live.",
			Mutating: true,
			Schema: objSchema(map[string]any{
				"name":        strProp("Short descriptive name"),
				"description": strProp("What this rule is for"),
				"chain":       enumProp("Which chain", []string{"input", "forward", "output", "dnat", "snat"}),
				"action":      enumProp("What to do", []string{"accept", "drop", "reject"}),
				"src":         strProp("Source address or CIDR, comma-separated for several"),
				"dst":         strProp("Destination address or CIDR"),
				"src_zone":    strProp("Source zone name"),
				"dst_zone":    strProp("Destination zone name"),
				"proto":       enumProp("Protocol", []string{"tcp", "udp", "icmp", "any"}),
				"dst_port":    strProp("Destination port, range (80-90) or comma-separated list"),
				"schedule":    strProp("Optional time window, e.g. \"mon-fri 09:00-17:00\""),
				"log":         boolProp("Log packets matching this rule"),
			}, []string{"name", "chain", "action"}),
		},
		{
			Name:        "set_rule_enabled",
			Description: "Enable or disable an existing firewall rule without deleting it.",
			Mutating:    true,
			Schema: objSchema(map[string]any{
				"rule_id": strProp("The rule id"),
				"enabled": boolProp("Whether the rule should be active"),
			}, []string{"rule_id", "enabled"}),
		},
		{
			Name:        "delete_firewall_rule",
			Description: "Permanently remove a firewall rule.",
			Mutating:    true,
			Schema: objSchema(map[string]any{
				"rule_id": strProp("The rule id"),
			}, []string{"rule_id"}),
		},
		{
			Name: "apply_firewall",
			Description: "Compile the rules into an nftables ruleset and load it atomically. " +
				"Required after any rule change. No-op unless the node is in inline mode.",
			Mutating: true,
			Schema:   objSchema(map[string]any{}, nil),
		},
		{
			Name:        "set_client_blocked",
			Description: "Cut a device off from the network entirely, or restore its access.",
			Mutating:    true,
			Schema: objSchema(map[string]any{
				"client_id": strProp("The device id"),
				"blocked":   boolProp("true to block, false to restore"),
			}, []string{"client_id", "blocked"}),
		},
		{
			Name:        "label_client",
			Description: "Give a device a human-readable name, so it stops showing up as a MAC address.",
			Mutating:    true,
			Schema: objSchema(map[string]any{
				"client_id": strProp("The device id"),
				"label":     strProp("The friendly name"),
			}, []string{"client_id", "label"}),
		},
		{
			Name:        "decide_ad_candidate",
			Description: "Resolve a smart-capture candidate: block it, allow it permanently, or dismiss it.",
			Mutating:    true,
			Schema: objSchema(map[string]any{
				"domain":   strProp("The candidate domain"),
				"decision": enumProp("What to do", []string{"block", "allow", "dismiss"}),
			}, []string{"domain", "decision"}),
		},
		{
			Name: "flush_dns_cache",
			Description: "Drop cached DNS answers so a policy change takes effect immediately. " +
				"Pass a domain to flush only that name and its subdomains.",
			Mutating: true,
			Schema: objSchema(map[string]any{
				"domain": strProp("Optional: flush only this domain"),
			}, nil),
		},
		{
			Name:        "refresh_blocklists",
			Description: "Force an immediate re-download of every enabled blocklist subscription.",
			Mutating:    true,
			Schema:      objSchema(map[string]any{}, nil),
		},
	}

	if allowWrite {
		return all
	}
	out := make([]ToolDef, 0, len(all))
	for _, t := range all {
		if !t.Mutating {
			out = append(out, t)
		}
	}
	return out
}

// Execute dispatches a tool call against the backend.
func Execute(ctx context.Context, b Backend, call ToolCall, allowWrite bool, actor string) (string, error) {
	var args map[string]any
	if len(call.Input) > 0 {
		if err := json.Unmarshal(call.Input, &args); err != nil {
			return "", fmt.Errorf("could not parse arguments: %w", err)
		}
	}
	if args == nil {
		args = map[string]any{}
	}

	mutating := map[string]bool{
		"block_domain": true, "allow_domain": true, "add_firewall_rule": true,
		"set_rule_enabled": true, "delete_firewall_rule": true, "apply_firewall": true,
		"set_client_blocked": true, "label_client": true, "decide_ad_candidate": true,
		"flush_dns_cache": true, "refresh_blocklists": true,
		"decide_recommendation": true, "report_problem": true,
		"add_shortcut": true, "remove_shortcut": true,
	}
	if mutating[call.Name] && !allowWrite {
		return "", fmt.Errorf("write access is disabled; this change needs to be made from the UI")
	}

	switch call.Name {
	case "get_network_summary":
		since := hoursAgo(args, "hours", 24, 720)
		return jsonOf(b.Summary(since))

	case "list_clients":
		clients := b.Clients()
		onlineOnly := boolArg(args, "online_only")
		search := strings.ToLower(strArg(args, "search"))
		out := make([]map[string]any, 0, len(clients))
		for _, c := range clients {
			if onlineOnly && !c.Online {
				continue
			}
			if search != "" && !clientMatches(c, search) {
				continue
			}
			out = append(out, map[string]any{
				"id": c.ID, "name": displayName(c), "ip": c.IP, "mac": c.MAC,
				"vendor": c.Vendor, "os": c.OSGuess, "type": c.DeviceType,
				"online": c.Online, "blocked": c.Blocked, "zone": c.Zone,
				"active_connections": c.ActiveFlows,
				"rate_in_bps":        int64(c.RateIn * 8),
				"rate_out_bps":       int64(c.RateOut * 8),
				"last_seen":          c.LastSeen.Format(time.RFC3339),
			})
		}
		sort.Slice(out, func(i, j int) bool {
			return fmt.Sprint(out[i]["name"]) < fmt.Sprint(out[j]["name"])
		})
		return jsonOf(map[string]any{"count": len(out), "clients": out}, nil)

	case "list_connections":
		limit := intArg(args, "limit", 50, 500)
		if boolArg(args, "active_only") {
			flows := b.ActiveFlows(limit)
			if cid := strArg(args, "client_id"); cid != "" {
				filtered := flows[:0]
				for _, f := range flows {
					if f.ClientID == cid {
						filtered = append(filtered, f)
					}
				}
				flows = filtered
			}
			return jsonOf(map[string]any{"count": len(flows), "connections": summarizeFlows(flows)}, nil)
		}
		since := hoursAgo(args, "hours", 24, 720)
		q := store.FlowQuery{
			Since: &since, ClientID: strArg(args, "client_id"),
			Verdict: strArg(args, "verdict"), Search: strArg(args, "search"),
			Country:  strings.ToUpper(strArg(args, "country")),
			MinBytes: int64(intArg(args, "min_bytes", 0, 1<<40)),
			Limit:    limit,
		}
		switch strArg(args, "order_by") {
		case "bytes":
			q.OrderBy = "bytes"
		case "risk":
			q.OrderBy = "risk"
		}
		flows, err := b.QueryFlows(q)
		if err != nil {
			return "", err
		}
		return jsonOf(map[string]any{"count": len(flows), "connections": summarizeFlows(flows)}, nil)

	case "top_destinations":
		since := hoursAgo(args, "hours", 24, 720)
		return jsonOf(b.TopDestinations(since, strArg(args, "client_id"), intArg(args, "limit", 20, 100)))

	case "dns_log":
		since := hoursAgo(args, "hours", 1, 720)
		queries, err := b.DNSLog(since, strArg(args, "client_id"), boolArg(args, "blocked_only"),
			strArg(args, "search"), intArg(args, "limit", 50, 300))
		if err != nil {
			return "", err
		}
		out := make([]map[string]any, 0, len(queries))
		for _, q := range queries {
			entry := map[string]any{
				"time": q.TS.Format(time.RFC3339), "domain": q.Name, "type": q.QType,
				"blocked": q.Blocked, "client": q.ClientIP, "rcode": q.RCode,
			}
			if q.Blocked {
				entry["blocked_by"] = q.BlockSource
			}
			if len(q.Answer) > 0 {
				entry["answer"] = q.Answer
			}
			if len(q.CNAMEChain) > 0 {
				entry["cname_chain"] = q.CNAMEChain
			}
			out = append(out, entry)
		}
		return jsonOf(map[string]any{"count": len(out), "queries": out}, nil)

	case "top_blocked_domains":
		since := hoursAgo(args, "hours", 24, 720)
		return jsonOf(b.TopBlocked(since, intArg(args, "limit", 20, 100)))

	case "list_events":
		since := hoursAgo(args, "hours", 24, 720)
		return jsonOf(b.Events(since, strArg(args, "severity"), boolArg(args, "unack_only"),
			intArg(args, "limit", 50, 300)))

	case "list_firewall_rules":
		return jsonOf(b.Rules())

	case "system_status":
		return jsonOf(b.SystemStatus(), nil)

	case "list_ad_candidates":
		return jsonOf(b.AdCandidates(strArg(args, "status"), floatArg(args, "min_score", 0),
			intArg(args, "limit", 30, 200)))

	case "device_detail":
		return deviceDetail(b, args)

	case "explain_domain":
		domain := strArg(args, "domain")
		if domain == "" {
			return "", fmt.Errorf("domain is required")
		}
		resolve := true
		if v, ok := args["resolve"].(bool); ok {
			resolve = v
		}
		return jsonOf(b.DiagnoseDomain(ctx, domain, strArg(args, "client_id"), resolve))

	case "lookup_ip":
		ip := strArg(args, "ip")
		if ip == "" {
			return "", fmt.Errorf("ip is required")
		}
		info, err := b.LookupIP(ip)
		if err != nil {
			return "", err
		}
		since := time.Now().Add(-24 * time.Hour)
		if flows, err := b.QueryFlows(store.FlowQuery{Since: &since, Search: ip, Limit: 10, OrderBy: "bytes"}); err == nil {
			info["recent_connections"] = summarizeFlows(flows)
		}
		return jsonOf(info, nil)

	case "youtube_status":
		return jsonOf(b.YouTubeStatus(), nil)

	case "traffic_timeline":
		metric := strArg(args, "metric")
		switch metric {
		case "throughput_in", "throughput_out", "dns_queries_total", "dns_blocked_total", "flows_active":
		default:
			return "", fmt.Errorf("unknown metric %q", metric)
		}
		since := hoursAgo(args, "hours", 6, 168)
		points, err := b.Series(metric, since, intArg(args, "points", 24, 200))
		if err != nil {
			return "", err
		}
		unit := "count"
		if strings.HasPrefix(metric, "throughput") {
			unit = "bytes_per_second"
		}
		return jsonOf(map[string]any{"metric": metric, "unit": unit, "points": points}, nil)

	case "country_breakdown":
		since := hoursAgo(args, "hours", 24, 720)
		rows, err := b.CountryTotals(since)
		if err != nil {
			return "", err
		}
		if limit := intArg(args, "limit", 15, 50); len(rows) > limit {
			rows = rows[:limit]
		}
		return jsonOf(map[string]any{"count": len(rows), "countries": rows}, nil)

	case "dhcp_leases":
		return jsonOf(b.Leases())

	case "audit_log":
		entries, err := b.AuditLog(intArg(args, "limit", 50, 300))
		if err != nil {
			return "", err
		}
		if needle := strings.ToLower(strArg(args, "search")); needle != "" {
			filtered := entries[:0]
			for _, e := range entries {
				hay := strings.ToLower(e.Actor + " " + e.Action + " " + e.Target + " " + e.After)
				if strings.Contains(hay, needle) {
					filtered = append(filtered, e)
				}
			}
			entries = filtered
		}
		return jsonOf(map[string]any{"count": len(entries), "entries": entries}, nil)

	case "service_usage":
		return jsonOf(b.ServiceUsage(hoursAgo(args, "hours", 24, 720), strArg(args, "client_id"), strArg(args, "service")))

	case "list_shortcuts":
		return jsonOf(map[string]any{"shortcuts": b.Shortcuts()}, nil)

	case "add_shortcut":
		sc, err := b.SaveShortcut(config.DNSShortcut{
			Name: strArg(args, "name"), Target: strArg(args, "target"), Mode: strArg(args, "mode"), Note: strArg(args, "note"),
		}, actor)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("Shortcut saved: http://%s now %s to %s.", sc.Name,
			map[bool]string{true: "relays", false: "redirects"}[sc.Mode == "proxy"], sc.Target), nil

	case "remove_shortcut":
		if err := b.DeleteShortcut(strArg(args, "name"), actor); err != nil {
			return "", err
		}
		return "Shortcut removed.", nil

	case "list_recommendations":
		recs, err := b.Recommendations(strArg(args, "status"), intArg(args, "limit", 30, 200))
		if err != nil {
			return "", err
		}
		return jsonOf(map[string]any{"count": len(recs), "recommendations": recs}, nil)

	case "list_notes":
		return jsonOf(b.Notes(100))

	case "remember":
		note := strArg(args, "note")
		if note == "" {
			return "", fmt.Errorf("note is required")
		}
		n, err := b.SaveNote(note, "assistant ("+actor+")")
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("Remembered (id %s).", n.ID), nil

	case "forget_note":
		if err := b.DeleteNote(strArg(args, "id")); err != nil {
			return "", err
		}
		return "Forgotten.", nil

	// ---- mutating ----
	case "decide_recommendation":
		rec, err := b.DecideRecommendation(strArg(args, "id"), strArg(args, "decision"), actor)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("%s suggestion for %s is now %s.", rec.Kind, rec.Domain, rec.Status), nil

	case "report_problem":
		title := strArg(args, "title")
		if title == "" {
			return "", fmt.Errorf("title is required")
		}
		issue, err := b.ReportIssue(ctx, title, strArg(args, "detail"), "assistant ("+actor+")")
		if err != nil {
			return "", err
		}
		if issue == nil {
			return "Problem recording is disabled in Settings → Problem reports.", nil
		}
		if issue.GitHubURL != "" {
			return fmt.Sprintf("Recorded and filed: %s", issue.GitHubURL), nil
		}
		return fmt.Sprintf("Recorded locally as %q (status %s). It appears on the Problems page; GitHub reporting is %s.",
			issue.Title, issue.Status, map[bool]string{true: "on", false: "off"}[issue.Status == "reported"]), nil

	case "block_domain":
		domain := strArg(args, "domain")
		if domain == "" {
			return "", fmt.Errorf("domain is required")
		}
		wildcard := true
		if v, ok := args["wildcard"].(bool); ok {
			wildcard = v
		}
		if err := b.BlockDomain(domain, wildcard, noteWithActor(args, actor)); err != nil {
			return "", err
		}
		flushed := b.FlushDNSCache(domain)
		return fmt.Sprintf("Blocked %s%s. Flushed %d cached DNS entries so it takes effect now.",
			wildcardPrefix(wildcard), domain, flushed), nil

	case "allow_domain":
		domain := strArg(args, "domain")
		if domain == "" {
			return "", fmt.Errorf("domain is required")
		}
		if err := b.AllowDomain(domain, noteWithActor(args, actor)); err != nil {
			return "", err
		}
		flushed := b.FlushDNSCache(domain)
		return fmt.Sprintf("Allowed %s, overriding any blocklist. Flushed %d cached entries.", domain, flushed), nil

	case "add_firewall_rule":
		r := &store.Rule{
			ID: uuid.NewString(), Enabled: true, Origin: "assistant",
			Name: strArg(args, "name"), Description: strArg(args, "description"),
			Chain: strArg(args, "chain"), Action: strArg(args, "action"),
			Src: strArg(args, "src"), Dst: strArg(args, "dst"),
			SrcZone: strArg(args, "src_zone"), DstZone: strArg(args, "dst_zone"),
			Proto: strArg(args, "proto"), DstPort: strArg(args, "dst_port"),
			Schedule: strArg(args, "schedule"), Log: boolArg(args, "log"),
		}
		if r.Name == "" || r.Chain == "" || r.Action == "" {
			return "", fmt.Errorf("name, chain and action are all required")
		}
		if err := b.AddRule(r); err != nil {
			return "", err
		}
		return fmt.Sprintf("Created rule %q (id %s) in the %s chain. It is not live until you call apply_firewall.",
			r.Name, r.ID, r.Chain), nil

	case "set_rule_enabled":
		id := strArg(args, "rule_id")
		enabled := boolArg(args, "enabled")
		if err := b.SetRuleEnabled(id, enabled); err != nil {
			return "", err
		}
		return fmt.Sprintf("Rule %s is now %s. Call apply_firewall to make it live.", id, enabledWord(enabled)), nil

	case "delete_firewall_rule":
		id := strArg(args, "rule_id")
		if err := b.DeleteRule(id); err != nil {
			return "", err
		}
		return fmt.Sprintf("Deleted rule %s. Call apply_firewall to make it live.", id), nil

	case "apply_firewall":
		if err := b.ApplyFirewall(ctx); err != nil {
			return "", err
		}
		return "Ruleset compiled and loaded.", nil

	case "set_client_blocked":
		id := strArg(args, "client_id")
		blocked := boolArg(args, "blocked")
		if err := b.SetClientBlocked(id, blocked); err != nil {
			return "", err
		}
		if blocked {
			return fmt.Sprintf("Device %s is now blocked from the network.", id), nil
		}
		return fmt.Sprintf("Device %s has network access again.", id), nil

	case "label_client":
		if err := b.SetClientLabel(strArg(args, "client_id"), strArg(args, "label")); err != nil {
			return "", err
		}
		return fmt.Sprintf("Renamed device to %q.", strArg(args, "label")), nil

	case "decide_ad_candidate":
		domain := strArg(args, "domain")
		decision := strArg(args, "decision")
		if err := b.DecideCandidate(domain, decision, actor); err != nil {
			return "", err
		}
		return fmt.Sprintf("Candidate %s: %sed.", domain, decision), nil

	case "flush_dns_cache":
		n := b.FlushDNSCache(strArg(args, "domain"))
		return fmt.Sprintf("Flushed %d cached DNS entries.", n), nil

	case "refresh_blocklists":
		if err := b.RefreshBlocklists(ctx); err != nil {
			return "", err
		}
		return "Blocklists refreshed and the matcher rebuilt.", nil
	}
	return "", fmt.Errorf("unknown tool %q", call.Name)
}

// summarizeFlows trims a flow to the fields worth spending tokens on.
func summarizeFlows(flows []store.Flow) []map[string]any {
	out := make([]map[string]any, 0, len(flows))
	for _, f := range flows {
		dest := f.Hostname
		if dest == "" {
			dest = f.SNI
		}
		if dest == "" {
			dest = f.DstIP
		}
		entry := map[string]any{
			"id": f.ID, "started": f.StartedAt.Format(time.RFC3339),
			"client_id": f.ClientID, "source": f.SrcIP,
			"destination": dest, "dest_ip": f.DstIP, "port": f.DstPort,
			"proto": f.Proto, "bytes_in": f.BytesIn, "bytes_out": f.BytesOut,
			"verdict": f.Verdict, "active": f.Active(),
		}
		if f.App != "" {
			entry["app"] = f.App
		}
		if f.Country != "" {
			entry["country"] = f.Country
		}
		if f.ASOrg != "" {
			entry["network"] = f.ASOrg
		}
		if f.Reason != "" {
			entry["reason"] = f.Reason
		}
		if f.Risk > 0 {
			entry["risk"] = f.Risk
		}
		out = append(out, entry)
	}
	return out
}

func clientMatches(c store.Client, needle string) bool {
	for _, field := range []string{c.Label, c.Hostname, c.IP, c.MAC, c.Vendor, c.DeviceType} {
		if strings.Contains(strings.ToLower(field), needle) {
			return true
		}
	}
	return false
}

func displayName(c store.Client) string {
	switch {
	case c.Label != "":
		return c.Label
	case c.Hostname != "":
		return c.Hostname
	case c.Vendor != "":
		return c.Vendor + " (" + c.IP + ")"
	default:
		return c.IP
	}
}

// ---- schema + arg helpers ----

func objSchema(props map[string]any, required []string) map[string]any {
	if props == nil {
		props = map[string]any{}
	}
	s := map[string]any{"type": "object", "properties": props}
	if len(required) > 0 {
		s["required"] = required
	}
	return s
}

func strProp(desc string) map[string]any {
	return map[string]any{"type": "string", "description": desc}
}
func numProp(desc string) map[string]any {
	return map[string]any{"type": "number", "description": desc}
}
func boolProp(desc string) map[string]any {
	return map[string]any{"type": "boolean", "description": desc}
}
func enumProp(desc string, values []string) map[string]any {
	return map[string]any{"type": "string", "description": desc, "enum": values}
}

func strArg(args map[string]any, key string) string {
	if v, ok := args[key].(string); ok {
		return strings.TrimSpace(v)
	}
	return ""
}

func boolArg(args map[string]any, key string) bool {
	v, _ := args[key].(bool)
	return v
}

func intArg(args map[string]any, key string, def, max int) int {
	f, ok := args[key].(float64)
	if !ok {
		return def
	}
	v := int(f)
	if v <= 0 {
		return def
	}
	if max > 0 && v > max {
		return max
	}
	return v
}

func floatArg(args map[string]any, key string, def float64) float64 {
	if f, ok := args[key].(float64); ok {
		return f
	}
	return def
}

func hoursAgo(args map[string]any, key string, def, max int) time.Time {
	h := intArg(args, key, def, max)
	return time.Now().Add(-time.Duration(h) * time.Hour)
}

func jsonOf(v any, err error) (string, error) {
	if err != nil {
		return "", err
	}
	out, e := json.Marshal(v)
	if e != nil {
		return "", e
	}
	// A tool result that blows the context window is worse than a truncated
	// one; the model can always narrow its query and ask again.
	const maxResult = 60000
	if len(out) > maxResult {
		return string(out[:maxResult]) + `… [truncated — narrow the query with a filter or a smaller limit]`, nil
	}
	return string(out), nil
}

func noteWithActor(args map[string]any, actor string) string {
	note := strArg(args, "note")
	if note == "" {
		return "via assistant (" + actor + ")"
	}
	return note + " — via assistant (" + actor + ")"
}

func wildcardPrefix(w bool) string {
	if w {
		return "*."
	}
	return ""
}

func enabledWord(b bool) string {
	if b {
		return "enabled"
	}
	return "disabled"
}

// deviceDetail composes the per-device picture from the existing read paths,
// so the model gets one result instead of five round-trips.
func deviceDetail(b Backend, args map[string]any) (string, error) {
	clients := b.Clients()
	var target *store.Client
	if id := strArg(args, "client_id"); id != "" {
		for i := range clients {
			if clients[i].ID == id {
				target = &clients[i]
				break
			}
		}
		if target == nil {
			return "", fmt.Errorf("no device with id %s", id)
		}
	} else if needle := strings.ToLower(strArg(args, "search")); needle != "" {
		var matches []store.Client
		for _, c := range clients {
			if clientMatches(c, needle) {
				matches = append(matches, c)
			}
		}
		switch len(matches) {
		case 0:
			return "", fmt.Errorf("no device matches %q", needle)
		case 1:
			target = &matches[0]
		default:
			options := make([]map[string]any, 0, len(matches))
			for _, c := range matches {
				options = append(options, map[string]any{"id": c.ID, "name": displayName(c), "ip": c.IP, "vendor": c.Vendor, "online": c.Online})
			}
			return jsonOf(map[string]any{
				"ambiguous": true, "message": "Several devices match; call again with one client_id.",
				"matches": options,
			}, nil)
		}
	} else {
		return "", fmt.Errorf("client_id or search is required")
	}

	since := hoursAgo(args, "hours", 24, 720)
	c := *target
	out := map[string]any{
		"id": c.ID, "name": displayName(c), "ip": c.IP, "mac": c.MAC, "vendor": c.Vendor,
		"os": c.OSGuess, "type": c.DeviceType, "zone": c.Zone, "online": c.Online, "blocked": c.Blocked,
		"policy_id": c.PolicyID, "vpn_route": c.VPNRoute, "notes": c.Notes,
		"first_seen": c.FirstSeen.Format(time.RFC3339), "last_seen": c.LastSeen.Format(time.RFC3339),
		"active_connections": c.ActiveFlows,
		"rate_in_bps":        int64(c.RateIn * 8),
		"rate_out_bps":       int64(c.RateOut * 8),
		"lifetime_bytes_in":  c.RxBytes,
		"lifetime_bytes_out": c.TxBytes,
	}
	if rows, err := b.TopDestinations(since, c.ID, 12); err == nil {
		out["top_destinations"] = rows
	}
	if queries, err := b.DNSLog(since, c.ID, false, "", 300); err == nil {
		blocked := 0
		domains := map[string]int{}
		var blockedNames []map[string]any
		for _, q := range queries {
			if q.Blocked {
				blocked++
				if len(blockedNames) < 15 {
					blockedNames = append(blockedNames, map[string]any{"domain": q.Name, "blocked_by": q.BlockSource, "time": q.TS.Format(time.RFC3339)})
				}
			}
			domains[q.Name]++
		}
		out["dns"] = map[string]any{
			"lookups_sampled": len(queries), "blocked": blocked,
			"distinct_domains": len(domains), "recent_blocked": blockedNames,
		}
	}
	if events, err := b.Events(since, "", false, 300); err == nil {
		var mine []map[string]any
		for _, e := range events {
			if e.ClientID == c.ID {
				mine = append(mine, map[string]any{"time": e.TS.Format(time.RFC3339), "severity": e.Severity, "category": e.Category, "title": e.Title})
			}
		}
		out["events"] = mine
	}
	active := 0
	for _, f := range b.ActiveFlows(2000) {
		if f.ClientID == c.ID {
			active++
		}
	}
	out["active_connections_now"] = active
	return jsonOf(out, nil)
}
