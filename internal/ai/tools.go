package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

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

		// ---- mutating ----
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

	// ---- mutating ----
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
