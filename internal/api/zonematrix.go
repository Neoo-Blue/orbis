package api

import (
	"net/http"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/Neoo-Blue/orbis/internal/config"
	"github.com/Neoo-Blue/orbis/internal/store"
	"github.com/go-chi/chi/v5"
)

const (
	zoneThisNode = "This node"
	trustSelf    = "self"
)

type MatrixZone struct {
	Name       string   `json:"name"`
	Trust      string   `json:"trust"`
	Interfaces []string `json:"interfaces"`
	Subnets    []string `json:"subnets"`
	Implicit   bool     `json:"implicit"`
}

type MatrixCell struct {
	Src           string       `json:"src"`
	Dst           string       `json:"dst"`
	Chain         string       `json:"chain"`
	DefaultAction string       `json:"default_action"`
	DefaultReason string       `json:"default_reason"`
	Verdict       string       `json:"verdict"`
	RuleCount     int          `json:"rule_count"`
	CounterPkts   int64        `json:"counter_pkts"`
	CounterBytes  int64        `json:"counter_bytes"`
	HasBlock      bool         `json:"has_block"`
	RuleIDs       []string     `json:"rule_ids"`
	Rules         []store.Rule `json:"rules"`
	Flows         int64        `json:"flows"`
	FlowBytes     int64        `json:"flow_bytes"`
	FlowsBlocked  int64        `json:"flows_blocked"`
}

type ZoneMatrixResponse struct {
	Mode           string       `json:"mode"`
	Enforced       bool         `json:"enforced"`
	DefaultForward string       `json:"default_forward"`
	WindowSeconds  int          `json:"window_seconds"`
	Zones          []MatrixZone `json:"zones"`
	Cells          []MatrixCell `json:"cells"`
}

func (s *Server) mountZoneMatrix(r chi.Router) {
	r.Get("/firewall/matrix", s.handleZoneMatrix)
}

func (s *Server) handleZoneMatrix(w http.ResponseWriter, r *http.Request) {
	cfg := s.cfg.Snapshot()
	rules, err := s.app.Store.Rules()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	totals, err := s.app.Store.FlowAddrTotals(time.Now().Add(-time.Hour))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeOK(w, buildZoneMatrix(cfg, rules, totals))
}

func buildZoneMatrix(cfg config.Config, rules []store.Rule, flowTotals []store.FlowAddrTotal) ZoneMatrixResponse {
	mode := string(cfg.Mode)
	if mode == "" {
		mode = string(config.ModeObserve)
	}
	defFwd := strings.ToLower(cfg.Firewall.DefaultForward)
	if defFwd != "accept" {
		defFwd = "drop"
	}

	zones := matrixZones(cfg)
	att := newZoneAttributor(zones)

	type flowAccum struct {
		flows   int64
		bytes   int64
		blocked int64
	}
	pairFlows := make(map[[2]string]flowAccum, len(zones)*len(zones))
	for _, ft := range flowTotals {
		srcZone := att.zoneForIP(ft.SrcIP)
		dstZone := att.zoneForIP(ft.DstIP)
		if srcZone == "" || dstZone == "" {
			continue
		}
		key := [2]string{srcZone, dstZone}
		cur := pairFlows[key]
		cur.flows += ft.Flows
		cur.bytes += ft.Bytes
		cur.blocked += ft.Blocked
		pairFlows[key] = cur
	}

	// Keep enabled filter rules sorted in the exact order nftables evaluates them.
	enabled := make([]store.Rule, 0, len(rules))
	for _, r := range rules {
		if !r.Enabled {
			continue
		}
		if ruleVerdictAction(r.Action) == "" {
			continue
		}
		switch strings.ToLower(r.Chain) {
		case "forward", "input", "output":
			enabled = append(enabled, r)
		}
	}
	sort.SliceStable(enabled, func(i, j int) bool {
		return enabled[i].Position < enabled[j].Position
	})

	anyIface := anyConfiguredZoneInterfaces(cfg)
	cells := make([]MatrixCell, 0, len(zones)*len(zones))
	for _, src := range zones {
		for _, dst := range zones {
			defAct, defReason := matrixDefaultAction(cfg, src, dst, anyIface)
			applying := matchingRulesForPair(enabled, src, dst, att)
			ruleIDs := make([]string, 0, len(applying))
			var pkts, bytesTotal int64
			hasBlock := false
			for _, r := range applying {
				ruleIDs = append(ruleIDs, r.ID)
				pkts += r.CounterPkts
				bytesTotal += r.CounterBytes
				if ruleVerdictAction(r.Action) == "block" {
					hasBlock = true
				}
			}
			fa := pairFlows[[2]string{src.Name, dst.Name}]
			cells = append(cells, MatrixCell{
				Src:           src.Name,
				Dst:           dst.Name,
				Chain:         pairChain(src, dst),
				DefaultAction: defAct,
				DefaultReason: defReason,
				Verdict:       computeCellVerdict(defAct, applying),
				RuleCount:     len(applying),
				CounterPkts:   pkts,
				CounterBytes:  bytesTotal,
				HasBlock:      hasBlock,
				RuleIDs:       ruleIDs,
				Rules:         applying,
				Flows:         fa.flows,
				FlowBytes:     fa.bytes,
				FlowsBlocked:  fa.blocked,
			})
		}
	}

	return ZoneMatrixResponse{
		Mode:           mode,
		Enforced:       cfg.Mode == config.ModeInline && cfg.Firewall.Enabled,
		DefaultForward: defFwd,
		WindowSeconds:  3600,
		Zones:          zones,
		Cells:          cells,
	}
}

func matrixZones(cfg config.Config) []MatrixZone {
	zones := make([]MatrixZone, 0, len(cfg.Firewall.Zones)+3)
	usedNames := make(map[string]bool, len(cfg.Firewall.Zones)+3)
	var hasLAN, hasWAN, hasSelf bool

	for _, z := range cfg.Firewall.Zones {
		trust := normalizeZoneTrust(z.Name, z.Trust)
		switch trust {
		case "lan":
			hasLAN = true
		case "wan":
			hasWAN = true
		case trustSelf:
			hasSelf = true
		}
		ifaces := nonNilStrings(z.Interfaces)
		subnets := nonNilStrings(z.Subnets)
		zones = append(zones, MatrixZone{
			Name:       z.Name,
			Trust:      trust,
			Interfaces: ifaces,
			Subnets:    subnets,
			Implicit:   false,
		})
		usedNames[strings.ToLower(z.Name)] = true
	}

	if !hasLAN {
		name := uniqueZoneName("LAN", usedNames)
		zones = append(zones, MatrixZone{
			Name:       name,
			Trust:      "lan",
			Interfaces: []string{},
			Subnets:    []string{},
			Implicit:   true,
		})
	}
	if !hasWAN {
		name := uniqueZoneName("WAN", usedNames)
		ifaces := []string{}
		if cfg.Firewall.WANInterface != "" {
			ifaces = []string{cfg.Firewall.WANInterface}
		}
		zones = append(zones, MatrixZone{
			Name:       name,
			Trust:      "wan",
			Interfaces: ifaces,
			Subnets:    []string{},
			Implicit:   true,
		})
	}
	if !hasSelf {
		name := uniqueZoneName(zoneThisNode, usedNames)
		zones = append(zones, MatrixZone{
			Name:       name,
			Trust:      trustSelf,
			Interfaces: []string{"lo"},
			Subnets:    []string{},
			Implicit:   true,
		})
	}
	return zones
}

func normalizeZoneTrust(name, trust string) string {
	t := strings.ToLower(strings.TrimSpace(trust))
	switch t {
	case "wan", "lan", "guest", "iot", "vpn", "dmz":
		return t
	case "self", "node":
		return trustSelf
	}
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "wan":
		return "wan"
	case "this node", "self", "node":
		return trustSelf
	default:
		return "lan"
	}
}

func uniqueZoneName(preferred string, used map[string]bool) string {
	cand := preferred
	for n := 2; used[strings.ToLower(cand)]; n++ {
		cand = preferred + " " + itoa(n)
	}
	used[strings.ToLower(cand)] = true
	return cand
}

func nonNilStrings(in []string) []string {
	if len(in) == 0 {
		return []string{}
	}
	out := make([]string, len(in))
	copy(out, in)
	return out
}

func anyConfiguredZoneInterfaces(cfg config.Config) bool {
	for _, z := range cfg.Firewall.Zones {
		if len(z.Interfaces) > 0 {
			return true
		}
	}
	return false
}

func pairChain(src, dst MatrixZone) string {
	switch {
	case src.Trust == trustSelf && dst.Trust != trustSelf:
		return "output"
	case dst.Trust == trustSelf:
		return "input"
	default:
		return "forward"
	}
}

// matrixDefaultAction mirrors internal/firewall/nftables.go so each cell shows
// the actual ruleset posture rather than a generic guess:
//   - output has policy accept; loopback is accepted on input.
//   - input has policy drop (with service openings for DNS/DHCP/SSH/UI/ICMP,
//     and full accept on tailscale0 when Tailscale is enabled).
//   - forward has policy cfg.Firewall.DefaultForward ("drop" unless "accept"),
//     with built-in rules isolating guest/iot from local zones before allowing
//     lan/vpn/guest/iot egress to WAN.
func matrixDefaultAction(cfg config.Config, src, dst MatrixZone, anyIface bool) (string, string) {
	if src.Trust == trustSelf && dst.Trust == trustSelf {
		return "allow", "loopback accepted in input chain"
	}
	if src.Trust == trustSelf {
		return "allow", "output chain policy accept"
	}
	if dst.Trust == trustSelf {
		if cfg.Tailscale.Enabled && isTailscaleOnly(src.Interfaces) {
			return "allow", "tailscale0 accepted in input chain"
		}
		if src.Trust == "lan" || src.Trust == "vpn" {
			return "block", "input chain policy drop (DNS, DHCP, SSH and UI ports open)"
		}
		return "block", "input chain policy drop"
	}

	fwdAction := "block"
	fwdReason := "forward chain policy drop"
	if strings.EqualFold(cfg.Firewall.DefaultForward, "accept") {
		fwdAction = "allow"
		fwdReason = "forward chain policy accept"
	}

	if src.Name == dst.Name {
		if src.Trust == "wan" || len(src.Interfaces) > 1 {
			return fwdAction, fwdReason
		}
		return "allow", "same local segment"
	}

	if cfg.Tailscale.Enabled && (isTailscaleOnly(src.Interfaces) || isTailscaleOnly(dst.Interfaces)) {
		return "allow", "tailscale0 accepted in forward chain"
	}

	srcActive := src.Implicit || len(src.Interfaces) > 0 || !anyIface
	dstActive := dst.Implicit || len(dst.Interfaces) > 0 || !anyIface
	if srcActive {
		switch src.Trust {
		case "guest", "iot":
			if dst.Trust != "wan" && dstActive {
				return "block", src.Name + " isolated from " + dst.Name
			}
			if dst.Trust == "wan" && matchesWANPosture(cfg, dst, anyIface) {
				return "allow", src.Name + " to internet allowed"
			}
		case "lan", "vpn":
			if dst.Trust == "wan" && matchesWANPosture(cfg, dst, anyIface) {
				return "allow", src.Name + " to internet allowed"
			}
		}
	}

	return fwdAction, fwdReason
}

func matchesWANPosture(cfg config.Config, dst MatrixZone, anyIface bool) bool {
	if dst.Implicit || !anyIface {
		return true
	}
	wan := cfg.Firewall.WANInterface
	if wan == "" {
		// Without wan_interface, nftables emits no oifname "<wan>" accept rule
		// when physical zone interfaces are already bound.
		return cfg.Mode != config.ModeInline
	}
	if len(dst.Interfaces) == 0 {
		return true
	}
	return slices.Contains(dst.Interfaces, wan)
}

func isTailscaleOnly(ifaces []string) bool {
	if len(ifaces) == 0 {
		return false
	}
	for _, iface := range ifaces {
		if iface != "tailscale0" {
			return false
		}
	}
	return true
}

func matchingRulesForPair(rules []store.Rule, src, dst MatrixZone, att *zoneAttributor) []store.Rule {
	out := []store.Rule{}
	for _, r := range rules {
		if ruleAppliesToPair(r, src, dst, att) {
			out = append(out, r)
		}
	}
	return out
}

func ruleAppliesToPair(r store.Rule, src, dst MatrixZone, att *zoneAttributor) bool {
	switch strings.ToLower(r.Chain) {
	case "input":
		if dst.Trust != trustSelf || src.Trust == trustSelf {
			return false
		}
		return zoneMatchesRuleEnd(r.SrcZone, r.Src, src, att)
	case "output":
		if src.Trust != trustSelf || dst.Trust == trustSelf {
			return false
		}
		return zoneMatchesRuleEnd(r.DstZone, r.Dst, dst, att)
	case "forward":
		if src.Trust == trustSelf || dst.Trust == trustSelf {
			return false
		}
		if src.Name == dst.Name && src.Trust != "wan" && len(src.Interfaces) <= 1 {
			return r.SrcZone != "" && r.DstZone != "" &&
				zoneNameMatches(r.SrcZone, src) && zoneNameMatches(r.DstZone, dst)
		}
		return zoneMatchesRuleEnd(r.SrcZone, r.Src, src, att) &&
			zoneMatchesRuleEnd(r.DstZone, r.Dst, dst, att)
	default:
		return false
	}
}

func zoneMatchesRuleEnd(ruleZone, addrSpec string, z MatrixZone, att *zoneAttributor) bool {
	if ruleZone != "" {
		return zoneNameMatches(ruleZone, z)
	}
	if addrSpec != "" {
		if matched := att.zonesForAddrSpec(addrSpec); len(matched) > 0 {
			return matched[z.Name]
		}
	}
	return true
}

func zoneNameMatches(ruleZone string, z MatrixZone) bool {
	if strings.EqualFold(strings.TrimSpace(ruleZone), z.Name) {
		return true
	}
	return z.Implicit && strings.EqualFold(strings.TrimSpace(ruleZone), z.Trust)
}

func ruleVerdictAction(action string) string {
	switch strings.ToLower(strings.TrimSpace(action)) {
	case "accept", "allow":
		return "allow"
	case "drop", "reject":
		return "block"
	default:
		return ""
	}
}

func ruleIsUnconditional(r store.Rule) bool {
	if strings.TrimSpace(r.Src) != "" || strings.TrimSpace(r.Dst) != "" {
		return false
	}
	proto := strings.ToLower(strings.TrimSpace(r.Proto))
	if proto != "" && proto != "any" {
		return false
	}
	if strings.TrimSpace(r.SrcPort) != "" || strings.TrimSpace(r.DstPort) != "" {
		return false
	}
	if strings.TrimSpace(r.Schedule) != "" {
		return false
	}
	return true
}

func computeCellVerdict(defaultAction string, rules []store.Rule) string {
	var sawAllow, sawBlock bool
	terminal := defaultAction
	for _, r := range rules {
		act := ruleVerdictAction(r.Action)
		if act == "" {
			continue
		}
		if ruleIsUnconditional(r) {
			terminal = act
			break
		}
		if act == "allow" {
			sawAllow = true
		} else {
			sawBlock = true
		}
	}
	if terminal == "allow" && sawBlock {
		return "mixed"
	}
	if terminal == "block" && sawAllow {
		return "mixed"
	}
	return terminal
}

type zonePrefix struct {
	prefix netip.Prefix
	zone   string
}

type zoneAttributor struct {
	prefixes []zonePrefix
	lanZone  string
	wanZone  string
	selfZone string
}

func newZoneAttributor(zones []MatrixZone) *zoneAttributor {
	att := &zoneAttributor{}
	for _, z := range zones {
		switch z.Trust {
		case "lan":
			if att.lanZone == "" {
				att.lanZone = z.Name
			}
		case "wan":
			if att.wanZone == "" {
				att.wanZone = z.Name
			}
		case trustSelf:
			if att.selfZone == "" {
				att.selfZone = z.Name
			}
		}
		for _, raw := range z.Subnets {
			if p, ok := parsePrefixOrAddr(raw); ok {
				att.prefixes = append(att.prefixes, zonePrefix{prefix: p, zone: z.Name})
			}
		}
	}
	// Longest prefix wins when one zone carves a subnet out of a wider supernet.
	sort.SliceStable(att.prefixes, func(i, j int) bool {
		return att.prefixes[i].prefix.Bits() > att.prefixes[j].prefix.Bits()
	})
	return att
}

func parsePrefixOrAddr(raw string) (netip.Prefix, bool) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return netip.Prefix{}, false
	}
	if p, err := netip.ParsePrefix(s); err == nil {
		u := p.Addr().Unmap()
		if u != p.Addr() {
			bits := p.Bits() - 96
			if bits < 0 {
				bits = 0
			}
			return netip.PrefixFrom(u, bits).Masked(), true
		}
		return p.Masked(), true
	}
	if a, err := netip.ParseAddr(s); err == nil {
		u := a.Unmap()
		return netip.PrefixFrom(u, u.BitLen()), true
	}
	return netip.Prefix{}, false
}

func (a *zoneAttributor) zoneForIP(raw string) string {
	addr, err := netip.ParseAddr(strings.TrimSpace(raw))
	if err != nil {
		return ""
	}
	return a.zoneForAddr(addr.Unmap())
}

func (a *zoneAttributor) zoneForAddr(addr netip.Addr) string {
	if addr.IsLoopback() && a.selfZone != "" {
		return a.selfZone
	}
	for _, zp := range a.prefixes {
		if zp.prefix.Contains(addr) {
			return zp.zone
		}
	}
	if isRFC1918OrULA(addr) {
		return a.lanZone
	}
	return a.wanZone
}

func (a *zoneAttributor) zonesForAddrSpec(spec string) map[string]bool {
	matched := map[string]bool{}
	parsedAny := false
	for _, part := range strings.Split(spec, ",") {
		p, ok := parsePrefixOrAddr(part)
		if !ok {
			continue
		}
		parsedAny = true
		overlapped := false
		for _, zp := range a.prefixes {
			if p.Overlaps(zp.prefix) {
				matched[zp.zone] = true
				overlapped = true
			}
		}
		if !overlapped {
			if z := a.zoneForAddr(p.Addr()); z != "" {
				matched[z] = true
			}
		}
	}
	if !parsedAny {
		return nil
	}
	return matched
}

// isRFC1918OrULA matches 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 and fc00::/7.
func isRFC1918OrULA(addr netip.Addr) bool {
	return addr.IsPrivate()
}
