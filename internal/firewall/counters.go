package firewall

import (
	"encoding/json"
	"strings"
)

// parseCounters walks `nft -j list table` output and pulls out per-rule
// counters, keyed by the rule id we embed in each comment.
//
// The JSON shape is a top-level {"nftables":[ {...}, {...} ]} array where rule
// objects look like {"rule":{"comment":"<id>|<name>","expr":[{"counter":{...}}]}}.
func parseCounters(raw []byte) (map[string][2]int64, error) {
	var doc struct {
		Nftables []map[string]json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	out := map[string][2]int64{}
	for _, item := range doc.Nftables {
		ruleRaw, ok := item["rule"]
		if !ok {
			continue
		}
		var rule struct {
			Comment string            `json:"comment"`
			Expr    []json.RawMessage `json:"expr"`
		}
		if err := json.Unmarshal(ruleRaw, &rule); err != nil {
			continue
		}
		id, _, found := strings.Cut(rule.Comment, "|")
		if !found || id == "" {
			continue
		}
		for _, e := range rule.Expr {
			var wrapper struct {
				Counter *struct {
					Packets int64 `json:"packets"`
					Bytes   int64 `json:"bytes"`
				} `json:"counter"`
			}
			if err := json.Unmarshal(e, &wrapper); err != nil || wrapper.Counter == nil {
				continue
			}
			out[id] = [2]int64{wrapper.Counter.Packets, wrapper.Counter.Bytes}
			break
		}
	}
	return out, nil
}
