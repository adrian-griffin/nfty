package counters

import (
	"encoding/json"
	"fmt"

	"github.com/adrian-griffin/nfty/nft"
)

// struct to hold each rules info
type RuleCounter struct {
	Comment string
	Packets uint64
	Bytes   uint64
	Chain   string
	Family  string
	Table   string
}

// parses nftables json output and looks for `nfty:` comments
func ParseCounters() ([]RuleCounter, error) {
	raw, err := nft.ListRulesetJson()
	if err != nil {
		return nil, fmt.Errorf("reading nft json: %w", err)
	}

	// nft -j list ruleset returns this format:
	// { "nftables": [ {metainfo}, {table}, {chain}, {rule}, ... ] }
	var toplevel struct {
		Nftables []json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal(raw, &toplevel); err != nil {
		return nil, fmt.Errorf("parsing nft json: %w", err)
	}

	var counters []RuleCounter

	// this is the actual json tier with deets
	for _, entry := range toplevel.Nftables {
		var wrapper map[string]json.RawMessage
		if err := json.Unmarshal(entry, &wrapper); err != nil {
			continue
		}

		ruleRaw, hit := wrapper["rule"]
		if !hit {
			continue // not a rule object
		}

		// parse the rule object
		var rule struct {
			Family string            `json:"family"`
			Table  string            `json:"table"`
			Chain  string            `json:"chain"`
			Expr   []json.RawMessage `json:"expr"`
		}
		if err := json.Unmarshal(ruleRaw, &rule); err != nil {
			continue
		}

		// look for comment and counter
		var comment string
		var packets, bytes uint64
		hasCounter := false

		for _, exprRaw := range rule.Expr {
			var expr map[string]json.RawMessage
			if err := json.Unmarshal(exprRaw, &expr); err != nil {
				continue
			}

			// check for comment
			if commentRaw, hit := expr["comment"]; hit {
				json.Unmarshal(commentRaw, &comment)
			}

			// check for counter
			if counterRaw, hit := expr["counter"]; hit {
				var counter struct {
					Packets uint64 `json:"packets"`
					Bytes   uint64 `json:"bytes"`
				}
				if err := json.Unmarshal(counterRaw, &counter); err == nil {
					packets = counter.Packets
					bytes = counter.Bytes
					hasCounter = true
				}
			}
		}

		// append rules with nfty comments and counters
		if hasCounter && len(comment) > 0 {
			counters = append(counters, RuleCounter{
				Comment: comment,
				Packets: packets,
				Bytes:   bytes,
				Chain:   rule.Chain,
				Family:  rule.Family,
				Table:   rule.Table,
			})
		}
	}

	return counters, nil
}

// converts byte count to human-readable string (KB, MB, GB, B)
// yeah man imma be real, only claude knows how this works
// or at least i dont..
func FormatBytes(b uint64) string {
	switch {
	case b >= 1<<30:
		return fmt.Sprintf("%.1f GB", float64(b)/(1<<30))
	case b >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(b)/(1<<20))
	case b >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(b)/(1<<10))
	default:
		return fmt.Sprintf("%d B", b)
	}
}

// formats large packet counts, adding comments to keep it readable
func FormatPackets(p uint64) string {
	s := fmt.Sprintf("%d", p)
	if len(s) <= 3 {
		return s
	}

	// insert commas from right to left
	var result []byte
	for i, c := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			result = append(result, ',')
		}
		result = append(result, byte(c))
	}
	return string(result)
}
