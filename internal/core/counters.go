package core

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/adrian-griffin/nfty/internal/colour"
	"github.com/adrian-griffin/nfty/internal/nft"
	"github.com/adrian-griffin/nfty/internal/tools"
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
			Family  string            `json:"family"`
			Table   string            `json:"table"`
			Chain   string            `json:"chain"`
			Expr    []json.RawMessage `json:"expr"`
			Comment string            `json:"comment"`
		}
		if err := json.Unmarshal(ruleRaw, &rule); err != nil {
			continue
		}

		// look for comment and counter
		var packets, bytes uint64
		hasCounter := false

		for _, exprRaw := range rule.Expr {
			var expr map[string]json.RawMessage
			if err := json.Unmarshal(exprRaw, &expr); err != nil {
				continue
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
		if hasCounter && len(rule.Comment) > 0 {
			counters = append(counters, RuleCounter{
				Comment: rule.Comment,
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

// runs counters parsing and displays output
func RunCounters() {
	counts, err := ParseCounters()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to read counters: %v\n", err)
		os.Exit(1)
	}

	if len(counts) == 0 {
		fmt.Printf("no nfty counters found, try re-applying nfty config")
		return
	}

	// print header output
	tools.CommandExecuteHeader("counters")

	const commentWidth = 50

	// header
	currentFamily := ""
	fmt.Print(colour.Bold(colour.Greyf("\n  %-*s %12s %10s\n", commentWidth, "RULE", "PACKETS", "BYTES")))
	fmt.Print(colour.Greyf("  %-*s %12s %10s\n", commentWidth, strings.Repeat("─", commentWidth), strings.Repeat("─", 12), strings.Repeat("─", 10)))

	for _, c := range counts {
		// print family/chain header when it changes
		familyChain := c.Family + " " + c.Chain
		if familyChain != currentFamily {
			fmt.Print(colour.Bold(colour.Greyf("\n  [%s/%s]\n", c.Family, c.Chain)))
			currentFamily = familyChain
		}

		// pad prior to ansi colouring
		padded := fmt.Sprintf("%-*s", commentWidth, tools.Truncate(c.Comment, commentWidth))
		fmt.Printf("    %s %12s %10s\n",
			colour.Grey(padded),
			FormatPackets(c.Packets),
			FormatBytes(c.Bytes))
	}
	fmt.Println()
}
