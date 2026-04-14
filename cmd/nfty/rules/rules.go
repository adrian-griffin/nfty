package rules

import (
	"fmt"
	"strings"

	"github.com/adrian-griffin/nfty/config"
)

// builds nftables output config in the following general design:
// | -- IPv4
// |  address lists/groups
// | INPUT
// |  default rules (if enabled)
// |  user-defined rules (in order supplied)
// |  log and extraneous rules
// | FORWARD
// |  default rules (if enabled)
// |  user-defined rules (in order supplied)
// |  log and extraneous rules
// | EXTRA CHAINS
// | -- IPv6
// |  address lists/groups
// | INPUT
// |  default rules (if enabled)
// |  user-defined rules (in order supplied)
// |  log and extraneous rules
// | FORWARD
// |  default rules (if enabled)
// |  user-defined rules (in order supplied)
// |  log and extraneous rules
// | EXTRA CHAINS

// =============================================================================
// DEFAULT RULE BUILDERS
// =============================================================================

// build out default input-chain rules
func buildDefaultInputs(family string, core config.CoreConfig) []string {
	var lines []string

	// loopback
	lines = append(lines,
		"        iif \"lo\" accept comment \"nfty: allow loopback\"")

	// icmp and ratelimiting
	icmpProto := "ipv4"
	icmpLimit := core.ICMPv4Limit
	if family == "ipv6" {
		icmpProto = "icmpv6"
		icmpLimit = core.ICMPv6Limit
	}

	// handle if user-passed icmp limit(s) are empty
	if icmpLimit != "" {
		lines = append(lines,
			fmt.Sprintf("        meta l4proto %s limit rate %s accept comment \"nfty: %s rate limit\"",
				icmpProto, icmpLimit, icmpProto))

		lines = append(lines,
			fmt.Sprintf("        meta l4proto %s drop comment \"nfty: %s over limit\"",
				icmpProto, icmpProto))
	}

	// established, related input
	lines = append(lines,
		"        ct state established,related accept comment \"nfty: allow established\"")
	// drop invalids
	lines = append(lines,
		"        ct state invalid drop comment \"nfty: drop invalid\"")

	return lines
}

// build out default forward-chain rules
func buildDefaultForwards() []string {
	return []string{
		"        ct state established,related accept comment \"nfty: allow established\"",
		"        ct state invalid drop comment \"nfty: drop invalid\"",
	}
}

// generates the SSH log+drop catch-all rules.
func buildSSHLogRules(family string) []string {
	return []string{
		"        tcp dport 22 log prefix \"NFTY DROP 22/TCP: \" level warn comment \"nfty: SSH log\"",
		"        tcp dport 22 drop comment \"nfty: SSH drop\"",
	}
}

// converts various dport formats (eg [22], [161-162], [443,80]) into NFTables-parsable syntax
func formatDPort(ports []config.PortValue) string {
	// if single port/range, no braces needed
	if len(ports) == 1 {
		return ports[0].String()
	}

	// multiple ports/ranges — wrap in curly braces
	strs := make([]string, len(ports))
	for i, p := range ports {
		strs[i] = p.String()
	}
	return "{ " + strings.Join(strs, ", ") + " }"
}

// converts address-list sets or lists (eg src_set = "ssh", src_ips = [...]) into NFTables-parsable syntax
// returns empty str if neither is set (ie allow on all src-addresses at the firewall lvl for that socket)
func formatSrcMatch(rule config.Rule, family string) string {
	// determine rule ip-family prefix
	prefix := "ip"
	if family == "ipv6" {
		prefix = "ip6"
	}

	// return NFTables config for named address-list/address set
	if rule.SrcSet != "" {
		return fmt.Sprintf("%s saddr @%s", prefix, rule.SrcSet)
	}

	// return NFTables config for raw srcIP list
	// creates an anonymous set in the rule itself
	if len(rule.SrcIPs) > 0 {
		return fmt.Sprintf("%s saddr { %s }", prefix, strings.Join(rule.SrcIPs, ", "))
	}

	// if nada, return blank string which will be interpreted as 0.0.0.0/0 or 0:: on NFT
	return ""
}
