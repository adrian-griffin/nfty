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

// build the nft log syntax from nfty config
// eg: log prefix "NFTY DROP 22/TCP: " level warn
func formatLog(log *config.LogConfig) string {
	logContents := fmt.Sprintf("log prefix \"%s\"", log.Prefix)
	if log.Level != "" {
		logContents += fmt.Sprintf(" level %s", log.Level)
	}
	return logContents
}

// wraps a rule-list into a chain block with policy, type, hook, etc.
func buildChain(name string, chainType string, hook string, priority int,
	policy string, ruleLines []string) string {

	var chainOutput strings.Builder

	// write chain declaration contents to chain block buffer
	chainOutput.WriteString(fmt.Sprintf("\n    chain %s {\n", name))
	chainOutput.WriteString(fmt.Sprintf("        type %s hook %s priority %d; policy %s;\n",
		chainType, hook, priority, policy))

	// inject each rule line
	for _, line := range ruleLines {
		chainOutput.WriteString(line + "\n")
	}

	// wrap 'er up
	chainOutput.WriteString("    }\n")
	return chainOutput.String()
}

// combines default, user-supplied, and other auto-generated rules into proper order for placement into table
func buildChainRules(userRules []config.Rule, family string,
	core config.CoreConfig, chainName string) ([]string, error) {

	var lines []string

	// default rules first
	if core.DefaultRules {
		if chainName == "input" {
			lines = append(lines, buildDefaultInputs(family, core)...)
		} else if chainName == "forward" {
			lines = append(lines, buildDefaultForwards()...)
		}
	}

	// inject user-defined rules, splitting multi-protocol nfty config entries into multiple nftables lines
	for _, rule := range userRules {
		ruleLine, err := buildRule(rule, family) // stubbing
		if err != nil {
			return nil, fmt.Errorf("chain %s, rule %q: %w", chainName, rule.Comment, err)
		}
		lines = append(lines, ruleLine...)
	}

	// logging and other auto-generated rules at the end, possibly more to add later
	if chainName == "input" && core.LogSSHFails {
		lines = append(lines, buildSSHLogRules(family)...)
	}

	return lines, nil
}

// builds out all the dynamic "matcher" portions of nft rules
// <interface-match>     <socket/procol+port>    <src-address>   <conn state>
// eg: ["iifname \"eth0\"", "tcp dport { 80, 443 }", "ip saddr @webui"]
func buildMatchCriteria(rule config.Rule, proto string, family string) []string {
	var parts []string

	// interface name matching
	// eventually need to add more robust validations here, possibly including collecting interface info from machine
	// TODO: interace-name validations/in safety (?)
	if rule.IIF != "" {
		parts = append(parts, fmt.Sprintf("iif \"%s\"", rule.IIF))
		fmt.Printf("iif verb used for interface matching, please use iifname instead,")
		fmt.Printf("unless this is a loopback interface or you are aware of the limitations")
	}
	if rule.IIFName != "" {
		parts = append(parts, fmt.Sprintf("iifname \"%s\"", rule.IIFName))
	}
	if rule.OIFName != "" {
		parts = append(parts, fmt.Sprintf("oifname \"%s\"", rule.OIFName))
	}

	// dport socket mapping
	// if tcp/udp, build <proto> dport
	if proto == "tcp" || proto == "udp" {
		if len(rule.DPort) > 0 {
			// "tcp dport 22" or "udp dport { 53, 5353 }"
			parts = append(parts, fmt.Sprintf("%s dport %s", proto, formatDPort(rule.DPort)))
		} else {
			// "meta l4proto tcp" — match protocol without port constraint
			parts = append(parts, fmt.Sprintf("meta l4proto %s", proto))
		}
		// or if icmp/icmp6, do `meta l4` writing
	} else if proto == "icmp" || proto == "icmpv6" {
		// "meta l4proto icmp" or "meta l4proto icmpv6"
		parts = append(parts, fmt.Sprintf("meta l4proto %s", proto))
	}
	// currently, if proto is "", skip protocol matching entirely

	// TODO: add source port logic

	// src address wrangling
	// either named address-list (@ssh) or array of ips ({10.0.0.1, 10.0.0.2})
	src := formatSrcMatch(rule, family)
	if src != "" {
		parts = append(parts, src)
	}

	// connection state writing
	if len(rule.CtState) > 0 {
		parts = append(parts, fmt.Sprintf("ct state %s", strings.Join(rule.CtState, ",")))
	}

	return parts
}
