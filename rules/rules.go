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

// generates full nftables ruleset as a string from a nfty config
func Generate(cfg *config.Config) (string, error) {
	var nftablesOutput strings.Builder

	// shebang
	nftablesOutput.WriteString("#!/usr/sbin/nft -f\n\n")

	// atomic table cleanup, because nft is sketchy af
	// always create table-name, then delete it to ensure a clean slate during rule application
	nftablesOutput.WriteString(fmt.Sprintf("table ip %s\ndelete table ip %s\n", cfg.Core.Table, cfg.Core.Table))
	nftablesOutput.WriteString(fmt.Sprintf("table ip6 %s\ndelete table ip6 %s\n\n", cfg.Core.Table, cfg.Core.Table))

	// build ip4 table
	ipv4Table, err := buildTable("ip", cfg.Core.Table, cfg.Lists.IPv4,
		cfg.Chains.IPv4, cfg.Chains.Policy, cfg.Core)
	if err != nil {
		return "", fmt.Errorf("building ipv4 table: %w", err)
	}
	nftablesOutput.WriteString(ipv4Table)
	nftablesOutput.WriteString("\n")

	// build ip6 table
	ipv6Table, err := buildTable("ip6", cfg.Core.Table, cfg.Lists.IPv6,
		cfg.Chains.IPv6, cfg.Chains.Policy, cfg.Core)
	if err != nil {
		return "", fmt.Errorf("building ipv6 table: %w", err)
	}
	nftablesOutput.WriteString(ipv6Table)

	return nftablesOutput.String(), nil
}

// build out default input-chain rules
func buildDefaultInputs(family string, core config.CoreConfig) []string {
	var lines []string

	// loopback
	lines = append(lines,
		"        iif \"lo\" counter accept comment \"nfty: allow loopback\"")

	// icmp and ratelimiting
	icmpProto := "icmp"
	icmpLimit := core.ICMPv4Limit
	if family == "ip6" {
		icmpProto = "icmpv6"
		icmpLimit = core.ICMPv6Limit
	}

	// handle if user-passed icmp limit(s) are empty
	if icmpLimit != "" {
		lines = append(lines,
			fmt.Sprintf("        meta l4proto %s limit rate %s counter accept comment \"nfty: %s rate limit\"",
				icmpProto, icmpLimit, icmpProto))

		lines = append(lines,
			fmt.Sprintf("        meta l4proto %s counter drop comment \"nfty: %s over limit\"",
				icmpProto, icmpProto))
	}

	// established, related input
	lines = append(lines,
		"        ct state established,related counter accept comment \"nfty: allow established\"")
	// drop invalids
	lines = append(lines,
		"        ct state invalid counter drop comment \"nfty: drop invalid\"")

	return lines
}

// build out default forward-chain rules
func buildDefaultForwards() []string {
	return []string{
		"        ct state established,related counter accept comment \"nfty: allow established\"",
		"        ct state invalid counter drop comment \"nfty: drop invalid\"",
	}
}

// generates SSH log+drop ruleset
func buildSSHLogRules() []string {
	return []string{
		"        tcp dport 22 counter log prefix \"NFTY DROP 22/TCP: \" level warn comment \"nfty: SSH log\"",
		"        tcp dport 22 counter drop comment \"nfty: SSH drop\"",
	}
}

// converts various dport formats (eg [22], [161-162], [443,80]) into NFTables-parsable syntax
func formatPort(ports []config.PortValue) string {
	// if single port/range, no braces needed
	if len(ports) == 1 {
		return ports[0].String()
	}

	// multiple ports/ranges - wrap in curly braces
	strs := make([]string, len(ports))
	for i, p := range ports {
		strs[i] = p.String()
	}
	return "{ " + strings.Join(strs, ", ") + " }"
}

// converts address-list sets or lists (eg src_list = "ssh", src_ips = [...]) into NFTables-parsable syntax
// returns empty str if neither is set (ie allow on all src-addresses at the firewall lvl for that socket)
func formatSrcMatch(rule config.Rule, family string) string {
	// determine rule ip-family prefix
	prefix := "ip"
	if family == "ip6" {
		prefix = "ip6"
	}

	// return NFTables config for named address-list/address set
	if rule.SrcList != "" {
		return fmt.Sprintf("%s saddr @%s", prefix, rule.SrcList)
	}

	// return NFTables config for raw srcIP list
	// creates an anonymous set in the rule itself
	if len(rule.SrcIPs) > 0 {
		return fmt.Sprintf("%s saddr { %s }", prefix, strings.Join(rule.SrcIPs, ", "))
	}

	// if nada, return blank string which will be interpreted as 0.0.0.0/0 or 0:: on NFT
	return ""
}

// converts address-list sets or lists (eg src_list = "ssh", src_ips = [...]) into NFTables-parsable syntax
// returns empty str if neither is set (ie allow on all src-addresses at the firewall lvl for that socket)
func formatDstMatch(rule config.Rule, family string) string {
	// determine rule ip-family prefix
	prefix := "ip"
	if family == "ip6" {
		prefix = "ip6"
	}

	// return NFTables config for named address-list/address set
	if rule.SrcList != "" {
		return fmt.Sprintf("%s daddr @%s", prefix, rule.SrcList)
	}

	// return NFTables config for raw srcIP list
	// creates an anonymous set in the rule itself
	if len(rule.SrcIPs) > 0 {
		return fmt.Sprintf("%s daddr { %s }", prefix, strings.Join(rule.SrcIPs, ", "))
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

// creates named address-list groups of IPs/CIDRs
func buildSet(name string, list config.AddressList, addrType string) string {
	var listOutput strings.Builder

	listOutput.WriteString(fmt.Sprintf("\n    set %s {\n", name))
	listOutput.WriteString(fmt.Sprintf("        type %s\n", addrType))
	listOutput.WriteString("        flags interval\n")
	listOutput.WriteString("        auto-merge\n")

	if list.Comment != "" {
		listOutput.WriteString(fmt.Sprintf("        comment \"%s\"\n", "nfty: "+list.Comment))
	}

	listOutput.WriteString(fmt.Sprintf("        elements = { %s }\n", strings.Join(list.Entries, ", ")))
	listOutput.WriteString("    }\n")

	return listOutput.String()
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
		lines = append(lines, buildSSHLogRules()...)
	}

	return lines, nil
}

// builds ratelimiter config, splitting rule into two (accept up to LIMIT, drop else)
func buildRateLimitLines(matchParts []string, rule config.Rule) []string {
	var lines []string

	// under-limit accept
	limitStr := fmt.Sprintf("limit rate %s", rule.RateLimit.Rate)
	if rule.RateLimit.Burst != "" {
		limitStr += fmt.Sprintf(" burst %s", rule.RateLimit.Burst)
	}

	// copy match parts (don't modify the original slice) and append
	// the rate limiter + action
	underParts := append([]string{}, matchParts...)
	underParts = append(underParts, limitStr, "counter", rule.RateLimit.Action)
	if rule.Comment != "" {
		underParts = append(underParts, fmt.Sprintf("comment \"%s\"", "nfty: "+rule.Comment))
	}
	lines = append(lines, "        "+strings.Join(underParts, " "))

	// over-limit handling
	if rule.OverLimit != "" {
		overParts := append([]string{}, matchParts...)
		overParts = append(overParts, "counter", rule.OverLimit)
		lines = append(lines, "        "+strings.Join(overParts, " "))
	}

	return lines
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
		// TODO: move iif warning to safety package sanity-checking
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
			parts = append(parts, fmt.Sprintf("%s dport %s", proto, formatPort(rule.DPort)))
		} else {
			// "meta l4proto tcp" - match protocol without port constraint
			parts = append(parts, fmt.Sprintf("meta l4proto %s", proto))
		}
		// or if icmp/icmp6, do `meta l4` writing
	} else if proto == "icmp" || proto == "icmpv6" {
		// "meta l4proto icmp" or "meta l4proto icmpv6"
		parts = append(parts, fmt.Sprintf("meta l4proto %s", proto))
	}
	// TODO: currently, if proto is "", skip protocol matching entirely

	// src port socket mapping
	if proto == "tcp" || proto == "udp" {
		if len(rule.SPort) > 0 {
			parts = append(parts, fmt.Sprintf("%s sport %s", proto, formatPort(rule.SPort)))
		}
	}

	// src address wrangling
	// either named address-list (@ssh) or array of ips ({10.0.0.1, 10.0.0.2})
	src := formatSrcMatch(rule, family)
	if src != "" {
		parts = append(parts, src)
	}

	// dst address handling
	// likewise either named addylist or array of ips
	dst := formatDstMatch(rule, family)
	if dst != "" {
		parts = append(parts, dst)
	}

	// connection state writing
	if len(rule.CtState) > 0 {
		parts = append(parts, fmt.Sprintf("ct state %s", strings.Join(rule.CtState, ",")))
	}

	return parts
}

// constructs ip or ip6 NFTables table string
// includes address-lists, auto-added rules, each chain, etc.
func buildTable(family string, tableName string, lists map[string]config.AddressList,
	chains config.FamilyChains, policy config.ChainPolicy,
	core config.CoreConfig) (string, error) {

	var tableOutput strings.Builder

	// nftables block starter
	tableOutput.WriteString(fmt.Sprintf("table %s %s {\n", family, tableName))

	// set proper address type based on supplied ip family
	addrType := "ipv4_addr"
	if family == "ip6" {
		addrType = "ipv6_addr"
	}

	// build address-list sets and write them to table output
	for name, list := range lists {
		tableOutput.WriteString(buildSet(name, list, addrType))
	}

	// set priority to 10 to not impede docker's auto-added rules
	filterPrio := 0
	if core.DockerCompat {
		filterPrio = 10
	}

	// input chain rulebuilder
	inputRules, err := buildChainRules(chains.Input, family, core, "input")
	if err != nil {
		return "", err
	}
	tableOutput.WriteString(buildChain("input", "filter", "input", filterPrio, policy.Input, inputRules))

	// forward chain rulebuilder
	fwdRules, err := buildChainRules(chains.Forward, family, core, "forward")
	if err != nil {
		return "", err
	}
	tableOutput.WriteString(buildChain("forward", "filter", "forward", filterPrio, policy.Forward, fwdRules))

	// output chain rulebuilder
	outRules, err := buildChainRules(chains.Output, family, core, "output")
	if err != nil {
		return "", err
	}
	tableOutput.WriteString(buildChain("output", "filter", "output", filterPrio, policy.Output, outRules))

	// postrouting chain rulebuilder
	// always priority 100
	postRules, err := buildChainRules(chains.Postrouting, family, core, "postrouting")
	if err != nil {
		return "", err
	}
	tableOutput.WriteString(buildChain("postrouting", "nat", "postrouting", 100, policy.Postrouting, postRules))

	// wrap up ip(6) table
	tableOutput.WriteString("}\n")
	return tableOutput.String(), nil
}

// build full rule per protocol defined, with match criteria, actions, etc. written in
func buildRule(rule config.Rule, family string) ([]string, error) {
	var results []string

	// parse protool array to accomodate tcp + udp rule definitions
	protocols := rule.Protocol.Protocols
	if len(protocols) == 0 {
		protocols = []string{""}
	}

	// generate one nft rule per protocol
	for _, proto := range protocols {

		// build match portion of rule
		// such as matching interface, protocol, src-address, etc.
		parts := buildMatchCriteria(rule, proto, family)

		// rlimit rules need to be split (1 rule in nfty = 2 rules in nftables)
		if rule.RateLimit != nil {
			results = append(results, buildRateLimitLines(parts, rule)...)
			continue // skip the normal action/comment logic below
		}

		// if log rule hit is enaabled, format log prefix into nftables-syntax
		if rule.Log != nil {
			parts = append(parts, formatLog(rule.Log))
		}

		// add counter tag to each rule
		parts = append(parts, "counter")

		/// add specified action to rule
		parts = append(parts, rule.Action)

		// add comment to every rule nfty writes for obvious reasons
		if rule.Comment != "" {
			parts = append(parts, fmt.Sprintf("comment \"%s\"", "nfty: "+rule.Comment))
		}

		// merge all parts for return
		results = append(results, "        "+strings.Join(parts, " "))
	}

	return results, nil
}
