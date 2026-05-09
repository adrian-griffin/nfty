// validate.go
// validate incoming toml
package config

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/adrian-griffin/nfty/internal/tools"
)

// validates content, ips, chains, options, etc. of supplied configfile
func validateConfig(cfg *Config) error {

	// valid protocol options
	validProtos := map[string]bool{"tcp": true, "udp": true, "icmp": true, "icmpv6": true}

	// valid action options
	validActions := map[string]bool{"accept": true, "drop": true, "masquerade": true}

	// valid log levels
	validLevels := map[string]bool{
		"emerg": true, "alert": true, "crit": true, "err": true,
		"warn": true, "warning": true, "notice": true,
		"info": true, "debug": true,
	}

	// valid connection state options
	validStates := map[string]bool{
		"new": true, "established": true, "related": true, "invalid": true, "untracked": true,
	}

	// valid burst syntax
	burstPattern := regexp.MustCompile(`^\d+ packets$`)

	// apply safe defaults if unset policy values
	setPolicyDefaults(&cfg.Chains.Policy)
	// reject invalid policy values
	if err := validatePolicy(&cfg.Chains.Policy); err != nil {
		return err
	}

	// core checks
	if cfg.Core.Name == "" {
		return fmt.Errorf("core.name is required")
	}
	if err := validateNFTString(cfg.Core.Name, "core.name"); err != nil {
		return err
	}

	if err := validateNFTString(cfg.Core.Description, "core.description"); err != nil {
		return err
	}

	if cfg.Core.Table == "" {
		return fmt.Errorf("core.table is required")
	}

	if cfg.Core.DefaultRules && cfg.Core.ICMPLimit == "" {
		return fmt.Errorf("core.icmp_limit is required when default_rules is enabled")
	}
	if err := validateNFTString(cfg.Core.ICMPLimit, "core.icmp_limit"); err != nil {
		return err
	}

	// validate icmp limit
	if cfg.Core.ICMPLimit != "" {
		normalized, err := normalizeRateLimit(cfg.Core.ICMPLimit)
		if err != nil {
			return fmt.Errorf("core.icmp_limit: %w", err)
		}
		cfg.Core.ICMPLimit = normalized
	}

	// validate all ratelimit syntaxes
	if err := normalizeAllRateLimits(cfg); err != nil {
		return err
	}

	// validate all ipv4 list comments and cidrs are safe
	for name, list := range cfg.Lists.IPv4 {
		if list.Comment != "" {
			if err := validateNFTString(list.Comment, "lists.ipv4.comment"); err != nil {
				return err
			}
		}
		for _, entry := range list.Entries {
			if err := tools.ValidateFamilyCIDR(entry, "ipv4"); err != nil {
				return fmt.Errorf("lists.ipv4.%s: invalid entry %q: %w", name, entry, err)
			}
		}
	}

	// stricter ip list name checking for v4
	for name := range cfg.Lists.IPv4 {
		if err := validateNFTString(name, "lists.ipv4.name"); err != nil {
			return err
		}
		if strings.ContainsAny(name, " \t@{}()") {
			return fmt.Errorf("lists.ipv4.%s: list name contains invalid characters", name)
		}
	}

	// stricter ip list name checking for v6
	for name := range cfg.Lists.IPv6 {
		if err := validateNFTString(name, "lists.ipv6.name"); err != nil {
			return err
		}
		if strings.ContainsAny(name, " \t@{}()") {
			return fmt.Errorf("lists.ipv6.%s: list name contains invalid characters", name)
		}
	}

	// and table name
	if err := validateNFTString(cfg.Core.Table, "core.table.name"); err != nil {
		return err
	}
	if strings.ContainsAny(cfg.Core.Table, " \t@{}()") {
		return fmt.Errorf("table name %s contains invalid characters", cfg.Core.Table)
	}

	// validate all ipv6 list comments and cidrs are safe
	for name, list := range cfg.Lists.IPv6 {
		if list.Comment != "" {
			if err := validateNFTString(list.Comment, "lists.ipv6.comment"); err != nil {
				return err
			}
		}
		for _, entry := range list.Entries {
			if err := tools.ValidateFamilyCIDR(entry, "ipv6"); err != nil {
				return fmt.Errorf("lists.ipv6.%s: invalid entry %q: %w", name, entry, err)
			}
		}
	}

	// collect and validate rules
	allRules := collectRulesMeta(cfg)
	for _, rule := range allRules {

		// require comment cuz its used as in
		if rule.Comment == "" {
			return fmt.Errorf("all rules require a comment")
		}
		// sanitize rule comment
		if err := validateNFTString(rule.Comment, "rule.comment"); err != nil {
			return err
		}

		// validate log prefix and levels
		if rule.Log != nil {
			if rule.Log.Prefix == "" {
				return fmt.Errorf("rule %q: log.prefix is required", rule.Comment)
			}
			if err := validateNFTString(rule.Log.Prefix, "rule.log.prefix"); err != nil {
				return err
			}
			if rule.Log.Level != "" {
				if !validLevels[rule.Log.Level] {
					return fmt.Errorf("rule %q: invalid log level %q",
						rule.Comment, rule.Log.Level)
				}
			}
		}

		// sanitize interface name strings
		for _, field := range []struct{ name, val string }{
			{"iif", rule.IIF},
			{"iifname", rule.IIFName},
			{"oifname", rule.OIFName},
		} {
			if field.val != "" {
				if err := validateNFTString(field.val, "rule.in_interface"); err != nil {
					return err
				}
			}
		}

		// rate_limit.rate is required if rate_limit is set
		if rule.RateLimit != nil {
			if rule.RateLimit.Rate == "" {
				return fmt.Errorf("rule %q: if rate_limit is set, a rate is required", rule.Comment)
			}

			// sanitize burst syntax
			if rule.RateLimit.Burst != "" {
				if !burstPattern.MatchString(rule.RateLimit.Burst) {
					return fmt.Errorf("rule %q: rate_limit.burst must be \"N packets\", got %q",
						rule.Comment, rule.RateLimit.Burst)
				}
			}

			// validate over_limit is drop or log if set
			if rule.OverLimit != "" && rule.OverLimit != "drop" && rule.OverLimit != "log" {
				return fmt.Errorf("rule %q: over_limit must be \"drop\" or \"log\", got %q",
					rule.Comment, rule.OverLimit)
			}
		}

		for _, state := range rule.CtState {
			if !validStates[strings.ToLower(state)] {
				return fmt.Errorf("rule %q: invalid ct_state %q", rule.Comment, state)
			}
		}

		// ensure only iif OR iffname are used
		if rule.IIF != "" && rule.IIFName != "" {
			return fmt.Errorf("rule %q: cannot use both iif and iifname", rule.Comment)
		}

		// validate src_ips are valid cidr formatting
		for _, ip := range rule.SrcIPs {
			if err := tools.ValidateCIDR(ip); err != nil {
				return fmt.Errorf("rule %q: invalid src_ips entry %q: %w", rule.Comment, ip, err)
			}
		}

		// validate dst_ips are valid cidr formatting
		for _, ip := range rule.DstIPs {
			if err := tools.ValidateCIDR(ip); err != nil {
				return fmt.Errorf("rule %q: invalid dst_ips entry %q: %w", rule.Comment, ip, err)
			}
		}

		// can't use both src_list and src_ips on the same rule
		if rule.SrcList != "" && len(rule.SrcIPs) > 0 {
			return fmt.Errorf("rule %q: cannot use both src_list and src_ips", rule.Comment)
		}

		// mutually exclusive dstlist/dstips
		if rule.DstList != "" && len(rule.DstIPs) > 0 {
			return fmt.Errorf("rule %q: cannot use both dst_list and dst_ips", rule.Comment)
		}

		// dport is only valid with tcp or udp protos
		if len(rule.DPort) > 0 {
			for _, proto := range rule.Protocol.Protocols {
				if proto != "tcp" && proto != "udp" {
					return fmt.Errorf("rule %q: dst_port is only valid with tcp or udp, got %q",
						rule.Comment, proto)
				}
			}
		}
		// sport is only valid w/ tcp or udp protos
		if len(rule.SPort) > 0 {
			for _, proto := range rule.Protocol.Protocols {
				if proto != "tcp" && proto != "udp" {
					return fmt.Errorf("rule %q: src_port is only valid with tcp or udp, got %q",
						rule.Comment, proto)
				}
			}
		}

		// tcp or udp only can be passed with corresponding dport number
		if len(rule.Protocol.Protocols) > 0 {
			for _, proto := range rule.Protocol.Protocols {
				if proto == "tcp" || proto == "udp" {
					if len(rule.DPort) == 0 {
						return fmt.Errorf("rule %q: protocol udp or tcp only valid with dport",
							rule.Comment)
					}
				}
			}
		}

		// validate protocols are valid (eg: tcp/udp/icmp/icmpv6)
		for _, proto := range rule.Protocol.Protocols {
			if !validProtos[proto] {
				return fmt.Errorf("rule %q: invalid protocol %q", rule.Comment, proto)
			}
		}

		// validate action is valid (eg: accept/drop/masquerade)
		if rule.Action == "" {
			return fmt.Errorf("rule %q: action is required", rule.Comment)
		}
		if !validActions[rule.Action] {
			return fmt.Errorf("rule %q: action must be accept, drop, or masquerade, got %q",
				rule.Comment, rule.Action)
		}

		// ensure masq is only used on postrouting
		if rule.Action == "masquerade" && rule.Chain != "postrouting" {
			return fmt.Errorf("rule %q: masquerade is only valid on postrouting chains, found in %s.%s",
				rule.Comment, rule.Family, rule.Chain)
		}

		// ensure iifname is not used with output or post chain
		if rule.IIFName != "" && (rule.Chain == "output" || rule.Chain == "postrouting") {
			return fmt.Errorf("rule %q: iifname has no effect on %s chain", rule.Comment, rule.Chain)
		}

		// ensure iif is not used with output or post chain
		if rule.IIF != "" && (rule.Chain == "output" || rule.Chain == "postrouting") {
			return fmt.Errorf("rule %q: iif has no effect on %s chain", rule.Comment, rule.Chain)
		}

		// ensure oifname is not used with input chain
		if rule.OIFName != "" && rule.Chain == "input" {
			return fmt.Errorf("rule %q: oifname has no effect on input chain", rule.Comment)
		}

		// max cap rule comment
		if len("nfty: "+rule.Comment) > 110 {
			return fmt.Errorf("rule %q: comment too long", rule.Comment)
		}
		// max cap log prefix
		if rule.Log != nil && len(rule.Log.Prefix) > 63 {
			return fmt.Errorf("rule %q: log prefix too long", rule.Comment)
		}

		// if over_limit is set, ensure rate_limit is set as well
		if rule.OverLimit != "" && rule.RateLimit == nil {
			return fmt.Errorf("rule %q: over_limit requires rate_limit", rule.Comment)
		}

		// dport requires a protocol
		if len(rule.DPort) > 0 && len(rule.Protocol.Protocols) == 0 {
			return fmt.Errorf("rule %q: dport requires a protocol (tcp or udp)", rule.Comment)
		}

		// and sport requires protocol
		if len(rule.SPort) > 0 && len(rule.Protocol.Protocols) == 0 {
			return fmt.Errorf("rule %q: sport requires a protocol (tcp or udp)", rule.Comment)
		}

		// cannot log & rlimit
		if rule.RateLimit != nil && rule.Log != nil {
			return fmt.Errorf("rule %q: log and rate_limit cannot be used together",
				rule.Comment)
		}

	}

	// validate src_list references only existing lists
	for _, rule := range allRules {
		var lists map[string]AddressList
		if rule.Family == "ipv4" {
			lists = cfg.Lists.IPv4
		} else {
			lists = cfg.Lists.IPv6
		}

		// prevent empty src_list
		if rule.SrcList != "" {
			var lists map[string]AddressList
			if rule.Family == "ipv4" {
				lists = cfg.Lists.IPv4
			} else {
				lists = cfg.Lists.IPv6
			}
			if list, ok := lists[rule.SrcList]; ok && len(list.Entries) == 0 {
				return fmt.Errorf("rule %q: list %q exists but has no entries", rule.Comment, rule.SrcList)
			}
		}

		// prevent empty dst_list
		if rule.DstList != "" {
			var lists map[string]AddressList
			if rule.Family == "ipv4" {
				lists = cfg.Lists.IPv4
			} else {
				lists = cfg.Lists.IPv6
			}
			if list, ok := lists[rule.DstList]; ok && len(list.Entries) == 0 {
				return fmt.Errorf("rule %q: list %q exists but has no entries", rule.Comment, rule.DstList)
			}
		}

		if rule.SrcList != "" {
			if _, ok := lists[rule.SrcList]; !ok {
				return fmt.Errorf("rule %q in %s chain references list %q which doesn't exist in %s lists",
					rule.Comment, rule.Family, rule.SrcList, rule.Family)
			}
		}
		if rule.DstList != "" {
			if _, ok := lists[rule.DstList]; !ok {
				return fmt.Errorf("rule %q in %s chain references list %q which doesn't exist in %s lists",
					rule.Comment, rule.Family, rule.DstList, rule.Family)
			}
		}
	}

	// validate no dupes on comments
	ruleSeen := map[string]bool{}
	for _, rule := range allRules {
		if ruleSeen[rule.Comment] {
			return fmt.Errorf("duplicate rule comment %q", rule.Comment)
		}
		ruleSeen[rule.Comment] = true
	}

	return nil
}
