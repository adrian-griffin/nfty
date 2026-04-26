// handles loading and parsing toml files
package config

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/BurntSushi/toml"
)

// top-level struct of parsed toml
type Config struct {
	Core   CoreConfig  `toml:"core"`
	Lists  ListsConfig `toml:"lists"`
	Chains ChainConfig `toml:"chains"`
}

// sub-config struct of parsed core config
type CoreConfig struct {
	Name         string `toml:"name"`
	Description  string `toml:"description"`
	Table        string `toml:"table"`
	DockerCompat bool   `toml:"docker_compat"` // sets prio to 10
	Persist      bool   `toml:"persist"`
	DefaultRules bool   `toml:"default_rules"`
	ICMPv4Limit  string `toml:"icmpv4_limit"`
	ICMPv6Limit  string `toml:"icmpv6_limit"`
	LogSSHFails  bool   `toml:"log_ssh_fails"`
}

// sub-config struct of parsed ip4 and ip6 Lists
type ListsConfig struct {
	IPv4 map[string]AddressList `toml:"ipv4"`
	IPv6 map[string]AddressList `toml:"ipv6"`
}

// sub-config struct for address set objects
type AddressList struct {
	Comment string   `toml:"comment"`
	Entries []string `toml:"entries"`
}

// holds rules for both ip4 and ip6 chains
type ChainConfig struct {
	Policy ChainPolicy  `toml:"policy"`
	IPv4   FamilyChains `toml:"ipv4"`
	IPv6   FamilyChains `toml:"ipv6"`
}

// defines chain policies
type ChainPolicy struct {
	Input       string `toml:"input"`
	Forward     string `toml:"forward"`
	Output      string `toml:"output"`
	Postrouting string `toml:"postrouting"`
}

// defines ip family chain object structure
type FamilyChains struct {
	Input       []Rule `toml:"input"`
	Forward     []Rule `toml:"forward"`
	Output      []Rule `toml:"output"`
	Postrouting []Rule `toml:"postrouting"`
}

// represents single port or a port range
// single ports are ints & ranges are strings (e.g "1024-65535")
type PortValue struct {
	Start int
	End   int
}

// custom objects for more robust toml handling
type ProtoValue struct {
	Protocols []string
}
type StringList []string

// returns final port-value object as string
func (port PortValue) String() string {
	if port.Start == port.End {
		return strconv.Itoa(port.Start)
	}
	return fmt.Sprintf("%d-%d", port.Start, port.End)
}

// validates whether user-supplied port(s) are range or single-value
func (port PortValue) IsSingle() bool {
	return port.Start == port.End
}

// manual unmarshalling of ips to allow slices or str
func (stringlist *StringList) UnmarshalTOML(data interface{}) error {
	switch v := data.(type) {
	case string:
		*stringlist = []string{v}
	case []interface{}:
		for _, item := range v {
			s, ok := item.(string)
			if !ok {
				return fmt.Errorf("list entries must be strings, got %T", item)
			}
			*stringlist = append(*stringlist, s)
		}
	default:
		return fmt.Errorf("expected string or array of strings, got %T", data)
	}
	return nil
}

// manual unmarshalling to catch various port ranges & lists
func (port *PortValue) UnmarshalTOML(data interface{}) error {
	switch value := data.(type) {
	case int64:
		if value < 1 || value > 65535 {
			return fmt.Errorf("port %d out of range (1-65535)", value)
		}
		port.Start = int(value)
		port.End = int(value)
	case string:
		parts := strings.SplitN(value, "-", 2)
		if len(parts) != 2 {
			return fmt.Errorf("invalid port range %q, expected \"start-end\"", value)
		}
		// trim and convert start-port
		start, err := strconv.Atoi(strings.TrimSpace(parts[0]))
		if err != nil {
			return fmt.Errorf("invalid range start in %q: %w", value, err)
		}
		// trim and convert end-port
		end, err := strconv.Atoi(strings.TrimSpace(parts[1]))
		if err != nil {
			return fmt.Errorf("invalid range end in %q: %w", value, err)
		}
		// validate converted range limits
		// and ensure proper port ordering
		if start < 1 || end > 65535 || start > end {
			return fmt.Errorf("invalid port range %d-%d", start, end)
		}
		port.Start = start
		port.End = end
	default:
		return fmt.Errorf("dport value must be an integer or a \"start-end\" string, got %T", data)
	}
	return nil
}

// manual unmarshalling to map protocol array
func (proto *ProtoValue) UnmarshalTOML(data interface{}) error {
	switch value := data.(type) {
	case string:
		proto.Protocols = []string{value}
	case []interface{}:
		for _, item := range value {
			protoItem, ok := item.(string)
			if !ok {
				return fmt.Errorf("protocol list entries must be strings")
			}
			proto.Protocols = append(proto.Protocols, protoItem)
		}
	default:
		return fmt.Errorf("protocol must be a string or list of strings, got %T", data)
	}
	return nil
}

// defines single rule entry, maps directly to nftables design
type Rule struct {
	Comment   string      `toml:"comment"`    // name and description
	IIF       string      `toml:"iif"`        // inbound interface (lo, etc.)
	IIFName   string      `toml:"iifname"`    // inbound interface name match
	OIFName   string      `toml:"oifname"`    // outbound interface name match
	Protocol  ProtoValue  `toml:"protocol"`   // icmp, icmpv6, tcp, udp
	DPort     []PortValue `toml:"dport"`      // destination port(s) or ranges
	SrcList   string      `toml:"src_list"`   // reference to a named address set
	SrcIPs    StringList  `toml:"src_ips"`    // inline source IPs/CIDRs (alternative to src_list)
	CtState   StringList  `toml:"ct_state"`   // conntrack states
	RateLimit *RateLimit  `toml:"rate_limit"` // rate limit packets
	OverLimit string      `toml:"over_limit"` // action when rate exceeded: drop/log
	Log       *LogConfig  `toml:"log"`        // log to kernel/nft logs
	Action    string      `toml:"action"`     // accept, drop, masquerade
	DstList   string      `toml:"dst_list"`   // destination address list
	DstIPs    StringList  `toml:"dst_ips"`    // destination ip array
	SPort     []PortValue `toml:"sport"`      // source port
	Disabled  bool        `toml:"disable"`
}

// define rate-limiter objects
type RateLimit struct {
	Rate   string `toml:"rate"`   // e.g. "50/second"
	Burst  string `toml:"burst"`  // e.g. "100 packets"
	Action string `toml:"action"` // action when under limit
}

// define optional logging
type LogConfig struct {
	Prefix string `toml:"prefix"` // log prefix string
	Level  string `toml:"level"`  // warn, info, debug
}

// parses toml file from path, returns config and/or error
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config %q: %w", path, err)
	}

	var cfg Config
	if _, err := toml.Decode(string(data), &cfg); err != nil {
		return nil, fmt.Errorf("parsing config %q: %w", path, err)
	}

	if err := validateConfig(&cfg); err != nil {
		return nil, fmt.Errorf("invalid config %q: %w", path, err)
	}

	return &cfg, nil
}

// validate chain policy
func validatePolicy(policy *ChainPolicy) error {
	// create lookup map of drop/accept
	valid := map[string]bool{"drop": true, "accept": true}
	// for each chain, validate whether 'drop' or 'accept' are passed
	for _, pair := range []struct{ name, val string }{ // anon struct is created inline
		{"input", policy.Input},
		{"forward", policy.Forward},
		{"output", policy.Output},
		{"postrouting", policy.Postrouting},
	} {
		// for each invalid pair, return error
		if !valid[pair.val] {
			return fmt.Errorf("chains.policy.%s must be \"drop\" or \"accept\", got %q",
				pair.name, pair.val)
		}
	}
	return nil
}

// validates content, ips, chains, options, etc. of supplied configfile
func validateConfig(cfg *Config) error {

	// apply safe defaults if unset policy values
	sanitizePolicyDefaults(&cfg.Chains.Policy)

	// reject invalid policy values
	if err := validatePolicy(&cfg.Chains.Policy); err != nil {
		return err
	}

	// core checks
	if cfg.Core.Name == "" {
		return fmt.Errorf("core.name is required")
	}
	if cfg.Core.Table == "" {
		return fmt.Errorf("core.table is required")
	}

	// validate all address-list entries are valid IPs or CIDRs
	for name, list := range cfg.Lists.IPv4 {
		for _, entry := range list.Entries {
			if err := validateCIDR(entry); err != nil {
				return fmt.Errorf("Lists.ipv4.%s: invalid entry %q: %w", name, entry, err)
			}
		}
	}
	for name, list := range cfg.Lists.IPv6 {
		for _, entry := range list.Entries {
			if err := validateCIDR(entry); err != nil {
				return fmt.Errorf("Lists.ipv6.%s: invalid entry %q: %w", name, entry, err)
			}
		}
	}

	// validate rules
	allRules := collectAllRules(cfg)

	// define valid protocol options
	validProtos := map[string]bool{"tcp": true, "udp": true, "icmp": true, "icmpv6": true}

	// define valid action options
	validActions := map[string]bool{"accept": true, "drop": true, "masquerade": true}

	for _, rule := range allRules {

		// require comment cuz its used as in ID sort of
		if rule.Comment == "" {
			return fmt.Errorf("all rules require a comment")
		}
		// no double quotes that can escape str
		if strings.ContainsAny(rule.Comment, "\"\\") {
			return fmt.Errorf("rule %q: comment must not contain quotes or backslashes", rule.Comment)
		}

		ruleSeen := map[string]bool{}
		for _, rule := range allRules {
			if ruleSeen[rule.Comment] {
				return fmt.Errorf("duplicate rule comment %q", rule.Comment)
			}
			ruleSeen[rule.Comment] = true
		}

		// rate_limit.rate is required if rate_limit is set
		if rule.RateLimit != nil {
			if rule.RateLimit.Rate == "" {
				return fmt.Errorf("rule %q: rate_limit.rate is required", rule.Comment)
			}
			if rule.RateLimit.Action == "" {
				return fmt.Errorf("rule %q: rate_limit.action is required", rule.Comment)
			}
			// validate over_limit is drop or log if set
			if rule.OverLimit != "" && rule.OverLimit != "drop" && rule.OverLimit != "log" {
				return fmt.Errorf("rule %q: over_limit must be \"drop\" or \"log\", got %q",
					rule.Comment, rule.OverLimit)
			}
		}

		// connection state validation
		validStates := map[string]bool{
			"new": true, "established": true, "related": true, "invalid": true, "untracked": true,
		}
		for _, state := range rule.CtState {
			if !validStates[state] {
				return fmt.Errorf("rule %q: invalid ct_state %q", rule.Comment, state)
			}
		}

		// ensure only iif OR iffname are used
		if rule.IIF != "" && rule.IIFName != "" {
			return fmt.Errorf("rule %q: cannot use both iif and iifname", rule.Comment)
		}

		// prevent empty src_list
		if rule.SrcList != "" {
			if list, ok := cfg.Lists.IPv4[rule.SrcList]; ok && len(list.Entries) == 0 {
				return fmt.Errorf("rule %q: list %q exists but has no entries", rule.Comment, rule.SrcList)
			}
			if list, ok := cfg.Lists.IPv6[rule.SrcList]; ok && len(list.Entries) == 0 {
				return fmt.Errorf("rule %q: list %q exists but has no entries", rule.Comment, rule.SrcList)
			}
		}

		// prevent empty dst_list
		if rule.DstList != "" {
			if list, ok := cfg.Lists.IPv4[rule.DstList]; ok && len(list.Entries) == 0 {
				return fmt.Errorf("rule %q: list %q exists but has no entries", rule.Comment, rule.DstList)
			}
			if list, ok := cfg.Lists.IPv6[rule.DstList]; ok && len(list.Entries) == 0 {
				return fmt.Errorf("rule %q: list %q exists but has no entries", rule.Comment, rule.DstList)
			}
		}

		// warn when a rule does not have any src-ip or in-interface matching (ie: open to all)
		if len(rule.SrcIPs) == 0 && rule.SrcList == "" && rule.IIF == "" && rule.IIFName == "" && len(rule.CtState) == 0 {
			if len(rule.DPort) > 0 {
				fmt.Fprintf(os.Stderr, "WARNING: Rule %q has dport but no source restriction (src_list, src_ips, iifname, etc), leaving it open to all addresses from all interfaces\n", rule.Comment)
			}
		}

		// validate src_list references only existing lists
		if rule.SrcList != "" {
			if _, ok := cfg.Lists.IPv4[rule.SrcList]; !ok {
				if _, ok := cfg.Lists.IPv6[rule.SrcList]; !ok {
					return fmt.Errorf("rule: %q references non-existent address list %q", rule.Comment, rule.SrcList)
				}
			}
		}
		// validate dst_list references only existing lists
		if rule.DstList != "" {
			if _, ok := cfg.Lists.IPv4[rule.DstList]; !ok {
				if _, ok := cfg.Lists.IPv6[rule.DstList]; !ok {
					return fmt.Errorf("rule: %q references non-existent address list %q", rule.Comment, rule.DstList)
				}
			}
		}

		// validate src_ips are valid cidr formatting
		for _, ip := range rule.SrcIPs {
			if err := validateCIDR(ip); err != nil {
				return fmt.Errorf("rule %q: invalid src_ips entry %q: %w", rule.Comment, ip, err)
			}
		}

		// validate dst_ips are valid cidr formatting
		for _, ip := range rule.DstIPs {
			if err := validateCIDR(ip); err != nil {
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

		// if over_limit is set, ensure rate_limit is set as well
		if rule.OverLimit != "" && rule.RateLimit == nil {
			return fmt.Errorf("rule %q: over_limit requires rate_limit", rule.Comment)
		}

		// dport requires a protocol
		if len(rule.DPort) > 0 && len(rule.Protocol.Protocols) == 0 {
			return fmt.Errorf("rule %q: dport requires a protocol (tcp or udp)", rule.Comment)
		}

		// and sport requires protocl
		if len(rule.SPort) > 0 && len(rule.Protocol.Protocols) == 0 {
			return fmt.Errorf("rule %q: sport requires a protocol (tcp or udp)", rule.Comment)
		}

	}

	// check user-supplied names for special chars
	for name := range cfg.Lists.IPv4 {
		if strings.ContainsAny(name, " \t\"\\@{}()") {
			return fmt.Errorf("Lists.ipv4.%s: list name contains invalid characters", name)
		}
	}
	for name := range cfg.Lists.IPv6 {
		if strings.ContainsAny(name, " \t\"\\@{}()") {
			return fmt.Errorf("Lists.ipv6.%s: list name contains invalid characters", name)
		}
	}
	// and table name
	if strings.ContainsAny(cfg.Core.Table, " \t\"\\@{}()") {
		return fmt.Errorf("core.table must not contain spaces")
	}

	return nil
}

func sanitizePolicyDefaults(policy *ChainPolicy) {
	if policy.Input == "" {
		policy.Input = "drop"
	}
	if policy.Forward == "" {
		policy.Forward = "drop"
	}
	if policy.Output == "" {
		policy.Output = "accept"
	}
	if policy.Postrouting == "" {
		policy.Postrouting = "accept"
	}
}

// validate whether passed IP string is valid cidr or single-ip notation (ip4, ip6)
func validateCIDR(s string) error {
	// try as CIDR first
	if _, _, err := net.ParseCIDR(s); err == nil {
		return nil
	}
	// try as plain IP
	if net.ParseIP(s) != nil {
		return nil
	}
	return fmt.Errorf("not a valid IP or CIDR: %q", s)
}

// flattens all chains' rules to a single slice for validation passes
func collectAllRules(cfg *Config) []Rule {
	var rules []Rule
	for _, chain := range [][]Rule{
		cfg.Chains.IPv4.Input,
		cfg.Chains.IPv4.Forward,
		cfg.Chains.IPv4.Output,
		cfg.Chains.IPv4.Postrouting,
		cfg.Chains.IPv6.Input,
		cfg.Chains.IPv6.Forward,
		cfg.Chains.IPv6.Output,
		cfg.Chains.IPv6.Postrouting,
	} {
		rules = append(rules, chain...)
	}
	return rules
}
