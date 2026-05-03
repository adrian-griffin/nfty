// config.go
// handles loading and parsing toml files
package config

import (
	"fmt"
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
	ICMPLimit    string `toml:"icmp_limit"`
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

// sanitize and normalize RLIMIT input
func normalizeRateLimit(rate string) (string, error) {
	shortToFull := map[string]string{
		"s": "second",
		"m": "minute",
		"h": "hour",
		"d": "day",
	}

	// splittin strs & validate int portion
	parts := strings.SplitN(rate, "/", 2)
	if len(parts) != 2 {
		return "", fmt.Errorf("invalid rate format %q, expected \"N/unit\"", rate)
	}
	if _, err := strconv.Atoi(parts[0]); err != nil {
		return "", fmt.Errorf("invalid rate in %q: %w", rate, err)
	}

	unit := parts[1]
	// expand shorthand if present
	if full, ok := shortToFull[unit]; ok {
		unit = full
	}

	validUnits := map[string]bool{
		"second": true, "minute": true,
		"hour": true, "day": true,
	}
	if !validUnits[unit] {
		return "", fmt.Errorf("invalid unit %q in rate %q, "+
			"expected second/minute/hour/day (or s/m/h/d)", parts[1], rate)
	}

	return parts[0] + "/" + unit, nil
}

// rule meta information, not defined per-rule in toml
type metaRule struct {
	Rule
	Family string // "ipv4" or "ipv6"
	Chain  string // "input", "forward", "output", "postrouting"
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
	Disabled  bool        `toml:"disable"`    // disable rule
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

	// decode toml, now with actual metadata handling!
	meta, err := toml.Decode(string(data), &cfg)
	if err != nil {
		return nil, fmt.Errorf("parsing config %q: %w", path, err)
	}

	// if any toml keys remain unmapped to struct field,
	// treat them as undecoded and error for each
	if undecoded := meta.Undecoded(); len(undecoded) > 0 {
		keys := make([]string, len(undecoded))
		for i, k := range undecoded {
			keys[i] = k.String()
		}
		return nil, fmt.Errorf("unknown config keys in %q: %s",
			path, strings.Join(keys, ", "))
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

// sanitize and normalize rate limits inputs
func normalizeAllRateLimits(cfg *Config) error {
	chains := []*[]Rule{
		&cfg.Chains.IPv4.Input, &cfg.Chains.IPv4.Forward,
		&cfg.Chains.IPv4.Output, &cfg.Chains.IPv4.Postrouting,
		&cfg.Chains.IPv6.Input, &cfg.Chains.IPv6.Forward,
		&cfg.Chains.IPv6.Output, &cfg.Chains.IPv6.Postrouting,
	}
	for _, chain := range chains {
		for i := range *chain {
			if (*chain)[i].RateLimit != nil && (*chain)[i].RateLimit.Rate != "" {
				normalized, err := normalizeRateLimit((*chain)[i].RateLimit.Rate)
				if err != nil {
					return fmt.Errorf("rule %q: rate_limit.rate: %w",
						(*chain)[i].Comment, err)
				}
				(*chain)[i].RateLimit.Rate = normalized
			}
		}
	}
	return nil
}

// sanitize any input strs
func validateNFTString(value, field string) error {
	if strings.ContainsAny(value, "\"\\\n\r;") {
		return fmt.Errorf("%s must not contain quotes, backslashes, newlines, or semicolons", field)
	}
	return nil
}

// set chains.policy defaults
func setPolicyDefaults(policy *ChainPolicy) {
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

// flattens all chains' rules to a single slice for validation passes
// now with metadata!
func collectRulesMeta(cfg *Config) []metaRule {
	var rules []metaRule

	type chainSource struct {
		family string
		chain  string
		rules  []Rule
	}

	sources := []chainSource{
		{"ipv4", "input", cfg.Chains.IPv4.Input},
		{"ipv4", "forward", cfg.Chains.IPv4.Forward},
		{"ipv4", "output", cfg.Chains.IPv4.Output},
		{"ipv4", "postrouting", cfg.Chains.IPv4.Postrouting},
		{"ipv6", "input", cfg.Chains.IPv6.Input},
		{"ipv6", "forward", cfg.Chains.IPv6.Forward},
		{"ipv6", "output", cfg.Chains.IPv6.Output},
		{"ipv6", "postrouting", cfg.Chains.IPv6.Postrouting},
	}

	for _, src := range sources {
		for _, rule := range src.rules {
			rules = append(rules, metaRule{
				Rule:   rule,
				Family: src.family,
				Chain:  src.chain,
			})
		}
	}
	return rules
}
