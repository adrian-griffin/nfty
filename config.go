// handles loading and parsing toml files
package config

import (
	"fmt"
	"net"
	"os"

	"github.com/BurntSushi/toml"
)

// top-level struct of parsed toml
type Config struct {
	Core   CoreConfig  `toml:"core"`
	Sets   SetsConfig  `toml:"sets"`
	Chains ChainConfig `toml:"chains"`
}

// sub-config struct of parsed core config
type CoreConfig struct {
	Name         string `toml:"name"`
	Description  string `toml:"description"`
	Table        string `toml:"table"`
	DockerCompat bool   `toml:"docker_compat"` // sets chain priority 10
	Persist      bool   `toml:"persist"`       // reapply on boot via systemd
}

// sub-config struct of parsed ip4 and ip6 sets
type SetsConfig struct {
	IPv4 map[string]AddressSet `toml:"ipv4"`
	IPv6 map[string]AddressSet `toml:"ipv6"`
}

// sub-config struct for address set objects
type AddressSet struct {
	Comment string   `toml:"comment"`
	Entries []string `toml:"entries"`
}

// holds rules for both ip4 and ip6 chains
type ChainConfig struct {
	IPv4 FamilyChains `toml:"ipv4"`
	IPv6 FamilyChains `toml:"ipv6"`
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

// defines single rule entry, maps directly to nftables design
type Rule struct {
	Comment   string      `toml:"comment"`  //name and description
	IIF       string      `toml:"iif"`      // inbound interface (lo, etc.)
	IIFName   string      `toml:"iifname"`  // inbound interface name match
	OIFName   string      `toml:"oifname"`  // outbound interface name match
	Protocol  string      `toml:"protocol"` // icmp, icmpv6, tcp, udp
	DPort     []PortValue `toml:"dport"`    // destination port(s) or ranges
	SrcSet    string      `toml:"src_set"`  // reference to a named address set
	SrcIPs    []string    `toml:"src_ips"`  // inline source IPs/CIDRs (alternative to src_set)
	CtState   []string    `toml:"ct_state"` // conntrack states
	RateLimit *RateLimit  `toml:"rate_limit"`
	OverLimit string      `toml:"over_limit"` // action when rate exceeded: drop/log
	Log       *LogConfig  `toml:"log"`
	Action    string      `toml:"action"` // accept, drop, masquerade
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

	if err := validate(&cfg); err != nil {
		return nil, fmt.Errorf("invalid config %q: %w", path, err)
	}

	return &cfg, nil
}

// validates content, ips
func validate(cfg *Config) error {
	// core checks
	if cfg.Core.Name == "" {
		return fmt.Errorf("core.name is required")
	}
	if cfg.Core.Table == "" {
		return fmt.Errorf("core.table is required")
	}

	// validate all address set entries are valid IPs or CIDRs
	for name, set := range cfg.Sets.IPv4 {
		for _, entry := range set.Entries {
			if err := validateCIDR(entry); err != nil {
				return fmt.Errorf("sets.ipv4.%s: invalid entry %q: %w", name, entry, err)
			}
		}
	}
	for name, set := range cfg.Sets.IPv6 {
		for _, entry := range set.Entries {
			if err := validateCIDR(entry); err != nil {
				return fmt.Errorf("sets.ipv6.%s: invalid entry %q: %w", name, entry, err)
			}
		}
	}

	// validate rules
	allRules := collectAllRules(cfg)
	for _, rule := range allRules {
		// validate src_set references point to sets that exist
		if rule.SrcSet != "" {
			if _, ok := cfg.Sets.IPv4[rule.SrcSet]; !ok {
				if _, ok := cfg.Sets.IPv6[rule.SrcSet]; !ok {
					return fmt.Errorf("rule %q references undefined set %q", rule.Comment, rule.SrcSet)
				}
			}
		}

		// validate inline src_ips are valid
		for _, ip := range rule.SrcIPs {
			if err := validateCIDR(ip); err != nil {
				return fmt.Errorf("rule %q: invalid src_ips entry %q: %w", rule.Comment, ip, err)
			}
		}

		// can't use both src_set and src_ips on the same rule
		if rule.SrcSet != "" && len(rule.SrcIPs) > 0 {
			return fmt.Errorf("rule %q: cannot use both src_set and src_ips", rule.Comment)
		}
	}

	return nil
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
