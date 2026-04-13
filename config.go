// handles loading and parsing toml files
package config

import (
	"fmt"
	"net"
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

// defines single rule entry, maps directly to nftables design
type Rule struct {
	Comment   string    `toml:"comment"`
	IIF       string    `toml:"iif"`      // inbound interface (lo, etc.)
	IIFName   string    `toml:"iifname"`  // inbound interface name match
	OIFName   string    `toml:"oifname"`  // outbound interface name match
	Protocol  string    `toml:"protocol"` // icmp, icmpv6, tcp, udp
	DPort     []int     `toml:"dport"`    // destination port(s)
	SrcSet    string    `toml:"src_set"`  // reference to a named address set
	CtState   []string  `toml:"ct_state"` // conntrack states
	RateLimit RateLimit `toml:"rate_limit"`
	OverLimit string    `toml:"over_limit"` // action when rate exceeded: drop/log
	Log       LogConfig `toml:"log"`
	Action    string    `toml:"action"` // accept, drop, masquerade
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
