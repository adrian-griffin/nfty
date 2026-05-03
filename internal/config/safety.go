// safety.go
// firewall logic and safety
package config

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"

	"github.com/adrian-griffin/nfty/internal/colour"
	"github.com/adrian-griffin/nfty/internal/tools"
)

type Severity int

const (
	SeverityWarn Severity = iota
	SeverityError
)

func (s Severity) String() string {
	if s == SeverityError {
		return "ERROR"
	}
	return "WARNING"
}

type familyInput struct {
	name  string
	input []Rule
}

type SSHSession struct {
	PeerIP   net.IP
	PeerAddr string // raw address as reported by ss, for display
}

type Issue struct {
	Severity Severity
	Category string
	RuleRef  string
	Message  string
	Hint     string
}

// run static config checks
// return issues for check/apply handling
func RunSafetyChecks(cfg *Config) []Issue {
	var issues []Issue
	issues = append(issues, checkSrcRestrictions(cfg)...)
	issues = append(issues, checkChainPolicies(cfg)...)
	issues = append(issues, CheckDefaultRules(cfg)...)
	issues = append(issues, CheckSSHRule(cfg)...)
	issues = append(issues, CheckSSHLockout(cfg)...)

	return issues
}

// writes notifications to stderr
// returns number of found safety issues
func PrintIssues(issues []Issue) int {
	if len(issues) == 0 {
		return 0
	}

	errCount := 0
	tools.Divider()
	for _, i := range issues {
		var marker string
		switch i.Severity {
		case SeverityError:
			marker = colour.Red("  ✗ ERROR  ")
			errCount++
		case SeverityWarn:
			marker = colour.Yellow("  ⚠ WARN   ")
		}

		// print rule reference
		ref := ""
		if i.RuleRef != "" {
			ref = colour.DarkGrey(fmt.Sprintf("  [%s]", i.RuleRef))
		}
		fmt.Fprintf(os.Stderr, "%s%s%s\n", marker, i.Message, ref)

		// hint/subtext
		if i.Hint != "" {
			fmt.Fprintf(os.Stderr, "    %s\n", colour.Grey(i.Hint))
		}
		tools.Divider()
	}
	tools.Divider()
	return errCount
}

// validate source restrictions (interfaces, src_ips, etc)
// warn if open to all
func checkSrcRestrictions(cfg *Config) []Issue {
	var issues []Issue

	for _, rule := range collectAllRules(cfg) {
		if rule.Disabled {
			continue
		}
		// legit any sort of filtering is OK
		if len(rule.SrcIPs) > 0 || rule.SrcList != "" || rule.IIF != "" || rule.IIFName != "" {
			continue
		}
		// only flag if it open a socket
		if len(rule.DPort) == 0 {
			continue
		}

		issues = append(issues, Issue{
			Severity: SeverityWarn,
			Category: "no-source-restriction",
			RuleRef:  rule.Comment,
			Message:  fmt.Sprintf("Rule %q has dport but no source restriction", rule.Comment),
			Hint:     "Likely unintended, leaves port open to all hosts. Dangerous if on a public machine.",
		})
	}

	return issues
}

// validate applied chain policies and warn if typically dangerous
func checkChainPolicies(cfg *Config) []Issue {
	var issues []Issue

	if strings.EqualFold(cfg.Chains.Policy.Input, "accept") {
		issues = append(issues, Issue{
			Severity: SeverityError,
			Category: "input-chain-accept",
			RuleRef:  "chains.policy.input",
			Message:  "Input chain policy is accept. Firewall will allow all input traffic",
			Hint:     "Opens machine to all incoming connections. Dangerous on a public machine!",
		})
	}

	if strings.EqualFold(cfg.Chains.Policy.Forward, "accept") {
		issues = append(issues, Issue{
			Severity: SeverityWarn,
			Category: "forward-chain-accept",
			RuleRef:  "chains.policy.forward",
			Message:  "Forward chain policy is accept. Firewall will allow all forwarded traffic",
			Hint:     "This can make sense on some docker or routing hosts, but is possibly unintended",
		})
	}

	return issues
}

func CheckSSHRule(cfg *Config) []Issue {
	var issues []Issue
	for _, fam := range activeFamilies(cfg) {
		hasSSH := false
		for _, rule := range fam.input {
			if rule.Disabled {
				continue
			}

			// check for ssh
			if portCovers(rule.DPort, 22) && protoIncludes(rule.Protocol, "tcp") && rule.Action == "accept" {
				hasSSH = true
				break
			}
		}
		if !hasSSH {
			issues = append(issues, Issue{
				Severity: SeverityError,
				Category: "no-ssh-input",
				RuleRef:  fmt.Sprintf("%s.input.ssh", fam.name),
				Message:  "No ssh input accept rule found",
				Hint:     "Any active SSH shell sessions will disconnect/time out after a few minutes!",
			})
		}
	}

	return issues
}

// validate default/critical rules exist that are covered by default_rules
func CheckDefaultRules(cfg *Config) []Issue {
	var issues []Issue
	if cfg.Core.DefaultRules {
		return nil
	}
	for _, fam := range activeFamilies(cfg) {
		hasLoopback := false
		hasEstablished := false
		hasDHCPv4 := false
		hasICMPv6 := false

		for _, rule := range fam.input {
			if rule.Disabled {
				continue
			}

			// check for loopback accept
			if (rule.IIF == "lo" || rule.IIFName == "lo") && rule.Action == "accept" {
				hasLoopback = true
			}

			// check for est/rel
			if rule.Action == "accept" && len(rule.CtState) > 0 {
				hasEst := false
				hasRel := false
				for _, state := range rule.CtState {
					switch strings.ToLower(state) {
					case "established":
						hasEst = true
					case "related":
						hasRel = true
					}
				}
				// if both
				if hasEst && hasRel {
					hasEstablished = true
				}
			}

			// family-specific address assignment checks
			switch fam.name {
			case "ipv4":
				if portCovers(rule.DPort, 68) && protoIncludes(rule.Protocol, "udp") && rule.Action == "accept" {
					hasDHCPv4 = true
				}
			case "ipv6":
				if protoIncludes(rule.Protocol, "icmpv6") && rule.Action == "accept" {
					hasICMPv6 = true
				}
			}

		}

		if !hasLoopback {
			issues = append(issues, Issue{
				Severity: SeverityWarn,
				Category: "no-loopback-input",
				RuleRef:  fmt.Sprintf("%s.input", fam.name),
				Message:  "default_rules is disabled and no input loopback accept rule found",
				Hint:     "Local machine services may break after a few minutes",
			})
		}

		if !hasEstablished {
			issues = append(issues, Issue{
				Severity: SeverityWarn,
				Category: "established-related",
				RuleRef:  fmt.Sprintf("%s.input", fam.name),
				Message:  "default_rules is disabled and no input established,related rule found",
				Hint:     "Existing inbound connection states will break unless they are explicitly defined in other rules",
			})
		}

		if fam.name == "ipv4" && !hasDHCPv4 {
			issues = append(issues, Issue{
				Severity: SeverityError,
				Category: "no-dhcpv4-input",
				RuleRef:  "ipv4.input.dhcp",
				Message:  "default_rules is disabled and no ipv4 dhcp input accept rule found",
				Hint:     "If your machine uses DHCP for IP assignment, it will lose its IP after the lease expires!",
			})
		}

		if fam.name == "ipv6" && !hasICMPv6 {
			issues = append(issues, Issue{
				Severity: SeverityWarn,
				Category: "no-icmpv6-input",
				RuleRef:  "ipv6.input.icmpv6",
				Message:  "default_rules is disabled and no icmpv6 input accept rule found",
				Hint:     "NDP and SLAAC require ICMPv6. Without it, you IPv6 address assignment may break",
			})
		}
	}
	return issues
}

// returns families of active IPs on machine
func activeFamilies(cfg *Config) []familyInput {
	fams := []familyInput{
		{"ipv4", cfg.Chains.IPv4.Input},
	}
	// globally-routed ip6 on device then return ipv6
	if tools.HasGlobalIPv6() {
		fams = append(fams, familyInput{"ipv6", cfg.Chains.IPv6.Input})
	}
	return fams
}

// validates that every currently-connected ssh session is explicitly allowed
// if not, ssh terminal disconnect can occur
// If `ss` is unavailable, return an Error Issue
func CheckSSHLockout(cfg *Config) []Issue {
	sessions, err := DetectSSHSessions()
	if err != nil {
		return []Issue{{
			Severity: SeverityWarn,
			Category: "ssh-detect-failed",
			Message:  fmt.Sprintf("Could not detect active SSH sessions: %v", err),
			Hint:     "Lockout safety check skipped. Verify your SSH allowlist manually",
		}}
	}
	if len(sessions) == 0 {
		return nil
	}

	var issues []Issue

	// for each session pulled from ss, validate peer IP allowed for SSH
	for _, sess := range sessions {
		var rules []Rule
		var lists map[string]AddressList
		if sess.PeerIP.To4() != nil {
			rules = cfg.Chains.IPv4.Input
			lists = cfg.Lists.IPv4
		} else {
			rules = cfg.Chains.IPv6.Input
			lists = cfg.Lists.IPv6
		}

		if !peerAllowedSSH(sess.PeerIP, rules, lists) {
			issues = append(issues, Issue{
				Severity: SeverityError,
				Category: "ssh-lockout",
				RuleRef:  sess.PeerAddr,
				Message:  fmt.Sprintf("Active SSH peer %s will be locked out by this config", sess.PeerIP),
				Hint:     "Allow this IP to your SSH list if needed",
			})
		}
	}
	return issues
}

// walks user rules and detects if peer IP is SSH allowed
func peerAllowedSSH(peer net.IP, rules []Rule, lists map[string]AddressList) bool {
	for _, rule := range rules {
		// skip if disabled or non-ssh rule
		if rule.Disabled || !ruleMatchesSSH(rule) {
			continue
		}
		if !ruleMatchesPeer(peer, rule, lists) {
			continue
		}
		switch strings.ToLower(rule.Action) {
		case "accept":
			return true
		case "drop", "reject":
			return false
		}
	}
	return false
}

// detects if rule pertains to ssh 22/tcp
func ruleMatchesSSH(rule Rule) bool {
	has22 := false
	// iterate dport list
	for _, p := range rule.DPort {
		if 22 >= p.Start && 22 <= p.End {
			has22 = true
			break
		}
	}
	if !has22 {
		return false
	}
	// protocol must include tcp
	if len(rule.Protocol.Protocols) == 0 {
		return true
	}
	for _, p := range rule.Protocol.Protocols {
		if strings.EqualFold(p, "tcp") {
			return true
		}
	}
	return false
}

// detects if rule allows active SSH peer's IP
func ruleMatchesPeer(peer net.IP, rule Rule, lists map[string]AddressList) bool {
	// if no src IP contraint
	if len(rule.SrcIPs) == 0 && rule.SrcList == "" {
		return true
	}
	// check provided src_ips
	if ipsContainPeer(peer, []string(rule.SrcIPs)) {
		return true
	}
	// and src_list, if passed
	if rule.SrcList != "" {
		if list, ok := lists[rule.SrcList]; ok {
			if ipsContainPeer(peer, list.Entries) {
				return true
			}
		}
	}
	return false
}

// checks if any CIDR or bare IP in entries contains peer IP
func ipsContainPeer(peer net.IP, entries []string) bool {
	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if _, cidr, err := net.ParseCIDR(entry); err == nil {
			if cidr.Contains(peer) {
				return true
			}
			continue
		}
		if ip := net.ParseIP(entry); ip != nil && ip.Equal(peer) {
			return true
		}
	}
	return false
}

// check ss for active SSH sessions
func DetectSSHSessions() ([]SSHSession, error) {
	cmd := exec.Command("ss", "-tnH", "state", "established", "(", "sport", "=", ":22", ")")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("running ss: %w", err)
	}

	var sessions []SSHSession
	// iterate thru output columns, 3 is what is needed
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		// target field
		peerField := fields[3]
		ip := tools.StripIPPorts(peerField)
		if ip == nil {
			continue
		}
		sessions = append(sessions, SSHSession{
			PeerIP:   ip,
			PeerAddr: peerField, // for display
		})
	}
	return sessions, nil
}

// validates whether any PortValue in the slice contains the target port
func portCovers(ports []PortValue, target int) bool {
	for _, p := range ports {
		if target >= p.Start && target <= p.End {
			return true
		}
	}
	return false
}

// validates whether the ProtoValue contains the target protocol
func protoIncludes(proto ProtoValue, target string) bool {
	for _, p := range proto.Protocols {
		if strings.EqualFold(p, target) {
			return true
		}
	}
	return false
}
