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

type Issue struct {
	Severity Severity
	Category string
	RuleRef  string // comment, peer addy, etc.
	Message  string
	Hint     string
}

// run static config checks
// return issues for check/apply handling
func RunStaticChecks(cfg *Config) []Issue {
	var issues []Issue
	issues = append(issues, checkSrcRestrictions(cfg)...)
	issues = append(issues, checkChainPolicies(cfg)...)
	issues = append(issues, CheckDefaultRules(cfg)...)

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

	return issues
}

// validate default/critical rules exist that are covered by default_rules
func CheckDefaultRules(cfg *Config) []Issue {
	var issues []Issue

	if cfg.Core.DefaultRules {
		return nil
	}

	// check for critical input rules
	families := []struct {
		name  string
		input []Rule
	}{
		{"ipv4", cfg.Chains.IPv4.Input},
		{"ipv6", cfg.Chains.IPv6.Input},
	}

	// for both v4 & v6
	for _, fam := range families {
		hasLoopback := false
		hasEstablished := false
		hasSSH := false
		hasDHCP := false

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

			// check for ssh
			if portCovers(rule.DPort, 22) && protoIncludes(rule.Protocol, "tcp") && rule.Action == "accept" {
				hasSSH = true
			}

			// check for dhcp
			if portCovers(rule.DPort, 68) && protoIncludes(rule.Protocol, "udp") && rule.Action == "accept" {
				hasDHCP = true
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

		if !hasSSH {
			issues = append(issues, Issue{
				Severity: SeverityError,
				Category: "no-ssh-input",
				RuleRef:  fmt.Sprintf("%s.input.ssh", fam.name),
				Message:  "default_rules is disabled and no ssh input accept rule found",
				Hint:     "Any active SSH shell sessions will disconnect/time out after a few minutes!",
			})
		}

		if !hasDHCP {
			issues = append(issues, Issue{
				Severity: SeverityError,
				Category: "no-dhcp-input",
				RuleRef:  fmt.Sprintf("%s.input.dhcp", fam.name),
				Message:  "default_rules is disabled and no dhcp input accept rule found",
				Hint:     "If your machine uses DHCP for IP assignment, it will lose its IP after the lease expires!",
			})
		}
	}
	return issues
}

type SSHSession struct {
	PeerIP   net.IP // ssh session ip
	PeerAddr string // raw address as reported by ss, for display
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
