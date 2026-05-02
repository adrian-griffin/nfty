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

// run static config checks
func RunStaticChecks(cfg *Config) {
	checkSrcRestrictions(cfg)
	checkChainPolicies(cfg)
}

// validate source restrictions (interfaces, src_ips, etc)
// warn if open to all
func checkSrcRestrictions(cfg *Config) {
	for _, rule := range collectAllRules(cfg) {
		if rule.Disabled {
			return
		}
		// warn when a rule does not have any src-ip or in-interface matching (ie: open to all)
		if len(rule.SrcIPs) == 0 && rule.SrcList == "" && rule.IIF == "" && rule.IIFName == "" {
			if len(rule.DPort) > 0 {
				tools.Divider()
				fmt.Fprintf(os.Stderr, colour.Yellowf("  ⚠ WARNING: Rule %q has dst_port but no source restriction (src_list, src_ips, iifname, etc)\n", rule.Comment))
				fmt.Fprintf(os.Stderr, colour.Grey("    Leaving the socket open from all addresses and interfaces\n"))
				tools.Divider()
			}
		}
	}
}

// validate applied chain policies and warn if typically dangerous
func checkChainPolicies(cfg *Config) {
	if cfg.Chains.Policy.Input == "accept" {
		tools.Divider()
		fmt.Fprintf(os.Stderr, colour.Yellowf("  ⚠ WARNING: Input chain policy is accept\n"))
		fmt.Fprintf(os.Stderr, colour.Grey("    This is likely unintended, and accepts all traffic to this host\n"))
		tools.Divider()
	}
}

// validate default/critical rules exist that are covered by default_rules
func CheckDefaultRules(cfg *Config) {
	if cfg.Core.DefaultRules {
		return
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
			tools.Divider()
			fmt.Fprintf(os.Stderr, colour.Yellowf("  ⚠ WARNING: [%s] default_rules is disabled and no loopback accept rule found\n", fam.name))
			fmt.Fprintf(os.Stderr, colour.Grey("    Without 'iif lo accept', local services may fail to communicate\n"))
			tools.Divider()
		}

		if !hasEstablished {
			tools.Divider()
			fmt.Fprintf(os.Stderr, colour.Yellowf("  ⚠ WARNING: [%s] default_rules is disabled and no established/related accept rule found\n", fam.name))
			fmt.Fprintf(os.Stderr, colour.Grey("    Without conntrack state matching, return traffic for outbound connections will be dropped\n"))
			tools.Divider()
		}

		if !hasSSH {
			tools.Divider()
			fmt.Fprintf(os.Stderr, colour.Redf("  ⚠ WARNING: [%s] default_rules is disabled and no ssh accept rule found\n", fam.name))
			fmt.Fprintf(os.Stderr, colour.Yellow("    Any active SSH shell sessions will time out after a few minutes, please rollback\n"))
			tools.Divider()
		}

		if !hasDHCP {
			tools.Divider()
			fmt.Fprintf(os.Stderr, colour.Yellowf("  ⚠ WARNING: [%s] default_rules is disabled and no dhcp accept rule found\n", fam.name))
			fmt.Fprintf(os.Stderr, colour.Grey("    If your device is using DHCP, it will lose its IP after the lease expires, please rollback if needed\n"))
			tools.Divider()
		}

	}
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
