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
